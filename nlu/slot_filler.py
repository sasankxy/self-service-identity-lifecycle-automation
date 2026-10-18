"""Slot filling: maps normalised entities to intent-specific slots without inventing values."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .preprocessing import Doc
from .schemas import LIST_SLOTS, REQUIRED_SLOTS, SLOT_SCHEMAS, Entity


def amb(type_: str, message: str, blocking: bool, question: Optional[str] = None,
        candidates: Optional[list] = None, field: Optional[str] = None) -> dict:
    return {"type": type_, "blocking": blocking, "message": message, "candidates": candidates or [],
            "field": field, "_question": question}


def assign_department_roles(doc: Doc, depts: List[Entity], cfg: dict) -> List[Optional[str]]:
    """Role of each department from the cue word before it: 'source' | 'target' | 'neutral' | None.

    The first department is NOT assumed to be the source; a role is only assigned when a cue word
    (from / to / into / leaving / joining / for / in ...) precedes the mention (determiners skipped).
    """
    cues, dets = cfg["department_role_cues"], set(cfg["determiners"])
    roles = []
    for d in depts:
        i, _ = doc.span_to_tokens(d.start, d.end)
        j = i - 1
        while j >= 0 and doc.tokens[j].norm in dets:
            j -= 1
        role = None
        if j >= 0:
            w = doc.tokens[j].norm
            if w == "of" and j > 0 and doc.tokens[j - 1].norm == "out":
                role = "source"
            else:
                for r in ("source", "target", "neutral"):
                    if w in cues[r]:
                        role = r
                        break
        roles.append(role)
    return roles


def _inside(doc: Doc, tok_idx: int, ents: List[Entity]) -> bool:
    t = doc.tokens[tok_idx]
    return any(e.start <= t.start and t.end <= e.end for e in ents)


class SlotResult:
    def __init__(self, slots, missing, ambiguities, used, unresolved):
        self.slots, self.missing, self.ambiguities = slots, missing, ambiguities
        self.used, self.unresolved = used, unresolved


class SlotFiller:
    def __init__(self, patterns_cfg: dict):
        self.cfg = patterns_cfg
        self.self_words = set(patterns_cfg["pronouns"]["self"])
        self.third_words = set(patterns_cfg["pronouns"]["third_person"])

    def fill(self, intent: str, doc: Doc, ents: List[Entity]) -> SlotResult:
        schema = SLOT_SCHEMAS[intent]
        slots: Dict[str, Any] = {k: ([] if k in LIST_SLOTS else None) for k in schema}
        ambs: List[dict] = []
        used: List[Entity] = []
        unresolved: Dict[str, List[str]] = {}
        if intent == "UNKNOWN":
            return SlotResult(slots, [], ambs, used, unresolved)
        by = lambda t: [e for e in ents if e.type == t]

        # ---- person / employee id / self reference
        persons, eids = by("PERSON"), by("EMPLOYEE_IDENTIFIER")
        if len(persons) == 1:
            slots["person"] = persons[0].normalized
            used.append(persons[0])
            if len(persons[0].text.split()) == 1:
                ambs.append(amb("partial_name", f"Only '{persons[0].text}' was given; a full name may be needed "
                                "downstream to identify the employee.", False, field="person"))
        elif len(persons) > 1:
            names = [p.normalized for p in persons]
            ambs.append(amb("multiple_persons", f"Several people are mentioned: {', '.join(names)}.", True,
                            f"I found several people ({', '.join(names)}). Which one is this request for?",
                            names, "person"))
            used.extend(persons)
        if len(eids) == 1:
            slots["employee_id"] = eids[0].normalized
            used.append(eids[0])
        elif len(eids) > 1:
            ids = [e.normalized for e in eids]
            ambs.append(amb("multiple_employee_ids", f"Several employee identifiers: {', '.join(ids)}.", True,
                            "Which employee ID is this request for?", ids, "person"))
            used.extend(eids)
        free = [t for t in doc.tokens if not _inside(doc, t.index, ents)]
        if not persons and not eids:
            if any(t.norm in self.self_words for t in free):
                slots["subject_reference"] = "SELF"
            elif any(t.norm in self.third_words for t in free):
                ambs.append(amb("unresolved_pronoun", "A pronoun is used but no employee is named.", True,
                                "Who does the pronoun (he/she/they/him/her) refer to? Please give the employee's name or ID.",
                                field="person"))

        # ---- departments
        depts = by("DEPARTMENT")
        if depts and intent in ("JOINER", "MOVER", "LEAVER"):
            roles = assign_department_roles(doc, depts, self.cfg)
            self._fill_departments(intent, depts, roles, slots, ambs, used, unresolved)

        # ---- applications / roles
        for key, etype in (("applications", "APPLICATION"), ("access_roles", "ACCESS_ROLE")):
            if key not in slots:
                continue
            for e in by(etype):
                used.append(e)
                if e.normalized:
                    if e.normalized not in slots[key]:
                        slots[key].append(e.normalized)
                else:
                    unresolved.setdefault(key, []).append(e.text)
                    kind = "application" if etype == "APPLICATION" else "access_role"
                    ambs.append(amb(f"unknown_{kind}", f"'{e.text}' is not in the configured {kind.replace('_', ' ')} dictionary.",
                                    True, f"I don't recognise '{e.text}'. Which {kind.replace('_', ' ')} do you mean?",
                                    [e.text], key))

        # ---- date
        dates = by("EFFECTIVE_DATE")
        if "effective_date" in slots and dates:
            used.extend(dates)
            if len(dates) > 1:
                ambs.append(amb("multiple_dates", "Several dates are mentioned: " + ", ".join(d.text for d in dates) + ".",
                                True, "Which date should apply? " + " / ".join(d.text for d in dates),
                                [d.text for d in dates], "effective_date"))
            else:
                n = dates[0].normalized
                slots["effective_date"] = {"value": n["value"], "expression": n["expression"], "resolved": n["resolved"]}
                if n.get("ambiguous"):
                    ambs.append(amb("ambiguous_date", f"'{n['expression']}' could mean {' or '.join(n['candidates'])}.", True,
                                    f"Did you mean {' or '.join(n['candidates'])} for '{n['expression']}'?",
                                    n["candidates"], "effective_date"))
                elif not n["resolved"]:
                    ambs.append(amb("unresolved_date", f"'{n['expression']}' cannot be turned into a specific date "
                                    f"({n.get('reason')}); kept as an unresolved expression.", False, field="effective_date"))
                elif n.get("in_past"):
                    ambs.append(amb("date_in_past", f"'{n['expression']}' resolves to a past date ({n['value']}).",
                                    False, field="effective_date"))

        # ---- reason
        reasons = by("REASON")
        if "reason" in slots and reasons:
            slots["reason"] = reasons[0].normalized
            used.append(reasons[0])

        # ---- fuzzy dictionary matches (typos)
        for e in ents:
            if e.match == "fuzzy" and e.normalized:
                ambs.append(amb("fuzzy_match", f"'{e.text}' was interpreted as '{e.normalized}' (typo tolerance).",
                                False, candidates=[e.normalized]))

        missing = self._missing(intent, slots)
        return SlotResult(slots, missing, ambs, used, unresolved)

    # ---------------------------------------------------------------------
    def _fill_departments(self, intent, depts, roles, slots, ambs, used, unresolved):
        def val(e):
            if e.normalized:
                return e.normalized
            unresolved.setdefault("department", []).append(e.text)
            ambs.append(amb("unknown_department", f"'{e.text}' is not in the configured department dictionary.", True,
                            f"I don't recognise the department '{e.text}'. Which department do you mean?",
                            [e.text], "department"))
            return None

        by_role: Dict[Optional[str], List[Entity]] = {}
        for d, r in zip(depts, roles):
            by_role.setdefault(r, []).append(d)
        used.extend(depts)

        def single(role_keys, slot_name):
            cands = [d for r in role_keys for d in by_role.get(r, [])]
            if len(cands) == 1:
                slots[slot_name] = val(cands[0])
            elif len(cands) > 1:
                names = [d.text for d in cands]
                ambs.append(amb("conflicting_department_roles", f"Several departments are given as {slot_name}: {', '.join(names)}.",
                                True, f"Several departments could be the {slot_name.replace('_', ' ')} ({', '.join(names)}). Which one is it?",
                                names, slot_name))

        if intent == "MOVER":
            single(["source"], "source_department")
            single(["target"], "target_department")
            leftovers = by_role.get(None, []) + by_role.get("neutral", [])
            for d in leftovers:
                ambs.append(amb("ambiguous_department_roles",
                                f"Cannot tell whether '{d.text}' is the source or the target department.", True,
                                f"Is '{d.text}' the department the person is moving from or moving to?",
                                [d.text], "target_department"))
            s, t = slots.get("source_department"), slots.get("target_department")
            if s and t and s == t:
                ambs.append(amb("same_source_and_target", f"Source and target department are both '{s}'.", True,
                                f"The source and target are both {s}. Which department is the person moving to?",
                                [s], "target_department"))
        elif intent == "JOINER":
            single(["target", "neutral"], "target_department")
            for d in by_role.get(None, []) + by_role.get("source", []):
                ambs.append(amb("unassigned_department", f"Department '{d.text}' has no clear role in a joiner request; not used.",
                                False, candidates=[d.text]))
        elif intent == "LEAVER":
            single(["source", "neutral"], "department")
            for d in by_role.get(None, []) + by_role.get("target", []):
                ambs.append(amb("unassigned_department", f"Department '{d.text}' has no clear role in a leaver request; not used.",
                                False, candidates=[d.text]))

    def _missing(self, intent: str, slots: dict) -> List[str]:
        out = []
        for req in REQUIRED_SLOTS[intent]:
            if req == "person":
                if not (slots.get("person") or slots.get("employee_id") or slots.get("subject_reference")):
                    out.append("person")
            elif not slots.get(req):
                out.append(req)
        return out
