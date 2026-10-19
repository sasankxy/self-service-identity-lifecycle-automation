"""Ambiguity detection, clarification questions and final status decision."""
from __future__ import annotations

from typing import List, Optional, Tuple

from .schemas import (STATUS_NEEDS_CLARIFICATION, STATUS_PARSED, STATUS_UNKNOWN_INTENT, Entity)
from .slot_filler import amb

MISSING_QUESTIONS = {
    "person": "Which employee is this request for? Please give a name or employee ID.",
    "target_department": "Which department should the employee move to?",
    "applications": "Which application is this about?",
}
INTENT_NAMES = {"JOINER": "onboarding", "MOVER": "a department move", "LEAVER": "offboarding",
                "ACCESS_REQUEST": "an access request", "ACCESS_REVOCATION": "an access revocation",
                "ACCESS_STATUS_QUERY": "an access status check"}


def analyze(intent: dict, slot_result, entities: List[Entity], conflicts: List[dict],
            unknown_question: str) -> Tuple[List[dict], List[str], str]:
    ambs: List[dict] = []
    label = intent["label"]

    # ---- intent-level problems
    if label == "UNKNOWN":
        if intent.get("negated_candidates"):
            names = ", ".join(INTENT_NAMES[c] for c in intent["negated_candidates"])
            ambs.append(amb("negated_action", f"The request negates {names}; no action is requested.", True,
                            f"You mention NOT doing {names}. Do you want to cancel something, or request a different action?"))
        elif intent.get("unsupported"):
            ambs.append(amb("unsupported_request", "The request looks outside the supported identity lifecycle scope.", True,
                            "I can only help with joiners, movers, leavers and access requests, revocations or status checks. "
                            "Could you rephrase your request in those terms?"))
        else:
            ambs.append(amb("unknown_intent", "No supported intent could be determined.", True, unknown_question))
    else:
        if intent.get("conflict"):
            cands = [c["label"] for c in intent["candidates"]]
            ambs.append(amb("multiple_intents", "The text contains several competing requests: " + ", ".join(cands) + ".", True,
                            "This looks like more than one request (" + ", ".join(INTENT_NAMES.get(c, c) for c in cands) +
                            "). Which one should I handle first?", cands))
        if intent.get("negated_candidates"):
            names = ", ".join(INTENT_NAMES[c] for c in intent["negated_candidates"])
            ambs.append(amb("mixed_negation", f"Part of the request is negated ({names}) while another part is affirmative; "
                            "extracted entities may belong to the negated part.", True,
                            f"You say not to do {names} but also ask for {INTENT_NAMES.get(label, label)}. "
                            "Please confirm what exactly should be done."))
        if intent.get("model_disagreement"):
            ambs.append(amb("intent_model_disagreement",
                            f"The statistical model prefers {intent['statistical']['label']}; the rule baseline decided {label}.",
                            False, candidates=[intent["statistical"]["label"]]))
        ambs.extend(slot_result.ambiguities)

        used_ids = {id(e) for e in slot_result.used}
        for e in entities:
            if e.type != "ACTION" and id(e) not in used_ids:
                ambs.append(amb("unused_entity", f"'{e.text}' ({e.type}) was found but is not used by the {label} slot schema.",
                                False, candidates=[e.text]))

    # ---- NER overlap conflicts worth reporting
    for c in conflicts:
        if c["significant"]:
            k, d = c["kept"], c["discarded"]
            ambs.append(amb("overlapping_entities",
                            f"'{d.text}' could be {d.type} but overlaps '{k.text}' ({k.type}); kept {k.type} ({c['reason']}).",
                            False, candidates=[k.type, d.type]))

    missing = slot_result.missing if label != "UNKNOWN" else []
    covered_fields = {a["field"] for a in ambs if a["blocking"] and a.get("field")}
    questions: List[str] = []
    for a in ambs:
        if a["blocking"] and a.get("_question") and a["_question"] not in questions:
            questions.append(a["_question"])
    for m in missing:
        if m in covered_fields or (m == "person" and any(a["type"] in ("unresolved_pronoun", "multiple_persons") for a in ambs)):
            continue
        q = MISSING_QUESTIONS.get(m, f"Please provide the missing information: {m}.")
        if q not in questions:
            questions.append(q)

    if label == "UNKNOWN":
        status = STATUS_UNKNOWN_INTENT
    elif missing or any(a["blocking"] for a in ambs):
        status = STATUS_NEEDS_CLARIFICATION
    else:
        status = STATUS_PARSED
    for a in ambs:
        a.pop("_question", None)
    return ambs, questions, status
