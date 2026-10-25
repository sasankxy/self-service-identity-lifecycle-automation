"""Quarantine boundary (dual-LLM / CaMeL-style): untrusted text -> typed, validated slots. Nothing else crosses.

The extractor (NLU, or the SLM fallback) reads the user's words; the planner only ever receives a `Slots` object. Every field is
either an enum, a date, a bounded name matching a strict pattern, or a value that exists in the live directory catalogue. A prompt
injection can therefore at worst produce a wrong-but-valid slot value, which the user sees and confirms and the policy engine
re-checks; it can never become an instruction, a tool name or an argument the schema doesn't know.

Free-text fields that must survive (reason, an unresolved date expression) are bounded strings stored as data on the request; the
planner copies them verbatim and nothing downstream interprets them.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

Label = Literal["MOVER", "ACCESS_REQUEST", "ACCESS_REVOCATION", "LEAVER", "ACCESS_STATUS_QUERY"]
PERSON_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,79}$")
EMPLOYEE_ID_RE = re.compile(r"^[A-Za-z0-9-]{2,40}$")


class Slots(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    label: Label
    person: Annotated[str, StringConstraints(pattern=PERSON_RE.pattern)] | None = None
    employee_id: Annotated[str, StringConstraints(pattern=EMPLOYEE_ID_RE.pattern)] | None = None
    target_department: str | None = None
    access_profile: Annotated[str, StringConstraints(max_length=120)] | None = None
    applications: tuple[str, ...] = ()
    entitlements: tuple[str, ...] = ()
    effective_date: date | None = None
    date_text: Annotated[str, StringConstraints(max_length=80)] | None = None
    reason: Annotated[str, StringConstraints(max_length=300)] | None = None


def _canon(value, allowed: list[str]) -> str | None:
    if not isinstance(value, str):
        return None
    if not allowed:                       # catalogue not loaded: keep the value; the tools validate against the DB
        return value.strip() or None
    v = value.strip().lower()
    return next((a for a in allowed if a.lower() == v), None)


def quarantine(label: str, s: dict, catalogue: dict | None) -> tuple[Slots, dict[str, list[str]]]:
    """Map the extractor's raw slot dict to Slots. Returns (slots, dropped) where dropped lists values that did not validate."""
    cat = catalogue or {}
    dropped: dict[str, list[str]] = {}

    def keep(field: str, value, allowed: list[str]):
        c = _canon(value, allowed)
        if value and c is None:
            dropped.setdefault(field, []).append(str(value)[:80])
        return c

    person = s.get("person") if isinstance(s.get("person"), str) and PERSON_RE.match(s["person"].strip()) else None
    if s.get("person") and not person:
        dropped.setdefault("person", []).append(str(s["person"])[:80])
    emp = s.get("employee_id") if isinstance(s.get("employee_id"), str) and EMPLOYEE_ID_RE.match(s["employee_id"]) else None
    d = s.get("effective_date") or {}
    eff = None
    if d.get("resolved"):
        try:
            eff = date.fromisoformat(d["value"])
        except (TypeError, ValueError):
            dropped.setdefault("effective_date", []).append(str(d.get("value"))[:40])
    apps = tuple(a for a in (keep("applications", x, cat.get("applications") or []) for x in s.get("applications") or []) if a)
    ents = tuple(e for e in (keep("entitlements", x, cat.get("entitlements") or []) for x in s.get("access_roles") or []) if e)
    reason = (s.get("reason") or "").strip()[:300] or None if isinstance(s.get("reason"), str) else None
    slots = Slots(label=label, person=person.strip() if person else None, employee_id=emp,
                  target_department=keep("target_department", s.get("target_department"), cat.get("departments") or []),
                  access_profile=(s.get("access_profile") or "").strip()[:120] or None if isinstance(s.get("access_profile"), str) else None,
                  applications=apps, entitlements=ents, effective_date=eff,
                  date_text=None if d.get("resolved") else (str(d.get("expression"))[:80] if d.get("expression") else None), reason=reason)
    return slots, dropped
