"""Planner (privileged side of the quarantine): typed Slots -> whitelisted ToolCalls. It never sees the user's text.

* plan_call      one intent -> exactly one tool call
* split_clauses  "Move Kai to Finance and remove his GitHub access" -> two clauses, each understood on its own
* verify_plan    checks that only make sense across steps: SoD conflicts created by the COMBINATION of steps, a person both moved
                 and offboarded, too many steps. It can only make the plan stricter.
"""
from __future__ import annotations

import re
import uuid

from app.agents.contract import ToolCall
from app.agents.security.quarantine import Slots
from app.services import policy

MAX_STEPS = 3
KIND = {"MOVER": "mover", "ACCESS_REQUEST": "access_request", "ACCESS_REVOCATION": "access_revocation"}
WRITE_LABELS = {"MOVER", "ACCESS_REQUEST", "ACCESS_REVOCATION", "LEAVER"}

_VERBS = r"(?:move|transfer|shift|give|grant|add|provide|remove|revoke|take away|drop|offboard|terminate|deprovision|disable)"
_SPLIT = re.compile(rf"\s*(?:;|\.\s+|,?\s+(?:and\s+)?then\s+|,?\s+and\s+(?:also\s+)?(?={_VERBS}\b)|,\s+(?={_VERBS}\b))\s*", re.IGNORECASE)


def split_clauses(text: str) -> list[str]:
    """Split a compound request at clause boundaries that start with an action verb. "Give Kai access to GitHub and Jira" stays one
    clause (the second part has no verb); "move Kai to Finance and revoke his GitHub" becomes two."""
    parts = [p.strip(" .") for p in _SPLIT.split(text or "") if p and p.strip(" .")]
    return parts if 2 <= len(parts) <= MAX_STEPS else [text]


def plan_call(slots: Slots, identity_id: uuid.UUID, plan_id: str | None = None) -> ToolCall:
    """Deterministic: the same Slots always give the same call. Arguments come only from typed slot values."""
    base = {"plan_id": plan_id, "proposed_by": "planner"}
    if slots.label == "ACCESS_STATUS_QUERY":
        return ToolCall(tool="inspect_user_access", args={"identity_id": str(identity_id), "applications": list(slots.applications),
                                                          "entitlements": list(slots.entitlements)}, **base)
    if slots.label == "LEAVER":
        reason = slots.reason if slots.reason and len(slots.reason) >= 3 else "Requested via the IAM assistant"
        return ToolCall(tool="deprovision_user", args={"identity_id": str(identity_id), "reason": reason,
                                                       "effective_date": slots.effective_date.isoformat() if slots.effective_date else None},
                        **base)
    mover = slots.label == "MOVER"
    return ToolCall(tool="modify_user_access", args={
        "identity_id": str(identity_id), "change": KIND[slots.label], "to_department": slots.target_department if mover else None,
        "access_profile": slots.access_profile if mover else None, "applications": list(slots.applications),
        "entitlements": list(slots.entitlements), "effective_date": slots.effective_date.isoformat() if slots.effective_date else None,
        "date_text": slots.date_text}, **base)


def verify_plan(steps: list[dict], held: dict[str, set], sod: list[tuple[str, set]]) -> tuple[str | None, list[str]]:
    """steps: [{"identity_id", "kind", "adds": [entitlement_id...], "removes": [...]}]; held: identity_id -> held entitlement ids.
    Returns (forced decision or None, reasons)."""
    reasons: list[str] = []
    forced = None
    if len(steps) > MAX_STEPS:
        return policy.DENY, [f"A single request can contain at most {MAX_STEPS} changes."]
    by_person: dict[str, list[dict]] = {}
    for st in steps:
        by_person.setdefault(st["identity_id"], []).append(st)
    for pid, sts in by_person.items():
        kinds = {s["kind"] for s in sts}
        if "leaver" in kinds and len(sts) > 1:
            forced = policy.DENY
            reasons.append("The request both offboards a person and changes their access. Submit the offboarding on its own.")
        if len(sts) < 2:
            continue
        resulting = set(held.get(pid, set()))
        for s in sts:
            resulting |= {str(x) for x in s["adds"]}
        for s in sts:
            resulting -= {str(x) for x in s["removes"]}
        for name, ids in sod:
            ids_s = {str(x) for x in ids}
            if ids_s and ids_s <= resulting and not any(ids_s <= (set(held.get(pid, set())) | {str(x) for x in s["adds"]}) for s in sts):
                forced = policy.DENY
                reasons.append(f"Together these changes would break the separation-of-duties policy “{name}”.")
    return forced, reasons
