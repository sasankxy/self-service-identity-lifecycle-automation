"""Deterministic scope gate: is this message about identity / access management at all?  Costs nothing (no model).

Runs BEFORE the local SLM, so chit-chat ("how are you?", "what's my timetable today?", "write a poem") never reaches it
and never burns model time. Generic verbs (give, move, leave, join) are deliberately NOT enough on their own; the message
needs a real domain term: an access/approval/risk word, a lifecycle word, or a directory department / application /
entitlement name (loaded from the database, aliases included).
"""
from __future__ import annotations

import re

from app.services import nlu

DOMAIN_WORDS = {
    "access", "accesses", "permission", "permissions", "entitlement", "entitlements", "privilege", "privileges", "privileged",
    "approval", "approvals", "approve", "approver", "identity", "identities", "employee", "employees", "contractor", "contractors",
    "onboard", "onboarding", "onboarded", "offboard", "offboarding", "offboarded", "joiner", "joiners", "mover", "movers", "leaver", "leavers",
    "revoke", "revoked", "revocation", "deprovision", "provision", "provisioning", "reprovision", "risk", "risky", "audit", "governance",
    "policy", "policies", "compliance", "sod", "segregation", "directory", "department", "departments", "profile", "profiles",
    "credential", "credentials", "mfa", "sso", "iam", "account", "accounts", "login", "role", "roles", "newhire", "terminate", "terminated",
}

SCOPE_MESSAGE = ("I'm the identity-management assistant, so I can only help with directory and access questions. Things I can do:")
EXAMPLES = ["What access does <name> have to Slack?", "Move <name> from Sales to Marketing", "Give <name> access to Zoom",
            "Revoke <name>'s access to AWS", "Show high-risk identities", "Show pending approvals"]


def _words(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", (s or "").lower()))


def _catalogue_phrases() -> list[str]:
    cat = nlu.catalogue()
    out = [*cat["departments"], *cat["applications"], *cat.get("entitlements", [])]
    out += [a for d in cat["departments"] for a in nlu.DEPT_ALIASES.get(d, [])] + [a for d in cat["applications"] for a in nlu.APP_ALIASES.get(d, [])]
    return [p.lower() for p in out if len(p) >= 3]


def in_scope(query: str, res: dict | None = None) -> bool:
    if res and res.get("intent", {}).get("label") in nlu.ASSISTANT_INTENTS and res.get("status") != "UNKNOWN_INTENT":
        return True                                  # the NLU recognised a lifecycle request
    if _words(query) & DOMAIN_WORDS:
        return True
    q = " ".join(re.findall(r"[a-z0-9]+", query.lower()))
    return any(re.search(rf"\b{re.escape(' '.join(re.findall(r'[a-z0-9]+', p)))}\b", q) for p in _catalogue_phrases())
