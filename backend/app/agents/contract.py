"""Integration Contract v1: the typed messages that cross agent boundaries (docs/contract/integration_contract_v1.md).

IntentV1 is a superset of the master plan's §5.1 intent JSON (additive fields only). Every model is strict (`extra="forbid"`)
so a field an LLM invents is a validation error, not silently ignored. Schemas are snapshot-tested (tests/agents/unit).
"""
from __future__ import annotations

import uuid
from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.0.0"

Action = Literal["onboard", "modify_access", "deprovision", "inspect"]
Change = Literal["mover", "access_request", "access_revocation"]
Decision = Literal["auto", "approval", "deny", "clarify", "noop", "blocked"]
Source = Literal["nlu", "slm", "memory", "governance"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IntentV1(Strict):
    """What the Extractor understood. Produced from UNTRUSTED text, so every value is re-validated downstream."""
    action: Action
    change: Change | None = None                       # additive: which kind of modify_access
    user_id: str | None = Field(None, max_length=200)  # employee id or name as written
    target_role: str | None = Field(None, max_length=160)   # access profile (the directory's "role" for a department)
    department: str | None = Field(None, max_length=120)
    source_department: str | None = Field(None, max_length=120)
    applications: tuple[str, ...] = ()                 # additive
    entitlements: tuple[str, ...] = ()                 # additive: specific entitlement names ("AP Payment Release")
    effective_date: date | None = None
    effective_date_text: str | None = Field(None, max_length=80)
    requester_id: str
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    missing_slots: tuple[str, ...] = ()
    source: Source = "nlu"
    self_reference: bool = False                       # "me" / "my access"


class ToolCall(Strict):
    """A proposed call. `args` is validated against the tool's own schema by the gateway, never trusted as-is."""
    tool: str = Field(max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    call_id: str = Field(default_factory=lambda: uuid.uuid4().hex, max_length=64)
    plan_id: str | None = Field(None, max_length=64)
    proposed_by: str = Field("planner", max_length=40)   # which agent proposed it (audit only)


class ToolResult(Strict):
    call_id: str
    tool: str
    ok: bool
    decision: Decision | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    reasons: tuple[str, ...] = ()
    error: str | None = None                           # machine code, e.g. "unknown_tool", "schema_invalid"
    audit_ref: str | None = None


class ActionPlan(Strict):
    plan_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    steps: tuple[ToolCall, ...]
    rationale: tuple[str, ...] = ()


# ─────────────────────────── adapter: current NLU output -> IntentV1
_LABEL = {"JOINER": ("onboard", None), "MOVER": ("modify_access", "mover"), "ACCESS_REQUEST": ("modify_access", "access_request"),
          "ACCESS_REVOCATION": ("modify_access", "access_revocation"), "LEAVER": ("deprovision", None),
          "ACCESS_STATUS_QUERY": ("inspect", None)}
_SLOT = {"person": "user_id", "target_department": "department", "applications": "applications"}


def from_nlu(res: dict | None, requester_id: str, source: Source = "nlu") -> IntentV1 | None:
    """Map the NLU pipeline's result (backend/nlu) to IntentV1. Returns None for intents outside the lifecycle catalogue."""
    if not res or res.get("intent", {}).get("label") not in _LABEL:
        return None
    action, change = _LABEL[res["intent"]["label"]]
    s = res.get("slots") or {}
    d = s.get("effective_date") or {}
    roles = s.get("access_roles") or []
    conf = res["intent"].get("confidence")
    return IntentV1(
        action=action, change=change, user_id=s.get("employee_id") or s.get("person"),
        target_role=s.get("access_profile"),
        department=s.get("target_department") or s.get("department"), source_department=s.get("source_department"),
        applications=tuple(s.get("applications") or ()), entitlements=tuple(roles),
        effective_date=date.fromisoformat(d["value"]) if d.get("resolved") else None,
        effective_date_text=None if d.get("resolved") else d.get("expression"),
        requester_id=requester_id, confidence=float(conf) if isinstance(conf, (int, float)) else 0.0,
        missing_slots=tuple(_SLOT.get(m, m) for m in res.get("missing_fields") or ()), source=source,
        self_reference=s.get("subject_reference") == "SELF")


# Default tool for each action (the Planner's deterministic route; plan §5.3)
ACTION_TOOL = {"onboard": "provision_user", "modify_access": "modify_user_access", "deprovision": "deprovision_user",
               "inspect": "inspect_user_access"}
