"""Integration Contract v1: adapter behaviour, strictness, and a frozen JSON-schema snapshot (contract drift fails CI).

Regenerate the snapshot ONLY for an agreed contract change (master plan §9.3):  UPDATE_CONTRACT_SNAPSHOT=1 pytest tests/agents/unit
"""
import json
import os
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.agents.contract import (ACTION_TOOL, CONTRACT_VERSION, ActionPlan, IntentV1, ToolCall, ToolResult, from_nlu)
from app.agents.tools.registry import REGISTRY, json_schemas

SNAPSHOT = Path(__file__).parent / "snapshots" / "contract_v1.json"


def nlu_result(label, slots=None, missing=(), confidence=0.93):
    return {"intent": {"label": label, "confidence": confidence}, "slots": slots or {}, "missing_fields": list(missing),
            "status": "PARSED" if not missing else "NEEDS_CLARIFICATION"}


@pytest.mark.parametrize("label,action,change", [
    ("JOINER", "onboard", None), ("MOVER", "modify_access", "mover"), ("ACCESS_REQUEST", "modify_access", "access_request"),
    ("ACCESS_REVOCATION", "modify_access", "access_revocation"), ("LEAVER", "deprovision", None), ("ACCESS_STATUS_QUERY", "inspect", None)])
def test_from_nlu_maps_every_lifecycle_intent(label, action, change):
    i = from_nlu(nlu_result(label, {"person": "Kai Chen"}), "req-1")
    assert (i.action, i.change, i.user_id, i.requester_id) == (action, change, "Kai Chen", "req-1")


def test_from_nlu_slots_dates_and_missing():
    i = from_nlu(nlu_result("MOVER", {"person": "Rahul Sharma", "source_department": "Engineering", "target_department": "Finance",
                                      "applications": ["GitHub"], "access_roles": ["AP Payment Release"],
                                      "effective_date": {"resolved": True, "value": "2026-11-02", "expression": "next monday"}}), "r")
    assert i.department == "Finance" and i.source_department == "Engineering"
    assert i.applications == ("GitHub",) and i.entitlements == ("AP Payment Release",)
    assert i.effective_date == date(2026, 11, 2) and i.effective_date_text is None
    j = from_nlu(nlu_result("MOVER", {"effective_date": {"resolved": False, "expression": "after the audit"}}, missing=["person", "target_department"]), "r")
    assert j.effective_date is None and j.effective_date_text == "after the audit"
    assert j.missing_slots == ("user_id", "department")


def test_from_nlu_ignores_non_lifecycle_and_empty():
    assert from_nlu(None, "r") is None
    assert from_nlu(nlu_result("GREETING"), "r") is None


def test_from_nlu_self_reference_and_bad_confidence():
    i = from_nlu(nlu_result("ACCESS_STATUS_QUERY", {"subject_reference": "SELF"}, confidence=None), "r")
    assert i.self_reference and i.confidence == 0.0


def test_models_are_strict():
    with pytest.raises(ValidationError):
        IntentV1(action="onboard", requester_id="r", approve_now=True)
    with pytest.raises(ValidationError):
        IntentV1(action="grant_admin", requester_id="r")
    with pytest.raises(ValidationError):
        ToolCall(tool="inspect_user_access", args={}, bypass=True)
    with pytest.raises(ValidationError):
        IntentV1(action="inspect", requester_id="r", confidence=1.5)


def test_every_action_routes_to_a_whitelisted_tool():
    assert set(ACTION_TOOL.values()) <= set(REGISTRY)
    assert {"provision_user", "modify_user_access", "deprovision_user", "inspect_user_access"} <= set(REGISTRY)   # plan §5.3


def test_contract_snapshot():
    current = {"version": CONTRACT_VERSION,
               "models": {m.__name__: m.model_json_schema() for m in (IntentV1, ToolCall, ToolResult, ActionPlan)},
               "tools": json_schemas()}
    if os.environ.get("UPDATE_CONTRACT_SNAPSHOT") == "1" or not SNAPSHOT.exists():
        SNAPSHOT.write_text(json.dumps(current, indent=2, sort_keys=True, default=str), encoding="utf-8")
    frozen = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert json.loads(json.dumps(current, sort_keys=True, default=str)) == frozen, \
        "Integration contract changed. Agree the change with your teammate, bump CONTRACT_VERSION, then UPDATE_CONTRACT_SNAPSHOT=1."
