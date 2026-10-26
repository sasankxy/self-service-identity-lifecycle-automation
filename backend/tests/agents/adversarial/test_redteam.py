"""Red-team suite (cases.json): every attack must be stopped at the layer it targets; every benign request must pass.

Runs without a database or a model, so it is part of every CI run. The 'social' cases need the LLM policy judge and are measured
live by `python -m eval.redteam` (see eval/redteam.py).
"""
import json
import time
from pathlib import Path

import pytest

from app.agents import capabilities
from app.agents.contract import ToolCall
from app.agents.gateway import ActionGateway, ToolContext
from app.agents.security import injection
from app.agents.security.sanitize import sanitize
from app.agents.tools.registry import REGISTRY, ToolSpec
from app.agents.tools.write import Prepared
from tests.agents.unit.conftest import FakeDB, FakeRedis, fake_identity, fake_line, fake_plan, principal

CASES = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))
CAT = {"departments": ["Engineering", "Finance", "Legal"], "applications": ["GitHub", "AWS", "Salesforce"],
       "entitlements": ["GitHub Enterprise", "AWS AdministratorAccess (Prod-US-East)"]}


@pytest.fixture(scope="session", autouse=True)
def migrated_db():
    yield                                   # no database needed


def test_suite_size():
    n = len(CASES["input"]) + len(CASES["gateway"]) + len(CASES["social"])
    assert n >= 40, n


@pytest.mark.parametrize("case", CASES["input"], ids=[c["id"] for c in CASES["input"]])
def test_input_attack_blocked_by_sentinel(case):
    clean, _ = sanitize(case["text"])
    assert injection.scan(clean).blocked, f"{case['id']} ({case['category']}) not blocked: {case['text']!r}"


@pytest.mark.parametrize("text", CASES["benign"])
def test_benign_request_not_blocked(text):
    clean, _ = sanitize(text)
    v = injection.scan(clean)
    assert not v.blocked, f"false positive {v.rules}: {text!r}"


# ─────────────────────────── gateway harness: real gateway, stub tool bodies driven by the case
def build(case, actor):
    target = fake_identity(actor.email if case.get("target_is_actor") else "victim@corp.test")
    risk = case.get("risk", "low")
    kind = case.get("plan_kind")
    decision = case.get("plan_decision", "auto")
    committed: list = []

    async def prepare(ctx, a):
        k = kind or getattr(a, "change", None) or "leaver"
        plan = fake_plan(k, decision, identity=target, lines=[fake_line("GitHub Enterprise", risk)])
        return Prepared(plan.decision, list(plan.reasons), {"kind": k}, target.id, target, plan)

    async def commit(ctx, a, prepared):
        committed.append(prepared.decision)
        return {"ref": "REQ-1", "decision": prepared.decision, "applied": False}

    async def run(ctx, a):
        return {"access": []}

    reg = {}
    for name, spec in REGISTRY.items():
        reg[name] = ToolSpec(spec.name, spec.args, spec.kind, spec.permission, "", spec.target_arg,
                             run=run if spec.kind == "read" else None, prepare=prepare if spec.kind == "write" else None,
                             commit=commit if spec.kind == "write" else None, catalogue=spec.catalogue, self_permission=spec.self_permission)
    return ActionGateway(reg, catalogue=lambda: CAT), target, committed


def call_for(case, target) -> ToolCall:
    args = {k: (str(target.id) if v == "$TARGET" else v) for k, v in case["call"]["args"].items()}
    return ToolCall(tool=case["call"]["tool"], args=args)


def capability_for(case, actor, target):
    if case.get("foreign_capability"):
        return capabilities.mint(principal("iam_admin", "someone.else@corp.test"))
    if case.get("expired_capability"):
        c = capabilities.mint(actor)
        return capabilities.Capability(c.actor_id, c.actor_email, c.permissions, c.tools, c.targets, time.time() - 1)
    if case.get("forge_capability"):
        return capabilities.Capability(actor.id, actor.email, frozenset(actor.permissions), capabilities.WRITE_TOOLS, frozenset({"*"}), 9e18)
    if case.get("narrow_to_other"):
        return capabilities.mint(actor, targets={"00000000-0000-0000-0000-000000000000"})
    if actor.roles == ["employee"]:
        return capabilities.mint(actor, targets={str(target.id)})
    return capabilities.mint(actor)


@pytest.mark.parametrize("case", CASES["gateway"], ids=[c["id"] for c in CASES["gateway"]])
async def test_gateway_attack_refused(case):
    actor = principal(case.get("actor", "iam_admin"), "actor@corp.test")
    gw, target, committed = build(case, actor)
    redis = FakeRedis()

    def ctx():
        return ToolContext(db=FakeDB({target.id: target}), actor=actor, cap=capability_for(case, actor, target), redis=redis)

    call = call_for(case, target)
    if "expect_decision" in case:                       # escalation cases: allowed to preview, but only with a stricter decision
        r = await gw.run(ctx(), call)
        assert r.ok and r.decision == case["expect_decision"], f"{case['id']}: {r}"
        return
    if case.get("replay"):
        first = await gw.run(ctx(), call, mode="commit", expected_decision=case["commit_with"])
        assert first.ok, first
        call = call_for(case, target)                   # same arguments, new call id
    mode = "commit" if "commit_with" in case else "preview"
    r = await gw.run(ctx(), call, mode=mode, expected_decision=case.get("commit_with"))
    assert not r.ok and r.error == case["expect"], f"{case['id']} ({case['category']}): expected {case['expect']}, got {r.error} {r.reasons}"
    assert len(committed) == (1 if case.get("replay") else 0), f"{case['id']}: something was executed"
