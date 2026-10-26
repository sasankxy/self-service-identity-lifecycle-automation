"""Action Gateway: every check, with stub tools so the enforcement logic is tested on its own (no database)."""
import uuid

import pytest

from app.agents import capabilities
from app.agents.contract import ToolCall
from app.agents.gateway import ActionGateway, ToolContext
from app.agents.tools import schemas as S
from app.agents.tools.registry import REGISTRY, ToolSpec
from app.agents.tools.write import Prepared
from app.services import policy
from tests.agents.unit.conftest import FakeDB, FakeRedis, fake_identity, fake_line, fake_plan, principal

CAT = {"departments": ["Engineering", "Finance"], "applications": ["GitHub", "AWS"], "entitlements": ["AWS Admin", "GitHub Write"]}


def make_gateway(plan_decision=policy.AUTO, risk="low", target_email="kai.chen@corp.test", committed=None):
    ident = fake_identity(target_email)

    async def run(ctx, a):
        return {"access": ["GitHub Write (GitHub) · low risk"]}

    async def prepare(ctx, a):
        plan = fake_plan(a.change, plan_decision, identity=ident, lines=[fake_line("GitHub Write", risk)])
        return Prepared(plan.decision, list(plan.reasons), {"kind": a.change}, ident.id, ident, plan)

    async def commit(ctx, a, prepared):
        (committed if committed is not None else []).append(prepared.decision)
        return {"ref": "REQ-1", "decision": prepared.decision, "applied": prepared.decision == policy.AUTO}

    reg = {"inspect_user_access": ToolSpec("inspect_user_access", S.InspectUserAccess, "read", "self:read", "", "identity_id", run=run,
                                           catalogue=REGISTRY["inspect_user_access"].catalogue),
           "modify_user_access": ToolSpec("modify_user_access", S.ModifyUserAccess, "write", "identities:write", "", "identity_id",
                                          prepare=prepare, commit=commit, catalogue=REGISTRY["modify_user_access"].catalogue,
                                          self_permission="self:request")}
    return ActionGateway(reg, catalogue=lambda: CAT), ident


def ctx_for(p, ident=None, cap=None, redis=None):
    db = FakeDB({ident.id: ident} if ident else {})
    return ToolContext(db=db, actor=p, cap=cap or capabilities.mint(p), redis=redis)


def modify(ident_id, **kw):
    return ToolCall(tool="modify_user_access", args={"identity_id": str(ident_id), "change": "access_request", "applications": ["GitHub"], **kw})


async def test_unknown_tool_blocked_and_audited(admin):
    gw, ident = make_gateway()
    ctx = ctx_for(admin, ident)
    r = await gw.run(ctx, ToolCall(tool="grant_super_admin", args={}))
    assert not r.ok and r.error == "unknown_tool" and r.decision == "blocked"
    assert ctx.db.audit_actions() == ["agent.action_blocked"]


@pytest.mark.parametrize("args", [
    {"identity_id": "not-a-uuid", "change": "access_request"},
    {"identity_id": str(uuid.uuid4()), "change": "make_admin"},
    {"identity_id": str(uuid.uuid4()), "change": "access_request", "auto_approve": True},       # smuggled field
    {"identity_id": str(uuid.uuid4()), "change": "access_request", "applications": ["x"] * 11},
    {"identity_id": str(uuid.uuid4()), "change": "mover", "effective_date": "2001-01-01"},
])
async def test_schema_violations_blocked(admin, args):
    gw, ident = make_gateway()
    r = await gw.run(ctx_for(admin, ident), ToolCall(tool="modify_user_access", args=args))
    assert r.error == "schema_invalid"


async def test_capability_must_cover_tool(admin):
    gw, ident = make_gateway()
    cap = capabilities.mint(admin, tools={"inspect_user_access"})
    r = await gw.run(ctx_for(admin, ident, cap), modify(ident.id))
    assert r.error == "capability_denied"


async def test_capability_must_cover_target(admin):
    gw, ident = make_gateway()
    cap = capabilities.mint(admin, targets={str(uuid.uuid4())})
    r = await gw.run(ctx_for(admin, ident, cap), modify(ident.id))
    assert r.error == "capability_denied"


async def test_capability_of_someone_else_rejected(admin):
    gw, ident = make_gateway()
    other = capabilities.mint(principal("iam_admin", "other@corp.test"))
    r = await gw.run(ctx_for(admin, ident, other), modify(ident.id))
    assert r.error == "capability_denied"


async def test_expired_capability_rejected(admin, expired_cap):
    gw, ident = make_gateway()
    r = await gw.run(ctx_for(admin, ident, expired_cap), modify(ident.id))
    assert r.error == "capability_denied"


async def test_permission_is_checked_even_with_forged_capability():
    auditor = principal("auditor")
    forged = capabilities.Capability(auditor.id, auditor.email, frozenset(auditor.permissions), capabilities.WRITE_TOOLS,
                                     frozenset({"*"}), 9e18)
    gw, ident = make_gateway()
    r = await gw.run(ctx_for(auditor, ident, forged), modify(ident.id))
    assert r.error == "forbidden"


async def test_unknown_catalogue_value_blocked(admin):
    gw, ident = make_gateway()
    r = await gw.run(ctx_for(admin, ident), modify(ident.id, applications=["Hacker Console"]))
    assert r.error == "unknown_catalogue_value"


async def test_read_tool_runs(admin):
    gw, ident = make_gateway()
    r = await gw.run(ctx_for(admin, ident), ToolCall(tool="inspect_user_access", args={"identity_id": str(ident.id)}))
    assert r.ok and r.data["access"]


async def test_employee_reads_only_self(employee):
    gw, ident = make_gateway(target_email="someone.else@corp.test")
    cap = capabilities.mint(employee)
    r = await gw.run(ctx_for(employee, ident, cap), ToolCall(tool="inspect_user_access", args={"identity_id": str(ident.id)}))
    assert r.error == "forbidden"
    gw, me = make_gateway(target_email=employee.email)
    r = await gw.run(ctx_for(employee, me, cap), ToolCall(tool="inspect_user_access", args={"identity_id": str(me.id)}))
    assert r.ok


async def test_preview_writes_nothing(admin):
    done = []
    gw, ident = make_gateway(committed=done)
    ctx = ctx_for(admin, ident)
    r = await gw.run(ctx, modify(ident.id))
    assert r.ok and r.decision == policy.AUTO and not done and ctx.db.commits == 0


async def test_commit_requires_confirmed_decision(admin):
    done = []
    gw, ident = make_gateway(committed=done)
    for expected in (None, policy.APPROVAL):
        r = await gw.run(ctx_for(admin, ident), modify(ident.id), mode="commit", expected_decision=expected)
        assert r.error == "policy_changed" and not done


async def test_commit_happy_path_audited(admin):
    done = []
    gw, ident = make_gateway(committed=done)
    ctx = ctx_for(admin, ident, redis=FakeRedis())
    r = await gw.run(ctx, modify(ident.id), mode="commit", expected_decision=policy.AUTO)
    assert r.ok and r.audit_ref == "REQ-1" and done == [policy.AUTO]
    assert "agent.tool_executed" in ctx.db.audit_actions()


async def test_idempotency_blocks_replay(admin):
    done, redis = [], FakeRedis()
    gw, ident = make_gateway(committed=done)
    call = modify(ident.id)
    assert (await gw.run(ctx_for(admin, ident, redis=redis), call, mode="commit", expected_decision=policy.AUTO)).ok
    r = await gw.run(ctx_for(admin, ident, redis=redis), modify(ident.id), mode="commit", expected_decision=policy.AUTO)
    assert r.error == "duplicate" and len(done) == 1


async def test_verifier_escalates_high_risk(admin):
    done = []
    gw, ident = make_gateway(risk="critical", committed=done)
    r = await gw.run(ctx_for(admin, ident), modify(ident.id))
    assert r.decision == policy.APPROVAL and "high_risk_grant" in r.data["verifier_rules"]
    r = await gw.run(ctx_for(admin, ident), modify(ident.id), mode="commit", expected_decision=policy.AUTO)
    assert r.error == "policy_changed" and not done             # the browser's stale AUTO cannot sneak it through


async def test_self_grant_cannot_auto_apply(admin):
    gw, ident = make_gateway(target_email=admin.email)
    r = await gw.run(ctx_for(admin, ident), modify(ident.id))
    assert r.decision == policy.APPROVAL and "self_grant" in r.data["verifier_rules"]


async def test_deny_is_never_executed(admin):
    done = []
    gw, ident = make_gateway(plan_decision=policy.DENY, committed=done)
    r = await gw.run(ctx_for(admin, ident), modify(ident.id), mode="commit", expected_decision=policy.DENY)
    assert r.error == "not_allowed" and not done


# ─────────────────────────── self-service (employee role: self:read + self:request)
async def test_employee_can_request_access_for_self_only_via_approval(employee):
    done = []
    gw, me = make_gateway(target_email=employee.email, committed=done)
    r = await gw.run(ctx_for(employee, me), modify(me.id))
    assert r.ok and r.decision == policy.APPROVAL and "self_grant" in r.data["verifier_rules"]     # never auto for yourself
    r = await gw.run(ctx_for(employee, me), modify(me.id), mode="commit", expected_decision=policy.APPROVAL)
    assert r.ok and done == [policy.APPROVAL]


async def test_employee_cannot_touch_someone_else(employee):
    gw, other = make_gateway(target_email="someone.else@corp.test")
    ctx = ctx_for(employee, other)
    r = await gw.run(ctx, modify(other.id))
    assert r.error == "forbidden" and ctx.db.audit_actions() == ["agent.action_blocked"]


async def test_employee_cannot_move_themselves(employee):
    gw, me = make_gateway(target_email=employee.email)
    r = await gw.run(ctx_for(employee, me), ToolCall(tool="modify_user_access", args={"identity_id": str(me.id), "change": "mover",
                                                                                      "to_department": "Finance"}))
    assert r.error == "forbidden" and "manager" in r.reasons[0]


async def test_employee_can_give_up_own_access(employee):
    gw, me = make_gateway(target_email=employee.email)
    r = await gw.run(ctx_for(employee, me), modify(me.id, change="access_revocation"))
    assert r.ok


async def test_min_decision_floor_forces_approval(admin):
    done = []
    gw, ident = make_gateway(plan_decision=policy.AUTO, committed=done)
    ctx = ctx_for(admin, ident)
    ctx.min_decision = policy.APPROVAL                        # agent-initiated (governance) changes always go to a person
    r = await gw.run(ctx, modify(ident.id, change="access_revocation"))
    assert r.decision == policy.APPROVAL and "own initiative" in r.reasons[0]
    r = await gw.run(ctx, modify(ident.id, change="access_revocation"), mode="commit", expected_decision=policy.APPROVAL)
    assert r.ok and done == [policy.APPROVAL]
