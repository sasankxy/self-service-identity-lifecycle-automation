"""Real tools through the Action Gateway against the seeded PostgreSQL + Redis (same fixtures as the rest of the suite)."""
import pytest
from sqlalchemy import select, text

from app.agents import capabilities
from app.agents.contract import ToolCall
from app.agents.gateway import ActionGateway, ToolContext
from app.core.rbac import ROLES
from app.models import Identity
from app.services import policy
from app.services.accounts import Principal


@pytest.fixture
async def agent_ctx(app, make_user):
    u = await make_user("agent-admin@corp.com", "iam_admin")
    actor = Principal(id=str(u.id), email=u.email, full_name=u.full_name, status="active", roles=["iam_admin"],
                      permissions=list(ROLES["iam_admin"]["permissions"]))
    sessions = []

    async def make() -> ToolContext:
        db = app.state.sessionmaker()
        sessions.append(db)
        return ToolContext(db=db, actor=actor, cap=capabilities.mint(actor), redis=app.state.redis, settings=app.state.settings,
                           user_text="test")
    yield make
    for s in sessions:
        await s.close()


async def bystander(app, offset: int):
    """A low-risk active identity no other test asserts on. Never use named seed people (e.g. Kai Chen): requests created here
    add risk assessments, and tests/test_data_api.py checks the seeded latest assessment of specific people."""
    async with app.state.sessionmaker() as db:
        return (await db.execute(text(
            "SELECT i.id FROM identities i JOIN departments d ON d.id = i.department_id WHERE i.lifecycle_state = 'active' "
            "AND i.risk_score < 40 AND d.name = 'Engineering' AND NOT EXISTS (SELECT 1 FROM lifecycle_requests r "
            "WHERE r.identity_id = i.id AND r.status = 'pending_approval') ORDER BY i.employee_id OFFSET :o LIMIT 1"), {"o": offset})).scalar_one()


async def audit_count(app, action):
    async with app.state.sessionmaker() as db:
        return (await db.execute(text("SELECT count(*) FROM audit_logs WHERE action = :a"), {"a": action})).scalar_one()


async def test_mover_preview_then_commit(app, agent_ctx):
    gw, who = ActionGateway(), await bystander(app, 0)
    call = ToolCall(tool="modify_user_access", args={"identity_id": str(who), "change": "mover", "to_department": "Finance"})
    prev = await gw.run(await agent_ctx(), call)
    assert prev.ok and prev.decision in (policy.AUTO, policy.APPROVAL), prev
    assert prev.data["to_department"] == "Finance"
    done = await gw.run(await agent_ctx(), call, mode="commit", expected_decision=prev.decision)
    assert done.ok and done.audit_ref.startswith("REQ-")
    assert await audit_count(app, "agent.tool_executed") >= 1


async def test_deprovision_always_needs_approval(app, agent_ctx):
    gw, who = ActionGateway(), await bystander(app, 1)
    call = ToolCall(tool="deprovision_user", args={"identity_id": str(who), "reason": "Contract ended"})
    prev = await gw.run(await agent_ctx(), call)
    assert prev.decision == policy.APPROVAL
    done = await gw.run(await agent_ctx(), call, mode="commit", expected_decision=policy.APPROVAL)
    assert done.ok and done.data["request_status"] == "pending_approval"
    again = await gw.run(await agent_ctx(), call, mode="commit", expected_decision=policy.APPROVAL)
    assert not again.ok                                   # open leaver request / idempotency: never a second one


async def test_provision_creates_pending_joiner(app, agent_ctx):
    gw = ActionGateway()
    call = ToolCall(tool="provision_user", args={"first_name": "Agent", "last_name": "Joiner", "email": "agent.joiner@corp.com",
                                                 "department": "Engineering", "access_profile": "Senior Developer"})
    prev = await gw.run(await agent_ctx(), call)
    assert prev.decision == policy.APPROVAL, prev
    done = await gw.run(await agent_ctx(), call, mode="commit", expected_decision=policy.APPROVAL)
    assert done.ok
    async with app.state.sessionmaker() as db:
        assert (await db.execute(select(Identity.lifecycle_state).where(Identity.email == "agent.joiner@corp.com"))).scalar_one() == "joiner"


async def test_blocked_calls_are_audited(app, agent_ctx):
    before = await audit_count(app, "agent.action_blocked")
    r = await ActionGateway().run(await agent_ctx(), ToolCall(tool="drop_all_identities", args={}))
    assert r.error == "unknown_tool"
    assert await audit_count(app, "agent.action_blocked") == before + 1
