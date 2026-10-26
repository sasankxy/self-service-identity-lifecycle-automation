"""Governance agent (findings -> proposals for approval), Access Advisor, Approver Copilot brief."""
from sqlalchemy import text

from app.agents import governance
from app.services import governance_scan
from tests.agents.integration.conftest import BUSY_DEPTS
from tests.agents.integration.test_agent_chat import chat, texts


async def _quiet_creep_findings(app, n=2):
    await governance_scan.run_scan(app.state.sessionmaker, app.state.redis, trigger="manual")
    async with app.state.sessionmaker() as db:
        return list((await db.execute(text(
            "SELECT f.id FROM governance_findings f JOIN identities i ON i.id = f.identity_id JOIN departments d ON d.id = i.department_id "
            "WHERE f.status = 'open' AND f.rule = 'excess_access' AND d.name NOT IN (SELECT unnest(CAST(:busy AS text[]))) "
            "AND NOT (f.details ? 'remediation') ORDER BY f.id LIMIT :n"), {"busy": list(BUSY_DEPTS), "n": n})).scalars())


async def test_governance_agent_proposes_fixes_for_approval_only(app):
    ids = await _quiet_creep_findings(app)
    assert ids, "seed should contain privilege-creep findings"
    out = await governance.remediate(app.state.sessionmaker, app.state.redis, app.state.settings, None, finding_ids=ids)
    assert len(out["proposed"]) == len(ids), out
    async with app.state.sessionmaker() as db:
        for p in out["proposed"]:
            st = (await db.execute(text("SELECT r.status, r.requester_name FROM lifecycle_requests r WHERE 'REQ-' || r.ref_no = :ref"),
                                   {"ref": p["ref"]})).one()
            assert st.status == "pending_approval" and st.requester_name == governance.SYSTEM_NAME   # never auto-applied
        rem = (await db.execute(text("SELECT details->'remediation'->>'status' FROM governance_findings WHERE id = ANY(:ids)"),
                                {"ids": ids})).scalars().all()
        assert set(rem) == {"proposed"}
        assert (await db.execute(text("SELECT status FROM users WHERE email = :e"), {"e": governance.SYSTEM_EMAIL})).scalar_one() == "disabled"
    again = await governance.remediate(app.state.sessionmaker, app.state.redis, app.state.settings, None, finding_ids=ids)
    assert again == {"proposed": [], "advice": [], "skipped": []}           # findings with a proposal are not re-processed


async def test_remediate_endpoint_requires_governance_manage(as_role):
    aud = await as_role("auditor")
    assert (await aud.post("/api/v1/agent/governance/remediate", {"limit": 1})).status_code == 403


async def test_access_advisor(as_role):
    c = await as_role("iam_admin")
    r = await chat(c, "What access should a new analyst in Finance get?", "sess-advisor-01")
    assert [t["node"] for t in r["trace"]][-1] == "advisor"
    assert "Access for a new person in Finance" in texts(r) and "Standard profile" in texts(r), texts(r)
    r = await chat(c, "What access should a new hire get?", "sess-advisor-02")
    assert "Which department" in texts(r)


async def test_approver_copilot_brief(as_role, app):
    async with app.state.sessionmaker() as db:
        aid = (await db.execute(text("SELECT id FROM approval_requests WHERE status = 'pending' LIMIT 1"))).scalar_one()
    apr = await as_role("approver", "brief-approver@corp.com")
    r = await apr.get(f"/api/v1/agent/approvals/{aid}/brief")
    assert r.status_code == 200, r.text
    f = r.json()["facts"]
    assert f["ref"].startswith("REQ-") and "changes" in f and "requester_flags" in f and r.json()["advice"] is None   # no LLM in CI
    emp = await as_role("employee", "brief-emp@corp.com")
    assert (await emp.get(f"/api/v1/agent/approvals/{aid}/brief")).status_code == 403
