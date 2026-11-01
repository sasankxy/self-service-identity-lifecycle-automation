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
    assert any(b["type"] == "action" and b["action"] == "send:IT Security" for b in r["blocks"])     # clickable choices
    r = await chat(c, "IT Sec", "sess-advisor-02")                  # the follow-up answers the question
    assert "Access for a new person in IT Security" in texts(r), texts(r)
    assert next(t for t in r["trace"] if t["node"] == "understand")["via"] == "answer"


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


# ─────────────────────────── Aadhaar verification (synthetic data only)
async def _joiner(admin, email):
    from datetime import date
    lk = (await admin.get("/api/v1/meta/lookups")).json()
    prof = next(p for p in lk["access_profiles"] if p["name"] == "Legal Counsel")
    dept = next(d for d in lk["departments"] if d["name"] == "Legal")
    r = await admin.post("/api/v1/identities", {"first_name": "Aditya", "last_name": "Rao", "email": email, "department_id": dept["id"],
                                                "access_profile_id": prof["id"], "start_date": date.today().isoformat()})
    assert r.status_code == 201, r.text
    return r.json()


async def test_aadhaar_link_upload_and_approval_gate(as_role, app, monkeypatch):
    from app.services import aadhaar as A
    admin = await as_role("iam_admin")
    j = await _joiner(admin, "aadhaar.joiner@corp.com")
    link = await admin.post(f"/api/v1/identities/{j['id']}/aadhaar/link", {"date_of_birth": "1999-05-14"})
    assert link.status_code == 201, link.text
    H = {"X-Verification-Token": link.json()["url"].split("#")[1]}
    http = admin.http
    assert (await http.get("/api/v1/public/aadhaar", headers={"X-Verification-Token": "wrong"})).status_code == 404
    assert (await http.get("/api/v1/public/aadhaar", headers=H)).json()["first_name"] == "Aditya"
    files = {"file": ("c.png", b"not-an-image", "image/png")}
    assert (await http.post("/api/v1/public/aadhaar", headers=H, files=files, data={"consent": "false"})).json()["error"]["code"] == "consent_required"
    assert (await http.post("/api/v1/public/aadhaar", headers=H, files=files, data={"consent": "true"})).json()["error"]["code"] == "bad_image"

    app.state.settings.aadhaar_required = True
    try:
        card = next(i for i in (await admin.get("/api/v1/approvals?limit=100")).json()["items"] if i["ref"] == j["request_ref"])
        assert card["aadhaar"] == "pending"
        assert (await admin.post(f"/api/v1/approvals/{card['id']}/approve", {})).json()["error"]["code"] == "aadhaar_required"
        monkeypatch.setattr(A, "verify_image", lambda *a, **k: A.Outcome("verified", {"secure_qr": {"result": "pass", "detail": "ok"}}, "XXXX XXXX 9012", "h" * 64))
        r = await http.post("/api/v1/public/aadhaar", headers=H, files=files, data={"consent": "true"})
        assert r.json()["status"] == "verified" and "checks" not in r.json()
        assert (await http.get("/api/v1/public/aadhaar", headers=H)).status_code == 404       # one-time link
        s = (await admin.get(f"/api/v1/identities/{j['id']}/aadhaar")).json()
        assert s["status"] == "verified" and s["masked_number"] == "XXXX XXXX 9012" and "number_hash" not in s
        assert (await admin.post(f"/api/v1/approvals/{card['id']}/approve", {})).status_code == 200
    finally:
        app.state.settings.aadhaar_required = False


async def test_aadhaar_number_is_masked_in_chat(as_role):
    c = await as_role("iam_admin")
    r = await chat(c, "Onboard Kai with aadhaar 2345 6789 0123", "sess-aadhaar-01")
    assert "aadhaar_masked" in r["trace"][0]["flags"] and "2345 6789" not in texts(r)
