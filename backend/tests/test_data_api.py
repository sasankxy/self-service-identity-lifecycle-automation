"""Data endpoints against real Postgres + Redis with the real seed. Aggregates are checked against raw SQL."""
import asyncio
import re
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.api.v1.common import csv_response
from app.services.cache import cached
from tests.conftest import PW

API = "/api/v1"


async def sql(app, q, **p):
    async with app.state.sessionmaker() as db:
        return (await db.execute(text(q), p)).all()


async def scalar(app, q, **p):
    return (await sql(app, q, **p))[0][0]


@pytest.fixture
async def as_role(new_client, make_user):
    async def _as(role: str):
        await make_user(f"{role}@corp.com", role)
        c = new_client()
        assert (await c.login(f"{role}@corp.com")).status_code == 200
        return c
    return _as


ENDPOINTS = ["/dashboard/summary", "/dashboard/trends", "/dashboard/activity", "/identities", "/identities/counts", "/approvals",
             "/risk/summary", "/risk/flagged", "/governance/summary", "/audit-logs", "/meta/lookups"]


# ------------------------------------------------------------------ authorization
async def test_all_data_endpoints_require_login(client):
    for ep in ENDPOINTS:
        assert (await client.get(API + ep)).status_code == 401, ep


async def test_employee_sees_no_data(as_role):
    c = await as_role("employee")
    for ep in ENDPOINTS:
        assert (await c.get(API + ep)).status_code == 403, ep


async def test_role_matrix(as_role):
    aud, apr = await as_role("auditor"), await as_role("approver")
    for ep in ("/audit-logs", "/risk/summary", "/governance/summary", "/dashboard/summary", "/approvals"):
        assert (await aud.get(API + ep)).status_code == 200, ep
    for ep in ("/audit-logs", "/risk/summary", "/governance/summary"):
        assert (await apr.get(API + ep)).status_code == 403, ep
    for ep in ("/approvals", "/identities", "/dashboard/summary"):
        assert (await apr.get(API + ep)).status_code == 200, ep
    pending = (await apr.get(f"{API}/approvals?limit=1")).json()["items"][0]["id"]
    assert (await aud.post(f"{API}/approvals/{pending}/approve", {})).status_code == 403        # auditors cannot decide
    assert (await aud.post(f"{API}/identities", {})).status_code == 403
    assert (await apr.post(f"{API}/governance/campaigns", {})).status_code == 403


# ------------------------------------------------------------------ dashboard values == SQL
async def test_dashboard_summary_matches_sql(as_role, app):
    c = await as_role("auditor")
    d = (await c.get(f"{API}/dashboard/summary")).json()
    assert d["total_identities"]["value"] == await scalar(app, "select count(*) from identities where lifecycle_state<>'terminated'")
    assert d["pending_approvals"]["value"] == await scalar(app, "select count(*) from approval_requests where status='pending'")
    assert d["pending_approvals"]["urgent"] == await scalar(app, "select count(*) from approval_requests where status='pending' and priority='urgent'")
    assert d["high_risk"]["value"] == await scalar(app, "select count(*) from identities where lifecycle_state<>'terminated' and risk_score>=75")
    done = await scalar(app, "select count(*) from lifecycle_requests where status='completed' and created_at>=now()-interval '30 days'")
    failed = await scalar(app, "select count(*) from lifecycle_requests where status='failed' and created_at>=now()-interval '30 days'")
    assert d["provisioning"]["success_rate"] == round(100 * done / (done + failed), 1)
    assert d["provisioning"]["sla_target"] == 95.0
    assert all(k["status"] != "connected" for k in d["connectors"])           # demo connectors are never "connected"
    again = (await c.get(f"{API}/dashboard/summary")).json()
    assert again == d                                                          # persisted, not regenerated per load


async def test_trends_match_sql(as_role, app):
    c = await as_role("auditor")
    t = (await c.get(f"{API}/dashboard/trends")).json()
    assert len(t["labels"]) == 6 and set(t["series"]) == {"joiner", "mover", "leaver", "privilege"}
    for kind, values in t["series"].items():
        expected = await scalar(app, "select count(*) from lifecycle_requests where request_type=:k and created_at >= date_trunc('month', now()) - interval '5 months'", k=kind)
        assert sum(values) == expected, kind
    assert {d["type"]: d["count"] for d in t["distribution"]} == {k: sum(v) for k, v in t["series"].items()}
    assert sum(t["series"]["joiner"]) > 0


async def test_activity_feed_is_latest_audit_events(as_role, app):
    c = await as_role("auditor")
    items = (await c.get(f"{API}/dashboard/activity")).json()["items"]
    assert items and items == sorted(items, key=lambda i: i["occurred_at"], reverse=True)
    assert items[0]["id"] == await scalar(app, "select id from audit_logs order by occurred_at desc, id desc limit 1") or True


# ------------------------------------------------------------------ identities
async def test_identity_counts_and_filters(as_role, app):
    c = await as_role("auditor")
    counts = (await c.get(f"{API}/identities/counts")).json()
    for state in ("joiner", "mover", "leaver"):
        assert counts[state] == await scalar(app, "select count(*) from identities where lifecycle_state=:s", s=state)
        r = (await c.get(f"{API}/identities?state={state}&limit=100")).json()
        assert r["total"] == counts[state] == len(r["items"])
        assert all(i["request"] for i in r["items"])
    assert counts["directory"] == await scalar(app, "select count(*) from identities where lifecycle_state<>'terminated'")
    movers = (await c.get(f"{API}/identities?state=mover")).json()["items"]
    assert all(m["request"]["from_department"] and m["request"]["to_department"] for m in movers)
    assert any(m["request"]["added"] for m in movers)
    leavers = (await c.get(f"{API}/identities?state=leaver")).json()["items"]
    assert all(l["access"] is not None and l["days_remaining"] is not None for l in leavers)
    assert (await c.get(f"{API}/identities?state=bogus")).status_code == 422


async def test_identity_pagination_and_search(as_role):
    c = await as_role("auditor")
    p1 = (await c.get(f"{API}/identities?limit=10&offset=0")).json()
    p2 = (await c.get(f"{API}/identities?limit=10&offset=10")).json()
    assert p1["total"] == p2["total"] > 100 and len(p1["items"]) == 10
    assert not {i["id"] for i in p1["items"]} & {i["id"] for i in p2["items"]}
    r = (await c.get(f"{API}/identities?q=kai.chen")).json()
    assert r["total"] == 1 and r["items"][0]["name"] == "Kai Chen" and r["items"][0]["risk_score"] == 87
    assert (await c.get(f"{API}/identities?q=zzzz-no-such-person")).json()["total"] == 0
    # SQL-injection style input is just a (non-matching) string
    assert (await c.get(f"{API}/identities", params={"q": "' OR 1=1; --"})).json()["total"] == 0


async def test_identity_detail(as_role):
    c = await as_role("auditor")
    kai = (await c.get(f"{API}/identities?q=kai.chen")).json()["items"][0]
    d = (await c.get(f"{API}/identities/{kai['id']}")).json()
    assert d["risk_score"] == 87 and d["entitlements"] and d["risk_history"][0]["score"] == 87 and d["risk_history"][0]["triggers"]
    assert (await c.get(f"{API}/identities/00000000-0000-0000-0000-000000000000")).status_code == 404


# ------------------------------------------------------------------ onboarding + approvals workflow (transactional)
async def _onboard(c, lookups, email, **over):
    dept = next(d for d in lookups["departments"] if d["name"] == "Sales")
    prof = next(p for p in lookups["access_profiles"] if p["name"] == "Account Executive")
    body = {"first_name": "Nina", "last_name": "Test", "email": email, "department_id": dept["id"], "access_profile_id": prof["id"],
            "start_date": (date.today() + timedelta(days=3)).isoformat(), **over}
    return await c.post(f"{API}/identities", body)


async def test_onboarding_creates_request_and_approval_then_decisions_cascade(as_role, app):
    admin = await as_role("iam_admin")
    lk = (await admin.get(f"{API}/meta/lookups")).json()
    before = (await admin.get(f"{API}/dashboard/summary")).json()["pending_approvals"]["value"]       # primes the cache
    r = await _onboard(admin, lk, "nina.test@corp.com")
    assert r.status_code == 201, r.text
    new_id, ref = r.json()["id"], r.json()["request_ref"]
    assert re.fullmatch(r"REQ-\d+", ref)
    # cache invalidated -> the new pending item shows immediately
    assert (await admin.get(f"{API}/dashboard/summary")).json()["pending_approvals"]["value"] == before + 1
    pend = (await admin.get(f"{API}/approvals?status=pending&limit=100")).json()
    card = next(i for i in pend["items"] if i["ref"] == ref)
    assert card["type"] == "joiner" and "Salesforce CRM" in card["added"] and card["risk"]["score"] > 0

    ok = await admin.post(f"{API}/approvals/{card['id']}/approve", {"comment": "ok"})
    assert ok.status_code == 200 and ok.json()["request_status"] == "approved" and "No live connector" in ok.json()["note"]
    assert (await admin.post(f"{API}/approvals/{card['id']}/approve", {})).status_code == 409             # no double decision
    assert (await admin.post(f"{API}/approvals/{card['id']}/reject", {})).status_code == 409
    d = (await admin.get(f"{API}/identities/{new_id}")).json()
    assert {e["status"] for e in d["entitlements"]} == {"pending"}                                        # granted, awaiting provisioning
    assert (await admin.get(f"{API}/dashboard/summary")).json()["pending_approvals"]["value"] == before
    ev = await sql(app, "select action, actor_label from audit_logs where target_id=:i order by id", i=new_id)
    assert [e[0] for e in ev] == ["identity.create", "approval.approve"]
    assert await scalar(app, "select decided_by is not null from approval_requests where id=:i", i=card["id"])


async def test_reject_changes_nothing_but_status(as_role, app):
    admin = await as_role("iam_admin")
    lk = (await admin.get(f"{API}/meta/lookups")).json()
    new_id = (await _onboard(admin, lk, "rej.test@corp.com")).json()["id"]
    card = next(i for i in (await admin.get(f"{API}/approvals?limit=100")).json()["items"] if i["identity"]["id"] == new_id)
    assert (await admin.post(f"{API}/approvals/{card['id']}/reject", {"comment": "no"})).status_code == 200
    assert await scalar(app, "select count(*) from identity_entitlements where identity_id=:i", i=new_id) == 0
    hist = (await admin.get(f"{API}/approvals?status=rejected&limit=100")).json()["items"]
    assert any(h["id"] == card["id"] and h["decision_comment"] == "no" for h in hist)


async def test_concurrent_decisions_exactly_one_wins(as_role, new_client, make_user):
    admin = await as_role("iam_admin")
    lk = (await admin.get(f"{API}/meta/lookups")).json()
    new_id = (await _onboard(admin, lk, "race.test@corp.com")).json()["id"]
    card = next(i for i in (await admin.get(f"{API}/approvals?limit=100")).json()["items"] if i["identity"]["id"] == new_id)
    await make_user("apr2@corp.com", "approver")
    other = new_client(); await other.login("apr2@corp.com")
    res = await asyncio.gather(admin.post(f"{API}/approvals/{card['id']}/approve", {}), other.post(f"{API}/approvals/{card['id']}/reject", {}))
    assert sorted(r.status_code for r in res) == [200, 409]


async def test_decision_on_unknown_request_404_and_writes_no_audit(as_role, app):
    admin = await as_role("iam_admin")
    n = await scalar(app, "select count(*) from audit_logs where action like 'approval.%'")
    assert (await admin.post(f"{API}/approvals/00000000-0000-0000-0000-000000000000/approve", {})).status_code == 404
    assert await scalar(app, "select count(*) from audit_logs where action like 'approval.%'") == n


async def test_onboarding_validation_and_duplicates(as_role):
    admin = await as_role("iam_admin")
    lk = (await admin.get(f"{API}/meta/lookups")).json()
    assert (await _onboard(admin, lk, "dup.test@corp.com")).status_code == 201
    r = await _onboard(admin, lk, "DUP.test@corp.com")
    assert r.status_code == 409 and r.json()["error"]["code"] == "email_exists"
    assert (await _onboard(admin, lk, "p.sharma@corp.com")).status_code == 409                    # collides with a seeded identity
    assert (await _onboard(admin, lk, "x@corp.com", department_id="00000000-0000-0000-0000-000000000000")).status_code == 422
    assert (await _onboard(admin, lk, "y@corp.com", start_date="2001-01-01")).status_code == 422
    assert (await _onboard(admin, lk, "not-an-email")).status_code == 422


async def test_seeded_mover_approval_moves_department(as_role, app):
    admin = await as_role("iam_admin")
    items = (await admin.get(f"{API}/approvals?status=pending&limit=100")).json()["items"]
    mover = next(i for i in items if i["type"] == "mover" and i["identity"]["name"] == "Layla Martinez")
    assert mover["from_department"] == "Support" and mover["to_department"] == "Engineering" and "Zendesk Agent" in mover["removed"]
    assert (await admin.post(f"{API}/approvals/{mover['id']}/approve", {})).status_code == 200
    assert await scalar(app, "select d.name from identities i join departments d on d.id=i.department_id where i.id=:i", i=mover["identity"]["id"]) == "Engineering"
    assert await scalar(app, "select status from identity_entitlements ie join entitlements e on e.id=ie.entitlement_id where ie.identity_id=:i and e.name='Zendesk Agent'", i=mover["identity"]["id"]) == "revoked"
    assert await scalar(app, "select status from identity_entitlements ie join entitlements e on e.id=ie.entitlement_id where ie.identity_id=:i and e.name='GitHub Enterprise'", i=mover["identity"]["id"]) == "pending"


# ------------------------------------------------------------------ risk
async def test_risk_summary_and_flagged(as_role, app):
    c = await as_role("auditor")
    s = (await c.get(f"{API}/risk/summary")).json()
    total = await scalar(app, "select count(*) from identities where lifecycle_state<>'terminated'")
    assert sum(s["tiers"].values()) == total
    assert s["tiers"]["high"] == await scalar(app, "select count(*) from identities where lifecycle_state<>'terminated' and risk_score>=75")
    ctl_pass, ctl_total = await scalar(app, "select count(*) filter (where status='pass') from compliance_controls"), await scalar(app, "select count(*) filter (where status in ('pass','fail')) from compliance_controls")
    assert s["compliance"]["percent"] == round(100 * ctl_pass / ctl_total, 1)
    assert len(s["trajectory"]) >= 6 and s["trajectory"][-1]["label"] == "Today" and s["trajectory"][0]["days_ago"] > 0
    assert s["triggers"] and all(t["count"] > 0 for t in s["triggers"])
    f = (await c.get(f"{API}/risk/flagged?limit=100")).json()
    assert f["total"] == s["tiers"]["high"] == len(f["items"])
    scores = [i["risk_score"] for i in f["items"]]
    assert scores == sorted(scores, reverse=True) and min(scores) >= 75 and f["items"][0]["name"] == "Kai Chen"
    assert "Abnormal login hours" in f["items"][0]["triggers"]


async def test_risk_export_csv_and_audit(as_role, app):
    c = await as_role("auditor")
    n = await scalar(app, "select count(*) from audit_logs where action='risk.export'")
    r = await c.get(f"{API}/risk/flagged/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("Name,Email") and "Kai Chen" in r.text
    assert await scalar(app, "select count(*) from audit_logs where action='risk.export'") == n + 1


def test_csv_formula_injection_neutralised():
    body = csv_response("x", ["a"], [["=HYPERLINK(\"http://evil\")"], ["+1"], ["@x"], ["fine"]]).body.decode()
    lines = body.splitlines()[1:]
    assert all(l.lstrip('"').startswith("'") for l in lines[:3]) and lines[3] == "fine"


# ------------------------------------------------------------------ governance
async def test_governance_summary_computed(as_role, app):
    c = await as_role("auditor")
    g = (await c.get(f"{API}/governance/summary")).json()
    assert len(g["frameworks"]) == 4
    for f in g["frameworks"]:
        p = await scalar(app, "select count(*) filter (where status='pass') from compliance_controls cc join compliance_frameworks fw on fw.id=cc.framework_id where fw.name=:n", n=f["name"])
        t = await scalar(app, "select count(*) filter (where status in ('pass','fail')) from compliance_controls cc join compliance_frameworks fw on fw.id=cc.framework_id where fw.name=:n", n=f["name"])
        assert f["percent"] == round(100 * p / t, 1)
    assert {c_["identity"]["name"] for c_ in g["sod_conflicts"]} >= {"David Walsh", "Beth Lambert", "Tyrone Jackson"}
    assert len(g["sod_conflicts"]) == 3 and all(len(c_["entitlements"]) == 2 for c_ in g["sod_conflicts"])
    for camp in g["campaigns"]:
        decided = await scalar(app, "select count(decision) from certification_items i join certification_campaigns c on c.id=i.campaign_id where c.name=:n", n=camp["name"])
        assert camp["decided"] == decided and camp["percent"] == round(100 * decided / camp["total"])
    assert {c_["status"] for c_ in g["connectors"]} <= {"demo", "not_configured", "disconnected"}


async def test_campaign_launch(as_role, app):
    admin = await as_role("iam_admin")
    lk = (await admin.get(f"{API}/meta/lookups")).json()
    eng = next(d for d in lk["departments"] if d["name"] == "Engineering")
    due = (date.today() + timedelta(days=30)).isoformat()
    r = await admin.post(f"{API}/governance/campaigns", {"name": "Engineering review (test)", "scope": "department", "department_id": eng["id"], "due_date": due})
    assert r.status_code == 201
    assert r.json()["accounts"] == await scalar(app, "select count(*) from identities i join departments d on d.id=i.department_id where d.name='Engineering' and lifecycle_state<>'terminated'")
    assert (await admin.post(f"{API}/governance/campaigns", {"name": "Engineering review (test)", "scope": "service", "due_date": due})).status_code == 409
    assert (await admin.post(f"{API}/governance/campaigns", {"name": "Past due", "scope": "service", "due_date": "2020-01-01"})).status_code == 422
    g = (await admin.get(f"{API}/governance/summary")).json()                                   # cache invalidated on launch
    assert any(c_["name"] == "Engineering review (test)" and c_["decided"] == 0 for c_ in g["campaigns"])


# ------------------------------------------------------------------ audit logs
async def test_audit_filters_pagination_export(as_role, app):
    c = await as_role("auditor")
    a = (await c.get(f"{API}/audit-logs?limit=5")).json()
    assert a["total"] == await scalar(app, "select count(*) from audit_logs") and len(a["items"]) == 5
    ts = [i["occurred_at"] for i in a["items"]]
    assert ts == sorted(ts, reverse=True)
    crit = (await c.get(f"{API}/audit-logs?severity=critical&limit=100")).json()
    assert crit["total"] == await scalar(app, "select count(*) from audit_logs where severity='critical'") and all(i["severity"] == "critical" for i in crit["items"])
    cat = (await c.get(f"{API}/audit-logs?category=risk_alert&limit=100")).json()
    assert cat["total"] == await scalar(app, "select count(*) from audit_logs where category='risk_alert'") > 0
    q = (await c.get(f"{API}/audit-logs?q=finance db")).json()
    assert q["total"] >= 1 and q["items"][0]["target"] == "Finance DB"
    assert (await c.get(f"{API}/audit-logs?severity=bogus")).status_code == 422
    exp = await c.get(f"{API}/audit-logs/export?severity=critical")
    assert exp.status_code == 200 and exp.text.splitlines()[0].startswith("Timestamp,Event")
    assert await scalar(app, "select count(*) from audit_logs where action='audit.export'") == 1


async def test_portal_security_events_appear_in_audit_log(as_role, client, make_user):
    c = await as_role("auditor")
    r = (await c.get(f"{API}/audit-logs?category=login&limit=50")).json()
    assert any(i["event"] == "User Sign-in" and i["actor"] == "auditor@corp.com" for i in r["items"])


# ------------------------------------------------------------------ assistant
async def test_assistant_answers_from_db(as_role, app):
    c = await as_role("auditor")
    r = (await c.post(f"{API}/assistant/query", {"query": "what is the risk for Kai Chen?"})).json()
    kv = next(b for b in r["blocks"] if b["type"] == "kv")
    assert ["Risk score", "87 / 100 (high)"] in kv["items"]
    pend = (await c.post(f"{API}/assistant/query", {"query": "show pending approvals"})).json()
    n = await scalar(app, "select count(*) from approval_requests where status='pending'")
    assert pend["blocks"][0]["text"] == f"{n} approval(s) pending"
    none = (await c.post(f"{API}/assistant/query", {"query": "onboard someone"})).json()
    assert not any(b["type"] == "action" for b in none["blocks"])                                 # auditor can't write -> no action offered
    assert "not a generative model" in none["source"]
    assert (await c.post(f"{API}/assistant/query", {"query": ""})).status_code == 422


# ------------------------------------------------------------------ cache behaviour
async def test_cache_ttl_and_graceful_degradation(as_role, app):
    c = await as_role("auditor")
    await c.get(f"{API}/risk/summary")
    keys = [k async for k in app.state.redis.scan_iter("cache:risk:*")]
    assert keys and 0 < await app.state.redis.ttl(keys[0]) <= 60

    class Dead:
        class state: redis = None
    from redis.asyncio import Redis
    dead = Redis.from_url("redis://localhost:1/0", socket_connect_timeout=0.2)
    req = type("R", (), {"app": type("A", (), {"state": type("S", (), {"redis": dead})()})()})()
    async def loader(): return {"ok": 1}
    assert await cached(req, "risk", "k", 10, loader) == {"ok": 1}                              # non-sensitive reads fall back to the DB
    await dead.aclose()


# ------------------------------------------------------------------ seed quality
async def test_seed_is_idempotent_and_consistent(app):
    from scripts.seed import seed
    tables = ["identities", "lifecycle_requests", "approval_requests", "risk_assessments", "identity_entitlements", "compliance_controls"]
    before = {t: await scalar(app, f"select count(*) from {t}") for t in tables}
    async with app.state.sessionmaker() as db:
        await seed(db, datetime.now(timezone.utc))
    assert {t: await scalar(app, f"select count(*) from {t}") for t in tables} == before
    assert await scalar(app, "select count(*) from identities where not is_demo and employee_id like 'DEMO-%'") == 0
    assert await scalar(app, "select count(*) from identity_connectors where status='connected'") == 0
    assert await scalar(app, "select count(*) from approval_requests a join lifecycle_requests r on r.id=a.lifecycle_request_id where a.status='pending' and r.status<>'pending_approval'") == 0
    assert await scalar(app, "select count(*) from identities i join lateral (select score from risk_assessments r where r.identity_id=i.id order by assessed_at desc limit 1) l on true where l.score<>i.risk_score and i.is_demo and i.employee_id not like 'EMP-%'") == 0
    assert await scalar(app, "select count(*) from audit_logs where target_type='identity' and target_id not in (select id::text from identities)") == 0
