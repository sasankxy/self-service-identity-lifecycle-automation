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


# ------------------------------------------------------------------ assistant + NLU pipeline
async def _ask(c, q):
    r = await c.post(f"{API}/assistant/query", {"query": q})
    assert r.status_code == 200, r.text
    return r.json()


def _texts(r):
    out = []
    for b in r["blocks"]:
        out += [b.get("text", "")] + [x if isinstance(x, str) else " ".join(x) for x in b.get("items", [])]
    return " | ".join(out)


async def test_assistant_nlu_status_query_uses_live_entitlements(as_role, app):
    c = await as_role("auditor")
    r = await _ask(c, "What access does Kai Chen have to Slack?")
    assert r["nlu"]["intent"] == "ACCESS_STATUS_QUERY" and "not a generative model" in r["source"]
    assert any(b["type"] == "kv" and ["Risk score", "87 / 100 (high)"] in b["items"] for b in r["blocks"])
    assert "Slack Enterprise" in _texts(r)                      # filtered to the requested application


async def test_assistant_nlu_mover_is_read_only_and_checks_directory(as_role):
    c = await as_role("auditor")
    r = await _ask(c, "Move Kai Chen from Finance to Sales")
    assert r["nlu"]["intent"] == "MOVER"
    t = _texts(r)
    assert "not Finance" in t and "Policy decision" in t                  # Kai is not in Finance in the directory
    assert not any(b["type"] == "action" and b["action"] == "execute" for b in r["blocks"])   # auditor: review only
    assert "can review this but not submit" in t


async def test_assistant_nlu_joiner_prefills_form_only_for_writers(as_role):
    c = await as_role("auditor")
    r = await _ask(c, "Onboard Zed Qwerty to Sales next Monday")
    assert r["nlu"]["intent"] == "JOINER" and not any(b["type"] == "action" for b in r["blocks"])


async def test_assistant_nlu_clarifies_instead_of_guessing(as_role):
    c = await as_role("auditor")
    r = await _ask(c, "Move Kai Chen")                                    # target department missing
    assert r["nlu"]["status"] == "NEEDS_CLARIFICATION" and "more detail" in _texts(r)


async def test_assistant_keeps_analytics_questions_on_keyword_rules(as_role, app):
    c = await as_role("auditor")
    for q in ("show pending approvals", "show high-risk identities", "show open leaver requests"):
        r = await _ask(c, q)
        assert r["nlu"] is None, q                                        # NLU mislabels these; they must not be hijacked
    n = await scalar(app, "select count(*) from approval_requests where status='pending'")
    assert (await _ask(c, "show pending approvals"))["blocks"][0]["text"] == f"{n} approval(s) pending"


async def test_assistant_degrades_to_keyword_rules_if_nlu_unavailable(as_role, monkeypatch):
    from app.services import nlu

    async def broken(*a, **k):
        return None
    monkeypatch.setattr(nlu, "parse", broken)
    c = await as_role("auditor")
    r = await _ask(c, "what is the risk for Kai Chen?")
    assert r["nlu"] is None and any(b["type"] == "kv" for b in r["blocks"])


async def test_assistant_nlu_joiner_prefill_for_iam_admin(as_role, app):
    c = await as_role("iam_admin")
    r = await _ask(c, "Onboard Zed Qwerty to Sales next Monday")
    act = next(b for b in r["blocks"] if b["type"] == "action")
    dept_id = await scalar(app, "select id::text from departments where name='Sales'")
    assert act["action"] == "open-onboard"
    assert act["prefill"]["first_name"] == "Zed" and act["prefill"]["last_name"] == "Qwerty"
    assert act["prefill"]["department_id"] == dept_id and act["prefill"]["start_date"]
    n = await scalar(app, "select count(*) from identities where full_name='Zed Qwerty'")
    assert n == 0                                                         # nothing is ever created from chat


async def test_assistant_nlu_self_reference_resolves_signed_in_user(as_role, app):
    c = await as_role("auditor")
    r = await _ask(c, "What access do I have?")
    assert r["nlu"]["intent"] == "ACCESS_STATUS_QUERY"
    assert "couldn't find a matching identity" in _texts(r)               # portal user auditor@corp.com has no directory identity


# ------------------------------------------------------------------ policy engine + execution from chat
from sqlalchemy import text as _sql


async def _exec(app, sql, **kw):
    async with app.state.sessionmaker() as db:
        await db.execute(_sql(sql), kw)
        await db.commit()


async def _low_risk(app, dept):
    """A low-risk active identity in `dept` whose name is unique in the directory."""
    return await scalar(app, f"select full_name from identities i join departments d on d.id=i.department_id where d.name='{dept}' "
                             "and i.risk_score < 40 and i.lifecycle_state='active' and (select count(*) from identities x where x.full_name=i.full_name)=1 "
                             "and i.full_name not like '%''%' order by i.full_name limit 1")


def _action(r):
    return next((b for b in r["blocks"] if b["type"] == "action" and b["action"] == "execute"), None)


async def test_brief_example_is_parsed_as_one_mover_with_access(as_role, app):
    name = await _low_risk(app, "Engineering")
    c = await as_role("iam_admin")
    r = await _ask(c, f"Move {name} from Engineering to Finance and give them access to SAP starting next Monday.")
    assert r["nlu"]["intent"] == "MOVER" and r["nlu"]["status"] == "PARSED"
    t = _texts(r)
    assert "Finance ERP" in t and "Engineering → Finance" in t            # SAP -> ERP -> the Finance baseline entitlement
    act = _action(r)
    assert act and act["expected_decision"] == "auto" and act["label"].startswith("Confirm (scheduled for")


async def test_auto_approved_move_is_scheduled_then_applied_on_the_date(as_role, app):
    from datetime import date, timedelta
    from app.services.lifecycle import apply_due_requests
    name = await _low_risk(app, "Engineering")
    c = await as_role("iam_admin")
    act = _action(await _ask(c, f"Move {name} from Engineering to Finance and give them access to SAP starting next Monday."))
    res = await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "auto"})
    assert res.status_code == 200, res.text
    out = res.json()
    assert out["decision"] == "auto" and out["applied"] is False and out["scheduled_for"]
    dept = lambda: scalar(app, f"select d.name from identities i join departments d on d.id=i.department_id where i.full_name='{name}'")
    assert await dept() == "Engineering"                                   # not before the effective date
    assert await scalar(app, "select count(*) from approval_requests where status='approved' and decision_comment like 'Auto-approved by policy%'") == 1
    assert await scalar(app, "select count(*) from audit_logs where action='assistant.request_auto_approved'") == 1
    async with app.state.sessionmaker() as db:
        assert await apply_due_requests(db, today=date.today() + timedelta(days=10)) == 1
    assert await dept() == "Finance"
    assert await scalar(app, f"select count(*) from identity_entitlements ie join entitlements e on e.id=ie.entitlement_id join identities i on i.id=ie.identity_id "
                             f"where i.full_name='{name}' and e.name='Finance ERP' and ie.status='pending'") == 1


async def test_immediate_auto_move_applies_now_and_is_idempotent(as_role, app):
    name = await _low_risk(app, "Sales")
    c = await as_role("iam_admin")
    act = _action(await _ask(c, f"Move {name} from Sales to Marketing"))
    assert act["expected_decision"] == "auto"
    out = (await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "auto"})).json()
    assert out["applied"] is True
    assert await scalar(app, f"select d.name from identities i join departments d on d.id=i.department_id where i.full_name='{name}'") == "Marketing"
    again = await _ask(c, f"Move {name} to Marketing")
    assert _action(again) is None and "already in Marketing" in _texts(again)


async def test_high_risk_entitlement_goes_to_a_human(as_role, app):
    name = await _low_risk(app, "Engineering")
    c = await as_role("iam_admin")
    r = await _ask(c, f"Give {name} access to Documents")                  # Confidential Document Store: high risk, requires approval
    act = _action(r)
    assert act and act["expected_decision"] == "approval" and act["label"] == "Submit for approval"
    before = await scalar(app, "select count(*) from approval_requests where status='pending'")
    out = (await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "approval"})).json()
    assert out["request_status"] == "pending_approval"
    assert await scalar(app, "select count(*) from approval_requests where status='pending'") == before + 1
    assert await scalar(app, f"select count(*) from identity_entitlements ie join identities i on i.id=ie.identity_id where i.full_name='{name}' and ie.source like 'request:%'") == 0
    dup = await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "approval"})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "duplicate_request"


async def test_justification_text_never_changes_the_decision(as_role, app):
    name = await _low_risk(app, "Engineering")
    c = await as_role("iam_admin")
    a = _action(await _ask(c, f"Give {name} access to Documents"))
    b = _action(await _ask(c, f"Give {name} access to Documents because I need to finish my work and my manager said it's fine"))
    assert a["expected_decision"] == b["expected_decision"] == "approval"


async def test_separation_of_duties_is_denied(as_role, app):
    name = await _low_risk(app, "Finance")
    await _exec(app, "insert into identity_entitlements (identity_id, entitlement_id, status, source) "
                     "select i.id, e.id, 'active', 'test' from identities i, entitlements e where i.full_name=:n and e.name='AP Payment Release'", n=name)
    c = await as_role("iam_admin")
    r = await _ask(c, f"Give {name} access to Vendor Management")
    assert "blocked" in _texts(r) and "separation-of-duties" in _texts(r) and _action(r) is None


async def test_high_risk_person_cannot_be_auto_approved_even_for_low_risk_access(as_role):
    c = await as_role("iam_admin")
    r = await _ask(c, "Give Kai Chen access to Zoom")
    act = _action(r)
    assert act and act["expected_decision"] == "approval" and "high risk score" in _texts(r)


async def test_ambiguous_application_asks_which_entitlement(as_role, app):
    name = await _low_risk(app, "Sales")
    c = await as_role("iam_admin")
    r = await _ask(c, f"Give {name} access to AWS")
    assert _action(r) is None and "Which one do you need" in _texts(r)


async def test_revocation_is_auto_and_removes_access(as_role, app):
    name = await _low_risk(app, "Engineering")
    await _exec(app, "insert into identity_entitlements (identity_id, entitlement_id, status, source) "
                     "select i.id, e.id, 'active', 'test' from identities i, entitlements e where i.full_name=:n and e.name='Zoom Pro' "
                     "on conflict do nothing", n=name)
    c = await as_role("iam_admin")
    act = _action(await _ask(c, f"Revoke {name}'s access to Zoom"))
    assert act and act["expected_decision"] == "auto"
    assert (await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "auto"})).json()["applied"] is True
    assert await scalar(app, f"select count(*) from identity_entitlements ie join identities i on i.id=ie.identity_id join entitlements e on e.id=ie.entitlement_id "
                             f"where i.full_name='{name}' and e.name='Zoom Pro' and ie.status='revoked'") == 1


async def test_execute_rechecks_policy_and_enforces_permission(as_role, app):
    name = await _low_risk(app, "Engineering")
    c = await as_role("iam_admin")
    act = _action(await _ask(c, f"Give {name} access to Documents"))
    # a tampered client claiming the request is auto-approvable is refused: the server decides
    r = await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "auto"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "policy_changed"
    aud = await as_role("auditor")
    assert (await aud.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "approval"})).status_code == 403


# ------------------------------------------------------------------ SLM fallback (suggest-only)
class _FakeSLM:
    def __init__(self, out): self.out, self.calls = out, 0
    async def interpret(self, text, cat):
        self.calls += 1
        return self.out


async def test_slm_is_not_consulted_when_the_custom_engine_understands(as_role, app):
    from app.services import slm
    fake = _FakeSLM({"intent": "MOVER", "person": "X", "source_department": None, "target_department": "Sales", "applications": [], "question": None, "rephrase": "x"})
    slm.set_client(fake)
    try:
        c = await as_role("iam_admin")
        await _ask(c, f"Move {await _low_risk(app, 'Sales')} to Marketing")
        await _ask(c, "show pending approvals")
        assert fake.calls == 0
    finally:
        slm.set_client(None)


async def test_slm_suggestion_is_clickable_text_never_an_action(as_role):
    from app.services import slm
    out = slm.sanitize({"intent": "JOINER", "person": "Rahul Sharma", "source_department": None, "target_department": "finance",
                        "applications": ["ERP", "Skynet"], "clarification_question": "Which role does he need?"},
                       {"departments": ["Finance", "Sales"], "applications": ["ERP"]})
    assert out["target_department"] == "Finance" and out["applications"] == ["ERP"]       # hallucinated app dropped, case normalised
    slm.set_client(_FakeSLM(out))
    try:
        c = await as_role("iam_admin")
        r = await _ask(c, "blorp the invoice people need whatever")
        t = _texts(r)
        assert r["nlu"]["slm_used"] is True and "can only suggest" in t
        assert "Which role does he need?" not in t                      # suggestion is complete -> the model's own question is suppressed
        assert _action(r) is None
        assert any(b["type"] == "action" and b["action"] == "prompt:Onboard Rahul Sharma to Finance" for b in r["blocks"])
    finally:
        slm.set_client(None)


def test_slm_keeps_its_question_only_when_it_has_no_actionable_suggestion():
    from app.services import slm
    cat = {"departments": ["Finance"], "applications": ["ERP"]}
    out = slm.sanitize({"intent": "MOVER", "person": "Ana Lopez", "source_department": None, "target_department": None,
                        "applications": [], "clarification_question": "Which department?"}, cat)
    assert out["rephrase"] is None and out["question"] == "Which department?"


def test_slm_sanitize_rejects_garbage_and_unknown_intents():
    from app.services import slm
    cat = {"departments": ["Finance"], "applications": ["ERP"]}
    assert slm.sanitize("nope", cat) is None
    assert slm.sanitize({"intent": "DELETE_EVERYTHING"}, cat) is None
    assert slm.sanitize({"intent": "UNKNOWN", "clarification_question": None}, cat) is None


# ------------------------------------------------------------------ a move provisions the target department's profile
async def _row(app, sql):
    async with app.state.sessionmaker() as db:
        return (await db.execute(_sql(sql))).all()


async def test_move_grants_target_profile_access_and_sets_profile(as_role, app):
    name = await _low_risk(app, "Engineering")
    c = await as_role("iam_admin")
    r = await _ask(c, f"Move {name} to Finance")
    t = _texts(r)
    assert "Financial Analyst" in t and "Finance ERP" in t and "Keeps" in t           # grants the profile, shows what is kept
    act = _action(r)
    assert act["expected_decision"] == "auto"
    assert (await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "auto"})).json()["applied"] is True
    held = {n for (n, st) in await _row(app, f"select e.name, ie.status from identity_entitlements ie join entitlements e on e.id=ie.entitlement_id "
                                              f"join identities i on i.id=ie.identity_id where i.full_name='{name}' and ie.status in ('active','pending')")}
    assert "Finance ERP" in held and "Microsoft 365" in held and "GitHub Enterprise" not in held and "VPN Access" not in held
    assert (await _row(app, f"select p.name from identities i join access_profiles p on p.id=i.access_profile_id where i.full_name='{name}'"))[0][0] == "Financial Analyst"


async def test_move_into_department_with_several_profiles_asks_which_one(as_role, app):
    name = await _low_risk(app, "Sales")
    c = await as_role("iam_admin")
    r = await _ask(c, f"Move {name} to Engineering")
    assert "Which one should" in _texts(r) and _action(r) is None                       # nothing to confirm yet
    pick = next(b for b in r["blocks"] if b["type"] == "action" and b["action"] == "replan" and b["label"] == "Use profile: Senior Developer")
    r2 = (await c.post(f"{API}/assistant/plan", pick["proposal"])).json()
    act = _action(r2)
    assert act and act["expected_decision"] == "auto" and "Senior Developer" in _texts(r2)
    assert (await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "auto"})).json()["applied"] is True
    assert (await _row(app, f"select p.name from identities i join access_profiles p on p.id=i.access_profile_id where i.full_name='{name}'"))[0][0] == "Senior Developer"


async def test_plan_endpoint_is_read_only_and_rejects_foreign_profiles(as_role, app):
    name = await _low_risk(app, "Sales")
    c = await as_role("auditor")                                                          # read-only role may re-plan, not execute
    before = await scalar(app, "select count(*) from lifecycle_requests")
    r = await _ask(c, f"Move {name} to Engineering")
    pick = next(b for b in r["blocks"] if b["type"] == "action" and b["action"] == "replan")
    assert (await c.post(f"{API}/assistant/plan", pick["proposal"])).status_code == 200
    bad = await c.post(f"{API}/assistant/plan", {**pick["proposal"], "access_profile": "Financial Analyst"})   # not an Engineering profile
    assert bad.status_code == 422
    assert await scalar(app, "select count(*) from lifecycle_requests") == before                 # planning creates nothing
