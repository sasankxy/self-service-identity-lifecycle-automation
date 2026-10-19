"""Proactive governance (orphan + privilege-creep detection, mover trigger, scheduler), the leaver/deprovision flow,
requester-history risk, and the audit filters. Real Postgres + Redis, real seed; planted cases are removed after each test."""
import asyncio
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

from app.models import (AccessProfile, Department, Entitlement, GovernanceFinding, Identity, IdentityEntitlement, LifecycleRequest)
from app.services import detection, governance_scan, lifecycle, scheduler
from tests.test_data_api import API, _action, _ask, _low_risk, as_role, scalar  # noqa: F401  (as_role is a fixture)

UTC = timezone.utc


# ------------------------------------------------------------------ fixtures / helpers
@pytest_asyncio.fixture(autouse=True)
async def clean(app):
    async def wipe():
        async with app.state.sessionmaker() as db:
            await db.execute(text("DELETE FROM governance_findings"))
            await db.execute(text("DELETE FROM governance_scan_runs"))
            await db.execute(text("DELETE FROM identities WHERE employee_id LIKE 'T-%'"))      # cascades to grants, requests, findings
            await db.commit()
    await wipe()
    yield
    await wipe()


async def _dept(db, name):
    return (await db.execute(select(Department).where(Department.name == name))).scalar_one()


async def _baseline_names(db, dept_name) -> list[str]:
    rows = await db.execute(text("select distinct e.name from entitlements e join access_profile_entitlements ap on ap.entitlement_id=e.id "
                                 "join access_profiles p on p.id=ap.access_profile_id join departments d on d.id=p.department_id where d.name=:d order by 1"),
                            {"d": dept_name})
    return [r[0] for r in rows]


async def _outside(db, dept_name, risk="high") -> Entitlement:
    """An entitlement of the given risk level that is in nobody's `dept_name` baseline."""
    base = await _baseline_names(db, dept_name)
    return (await db.execute(select(Entitlement).where(Entitlement.risk_level == risk, Entitlement.name.notin_(base)).order_by(Entitlement.name))).scalars().first()


async def _ent(db, name) -> Entitlement:
    return (await db.execute(select(Entitlement).where(Entitlement.name == name))).scalar_one()


async def _plant(app, name, *, dept="Finance", state="active", itype="employee", profile="Financial Analyst", manager=None, end_date=None,
                 last_auth_days: int | None = 1, start_days_ago=400, grants=(), source="profile") -> uuid.UUID:
    """Insert an identity. `grants` = entitlement names (source=`source`) or (name, source) tuples."""
    async with app.state.sessionmaker() as db:
        d = await _dept(db, dept) if dept else None
        prof = (await db.execute(select(AccessProfile).where(AccessProfile.name == profile))).scalar_one_or_none() if profile else None
        now = datetime.now(UTC)
        i = Identity(employee_id=f"T-{uuid.uuid4().hex[:8]}", full_name=name, email=f"{uuid.uuid4().hex[:10]}@planted.test", identity_type=itype,
                     department_id=d.id if d else None, access_profile_id=prof.id if prof else None, manager_id=manager, lifecycle_state=state,
                     start_date=date.today() - timedelta(days=start_days_ago), end_date=end_date,
                     last_authentication_at=None if last_auth_days is None else now - timedelta(days=last_auth_days))
        db.add(i)
        await db.flush()
        for g in grants:
            gname, gsrc = (g, source) if isinstance(g, str) else g
            db.add(IdentityEntitlement(identity_id=i.id, entitlement_id=(await _ent(db, gname)).id, status="active", source=gsrc))
        await db.commit()
        return i.id


async def _exec(app, q, **p):
    async with app.state.sessionmaker() as db:
        await db.execute(text(q), p)
        await db.commit()


async def _scan(app, trigger="manual"):
    out = await governance_scan.run_scan(app.state.sessionmaker, app.state.redis, trigger=trigger)
    assert out is not None
    return out


async def _findings(app, *ids, status=None) -> dict[uuid.UUID, dict[str, GovernanceFinding]]:
    async with app.state.sessionmaker() as db:
        q = select(GovernanceFinding).where(GovernanceFinding.identity_id.in_(ids))
        if status:
            q = q.where(GovernanceFinding.status == status)
        out: dict = {i: {} for i in ids}
        for f in (await db.execute(q)).scalars():
            out[f.identity_id][f.rule if not f.subject_key else f"{f.rule}:{f.subject_key}"] = f
        return out


# ------------------------------------------------------------------ orphaned accounts
async def test_orphan_rules_flag_planted_cases_and_leave_clean_accounts_alone(app):
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:2]
    today = date.today()
    boss = await _plant(app, "Boss Active", grants=base)
    gone_boss = await _plant(app, "Boss Gone", state="terminated", grants=[])
    cases = {
        "terminated": await _plant(app, "T Terminated", state="terminated", grants=base, last_auth_days=200),
        "leaver_overdue": await _plant(app, "T Leaver Overdue", state="leaver", end_date=today - timedelta(days=5), grants=base),
        "leaver_future": await _plant(app, "T Leaver Future", state="leaver", end_date=today + timedelta(days=5), grants=base),
        "expired": await _plant(app, "T Expired", itype="contractor", end_date=today - timedelta(days=3), grants=base, manager=boss),
        "dormant": await _plant(app, "T Dormant", last_auth_days=120, grants=base, manager=boss),
        "never": await _plant(app, "T Never", last_auth_days=None, start_days_ago=100, grants=base, manager=boss),
        "new_never": await _plant(app, "T Brand New", last_auth_days=None, start_days_ago=3, grants=base, manager=boss),
        "svc": await _plant(app, "T svc-orphan", itype="service", dept=None, profile=None, manager=None),
        "sponsorless": await _plant(app, "T Contractor", itype="contractor", grants=base, manager=None),
        "mgr_gone": await _plant(app, "T Orphaned Report", grants=base, manager=gone_boss),
        "clean": await _plant(app, "T Clean", grants=base, manager=boss),
    }
    out = await _scan(app)
    assert out["status"] == "ok" and out["identities_scanned"] >= len(cases) + 2
    f = await _findings(app, *cases.values())
    rules = {k: {r for r in f[i] if not r.startswith("excess")} for k, i in cases.items()}
    assert rules["terminated"] == {"leaver_with_access"} and f[cases["terminated"]]["leaver_with_access"].severity == "critical"
    assert rules["leaver_overdue"] == {"leaver_with_access"} and f[cases["leaver_overdue"]]["leaver_with_access"].severity == "high"
    assert rules["leaver_future"] == set()                                           # still inside the notice window: normal
    assert rules["expired"] == {"expired_still_active"}
    assert rules["dormant"] == {"dormant_account"} and f[cases["dormant"]]["dormant_account"].details["days_inactive"] >= 119
    assert rules["never"] == {"dormant_account"} and f[cases["never"]]["dormant_account"].details["never_signed_in"] is True
    assert rules["new_never"] == set()                                               # grace period for brand-new joiners
    assert rules["svc"] == {"no_owner"} and rules["sponsorless"] == {"no_owner"}
    assert rules["mgr_gone"] == {"manager_departed"}
    assert rules["clean"] == set() and not f[cases["clean"]]
    # every finding is explainable and the planted critical one was alerted in the audit log
    assert all(x.title and x.details and x.kind == "orphan" for i in cases.values() for x in f[i].values())
    assert await scalar(app, "select count(*) from audit_logs where action='governance.finding_opened' and severity='critical' and category='risk_alert'") >= 1
    assert await scalar(app, "select count(*) from audit_logs where action='governance.scan' and actor_label='system'") == 1
    assert await scalar(app, "select count(*) from governance_scan_runs where trigger='manual' and status='ok'") == 1


# ------------------------------------------------------------------ privilege creep
async def test_privilege_creep_is_what_exceeds_the_role_baseline(app):
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:2]
        extra = await _outside(db, "Finance", "high")
        extra2 = await _outside(db, "Finance", "medium")
        extra_name, extra2_name = extra.name, extra2.name
        extra_id = str(extra.id)
    boss = await _plant(app, "Boss", grants=base)
    creepy = await _plant(app, "T Creepy", manager=boss, grants=[*base, (extra_name, "manual")])
    approved = await _plant(app, "T Approved Exception", manager=boss, grants=[*base, (extra_name, "request:5001")])
    svc = await _plant(app, "T svc-creep", itype="service", dept=None, profile=None, manager=boss, grants=[(extra_name, "manual")])
    nobase = await _plant(app, "T No Baseline", dept=None, profile=None, manager=boss, grants=[(extra_name, "manual")])
    two = await _plant(app, "T Two Excess", manager=boss, grants=[*base, (extra_name, "manual"), (extra2_name, "import")])
    await _scan(app)
    f = await _findings(app, creepy, approved, svc, nobase, two)
    assert list(f[creepy]) == [f"excess_access:{extra_id}"]
    hit = f[creepy][f"excess_access:{extra_id}"]
    assert hit.kind == "creep" and hit.severity == "high" and hit.details["entitlement"] == extra_name and hit.details["source"] == "manual"
    assert not f[approved]                      # an approved request is its own justification
    assert not f[svc] and not f[nobase]         # no role baseline -> not judged
    assert {x.severity for x in f[two].values()} == {"high", "medium"}      # severity follows the entitlement's risk


async def test_findings_open_refresh_resolve_reopen_and_dismiss(app, as_role):
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:1]
        extra = await _outside(db, "Finance", "high")
        extra_name, key = extra.name, f"excess_access:{extra.id}"
    boss = await _plant(app, "Boss", grants=base)
    i = await _plant(app, "T Lifecycle", manager=boss, grants=[*base, (extra_name, "manual")])
    r1 = await _scan(app)
    assert (await _findings(app, i))[i][key].status == "open" and r1["opened"] >= 1
    first = (await _findings(app, i))[i][key].first_detected_at
    r2 = await _scan(app)                                                 # idempotent: same finding refreshed, nothing new for it
    f2 = (await _findings(app, i))[i][key]
    assert f2.status == "open" and f2.first_detected_at == first and f2.last_detected_at > first
    assert await scalar(app, f"select count(*) from governance_findings where identity_id='{i}'") == 1
    # fix it -> the next scan auto-resolves
    await _exec(app, f"update identity_entitlements set status='revoked' where identity_id='{i}' and source='manual'")
    r3 = await _scan(app)
    assert (await _findings(app, i))[i][key].status == "resolved" and r3["resolved"] >= 1
    # it comes back -> re-opened (and alerted again)
    await _exec(app, f"update identity_entitlements set status='active' where identity_id='{i}' and source='manual'")
    await _scan(app)
    fo = (await _findings(app, i))[i][key]
    assert fo.status == "open" and fo.resolved_at is None
    # dismiss through the API (manage permission only) and it stays dismissed while still detected
    auditor, admin = await as_role("auditor"), await as_role("iam_admin")
    assert (await auditor.post(f"{API}/governance/findings/{fo.id}/dismiss", {"reason": "Approved by CISO"})).status_code == 403
    assert (await admin.post(f"{API}/governance/findings/{fo.id}/dismiss", {"reason": "x"})).status_code == 422
    ok = await admin.post(f"{API}/governance/findings/{fo.id}/dismiss", {"reason": "Approved by CISO, ticket 123"})
    assert ok.status_code == 200 and ok.json()["status"] == "dismissed"
    assert (await admin.post(f"{API}/governance/findings/{fo.id}/dismiss", {"reason": "again please"})).status_code == 409
    assert await scalar(app, "select count(*) from audit_logs where action='governance.finding_dismissed'") == 1
    await _scan(app)
    assert (await _findings(app, i))[i][key].status == "dismissed"
    assert (await admin.post(f"{API}/governance/findings/{uuid.uuid4()}/dismiss", {"reason": "does not exist"})).status_code == 404


# ------------------------------------------------------------------ mover-event trigger
async def _approved_move(app, ident_id, to_dept="Finance", profile="Financial Analyst"):
    async with app.state.sessionmaker() as db:
        d, prof = await _dept(db, to_dept), (await db.execute(select(AccessProfile).where(AccessProfile.name == profile))).scalar_one()
        req = LifecycleRequest(identity_id=ident_id, request_type="mover", status="approved", to_department_id=d.id,
                               effective_date=date.today(), payload={"access_profile_id": str(prof.id)})
        db.add(req)
        await db.flush()
        ident = await db.get(Identity, ident_id)
        await lifecycle.apply_effects(db, req, ident, None, datetime.now(UTC))
        await db.commit()


async def test_mover_event_rechecks_the_person_right_after_the_move(app):
    async with app.state.sessionmaker() as db:
        eng_base = await _baseline_names(db, "Engineering")
    boss = await _plant(app, "Boss", dept="Engineering", profile="Senior Developer", grants=eng_base[:1])
    i = await _plant(app, "T Mover", dept="Engineering", profile="Senior Developer", manager=boss, grants=eng_base)
    await _scan(app)
    assert not (await _findings(app, i))[i]                               # fine as an engineer
    await _approved_move(app, i)                                          # moves to Finance; nobody ran a scan
    f = (await _findings(app, i))[i]
    assert f and all(x.rule == "excess_access" and x.source == "mover_trigger" and x.status == "open" for x in f.values())
    assert await scalar(app, f"select count(*) from audit_logs where action='governance.mover_recheck' and target_id='{i}' and details->>'opened' <> '0'") == 1
    assert await scalar(app, f"select d.name from identities x join departments d on d.id=x.department_id where x.id='{i}'") == "Finance"


async def test_mover_recheck_can_never_block_the_move(app, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("detector exploded")
    monkeypatch.setattr(detection, "detect", boom)
    i = await _plant(app, "T Resilient", dept="Engineering", profile="Senior Developer", grants=[])
    await _approved_move(app, i)
    assert await scalar(app, f"select d.name from identities x join departments d on d.id=x.department_id where x.id='{i}'") == "Finance"


# ------------------------------------------------------------------ scheduler / scan runner
async def test_only_one_scan_runs_at_a_time(app):
    a, b = await asyncio.gather(governance_scan.run_scan(app.state.sessionmaker, app.state.redis, trigger="manual"),
                                governance_scan.run_scan(app.state.sessionmaker, app.state.redis, trigger="manual"))
    assert [a is None, b is None].count(True) == 1                        # the loser backs off instead of scanning twice
    assert await scalar(app, "select count(*) from governance_scan_runs") == 1
    assert await app.state.redis.get(governance_scan.LOCK_KEY) is None    # lock released


async def test_scan_applies_due_requests_before_detecting(app):
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:2]
    boss = await _plant(app, "Boss", grants=base)
    i = await _plant(app, "T Due Leaver", manager=boss, grants=base)
    async with app.state.sessionmaker() as db:
        db.add(LifecycleRequest(identity_id=i, request_type="leaver", status="approved", effective_date=date.today() - timedelta(days=1),
                                payload={"scheduled": True, "applied": False}))
        await db.commit()
    out = await _scan(app, "scheduled")
    assert out["applied_due"] >= 1
    assert await scalar(app, f"select lifecycle_state from identities where id='{i}'") == "terminated"
    assert await scalar(app, f"select count(*) from identity_entitlements where identity_id='{i}' and status in ('active','pending')") == 0
    assert not (await _findings(app, i))[i]                               # nothing left to flag: it was offboarded first


async def test_background_loop_runs_scans_and_stops_cleanly(app, settings):
    assert scheduler.start(app, settings) is None                         # never auto-starts under ENV=test
    task = asyncio.create_task(scheduler.scan_loop(app, interval_s=0.5, initial_delay_s=0))
    for _ in range(40):
        await asyncio.sleep(0.25)
        if await scalar(app, "select count(*) from governance_scan_runs where trigger='scheduled'"):
            break
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled() or task.done()
    assert await scalar(app, "select count(*) from governance_scan_runs where trigger='scheduled' and status='ok'") >= 1


# ------------------------------------------------------------------ findings API
async def test_findings_api_permissions_listing_and_scan_now(app, as_role, client):
    assert (await client.get(f"{API}/governance/findings")).status_code == 401
    assert (await (await as_role("employee")).get(f"{API}/governance/findings")).status_code == 403
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:1]
    await _plant(app, "T Terminated API", state="terminated", grants=base, last_auth_days=300)
    auditor, admin = await as_role("auditor"), await as_role("iam_admin")
    assert (await auditor.post(f"{API}/governance/scan")).status_code == 403
    scan = await admin.post(f"{API}/governance/scan")
    assert scan.status_code == 200 and scan.json()["trigger"] == "manual" and scan.json()["opened"] >= 1
    d = (await auditor.get(f"{API}/governance/findings")).json()
    assert d["last_scan"]["status"] == "ok" and d["counts"]["open"] == d["total"] and d["counts"]["critical"] >= 1
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sev = [order[x["severity"]] for x in d["items"]]
    assert sev == sorted(sev) and d["items"][0]["severity"] == "critical"          # worst first
    assert {"id", "title", "rule", "kind", "details", "identity"} <= set(d["items"][0])
    orphan = (await auditor.get(f"{API}/governance/findings?kind=orphan&severity=critical")).json()
    assert orphan["total"] >= 1 and all(x["kind"] == "orphan" and x["severity"] == "critical" for x in orphan["items"])
    assert (await auditor.get(f"{API}/governance/findings?kind=bogus")).status_code == 422


# ------------------------------------------------------------------ leaver / deprovision flow
async def _open_leaver_refs(app, name):
    return await scalar(app, f"select count(*) from lifecycle_requests r join identities i on i.id=r.identity_id where i.full_name='{name}' "
                             "and r.request_type='leaver' and r.status='pending_approval'")


async def test_offboarding_from_chat_is_always_approval_gated_and_applies_on_approval(app, as_role):
    name = await _low_risk(app, "Engineering")
    c, approver = await as_role("iam_admin"), await as_role("approver")
    r = await _ask(c, f"Offboard {name}")
    blocks = r["blocks"]
    assert not any("isn't available" in b.get("text", "") for b in blocks)
    act = _action(r)
    assert act and act["expected_decision"] == "approval" and act["label"] == "Submit for approval" and act["proposal"]["kind"] == "leaver"
    assert any(b["type"] == "kv" and ["Offboarding", "Deactivates the account and revokes all access"] in b["items"] for b in blocks)
    held = await scalar(app, f"select count(*) from identity_entitlements ie join identities i on i.id=ie.identity_id where i.full_name='{name}' and ie.status in ('active','pending')")
    out = await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "approval"})
    assert out.status_code == 200, out.text
    assert out.json()["request_status"] == "pending_approval"
    assert await _open_leaver_refs(app, name) == 1
    # nothing is revoked until a person approves
    assert await scalar(app, f"select count(*) from identity_entitlements ie join identities i on i.id=ie.identity_id where i.full_name='{name}' and ie.status in ('active','pending')") == held
    assert await scalar(app, f"select lifecycle_state from identities where full_name='{name}'") == "active"
    # asking again does not create a second request
    again = await _ask(c, f"Offboard {name}")
    assert _action(again) is None and any("already open" in b.get("text", "") for b in again["blocks"])
    dup = await c.post(f"{API}/assistant/execute", {"proposal": act["proposal"], "expected_decision": "approval"})
    assert dup.status_code in (409, 422)
    # approve -> terminated, everything revoked
    ap_id = await scalar(app, f"select a.id from approval_requests a join lifecycle_requests r on r.id=a.lifecycle_request_id join identities i on i.id=r.identity_id "
                              f"where i.full_name='{name}' and r.request_type='leaver' and a.status='pending'")
    assert (await approver.post(f"{API}/approvals/{ap_id}/approve", {"comment": "Last day confirmed by HR"})).status_code == 200
    assert await scalar(app, f"select lifecycle_state from identities where full_name='{name}'") == "terminated"
    assert await scalar(app, f"select count(*) from identity_entitlements ie join identities i on i.id=ie.identity_id where i.full_name='{name}' and ie.status in ('active','pending')") == 0
    assert await scalar(app, f"select end_date is not null from identities where full_name='{name}'") is True
    again = await _ask(c, f"Offboard {name}")
    assert _action(again) is None and any("already terminated" in b.get("text", "") for b in again["blocks"])


async def test_deprovision_api_creates_a_pending_request_and_validates(app, as_role):
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:2]
    i = await _plant(app, "T Leaving Person", grants=base)
    admin, auditor = await as_role("iam_admin"), await as_role("auditor")
    url = f"{API}/identities/{i}/deprovision"
    assert (await auditor.post(url, {"reason": "Resigned"})).status_code == 403
    assert (await admin.post(url, {"reason": "x"})).status_code == 422
    assert (await admin.post(f"{API}/identities/{uuid.uuid4()}/deprovision", {"reason": "Resigned"})).status_code == 404
    assert (await admin.post(url, {"reason": "Resigned", "effective_date": (date.today() - timedelta(days=1)).isoformat()})).status_code == 422
    ok = await admin.post(url, {"reason": "Resigned, last day Friday"})
    assert ok.status_code == 202, ok.text
    body = ok.json()
    assert body["status"] == "pending_approval" and body["decision"] == "approval" and sorted(body["revokes"]) == sorted(base)
    assert await scalar(app, f"select count(*) from identity_entitlements where identity_id='{i}' and status='active'") == len(base)     # untouched
    assert await scalar(app, "select count(*) from audit_logs where action='identity.deprovision_requested'") == 1
    dup = await admin.post(url, {"reason": "Resigned again"})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "nothing_to_do"


async def test_future_dated_offboarding_marks_leaver_now_and_revokes_on_the_date(app, as_role):
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:2]
    i = await _plant(app, "T Future Leaver", grants=base)
    admin = await as_role("iam_admin")
    when = date.today() + timedelta(days=10)
    ref = (await admin.post(f"{API}/identities/{i}/deprovision", {"reason": "Notice period", "effective_date": when.isoformat()})).json()["request_ref"]
    ap_id = await scalar(app, f"select a.id from approval_requests a join lifecycle_requests r on r.id=a.lifecycle_request_id where r.ref_no={int(ref[4:])}")
    assert (await admin.post(f"{API}/approvals/{ap_id}/approve", {"comment": "ok"})).status_code == 200
    assert await scalar(app, f"select lifecycle_state from identities where id='{i}'") == "leaver"
    assert await scalar(app, f"select end_date from identities where id='{i}'") == when
    assert await scalar(app, f"select count(*) from identity_entitlements where identity_id='{i}' and status='active'") == len(base)     # still has access until then
    async with app.state.sessionmaker() as db:
        assert await lifecycle.apply_due_requests(db, today=when - timedelta(days=1)) == 0
        assert await lifecycle.apply_due_requests(db, today=when) >= 1
        assert await lifecycle.apply_due_requests(db, today=when) == 0                # idempotent
    assert await scalar(app, f"select lifecycle_state from identities where id='{i}'") == "terminated"
    assert await scalar(app, f"select count(*) from identity_entitlements where identity_id='{i}' and status in ('active','pending')") == 0


# ------------------------------------------------------------------ requester history as a risk factor
async def _auto_request(app, name):
    """A low-risk, no-approval entitlement the person does not hold -> the policy would normally AUTO-approve it."""
    app_name = await scalar(app, "select e.application from entitlements e where e.risk_level='low' and not e.requires_approval "
                                 "and (select count(*) from entitlements x where x.application=e.application)=1 "
                                 f"and not exists (select 1 from identity_entitlements ie join identities i on i.id=ie.identity_id where ie.entitlement_id=e.id and i.full_name='{name}') "
                                 "order by e.application limit 1")
    return f"Give {name} access to {app_name}"


async def _user_id(app, email):
    return await scalar(app, f"select id from users where email='{email}'")


async def test_requester_history_turns_an_auto_request_into_an_approval(app, as_role):
    name = await _low_risk(app, "Sales")
    c = await as_role("iam_admin")
    q = await _auto_request(app, name)
    base = _action(await _ask(c, q))
    assert base and base["expected_decision"] == "auto"                                   # control: normal requester -> auto
    uid = await _user_id(app, "iam_admin@corp.com")
    async with app.state.sessionmaker() as db:
        t = await _dept(db, "Sales")
        for _ in range(2):                                                               # two recent rejections
            db.add(LifecycleRequest(identity_id=(await db.execute(select(Identity.id).where(Identity.full_name == name))).scalar_one(), request_type="privilege",
                                    status="rejected", requested_by=uid, from_department_id=t.id))
        await db.commit()
    r = await _ask(c, q)
    act = _action(r)
    assert act and act["expected_decision"] == "approval" and act["label"] == "Submit for approval"
    assert any("rejected" in str(b) for b in r["blocks"])                                 # and it says why
    stale = await c.post(f"{API}/assistant/execute", {"proposal": base["proposal"], "expected_decision": "auto"})
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "policy_changed"     # the server re-decides on execute


async def test_requester_burst_is_flagged(app, as_role):
    name = await _low_risk(app, "Marketing")
    c = await as_role("super_admin")
    q = await _auto_request(app, name)
    assert _action(await _ask(c, q))["expected_decision"] == "auto"
    uid = await _user_id(app, "super_admin@corp.com")
    async with app.state.sessionmaker() as db:
        ident = (await db.execute(select(Identity.id).where(Identity.full_name == name))).scalar_one()
        for _ in range(10):
            db.add(LifecycleRequest(identity_id=ident, request_type="privilege", status="cancelled", requested_by=uid))
        await db.commit()
    r = await _ask(c, q)
    act = _action(r)
    assert act and act["expected_decision"] == "approval"
    assert any("10 requests" in str(b) for b in r["blocks"])


# ------------------------------------------------------------------ audit filters
async def test_audit_filters_by_actor_action_target_and_date(app, as_role):
    async with app.state.sessionmaker() as db:
        base = (await _baseline_names(db, "Finance"))[:1]
    i = await _plant(app, "T Audit Target", grants=base)
    admin, auditor = await as_role("iam_admin"), await as_role("auditor")
    email = await scalar(app, f"select email from identities where id='{i}'")
    assert (await admin.post(f"{API}/identities/{i}/deprovision", {"reason": "Audit filter test"})).status_code == 202
    get = lambda qs: auditor.get(f"{API}/audit-logs?{qs}&limit=200")

    by_actor = (await get("actor=IAM_ADMIN@corp")).json()                                  # case-insensitive substring
    assert by_actor["total"] >= 1 and all("iam_admin@corp.com" in x["actor"].lower() for x in by_actor["items"])
    by_action = (await get("action=identity.depro")).json()                                # prefix
    assert by_action["total"] == 1 and by_action["items"][0]["action"] == "identity.deprovision_requested"
    assert all(x["action"].startswith("auth.") for x in (await get("action=auth.")).json()["items"])
    by_target = (await get(f"target={email[:12]}")).json()
    assert by_target["total"] == 1 and by_target["items"][0]["target"] == email
    both = (await get(f"actor=iam_admin&action=identity.&target={email[:12]}")).json()
    assert both["total"] == 1
    assert (await get("actor=iam_admin&action=auth.&target=nobody@nowhere")).json()["total"] == 0
    # wildcards typed by a user are literals, not patterns
    assert (await get("action=%25")).json()["total"] == 0
    assert (await get("actor=i_m")).json()["total"] == 0 and (await get("actor=iam_a")).json()["total"] >= 1      # "_" is a literal, not "any char"
    # date range
    soon = (datetime.now(UTC) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    assert (await get(f"since={soon}")).json()["total"] == 0
    assert (await get(f"until={(datetime.now(UTC) - timedelta(days=400)).isoformat().replace('+00:00', 'Z')}")).json()["total"] == 0
    assert (await get(f"since={(datetime.now(UTC) - timedelta(days=1)).isoformat().replace('+00:00', 'Z')}&action=identity.")).json()["total"] == 1
    # export honours the same filters
    csv = await auditor.get(f"{API}/audit-logs/export?actor=iam_admin&action=identity.&target={email[:12]}")
    assert csv.status_code == 200 and csv.text.count("\n") == 2 and "Offboarding Requested" in csv.text
