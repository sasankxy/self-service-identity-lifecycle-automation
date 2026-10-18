"""Deterministic, idempotent demo-data seeder.

    python -m scripts.seed            # insert anything missing (safe to re-run)
    python -m scripts.seed --reset    # delete all is_demo rows first, then re-seed (refreshes timestamps)

Rules:
* Every seeded row has is_demo = true (or a DEMO- employee id) so it is always distinguishable from real data.
* Primary keys are uuid5(namespace, key): re-running never duplicates anything.
* Referential integrity is built in: every approval has a request, every request an identity, every audit
  event a valid target, and all dashboard numbers are *computed from these rows* by the API, never stored.
* No connector is ever seeded as 'connected'.
"""
import argparse
import asyncio
import random
import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.models import (
    AccessProfile, AccessProfileEntitlement, ApprovalRequest, AuditLog, CertificationCampaign, CertificationItem,
    ComplianceControl, ComplianceFramework, Department, Entitlement, GovernancePolicy, Identity, IdentityConnector,
    IdentityEntitlement, LifecycleRequest, LifecycleRequestEntitlement, RiskAssessment,
)

NS = uuid.UUID("6f1d3c52-0b6e-4a77-9d0e-1d3e5f7a9b11")
DEMO_DOMAIN = "corp.com"


def uid(kind: str, key: str) -> uuid.UUID:
    return uuid.uuid5(NS, f"{kind}:{key}")


DEPTS = [("ENG", "Engineering"), ("FIN", "Finance"), ("SAL", "Sales"), ("MKT", "Marketing"), ("DES", "Product Design"),
         ("SUP", "Support"), ("HR", "Human Resources"), ("LEG", "Legal"), ("SEC", "IT Security"), ("OPS", "Operations")]

CONNECTORS = [  # (name, type, status) - nothing is ever 'connected'
    ("Active Directory Domain Services", "ldap", "demo"), ("Microsoft Entra ID", "oidc", "demo"),
    ("Google Workspace", "google", "not_configured"), ("Okta Identity Cloud", "okta", "demo"),
    ("AWS Identity Center", "aws", "disconnected"), ("Splunk SIEM Connector", "siem", "not_configured"),
    ("ServiceNow ITOM", "itsm", "demo"),
]

# (application, name, risk, requires_approval, connector)
ENTS = [
    ("GitHub", "GitHub Enterprise", "medium", False, "Okta Identity Cloud"),
    ("Jira", "Jira Core", "low", False, "Okta Identity Cloud"), ("Jira", "Jira Dev", "low", False, "Okta Identity Cloud"),
    ("Slack", "Slack Enterprise", "low", False, "Okta Identity Cloud"), ("Zoom", "Zoom Pro", "low", False, "Okta Identity Cloud"),
    ("Microsoft 365", "Microsoft 365", "low", False, "Microsoft Entra ID"),
    ("Salesforce", "Salesforce CRM", "medium", False, "Okta Identity Cloud"),
    ("Zendesk", "Zendesk Agent", "low", False, "Okta Identity Cloud"), ("Figma", "Figma Enterprise", "low", False, "Okta Identity Cloud"),
    ("ERP", "Finance ERP", "high", True, "Active Directory Domain Services"),
    ("ERP", "AP Payment Release", "high", True, "Active Directory Domain Services"),
    ("ERP", "Vendor Management", "high", True, "Active Directory Domain Services"),
    ("Database", "Production DB Deployer", "high", True, "Active Directory Domain Services"),
    ("Database", "Audit Read-Only", "medium", False, "Active Directory Domain Services"),
    ("HRIS", "HR Admin", "high", True, "Active Directory Domain Services"),
    ("HRIS", "Payroll Release", "high", True, "Active Directory Domain Services"),
    ("AWS", "AWS Staging Sandbox", "medium", False, "AWS Identity Center"),
    ("AWS", "AWS AdministratorAccess (Prod-US-East)", "critical", True, "AWS Identity Center"),
    ("Network", "VPN Access", "low", False, "Active Directory Domain Services"),
    ("Google", "Google Workspace", "low", False, "Google Workspace"),
    ("Splunk", "Splunk Viewer", "medium", False, "Splunk SIEM Connector"),
    ("ServiceNow", "ServiceNow Fulfiller", "medium", False, "ServiceNow ITOM"),
    ("Documents", "Confidential Document Store", "high", True, "Microsoft Entra ID"),
]

PROFILES = {  # profile -> (dept code, entitlement names)
    "Senior Developer": ("ENG", ["GitHub Enterprise", "Jira Dev", "Slack Enterprise", "Microsoft 365", "AWS Staging Sandbox", "VPN Access"]),
    "Engineering Manager": ("ENG", ["GitHub Enterprise", "Jira Core", "Slack Enterprise", "Microsoft 365", "VPN Access"]),
    "Product Designer": ("DES", ["Figma Enterprise", "Slack Enterprise", "Microsoft 365", "Zoom Pro"]),
    "Account Executive": ("SAL", ["Salesforce CRM", "Slack Enterprise", "Zoom Pro", "Microsoft 365"]),
    "Financial Analyst": ("FIN", ["Finance ERP", "Microsoft 365", "Slack Enterprise"]),
    "HR Specialist": ("HR", ["HR Admin", "Microsoft 365", "Slack Enterprise"]),
    "Support Agent": ("SUP", ["Zendesk Agent", "Slack Enterprise", "Microsoft 365", "Zoom Pro"]),
    "Security Analyst": ("SEC", ["Splunk Viewer", "ServiceNow Fulfiller", "VPN Access", "Microsoft 365", "Audit Read-Only"]),
    "Legal Counsel": ("LEG", ["Microsoft 365", "Confidential Document Store", "Slack Enterprise"]),
    "Marketing Specialist": ("MKT", ["Microsoft 365", "Slack Enterprise", "Zoom Pro", "Figma Enterprise"]),
    "Operations Analyst": ("OPS", ["Microsoft 365", "Slack Enterprise", "ServiceNow Fulfiller"]),
}
DEPT_PROFILES = {"ENG": ["Senior Developer", "Senior Developer", "Engineering Manager"], "FIN": ["Financial Analyst"],
                 "SAL": ["Account Executive"], "MKT": ["Marketing Specialist"], "DES": ["Product Designer"],
                 "SUP": ["Support Agent"], "HR": ["HR Specialist"], "LEG": ["Legal Counsel"],
                 "SEC": ["Security Analyst"], "OPS": ["Operations Analyst"]}

TRIGGERS = {
    "abnormal_login": "Abnormal login hours", "failed_mfa": "Multiple failed MFA challenges",
    "dormant_reactivation": "Dormant account reactivation", "excess_privilege": "Excessive privilege grant",
    "bulk_access": "Confidential document bulk access via unmanaged IP", "sod_violation": "Segregation-of-duties violation",
    "privilege_request": "Elevated privilege request", "impossible_travel": "Impossible travel", "stale_access": "Stale entitlements",
}

FIRST = ["Aarav", "Meera", "Rohan", "Ananya", "Vikram", "Neha", "Karthik", "Isha", "Aditya", "Divya", "Sanjay", "Pooja", "Rahul",
         "Kavya", "Arun", "Shreya", "Emma", "Liam", "Olivia", "Noah", "Ava", "Ethan", "Mia", "Lucas", "Chloe", "Daniel", "Grace",
         "Henry", "Zoe", "Samuel", "Nora", "Omar", "Fatima", "Yusuf", "Leila", "Mateo", "Lucia", "Hiro", "Yuki", "Wei", "Mei"]
LAST = ["Iyer", "Nair", "Reddy", "Patel", "Gupta", "Menon", "Rao", "Bose", "Das", "Singh", "Kapoor", "Joshi", "Shetty", "Pillai",
        "Mehta", "Bhat", "Smith", "Johnson", "Brown", "Taylor", "Wilson", "Moore", "Clark", "Lewis", "Walker", "Young", "Allen",
        "King", "Wright", "Scott", "Green", "Baker", "Adams", "Nelson", "Hill", "Campbell", "Mitchell", "Roberts", "Carter", "Okafor"]
MONTH_COUNTS = {  # months-ago -> (joiners, movers, leavers, privilege) historical volume (current month is partial)
    5: (22, 10, 6, 4), 4: (30, 14, 8, 6), 3: (26, 16, 5, 5), 2: (38, 15, 7, 8), 1: (34, 18, 6, 7), 0: (14, 8, 3, 4)}


async def ins(db: AsyncSession, model, rows: list[dict], chunk: int = 250) -> None:
    keys = {k for r in rows for k in r}
    rows = [{k: r.get(k) for k in keys} for r in rows]       # multi-row INSERT needs uniform columns
    for i in range(0, len(rows), chunk):
        await db.execute(pg_insert(model).values(rows[i:i + chunk]).on_conflict_do_nothing())


async def reset(db: AsyncSession) -> None:
    for model in (CertificationItem, CertificationCampaign, ComplianceControl, ComplianceFramework, AuditLog, ApprovalRequest,
                  LifecycleRequestEntitlement, RiskAssessment, LifecycleRequest, IdentityEntitlement, Identity,
                  AccessProfileEntitlement, AccessProfile, Entitlement, GovernancePolicy, IdentityConnector, Department):
        if hasattr(model, "is_demo"):
            await db.execute(delete(model).where(model.is_demo.is_(True)))
        elif model is CertificationItem:
            await db.execute(delete(CertificationItem).where(CertificationItem.campaign_id.in_(
                select(CertificationCampaign.id).where(CertificationCampaign.is_demo.is_(True)))))
        elif model is LifecycleRequestEntitlement:
            await db.execute(delete(LifecycleRequestEntitlement).where(LifecycleRequestEntitlement.request_id.in_(
                select(LifecycleRequest.id).where(LifecycleRequest.is_demo.is_(True)))))
        elif model is AccessProfileEntitlement:
            await db.execute(delete(AccessProfileEntitlement).where(AccessProfileEntitlement.access_profile_id.in_(
                select(AccessProfile.id).where(AccessProfile.is_demo.is_(True)))))
        elif model is IdentityEntitlement:
            await db.execute(delete(IdentityEntitlement).where(IdentityEntitlement.identity_id.in_(
                select(Identity.id).where(Identity.is_demo.is_(True)))))
        elif model is Department:
            await db.execute(delete(Department).where(Department.code.in_([c for c, _ in DEPTS])))
    await db.commit()


async def seed(db: AsyncSession, now: datetime) -> dict:
    rng = random.Random(20261016)
    today = now.date()
    ago = lambda **kw: now - timedelta(**kw)  # noqa: E731

    # ------------------------------------------------------------ reference data
    dept_id = {c: uid("dept", c) for c, _ in DEPTS}
    dept_name = dict(DEPTS)
    await ins(db, Department, [dict(id=dept_id[c], code=c, name=n, cost_center=f"CC-{i + 1:03d}") for i, (c, n) in enumerate(DEPTS)])

    conn_id = {n: uid("connector", n) for n, _, _ in CONNECTORS}
    await ins(db, IdentityConnector, [dict(
        id=conn_id[n], name=n, connector_type=t, status=s, is_demo=True,
        config={"note": "Simulated connector: no live connection is configured."}) for n, t, s in CONNECTORS])

    ent_id = {name: uid("ent", name) for _, name, *_ in ENTS}
    ent_risk = {name: risk for _, name, risk, *_ in ENTS}
    await ins(db, Entitlement, [dict(id=ent_id[name], application=app, name=name, risk_level=risk, requires_approval=ra,
                                     connector_id=conn_id[c], is_demo=True) for app, name, risk, ra, c in ENTS])

    prof_id = {n: uid("profile", n) for n in PROFILES}
    await ins(db, AccessProfile, [dict(id=prof_id[n], name=n, description=f"Standard access for {n}", department_id=dept_id[d],
                                       is_demo=True) for n, (d, _) in PROFILES.items()])
    await ins(db, AccessProfileEntitlement, [dict(access_profile_id=prof_id[n], entitlement_id=ent_id[e])
                                             for n, (_, es) in PROFILES.items() for e in es])

    # ------------------------------------------------------------ identities
    identities: dict[str, dict] = {}
    used_emails: set[str] = set()

    def add_identity(key, name, local, dept, title, profile, state, itype="employee", start=None, end=None,
                     auth_hours=None, manager=None):
        email = f"{local}@{DEMO_DOMAIN}"
        n = 2
        while email in used_emails:
            email = f"{local}{n}@{DEMO_DOMAIN}"; n += 1
        used_emails.add(email)
        start_dt = datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=9) if start else ago(days=800)
        identities[key] = dict(
            id=uid("identity", key), employee_id=f"DEMO-{len(identities) + 1:04d}", full_name=name, email=email,
            identity_type=itype, job_title=title, department_id=dept_id[dept], access_profile_id=prof_id.get(profile) if profile else None,
            lifecycle_state=state, risk_score=0, start_date=start, end_date=end, is_demo=True,
            last_authentication_at=ago(hours=auth_hours) if auth_hours is not None else None,
            created_at=min(start_dt, ago(hours=1)), updated_at=ago(hours=1), _dept=dept, _profile=profile, _manager=manager)
        return identities[key]

    D = lambda off: today + timedelta(days=off)  # noqa: E731
    # -- people the original UI showed (kept so the console feels familiar; all values still come from DB) --
    add_identity("priya", "Priya Sharma", "p.sharma", "ENG", "Senior Developer", "Senior Developer", "joiner", start=D(-1), auth_hours=2)
    add_identity("sofia", "Sofia Torres", "s.torres", "DES", "Product Designer", "Product Designer", "joiner", start=D(-2), auth_hours=5)
    add_identity("arjun", "Arjun Kumar", "a.kumar", "SAL", "Account Executive", "Account Executive", "joiner", start=D(1))
    add_identity("james", "James O'Brien", "j.obrien", "MKT", "Marketing Specialist", "Marketing Specialist", "mover", start=D(-900), auth_hours=3)
    add_identity("layla", "Layla Martinez", "l.martinez", "SUP", "Support Agent", "Support Agent", "mover", start=D(-700), auth_hours=1)
    add_identity("marcus", "Marcus Wren", "m.wren", "ENG", "Senior Developer", "Senior Developer", "leaver", start=D(-1200), end=D(-13), auth_hours=24 * 13)
    add_identity("rachel", "Rachel Nguyen", "r.nguyen", "HR", "HR Specialist", "HR Specialist", "leaver", start=D(-1500), end=D(6), auth_hours=6)
    add_identity("xl004", "Contractor XL-004", "xl-004", "LEG", "External Counsel (Contractor)", "Legal Counsel", "leaver", itype="contractor",
                 start=D(-300), end=D(0), auth_hours=30)
    add_identity("admin", "Admin User", "admin", "SEC", "Super Admin", "Security Analyst", "active", start=D(-2000), auth_hours=0)
    add_identity("kai", "Kai Chen", "kai.chen", "ENG", "Staff Engineer", "Senior Developer", "active", start=D(-1400), auth_hours=4)
    add_identity("beth", "Beth Lambert", "b.lambert", "FIN", "Financial Analyst", "Financial Analyst", "active", start=D(-1000), auth_hours=1)
    add_identity("david", "David Walsh", "d.walsh", "FIN", "Senior Financial Analyst", "Financial Analyst", "active", start=D(-1600), auth_hours=9)
    add_identity("maria", "Maria Ruiz", "m.ruiz", "LEG", "Legal Counsel", "Legal Counsel", "active", start=D(-1100), auth_hours=7)
    add_identity("tjackson", "Tyrone Jackson", "t.jackson", "HR", "HR Operations Lead", "HR Specialist", "active", start=D(-900), auth_hours=2)

    # -- department heads (also the "executive" cohort) --
    for code, name in DEPTS:
        f, l = rng.choice(FIRST), rng.choice(LAST)
        add_identity(f"head-{code}", f"{f} {l}", f"{f}.{l}".lower(), code, f"Head of {name}", DEPT_PROFILES[code][-1], "active",
                     start=D(-rng.randint(1500, 3000)), auth_hours=rng.randint(1, 40))
    for i in range(6):
        f, l = rng.choice(FIRST), rng.choice(LAST)
        add_identity(f"vp-{i}", f"{f} {l}", f"{f}.{l}".lower(), rng.choice(["ENG", "FIN", "SAL", "OPS", "SEC", "HR"]), "VP",
                     "Engineering Manager" if i % 2 else "Financial Analyst", "active", start=D(-rng.randint(1500, 3000)), auth_hours=rng.randint(1, 40))

    def person(prefix, i, dept, state, start=None, end=None, itype="employee"):
        f, l = rng.choice(FIRST), rng.choice(LAST)
        prof = rng.choice(DEPT_PROFILES[dept])
        return add_identity(f"{prefix}-{i}", f"{f} {l}", f"{f}.{l}".lower(), dept, prof, prof, state, itype=itype, start=start, end=end,
                            auth_hours=None if state == "joiner" and start and start > today else rng.randint(1, 72))

    depts = [c for c, _ in DEPTS]
    dweights = [5, 3, 3, 2, 2, 3, 1, 1, 2, 2]
    # historical hires (joiner requests in the last 6 months) – completed, so state is 'active'
    hires = []
    for months_ago, (nj, nm, nl, npv) in MONTH_COUNTS.items():
        for k in range(nj):
            day = rng.randint(1, 28)
            d0 = (today.replace(day=1) - timedelta(days=31 * months_ago)).replace(day=1) + timedelta(days=day - 1)
            if d0 > today - timedelta(days=3):
                d0 = today - timedelta(days=rng.randint(3, 25))
            hires.append(person("hire", len(hires), rng.choices(depts, dweights)[0], "active", start=d0))
    older = [person("emp", i, rng.choices(depts, dweights)[0], "active", start=D(-rng.randint(200, 3000))) for i in range(160)]
    # in-flight lifecycle people beyond the named ones
    extra_joiners = [person("jn", i, rng.choice(depts), "joiner", start=D(rng.randint(-3, 6))) for i in range(4)]
    extra_movers = [person("mv", i, rng.choice(depts), "mover", start=D(-rng.randint(300, 900))) for i in range(3)]
    extra_leavers = [person("lv", i, rng.choice(depts), "leaver", start=D(-rng.randint(300, 900)), end=D(rng.randint(2, 20))) for i in range(3)]
    # historical leavers -> terminated
    terminated = []
    for months_ago, (nj, nm, nl, npv) in MONTH_COUNTS.items():
        for k in range(nl):
            d0 = max(today - timedelta(days=30 * months_ago + rng.randint(0, 27)), today - timedelta(days=170))
            if months_ago == 0:
                d0 = today - timedelta(days=rng.randint(1, 12))
            terminated.append(person("term", len(terminated), rng.choices(depts, dweights)[0], "terminated", start=D(-rng.randint(400, 2500)), end=d0))
    # service principals / non-human identities
    for i, svc in enumerate(["ci-pipeline", "backup-agent", "etl-runner", "payments-api", "monitoring", "log-shipper", "scheduler", "vpn-gateway",
                             "data-sync", "mailer", "sso-bridge", "terraform", "billing-job", "reporting", "scanner", "cdn-purge",
                             "chatops", "artifact-store", "secrets-rotator", "dr-failover", "iam-sync", "cost-export", "ocr-worker", "notifier"]):
        add_identity(f"svc-{i}", f"svc-{svc}", f"svc-{svc}", "OPS" if i % 2 else "ENG", "Service Principal", None, "active",
                     itype="service", start=D(-rng.randint(100, 1500)), auth_hours=rng.randint(0, 5))

    # managers
    for key, ident in identities.items():
        head = identities.get(f"head-{ident['_dept']}")
        ident["manager_id"] = head["id"] if head and key != f"head-{ident['_dept']}" and ident["identity_type"] != "service" else None

    # ------------------------------------------------------------ lifecycle requests, entitlement deltas, approvals
    requests, req_ents, approvals = [], [], []
    ref = [4000]   # seeded refs stay below the live sequence (starts at 5000)

    def add_request(key, ident_key, rtype, status, created, requester, to_dept=None, from_dept=None, eff=None, adds=(), removes=(),
                    justification=None, duration=None, priority="normal", decided=None, comment=None, completed=None):
        ref[0] += 1
        rid = uid("request", key)
        requests.append(dict(id=rid, identity_id=identities[ident_key]["id"], request_type=rtype, status=status,
                             from_department_id=dept_id[from_dept] if from_dept else None, to_department_id=dept_id[to_dept] if to_dept else None,
                             effective_date=eff, requester_name=requester, justification=justification, duration_hours=duration,
                             payload={}, created_at=created, updated_at=decided or created, completed_at=completed, ref_no=ref[0], is_demo=True))
        req_ents.extend(dict(request_id=rid, entitlement_id=ent_id[e], action="add") for e in adds)
        req_ents.extend(dict(request_id=rid, entitlement_id=ent_id[e], action="remove") for e in removes)
        astatus = {"pending_approval": "pending", "rejected": "rejected"}.get(status, "approved")
        approvals.append(dict(id=uid("approval", key), lifecycle_request_id=rid, status=astatus, priority=priority, requested_at=created,
                              decided_at=decided if astatus != "pending" else None,
                              decision_comment=comment if astatus != "pending" else None,
                              entitlement_id=ent_id[adds[0]] if rtype == "privilege" and adds else None, is_demo=True))
        return rid

    # named, in-flight requests (these are the pending/active items the UI showed)
    add_request("priya-join", "priya", "joiner", "provisioning", ago(days=2), "HR Operations", eff=D(-1),
                adds=PROFILES["Senior Developer"][1], decided=ago(days=1, hours=20), comment="Approved per standard Joiner policy")
    add_request("sofia-join", "sofia", "joiner", "completed", ago(days=3), "HR Operations", eff=D(-2), adds=PROFILES["Product Designer"][1],
                decided=ago(days=2, hours=20), comment="Approved per standard Joiner policy", completed=ago(days=2, hours=12))
    add_request("arjun-join", "arjun", "joiner", "pending_approval", ago(minutes=15), "HR Operations", eff=D(1), adds=PROFILES["Account Executive"][1])
    add_request("james-move", "james", "mover", "provisioning", ago(days=1, hours=18), "Finance Manager", from_dept="MKT", to_dept="FIN", eff=D(-2),
                adds=["Finance ERP"], decided=ago(days=1, hours=10), comment="Approved by department head")
    add_request("layla-move", "layla", "mover", "pending_approval", ago(hours=2), "Engineering Manager", from_dept="SUP", to_dept="ENG", eff=D(-10) + timedelta(days=16),
                adds=["GitHub Enterprise", "AWS Staging Sandbox", "Jira Core"], removes=["Zendesk Agent"])
    add_request("marcus-leave", "marcus", "leaver", "completed", ago(days=15), "Engineering Manager", eff=D(-13),
                removes=PROFILES["Senior Developer"][1], decided=ago(days=14), comment="Termination confirmed by HR", completed=ago(days=13))
    add_request("rachel-leave", "rachel", "leaver", "approved", ago(days=4), "HR Operations", eff=D(6), removes=PROFILES["HR Specialist"][1],
                decided=ago(days=3), comment="Scheduled departure")
    add_request("xl004-leave", "xl004", "leaver", "pending_approval", ago(hours=5), "Legal Operations", eff=D(0), justification="Contract Terminated",
                removes=PROFILES["Legal Counsel"][1], priority="urgent")
    add_request("priya-priv", "priya", "privilege", "pending_approval", ago(hours=3), "DevOps Lead", eff=D(0), justification="Production hotfix deployment",
                duration=48, adds=["AWS AdministratorAccess (Prod-US-East)"], priority="urgent")
    # generated in-flight items
    for i, p in enumerate(extra_joiners):
        st = ["pending_approval", "provisioning", "completed", "completed"][i]
        prof = p["_profile"]
        add_request(f"jn-{i}", f"jn-{i}", "joiner", st, ago(hours=6 + 7 * i), "HR Operations", eff=p["start_date"], adds=PROFILES[prof][1],
                    decided=None if st == "pending_approval" else ago(hours=3 + 7 * i), comment="Approved per standard Joiner policy",
                    completed=ago(hours=1 + 7 * i) if st == "completed" else None)
    for i, p in enumerate(extra_movers):
        tgt = rng.choice([d for d in depts if d != p["_dept"]])
        st = ["pending_approval", "provisioning", "approved"][i]
        add_request(f"mv-{i}", f"mv-{i}", "mover", st, ago(hours=9 + 8 * i), "Department Manager", from_dept=p["_dept"], to_dept=tgt,
                    eff=D(i + 1), adds=PROFILES[DEPT_PROFILES[tgt][0]][1][:3], decided=None if st == "pending_approval" else ago(hours=5 + 8 * i),
                    comment="Approved by department head")
        p["_target"] = tgt
    for i, p in enumerate(extra_leavers):
        st = ["pending_approval", "approved", "approved"][i]
        add_request(f"lv-{i}", f"lv-{i}", "leaver", st, ago(hours=20 + 10 * i), "HR Operations", eff=p["end_date"], justification="Resignation",
                    removes=PROFILES[p["_profile"]][1], decided=None if st == "pending_approval" else ago(hours=10 + 10 * i), comment="Confirmed by HR")
    add_request("priv-pending-1", "kai", "privilege", "pending_approval", ago(hours=8), "Security Lead", eff=D(0), justification="Incident response access",
                duration=24, adds=["Production DB Deployer"])

    # historical requests (feed trend charts and request distribution)
    def hist_time(months_ago):
        base = today.replace(day=1) - timedelta(days=31 * months_ago)
        base = base.replace(day=1)
        d = base + timedelta(days=rng.randint(0, 27))
        if d >= today:
            d = today - timedelta(days=rng.randint(1, 12))
        return datetime.combine(d, datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=rng.randint(8, 18))

    hi = iter(hires)
    ti = iter(terminated)
    pool = hires + older
    mover_pool = rng.sample(older, 94)
    mi = iter(mover_pool)
    for months_ago, (nj, nm, nl, npv) in MONTH_COUNTS.items():
        for k in range(nj):
            p = next(hi)
            created = datetime.combine(p["start_date"], datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=8) - timedelta(days=2)
            recent = (now - created).days <= 30
            st = "failed" if recent and rng.random() < 0.05 else "completed"
            add_request(f"h-join-{p['employee_id']}", [k_ for k_, v in identities.items() if v is p][0], "joiner", st, created, "HR Operations",
                        eff=p["start_date"], adds=PROFILES[p["_profile"]][1], decided=created + timedelta(hours=3),
                        comment="Approved per standard Joiner policy", completed=created + timedelta(hours=5) if st == "completed" else None)
        for k in range(nm):
            p = next(mi)
            created = hist_time(months_ago)
            src = rng.choice([d for d in depts if d != p["_dept"]])
            recent = (now - created).days <= 30
            st = "failed" if recent and rng.random() < 0.05 else "completed"
            add_request(f"h-move-{p['employee_id']}", [k_ for k_, v in identities.items() if v is p][0], "mover", st, created, "Department Manager",
                        from_dept=src, to_dept=p["_dept"], eff=created.date(), adds=PROFILES[p["_profile"]][1][:2], decided=created + timedelta(hours=4),
                        comment="Approved by department head", completed=created + timedelta(hours=6) if st == "completed" else None)
        for k in range(nl):
            p = next(ti)
            created = datetime.combine(p["end_date"], datetime.min.time(), tzinfo=timezone.utc) - timedelta(days=1) + timedelta(hours=9)
            add_request(f"h-leave-{p['employee_id']}", [k_ for k_, v in identities.items() if v is p][0], "leaver", "completed", created, "HR Operations",
                        eff=p["end_date"], justification="Departure", removes=PROFILES[p["_profile"]][1], decided=created + timedelta(hours=1),
                        comment="Termination confirmed by HR", completed=created + timedelta(hours=2))
        for k in range(npv):
            p = rng.choice(pool)
            created = hist_time(months_ago)
            ent = rng.choice(["AWS AdministratorAccess (Prod-US-East)", "Production DB Deployer", "Finance ERP", "Confidential Document Store"])
            st = "rejected" if rng.random() < 0.18 else "completed"
            add_request(f"h-priv-{months_ago}-{k}", [k_ for k_, v in identities.items() if v is p][0], "privilege", st, created, "Team Lead",
                        eff=created.date(), justification="Time-boxed elevated access", duration=rng.choice([8, 24, 48]), adds=[ent],
                        decided=created + timedelta(hours=2), comment="Rejected: insufficient justification" if st == "rejected" else "Approved, time-boxed",
                        completed=created + timedelta(hours=3) if st == "completed" else None)

    # completed movers actually changed department in identities (already set to target dept); terminated/leavers handled by state

    # ------------------------------------------------------------ identity entitlements
    ie = {}  # (identity key, ent) -> status

    def grant(ikey, ents, status):
        for e in ents:
            ie[(ikey, e)] = status

    for key, ident in identities.items():
        prof = ident["_profile"]
        if not prof or ident["lifecycle_state"] == "joiner":
            continue
        grant(key, PROFILES[prof][1], "revoked" if ident["lifecycle_state"] == "terminated" else "active")
    for key in ("priya", "james"):
        grant(key, PROFILES[identities[key]["_profile"]][1], "pending")
    grant("priya", PROFILES["Senior Developer"][1], "pending")
    grant("sofia", PROFILES["Product Designer"][1], "active")
    grant("marcus", PROFILES["Senior Developer"][1], "revoked")
    for i in range(4):
        st = ["pending_approval", "provisioning", "completed", "completed"][i]
        if st != "pending_approval":
            grant(f"jn-{i}", PROFILES[identities[f"jn-{i}"]["_profile"]][1], "pending" if st == "provisioning" else "active")
    # segregation-of-duties conflicts (detected by the governance API, not hardcoded there)
    grant("david", ["AP Payment Release", "Vendor Management"], "active")
    grant("beth", ["Production DB Deployer", "Audit Read-Only"], "active")
    grant("tjackson", ["HR Admin", "Payroll Release"], "active")
    grant("kai", ["Production DB Deployer", "AWS Staging Sandbox"], "active")
    grant("maria", ["Confidential Document Store"], "active")
    for i in (0, 1, 2, 3):
        grant(f"vp-{i}", ["Finance ERP"] if i % 2 == 0 else ["AWS Staging Sandbox"], "active")
    for i in range(24):
        grant(f"svc-{i}", ["VPN Access"] if i % 3 == 0 else ["Microsoft 365"], "active")
    ie_rows = [dict(id=uid("ie", f"{k}:{e}"), identity_id=identities[k]["id"], entitlement_id=ent_id[e], status=st, source="profile",
                    granted_at=identities[k]["created_at"]) for (k, e), st in ie.items()]

    # ------------------------------------------------------------ risk assessments (history + current)
    risk_target = {"priya": 84, "kai": 87, "david": 82, "maria": 76, "beth": 54, "admin": 12, "sofia": 10, "arjun": 12, "layla": 42}
    named_triggers = {
        "kai": ["abnormal_login", "failed_mfa"], "david": ["dormant_reactivation", "excess_privilege", "sod_violation"],
        "maria": ["bulk_access"], "priya": ["privilege_request"], "beth": ["sod_violation"], "layla": ["stale_access"],
    }
    latest_req = {}
    for r in requests:
        latest_req.setdefault(r["identity_id"], []).append(r)
    assessments = []
    generated_high = 0
    for key, ident in identities.items():
        if ident["lifecycle_state"] == "terminated":
            continue
        if key in risk_target:
            base = risk_target[key]
        else:
            roll = rng.random()
            if roll < 0.055:
                base = rng.randint(40, 74)
            elif roll < 0.063 and generated_high < 4:
                base = rng.randint(76, 92); generated_high += 1
            else:
                base = rng.randint(3, 35)
        ident["risk_score"] = base
        trig_codes = named_triggers.get(key) or ([rng.choice(list(TRIGGERS))] if base >= 40 else [])
        if base >= 40 and key not in named_triggers and rng.random() < 0.4:
            trig_codes = trig_codes + [rng.choice(list(TRIGGERS))]
        trig = [{"code": c, "label": TRIGGERS[c]} for c in dict.fromkeys(trig_codes)]
        latest_request = max(latest_req.get(ident["id"], []), key=lambda r: r["created_at"], default=None)
        for b in range(7):
            score = base if b == 0 else max(0, min(100, base + rng.randint(-6, 10) + (2 if b > 3 else 0)))
            level = "critical" if score >= 90 else "high" if score >= 75 else "medium" if score >= 40 else "low"
            at = ago(days={"kai": 3, "david": 7, "maria": 2}.get(key, 0) + 5 * b, hours=rng.randint(0, 6)) if b else (
                latest_request["created_at"] + timedelta(minutes=1) if latest_request and key in ("priya", "arjun", "layla") else
                ago(days={"kai": 3, "david": 7, "maria": 2}.get(key, 0), hours=rng.randint(1, 5)))
            if b == 0 and at > now:
                at = now - timedelta(minutes=1)
            assessments.append(dict(
                id=uid("risk", f"{key}:{b}"), identity_id=ident["id"], score=score, level=level, assessed_at=at, is_demo=True,
                triggers=trig if (b == 0 or score >= 40) and trig else [],
                lifecycle_request_id=(latest_request["id"] if b == 0 and latest_request and key in ("priya", "arjun", "layla") else None)))
    # link each approval to the newest assessment for its identity so cards show real scores
    by_ident_latest = {}
    for a in assessments:
        cur = by_ident_latest.get(a["identity_id"])
        if cur is None or a["assessed_at"] > cur["assessed_at"]:
            by_ident_latest[a["identity_id"]] = a
    req_by_id = {r["id"]: r for r in requests}
    for ap in approvals:
        ident_id = req_by_id[ap["lifecycle_request_id"]]["identity_id"]
        if ident_id in by_ident_latest:
            ap["risk_assessment_id"] = by_ident_latest[ident_id]["id"]
    for a in assessments:  # priya's newest assessment belongs to her privilege request
        pass

    # ------------------------------------------------------------ audit events derived from the records above
    audit = []
    name_of = {v["id"]: v for v in identities.values()}

    def ev(at, action, category, actor, target_ident=None, target_label=None, target_type="identity", severity="info", outcome="success", details=None):
        audit.append(dict(occurred_at=at, action=action, category=category, actor_label=actor,
                          target_type=target_type if (target_ident or target_label) else None,
                          target_id=str(target_ident["id"]) if target_ident else None,
                          target_label=target_label or (target_ident["email"] if target_ident else None),
                          severity=severity, outcome=outcome, details=details or {}, is_demo=True))

    for r in requests:
        if (now - r["created_at"]).days > 45:
            continue
        ident = name_of[r["identity_id"]]
        ev(r["created_at"] + timedelta(seconds=30), "Approval Requested", "approval", r["requester_name"] or "Requester", ident,
           severity="info", outcome="pending" if r["status"] == "pending_approval" else "success", details={"request": f"REQ-{r['ref_no']}", "type": r["request_type"]})
        if r["status"] == "rejected":
            ev(r["updated_at"], "Request Rejected", "approval", "Approval Workflow", ident, severity="low", outcome="success")
        elif r["status"] != "pending_approval":
            ev(r["updated_at"], "Request Approved", "approval", "Approval Workflow", ident, outcome="success")
        if r["status"] == "completed":
            when = r["completed_at"] or r["updated_at"]
            if r["request_type"] == "joiner":
                ev(when, "Identity Provisioned", "provisioning", "Automated Engine", ident)
                ev(when + timedelta(minutes=2), "Role Assignment", "access_change", "Automated Engine", ident)
            elif r["request_type"] == "mover":
                ev(when, "Entitlements Updated", "access_change", "Automated Engine", ident)
            elif r["request_type"] == "leaver":
                ev(when - timedelta(minutes=30), "Entitlement Revoked", "access_change", "Admin User", ident, severity="medium")
                ev(when, "Offboarding Finalized", "provisioning", "Lifecycle System", ident)
        if r["status"] == "failed":
            ev(r["completed_at"] or r["updated_at"], "Provisioning Failed", "provisioning", "Automated Engine", ident, severity="high", outcome="failure")
    for a in assessments:
        if a["score"] >= 75 and (now - a["assessed_at"]).days <= 14:
            ev(a["assessed_at"], "Risk Threshold Exceeded", "risk_alert", "Risk Engine", name_of[a["identity_id"]], severity="high", outcome="flagged",
               details={"score": a["score"]})
    ev(ago(hours=2, minutes=40), "MFA Challenge Blocked", "login", "kai.chen", target_label="AWS Console", target_type="resource", severity="critical", outcome="blocked")
    ev(ago(days=1, hours=3), "Policy Violation (SoD)", "risk_alert", "d.walsh", target_label="Finance DB", target_type="resource", severity="critical", outcome="flagged")
    ev(ago(days=1, hours=1), "Policy Violation (SoD)", "risk_alert", "t.jackson", target_label="HRIS Payroll", target_type="resource", severity="critical", outcome="flagged")

    # ------------------------------------------------------------ governance
    policies = [
        ("AP Payment + Vendor Management Role Conflict", "sod", "critical", {"entitlements": [str(ent_id["AP Payment Release"]), str(ent_id["Vendor Management"])]}),
        ("Production DB Deployer + Auditor Dual Role", "sod", "critical", {"entitlements": [str(ent_id["Production DB Deployer"]), str(ent_id["Audit Read-Only"])]}),
        ("HR Admin + Payroll Release Privilege", "sod", "critical", {"entitlements": [str(ent_id["HR Admin"]), str(ent_id["Payroll Release"])]}),
        ("Provisioning success target", "sla", "medium", {"target_percent": 95}),
        ("Elevated privileges require approval", "access", "high", {"requires_approval": True, "max_duration_hours": 72}),
        ("Quarterly privileged recertification", "certification", "medium", {"frequency_days": 90}),
    ]
    await ins(db, GovernancePolicy, [dict(id=uid("policy", n), name=n, policy_type=t, severity=s, rules=r, is_demo=True,
                                           description=f"Demo policy: {n}") for n, t, s, r in policies])

    frameworks = {  # name -> (control topics, failing indexes)
        "SOX 404 Access Controls": ("SOX-AC", 20, {7}), "GDPR / Data Privacy Mandate": ("GDPR", 13, {4}),
        "Zero Trust Architecture Policy": ("ZT", 17, {2, 11}), "ISO/IEC 27001 ISMS Standards": ("ISO", 24, {9}),
    }
    topics = ["Periodic access review", "Least-privilege enforcement", "Joiner provisioning approval", "Leaver deprovisioning SLA",
              "Privileged access time-boxing", "MFA enforcement", "Segregation of duties", "Audit log retention", "Service account ownership",
              "Dormant account cleanup", "Emergency access review", "Role certification"]
    fw_rows, ctl_rows = [], []
    for name, (pfx, n, fails) in frameworks.items():
        fid = uid("framework", name)
        fw_rows.append(dict(id=fid, name=name, description=f"Demo framework: {name}", is_demo=True))
        for i in range(n):
            ctl_rows.append(dict(id=uid("control", f"{pfx}-{i}"), framework_id=fid, code=f"{pfx}-{i + 1:02d}",
                                 name=topics[i % len(topics)], status="fail" if i in fails else "pass",
                                 last_tested_at=ago(days=rng.randint(1, 20)), is_demo=True))
    await ins(db, ComplianceFramework, fw_rows)
    await ins(db, ComplianceControl, ctl_rows)

    execs = [v for k, v in identities.items() if k.startswith(("head-", "vp-"))]
    privileged = [v for (k, e), st in ie.items() if st == "active" and ent_risk[e] in ("high", "critical") for v in [identities[k]]]
    privileged = list({v["id"]: v for v in privileged}.values())[:40]
    services = [v for k, v in identities.items() if k.startswith("svc-")]
    campaigns = [
        ("Q4 2026 Executive Access Review", "Department heads and VPs", today + timedelta(days=14), "active", execs, 0.34),
        ("Privileged Identity Recertification", "Identities holding high/critical entitlements", today + timedelta(days=5), "active", privileged, 0.75),
        ("Service Principal & Non-Human IDs", "All service identities", today - timedelta(days=15), "completed", services, 1.0),
    ]
    camp_rows, item_rows = [], []
    for name, scope, due, status, members, ratio in campaigns:
        cid = uid("campaign", name)
        camp_rows.append(dict(id=cid, name=name, scope_description=scope, due_date=due, status=status, is_demo=True,
                              completed_at=ago(days=15) if status == "completed" else None))
        k = round(len(members) * ratio)
        for i, m in enumerate(members):
            item_rows.append(dict(campaign_id=cid, identity_id=m["id"], decision="certified" if i < k else None,
                                  decided_at=ago(days=rng.randint(1, 10)) if i < k else None))
    await ins(db, CertificationCampaign, camp_rows)

    # ------------------------------------------------------------ persist (FK order)
    id_rows = []
    heads = [v for k, v in identities.items() if k.startswith("head-")]
    rest = [v for k, v in identities.items() if not k.startswith("head-")]
    for v in heads + rest:
        row = {k: val for k, val in v.items() if not k.startswith("_")}
        id_rows.append(row)
    await ins(db, Identity, id_rows)
    await ins(db, IdentityEntitlement, ie_rows)
    await ins(db, LifecycleRequest, requests)
    await ins(db, LifecycleRequestEntitlement, req_ents)
    await ins(db, RiskAssessment, assessments)
    await ins(db, ApprovalRequest, approvals)
    await ins(db, CertificationItem, item_rows)
    # current risk on the identity row = its latest assessment (kept consistent by construction)
    # completed movers: identity already carries the target department; in-flight movers keep their source department
    if (await db.execute(select(func.count()).select_from(AuditLog).where(AuditLog.is_demo.is_(True)))).scalar_one() == 0:
        await ins(db, AuditLog, audit, chunk=400)
    await db.commit()
    return {"identities": len(id_rows), "requests": len(requests), "approvals": len(approvals), "assessments": len(assessments),
            "audit_events": len(audit), "entitlement_grants": len(ie_rows)}


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="delete all demo rows first")
    ap.add_argument("--anchor", help="fix 'now' (YYYY-MM-DDTHH:MM) for fully reproducible timestamps")
    args = ap.parse_args()
    now = datetime.fromisoformat(args.anchor).replace(tzinfo=timezone.utc) if args.anchor else datetime.now(timezone.utc).replace(microsecond=0)
    engine = create_async_engine(get_settings().database_url)
    async with async_sessionmaker(engine, expire_on_commit=False)() as db:
        if args.reset:
            await reset(db)
        counts = await seed(db, now)
    await engine.dispose()
    print("Seeded demo data:", counts)


if __name__ == "__main__":
    asyncio.run(main())
