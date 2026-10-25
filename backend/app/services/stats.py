"""Aggregates computed from persisted rows. Nothing here is stored or randomised."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import String, and_, case, cast, func, literal, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models import (
    ApprovalRequest, AuditLog, CertificationCampaign, CertificationItem, ComplianceControl, ComplianceFramework,
    Department, Entitlement, GovernancePolicy, Identity, IdentityConnector, IdentityEntitlement, LifecycleRequest,
    RiskAssessment,
)

HIGH, MEDIUM = 75, 40
ACTIVE_STATES = ("joiner", "active", "mover", "leaver")   # i.e. not terminated


def risk_level(score: int) -> str:
    return "critical" if score >= 90 else "high" if score >= HIGH else "medium" if score >= MEDIUM else "low"


def latest_assessments():
    """Subquery: newest assessment per identity (DISTINCT ON)."""
    q = (select(RiskAssessment).distinct(RiskAssessment.identity_id)
         .order_by(RiskAssessment.identity_id, RiskAssessment.assessed_at.desc()))
    return aliased(RiskAssessment, q.subquery())


async def dashboard_summary(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    total = (await db.execute(select(func.count()).select_from(Identity).where(Identity.lifecycle_state != "terminated"))).scalar_one()
    prev = (await db.execute(select(func.count()).select_from(Identity).where(
        Identity.lifecycle_state != "terminated", Identity.created_at <= now - timedelta(days=7)))).scalar_one()
    rows = dict((await db.execute(select(LifecycleRequest.status, func.count()).where(
        LifecycleRequest.created_at >= now - timedelta(days=30), LifecycleRequest.status.in_(("completed", "failed")))
        .group_by(LifecycleRequest.status))).all())
    done, failed = rows.get("completed", 0), rows.get("failed", 0)
    rate = round(100 * done / (done + failed), 1) if done + failed else None
    target = (await db.execute(select(GovernancePolicy.rules["target_percent"].as_float()).where(
        GovernancePolicy.policy_type == "sla", GovernancePolicy.is_active.is_(True)).limit(1))).scalar()
    pend = (await db.execute(select(
        func.count(), func.count().filter(ApprovalRequest.priority == "urgent"),
        func.avg(func.extract("epoch", func.now() - ApprovalRequest.requested_at))).where(ApprovalRequest.status == "pending"))).one()
    high = (await db.execute(select(func.count()).select_from(Identity).where(
        Identity.lifecycle_state != "terminated", Identity.risk_score >= HIGH))).scalar_one()
    flagged_7d = (await db.execute(select(func.count(func.distinct(RiskAssessment.identity_id))).where(
        RiskAssessment.level.in_(("high", "critical")), RiskAssessment.assessed_at >= now - timedelta(days=7)))).scalar_one()
    connectors = (await db.execute(select(IdentityConnector.id, IdentityConnector.name, IdentityConnector.status,
                                          IdentityConnector.last_sync_at).order_by(IdentityConnector.name))).mappings().all()
    return {
        "total_identities": {"value": total, "growth_pct_7d": round(100 * (total - prev) / prev, 1) if prev else None},
        "provisioning": {"success_rate": rate, "sla_target": target, "completed": done, "failed": failed, "window_days": 30,
                         "sla_met": (rate >= target) if rate is not None and target is not None else None},
        "pending_approvals": {"value": pend[0], "urgent": pend[1], "avg_wait_hours": round(float(pend[2]) / 3600, 1) if pend[2] else None},
        "high_risk": {"value": high, "flagged_last_7d": flagged_7d},
        "connectors": [dict(c) for c in connectors],
        "generated_at": now,
    }


def _month_starts(now: datetime, n: int = 6) -> list[datetime]:
    y, m = now.year, now.month
    out = []
    for i in range(n - 1, -1, -1):
        mm = m - i
        yy = y + (mm - 1) // 12
        mm = (mm - 1) % 12 + 1
        out.append(datetime(yy, mm, 1, tzinfo=timezone.utc))
    return out


async def dashboard_trends(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    months = _month_starts(now)
    # bucket in UTC like `months` above; a bare date_trunc would use the database session's time zone and shift buckets
    rows = (await db.execute(select(func.date_trunc("month", func.timezone("UTC", LifecycleRequest.created_at)).label("m"), LifecycleRequest.request_type,
                                    func.count()).where(LifecycleRequest.created_at >= months[0]).group_by("m", LifecycleRequest.request_type))).all()
    idx = {(r[0].year, r[0].month, r[1]): r[2] for r in rows}
    series = {t: [idx.get((m.year, m.month, t), 0) for m in months] for t in ("joiner", "mover", "leaver", "privilege")}
    return {
        "labels": [m.strftime("%b") for m in months], "months": [m.strftime("%Y-%m") for m in months], "series": series,
        "distribution": [{"type": t, "count": sum(v)} for t, v in series.items()], "window": "last 6 months",
    }


async def dashboard_activity(db: AsyncSession, limit: int = 6) -> list[dict]:
    rows = (await db.execute(
        select(AuditLog, Identity.full_name, Department.name)
        .outerjoin(Identity, and_(AuditLog.target_type == "identity", AuditLog.target_id == cast(Identity.id, String)))
        .outerjoin(Department, Department.id == Identity.department_id)
        .order_by(AuditLog.occurred_at.desc()).limit(limit))).all()
    return [{"id": a.id, "occurred_at": a.occurred_at, "identity": name or a.target_label or a.actor_label, "department": dept,
             "event": humanize_action(a.action), "category": a.category, "severity": a.severity, "outcome": a.outcome} for a, name, dept in rows]


ACTION_LABELS = {
    "auth.login": "User Sign-in", "auth.logout": "User Sign-out", "auth.logout_all": "All Sessions Revoked", "auth.signup": "Portal Signup",
    "auth.refresh": "Session Refresh", "auth.refresh_reuse_detected": "Refresh Token Reuse Detected",
    "user.approve": "Portal Account Approved", "user.reject": "Portal Account Rejected", "user.suspend": "Portal Account Suspended",
    "user.reactivate": "Portal Account Reactivated", "user.roles_changed": "Portal Roles Changed", "user.bootstrap_admin": "Admin Bootstrapped",
    "approval.approve": "Request Approved", "approval.reject": "Request Rejected", "identity.create": "Identity Onboarding Requested",
    "governance.campaign_create": "Certification Campaign Launched", "audit.export": "Audit Log Exported", "risk.export": "Risk Report Exported",
    "governance.scan": "Governance Scan Completed", "governance.finding_opened": "Governance Finding Opened",
    "governance.finding_dismissed": "Governance Finding Dismissed", "governance.mover_recheck": "Mover Access Re-check",
    "identity.deprovision_requested": "Offboarding Requested", "assistant.request_submitted": "Request Submitted for Approval (Assistant)",
    "assistant.request_auto_approved": "Request Auto-approved (Assistant)",
}


def humanize_action(action: str) -> str:
    return ACTION_LABELS.get(action, action)


async def risk_summary(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    t = (await db.execute(select(
        func.count().filter(Identity.risk_score >= HIGH),
        func.count().filter(Identity.risk_score.between(MEDIUM, HIGH - 1)),
        func.count().filter(Identity.risk_score < MEDIUM)).where(Identity.lifecycle_state != "terminated"))).one()
    ctl = (await db.execute(select(func.count().filter(ComplianceControl.status == "pass"),
                                   func.count().filter(ComplianceControl.status.in_(("pass", "fail")))))).one()
    # trajectory: average assessed score per 5-day bucket, newest bucket = "Today"
    bucket = func.floor(func.extract("epoch", func.now() - RiskAssessment.assessed_at) / 432000).label("b")
    traj = (await db.execute(select(bucket, func.avg(RiskAssessment.score), func.count())
                             .where(RiskAssessment.assessed_at >= now - timedelta(days=33)).group_by("b").order_by(bucket.desc()))).all()
    trajectory = [{"days_ago": int(b) * 5, "label": "Today" if int(b) == 0 else f"{int(b) * 5}d ago", "avg_score": round(float(a), 1), "assessments": n}
                  for b, a, n in traj]
    latest = latest_assessments()
    primary = latest.triggers[0]["label"].astext
    trig = (await db.execute(select(primary.label("label"), func.count()).select_from(latest)
                             .join(Identity, Identity.id == latest.identity_id)
                             .where(Identity.lifecycle_state != "terminated", latest.score >= MEDIUM, primary.is_not(None))
                             .group_by("label").order_by(func.count().desc()))).all()
    return {
        "tiers": {"high": t[0], "medium": t[1], "low": t[2]},
        "compliance": {"percent": round(100 * ctl[0] / ctl[1], 1) if ctl[1] else None, "passing": ctl[0], "total": ctl[1]},
        "trajectory": trajectory, "triggers": [{"label": l, "count": c} for l, c in trig],
    }


async def flagged_identities(db: AsyncSession, limit: int, offset: int, min_score: int = HIGH) -> tuple[int, list[dict]]:
    latest = latest_assessments()
    base = (select(Identity, Department.name, latest.triggers, latest.assessed_at)
            .join(latest, latest.identity_id == Identity.id).outerjoin(Department, Department.id == Identity.department_id)
            .where(Identity.lifecycle_state != "terminated", Identity.risk_score >= min_score))
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (await db.execute(base.order_by(Identity.risk_score.desc(), Identity.full_name).limit(limit).offset(offset))).all()
    return total, [{"id": i.id, "name": i.full_name, "email": i.email, "department": d, "risk_score": i.risk_score, "risk_level": risk_level(i.risk_score),
                    "triggers": [t["label"] for t in (trig or [])], "last_review": at} for i, d, trig, at in rows]


async def governance_summary(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    fw = (await db.execute(select(ComplianceFramework.id, ComplianceFramework.name,
                                  func.count().filter(ComplianceControl.status == "pass"),
                                  func.count().filter(ComplianceControl.status.in_(("pass", "fail"))))
                           .outerjoin(ComplianceControl, ComplianceControl.framework_id == ComplianceFramework.id)
                           .group_by(ComplianceFramework.id, ComplianceFramework.name).order_by(ComplianceFramework.name))).all()
    frameworks = [{"id": i, "name": n, "passing": p, "total": t, "percent": round(100 * p / t, 1) if t else None} for i, n, p, t in fw]
    tp, tt = sum(f["passing"] for f in frameworks), sum(f["total"] for f in frameworks)
    camps = (await db.execute(select(CertificationCampaign, func.count(CertificationItem.identity_id),
                                     func.count(CertificationItem.decision))
                              .outerjoin(CertificationItem, CertificationItem.campaign_id == CertificationCampaign.id)
                              .group_by(CertificationCampaign.id).order_by(CertificationCampaign.due_date.desc()))).all()
    campaigns = [{"id": c.id, "name": c.name, "scope": c.scope_description, "due_date": c.due_date, "status": c.status, "total": n, "decided": d,
                  "percent": round(100 * d / n) if n else 0, "overdue": c.status == "active" and c.due_date < now.date(),
                  "completed_at": c.completed_at} for c, n, d in camps]
    # SoD conflicts: identities that hold *all* entitlements of an active SoD policy
    pol = (await db.execute(select(GovernancePolicy).where(GovernancePolicy.policy_type == "sod", GovernancePolicy.is_active.is_(True)))).scalars().all()
    conflicts = []
    ent_names = dict((await db.execute(select(Entitlement.id, Entitlement.name))).all())
    for p in pol:
        ids = p.rules.get("entitlements", [])
        if len(ids) < 2:
            continue
        rows = (await db.execute(
            select(Identity.id, Identity.full_name, Identity.email).join(IdentityEntitlement, IdentityEntitlement.identity_id == Identity.id)
            .where(IdentityEntitlement.entitlement_id.in_(ids), IdentityEntitlement.status.in_(("active", "pending")),
                   Identity.lifecycle_state != "terminated")
            .group_by(Identity.id).having(func.count(func.distinct(IdentityEntitlement.entitlement_id)) == len(ids))
            .order_by(Identity.full_name))).all()
        import uuid as _u
        for i, n, e in rows:
            conflicts.append({"policy_id": p.id, "policy": p.name, "severity": p.severity,
                              "identity": {"id": i, "name": n, "email": e}, "entitlements": [ent_names[_u.UUID(x)] for x in ids]})
    connectors = (await db.execute(select(IdentityConnector.name, IdentityConnector.status).order_by(IdentityConnector.name))).mappings().all()
    return {"frameworks": frameworks, "overall": {"percent": round(100 * tp / tt, 1) if tt else None, "passing": tp, "total": tt},
            "campaigns": campaigns, "sod_conflicts": conflicts, "connectors": [dict(c) for c in connectors]}
