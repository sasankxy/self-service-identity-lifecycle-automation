"""Side effects of an approved lifecycle request. Shared by the approvals API and the policy auto-approval path,
so both apply exactly the same changes. The caller owns the transaction (commit/rollback)."""
import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Identity, IdentityEntitlement, LifecycleRequest, LifecycleRequestEntitlement


async def apply_effects(db: AsyncSession, req: LifecycleRequest, ident: Identity, granted_by: uuid.UUID | None, now: datetime) -> None:
    deltas = (await db.execute(select(LifecycleRequestEntitlement).where(LifecycleRequestEntitlement.request_id == req.id))).scalars().all()
    for d in deltas:
        if d.action == "add":
            stmt = pg_insert(IdentityEntitlement).values(
                identity_id=ident.id, entitlement_id=d.entitlement_id, status="pending", source=f"request:{req.ref_no}", granted_by=granted_by,
                expires_at=now + timedelta(hours=req.duration_hours) if req.duration_hours else None)
            await db.execute(stmt.on_conflict_do_update(constraint="uq_identity_entitlements_pair",
                                                         set_={"status": "pending", "source": f"request:{req.ref_no}", "expires_at": stmt.excluded.expires_at}))
        else:
            await db.execute(IdentityEntitlement.__table__.update().where(
                IdentityEntitlement.identity_id == ident.id, IdentityEntitlement.entitlement_id == d.entitlement_id).values(status="revoked"))
    if req.request_type == "mover" and req.to_department_id:
        ident.department_id = req.to_department_id
        pid = (req.payload or {}).get("access_profile_id")
        if pid:
            ident.access_profile_id = uuid.UUID(pid)
    if req.request_type == "leaver":
        await db.execute(IdentityEntitlement.__table__.update().where(IdentityEntitlement.identity_id == ident.id).values(status="revoked"))


async def apply_due_requests(db: AsyncSession, today: date | None = None) -> int:
    """Apply policy-approved requests whose effective date has arrived (they were scheduled, not applied).
    Run from cron / a scheduler: `python -m scripts.apply_due`. Returns how many were applied."""
    today = today or datetime.now(timezone.utc).date()
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(LifecycleRequest).where(
        LifecycleRequest.status == "approved", LifecycleRequest.effective_date <= today,
        text("lifecycle_requests.payload->>'scheduled' = 'true'"), text("coalesce(lifecycle_requests.payload->>'applied','false') = 'false'"))
        .with_for_update(skip_locked=True))).scalars().all()
    for req in rows:
        ident = await db.get(Identity, req.identity_id)
        await apply_effects(db, req, ident, None, now)
        req.payload = {**req.payload, "applied": True, "applied_at": now.isoformat()}
    await db.commit()
    return len(rows)


async def execute_plan(db: AsyncSession, request, actor, plan, text_in: str) -> dict:
    """Persist a policy Plan as a lifecycle request and (for AUTO) apply it. Never called for DENY/CLARIFY/NOOP.
    One transaction: request + deltas + approval row + (effects) + audit, or nothing."""
    from app.models import ApprovalRequest, RiskAssessment
    from app.services import audit, policy, stats
    assert plan.decision in (policy.AUTO, policy.APPROVAL)
    now, today = datetime.now(timezone.utc), datetime.now(timezone.utc).date()
    ident, auto = plan.identity, plan.decision == policy.AUTO
    due = (plan.effective_date or today) <= today
    req = LifecycleRequest(
        identity_id=ident.id, request_type="mover" if plan.kind == "mover" else "privilege",
        status="pending_approval" if not auto else "approved",
        from_department_id=plan.from_dept.id if plan.from_dept else None,
        to_department_id=plan.to_dept.id if plan.kind == "mover" and plan.to_dept else None,
        requested_by=uuid.UUID(actor.id), requester_name=actor.full_name, effective_date=plan.effective_date,
        justification=f"Requested via AI assistant: {text_in[:400]}",
        payload={"source": "assistant", "text": text_in[:500], "policy": {"decision": plan.decision, "reasons": plan.reasons},
                 **({"access_profile_id": str(plan.profile.id)} if plan.profile else {}),
                 **({"scheduled": True, "applied": False} if auto and not due else {})})
    db.add(req)
    await db.flush()
    for l in plan.lines:
        db.add(LifecycleRequestEntitlement(request_id=req.id, entitlement_id=l.entitlement_id, action=l.action))
    score = ident.risk_score
    assess = RiskAssessment(identity_id=ident.id, lifecycle_request_id=req.id, score=score, level=stats.risk_level(score),
                            triggers=[{"label": r} for r in plan.reasons[:3]] if not auto else [])
    db.add(assess)
    await db.flush()
    urgent = score >= 75 or any(l.risk_level == "critical" for l in plan.adds)
    ap = ApprovalRequest(lifecycle_request_id=req.id, risk_assessment_id=assess.id, status="pending" if not auto else "approved",
                         priority="urgent" if urgent and not auto else "normal",
                         decided_at=now if auto else None,
                         decision_comment=("Auto-approved by policy engine. " + " ".join(plan.reasons[:3])) if auto else None)
    db.add(ap)
    applied = False
    if auto and due:
        await apply_effects(db, req, ident, None, now)
        applied = True
    audit.record(db, request, "assistant.request_auto_approved" if auto else "assistant.request_submitted", actor_id=actor.id,
                 actor_label=actor.email, target_type="identity", target_id=ident.id, target_label=ident.email,
                 severity="info" if auto else "medium", category="provisioning",
                 details={"request": f"REQ-{req.ref_no}", "kind": plan.kind, "decision": plan.decision, "reasons": plan.reasons[:5],
                          "adds": [l.name for l in plan.adds], "removes": [l.name for l in plan.removes],
                          "to_department": plan.to_dept.name if plan.to_dept else None, "applied": applied, "text": text_in[:300]})
    await db.commit()
    return {"ref": f"REQ-{req.ref_no}", "decision": plan.decision, "request_status": req.status, "applied": applied,
            "scheduled_for": plan.effective_date.isoformat() if auto and not due else None}
