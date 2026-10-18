import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.api.v1.common import request_deltas
from app.core import csrf
from app.core.deps import get_db, require_permission
from app.core.errors import ApiError
from app.models import (
    ApprovalRequest, Department, Identity, IdentityEntitlement, LifecycleRequest, LifecycleRequestEntitlement, RiskAssessment,
)
from app.services import audit, lifecycle, stats
from app.services.accounts import Principal
from app.services.cache import invalidate

router = APIRouter(prefix="/approvals", tags=["approvals"], dependencies=[Depends(csrf.csrf_protect)])


@router.get("")
async def list_approvals(status: Literal["pending", "approved", "rejected", "all"] = "pending", limit: int = Query(25, ge=1, le=100),
                         offset: int = Query(0, ge=0), db: AsyncSession = Depends(get_db),
                         _: Principal = Depends(require_permission("approvals:read"))):
    fd, td, idd = aliased(Department), aliased(Department), aliased(Department)
    cond = [] if status == "all" else [ApprovalRequest.status == status]
    q = (select(ApprovalRequest, LifecycleRequest, Identity, idd.name, fd.name, td.name, RiskAssessment.score, RiskAssessment.level)
         .join(LifecycleRequest, LifecycleRequest.id == ApprovalRequest.lifecycle_request_id)
         .join(Identity, Identity.id == LifecycleRequest.identity_id)
         .outerjoin(idd, idd.id == Identity.department_id).outerjoin(fd, fd.id == LifecycleRequest.from_department_id)
         .outerjoin(td, td.id == LifecycleRequest.to_department_id)
         .outerjoin(RiskAssessment, RiskAssessment.id == ApprovalRequest.risk_assessment_id).where(*cond))
    total = (await db.execute(select(func.count()).select_from(ApprovalRequest).where(*cond))).scalar_one()
    counts = dict((await db.execute(select(ApprovalRequest.status, func.count()).group_by(ApprovalRequest.status))).all())
    order = ([case((ApprovalRequest.priority == "urgent", 0), else_=1), ApprovalRequest.requested_at.desc()] if status == "pending"
             else [func.coalesce(ApprovalRequest.decided_at, ApprovalRequest.requested_at).desc()])
    rows = (await db.execute(q.order_by(*order).limit(limit).offset(offset))).all()
    deltas = await request_deltas(db, [r[1].id for r in rows])
    items = [{
        "id": a.id, "request_id": r.id, "ref": f"REQ-{r.ref_no}", "type": r.request_type, "status": a.status, "request_status": r.status,
        "priority": a.priority, "requested_at": a.requested_at, "decided_at": a.decided_at, "decision_comment": a.decision_comment,
        "identity": {"id": i.id, "name": i.full_name, "email": i.email}, "department": dn, "from_department": fn, "to_department": tn,
        "effective_date": r.effective_date, "requester": r.requester_name, "justification": r.justification, "duration_hours": r.duration_hours,
        "added": deltas[r.id]["added"], "removed": deltas[r.id]["removed"],
        "risk": {"score": score, "level": level} if score is not None else None,
    } for a, r, i, dn, fn, tn, score, level in rows]
    return {"total": total, "counts": {"pending": counts.get("pending", 0), "approved": counts.get("approved", 0),
                                       "rejected": counts.get("rejected", 0)}, "items": items}


class DecisionIn(BaseModel):
    comment: str = Field("", max_length=500)


async def _decide(approval_id: uuid.UUID, decision: str, body: DecisionIn, request: Request, db: AsyncSession, actor: Principal) -> dict:
    now = datetime.now(timezone.utc)
    ap = (await db.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id).with_for_update())).scalar_one_or_none()
    if not ap:
        raise ApiError(404, "not_found", "Approval request not found.")
    if ap.status != "pending":
        raise ApiError(409, "already_decided", f"This request was already {ap.status}.")
    req = (await db.execute(select(LifecycleRequest).where(LifecycleRequest.id == ap.lifecycle_request_id).with_for_update())).scalar_one()
    ident = await db.get(Identity, req.identity_id)
    ap.status, ap.decided_by, ap.decided_at, ap.decision_comment = decision, uuid.UUID(actor.id), now, body.comment or None
    req.status = "approved" if decision == "approved" else "rejected"

    if decision == "approved":
        await lifecycle.apply_effects(db, req, ident, uuid.UUID(actor.id), now)

    sev = "medium" if req.request_type in ("privilege", "leaver") else "info"
    audit.record(db, request, f"approval.{'approve' if decision == 'approved' else 'reject'}", actor_id=actor.id, actor_label=actor.email,
                 target_type="identity", target_id=ident.id, target_label=ident.email, severity=sev, category="approval",
                 details={"request": f"REQ-{req.ref_no}", "type": req.request_type, "comment": body.comment})
    await db.commit()      # one transaction: decision + side effects + audit, or nothing
    await invalidate(request)
    return {"id": ap.id, "ref": f"REQ-{req.ref_no}", "status": ap.status, "request_status": req.status,
            "note": ("Decision recorded. No live connector is configured, so no provisioning action was executed."
                     if decision == "approved" else "Request rejected.")}


@router.post("/{approval_id}/approve")
async def approve(approval_id: uuid.UUID, request: Request, body: DecisionIn = DecisionIn(), db: AsyncSession = Depends(get_db),
                  actor: Principal = Depends(require_permission("approvals:decide"))):
    return await _decide(approval_id, "approved", body, request, db, actor)


@router.post("/{approval_id}/reject")
async def reject(approval_id: uuid.UUID, request: Request, body: DecisionIn = DecisionIn(), db: AsyncSession = Depends(get_db),
                 actor: Principal = Depends(require_permission("approvals:decide"))):
    return await _decide(approval_id, "rejected", body, request, db, actor)
