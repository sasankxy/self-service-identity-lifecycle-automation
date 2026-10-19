import uuid
from datetime import date, datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import csrf
from app.core.deps import get_db, require_permission
from app.core.errors import ApiError
from app.models import (CertificationCampaign, CertificationItem, Department, Entitlement, GovernanceFinding, Identity,
                        IdentityEntitlement)
from app.services import audit, governance_scan, stats
from app.services.accounts import Principal
from app.services.cache import cached, invalidate

router = APIRouter(prefix="/governance", tags=["governance"], dependencies=[Depends(csrf.csrf_protect)])


@router.get("/summary")
async def summary(request: Request, db: AsyncSession = Depends(get_db), _: Principal = Depends(require_permission("governance:read"))):
    return await cached(request, "governance", "summary", 60, lambda: stats.governance_summary(db))


class CampaignIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    scope: Literal["department", "privileged", "service"]
    department_id: uuid.UUID | None = None
    due_date: date

    @field_validator("due_date")
    @classmethod
    def _future(cls, v: date) -> date:
        if v <= datetime.now(timezone.utc).date():
            raise ValueError("Due date must be in the future")
        return v


@router.post("/campaigns", status_code=201)
async def create_campaign(body: CampaignIn, request: Request, db: AsyncSession = Depends(get_db),
                          actor: Principal = Depends(require_permission("governance:manage"))):
    live = Identity.lifecycle_state != "terminated"
    if body.scope == "department":
        if not body.department_id or not (dept := await db.get(Department, body.department_id)):
            raise ApiError(422, "validation_error", "Choose a department.", fields={"department_id": "Required"})
        members = (await db.execute(select(Identity.id).where(live, Identity.department_id == dept.id))).scalars().all()
        scope_desc = f"All identities in {dept.name}"
    elif body.scope == "privileged":
        members = (await db.execute(select(Identity.id).join(IdentityEntitlement, IdentityEntitlement.identity_id == Identity.id)
                                    .join(Entitlement, Entitlement.id == IdentityEntitlement.entitlement_id)
                                    .where(live, IdentityEntitlement.status.in_(("active", "pending")), Entitlement.risk_level.in_(("high", "critical")))
                                    .distinct())).scalars().all()
        scope_desc = "Identities holding high/critical entitlements"
    else:
        members = (await db.execute(select(Identity.id).where(live, Identity.identity_type == "service"))).scalars().all()
        scope_desc = "All service identities"
    if not members:
        raise ApiError(422, "empty_scope", "No identities match that scope, so no campaign was created.")
    camp = CertificationCampaign(name=body.name.strip(), scope_description=scope_desc, due_date=body.due_date, created_by=uuid.UUID(actor.id))
    db.add(camp)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise ApiError(409, "name_exists", "A campaign with this name already exists.", fields={"name": "Already exists"})
    db.add_all([CertificationItem(campaign_id=camp.id, identity_id=m) for m in members])
    audit.record(db, request, "governance.campaign_create", actor_id=actor.id, actor_label=actor.email, target_type="campaign", target_id=camp.id,
                 target_label=camp.name, category="access_change", details={"accounts": len(members)})
    await db.commit()
    await invalidate(request, "governance", "audit")
    return {"id": camp.id, "name": camp.name, "accounts": len(members)}


# ------------------------------------------------------------------ proactive findings (orphaned accounts, privilege creep)
_SEV_ORDER = case({"critical": 0, "high": 1, "medium": 2, "low": 3}, value=GovernanceFinding.severity, else_=4)


def _finding(f: GovernanceFinding, i: Identity, dept: str | None) -> dict:
    return {"id": f.id, "kind": f.kind, "rule": f.rule, "severity": f.severity, "status": f.status, "title": f.title, "details": f.details,
            "identity": {"id": i.id, "name": i.full_name, "email": i.email, "department": dept, "state": i.lifecycle_state},
            "first_detected_at": f.first_detected_at, "last_detected_at": f.last_detected_at, "resolved_at": f.resolved_at,
            "dismissed_reason": f.dismissed_reason}


@router.get("/findings")
async def findings(kind: Literal["orphan", "creep"] | None = None, severity: Literal["low", "medium", "high", "critical"] | None = None,
                   status: Literal["open", "resolved", "dismissed", "all"] = "open", rule: str | None = Query(None, max_length=40),
                   limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0), db: AsyncSession = Depends(get_db),
                   _: Principal = Depends(require_permission("governance:read"))):
    cond = []
    if kind:
        cond.append(GovernanceFinding.kind == kind)
    if severity:
        cond.append(GovernanceFinding.severity == severity)
    if rule:
        cond.append(GovernanceFinding.rule == rule)
    if status != "all":
        cond.append(GovernanceFinding.status == status)
    total = (await db.execute(select(func.count()).select_from(GovernanceFinding).where(*cond))).scalar_one()
    rows = (await db.execute(select(GovernanceFinding, Identity, Department.name).join(Identity, Identity.id == GovernanceFinding.identity_id)
                             .outerjoin(Department, Department.id == Identity.department_id).where(*cond)
                             .order_by(_SEV_ORDER, GovernanceFinding.last_detected_at.desc(), GovernanceFinding.id).limit(limit).offset(offset))).all()
    open_by = (await db.execute(select(GovernanceFinding.kind, GovernanceFinding.severity, func.count()).where(GovernanceFinding.status == "open")
                                .group_by(GovernanceFinding.kind, GovernanceFinding.severity))).all()
    counts = {"open": sum(n for _, _, n in open_by), "orphan": sum(n for k, _, n in open_by if k == "orphan"),
              "creep": sum(n for k, _, n in open_by if k == "creep"), "critical": sum(n for _, s, n in open_by if s == "critical"),
              "high": sum(n for _, s, n in open_by if s == "high")}
    return {"total": total, "items": [_finding(f, i, d) for f, i, d in rows], "counts": counts, "last_scan": await governance_scan.latest_run(db)}


@router.post("/scan")
async def scan_now(request: Request, db: AsyncSession = Depends(get_db), actor: Principal = Depends(require_permission("governance:manage"))):
    """Run the orphan / privilege-creep scan now (the scheduler does the same on its interval)."""
    out = await governance_scan.run_scan(request.app.state.sessionmaker, request.app.state.redis, trigger="manual", request=request, actor=actor)
    if out is None:
        raise ApiError(409, "scan_running", "A governance scan is already running. Try again in a moment.")
    await invalidate(request, "governance", "audit")
    return out


class DismissIn(BaseModel):
    reason: str = Field(min_length=3, max_length=300)


@router.post("/findings/{finding_id}/dismiss")
async def dismiss_finding(finding_id: uuid.UUID, body: DismissIn, request: Request, db: AsyncSession = Depends(get_db),
                          actor: Principal = Depends(require_permission("governance:manage"))):
    """Accept the risk: the finding stays dismissed (and is not re-opened by later scans) while it is still detected."""
    f = (await db.execute(select(GovernanceFinding).where(GovernanceFinding.id == finding_id).with_for_update())).scalar_one_or_none()
    if not f:
        raise ApiError(404, "not_found", "Finding not found.")
    if f.status != "open":
        raise ApiError(409, "not_open", f"This finding is already {f.status}.")
    f.status, f.dismissed_by, f.dismissed_reason = "dismissed", uuid.UUID(actor.id), body.reason.strip()
    audit.record(db, request, "governance.finding_dismissed", actor_id=actor.id, actor_label=actor.email, target_type="finding", target_id=f.id,
                 target_label=f.title[:300], severity="medium", category="risk_alert",
                 details={"kind": f.kind, "rule": f.rule, "identity_id": str(f.identity_id), "reason": body.reason.strip()})
    await db.commit()
    await invalidate(request, "governance", "audit")
    return {"id": f.id, "status": f.status}
