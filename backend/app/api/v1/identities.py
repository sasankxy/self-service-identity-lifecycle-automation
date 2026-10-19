import secrets
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.common import request_deltas
from app.core import csrf
from app.core.deps import get_db, require_permission
from app.core.errors import ApiError
from app.models import (
    AccessProfile, AccessProfileEntitlement, ApprovalRequest, Department, Entitlement, Identity, IdentityEntitlement,
    LifecycleRequest, LifecycleRequestEntitlement, RiskAssessment,
)
from app.services import audit, lifecycle, policy, stats
from app.services.accounts import Principal
from app.services.cache import cached, invalidate

router = APIRouter(prefix="/identities", tags=["identities"], dependencies=[Depends(csrf.csrf_protect)])
STATES = ("joiner", "mover", "leaver", "active", "terminated")


def _initials(name: str) -> str:
    return "".join(w[0] for w in name.replace("-", " ").split()[:2]).upper()


@router.get("/counts")
async def counts(request: Request, db: AsyncSession = Depends(get_db), _: Principal = Depends(require_permission("identities:read"))):
    async def load():
        rows = dict((await db.execute(select(Identity.lifecycle_state, func.count()).group_by(Identity.lifecycle_state))).all())
        return {"joiner": rows.get("joiner", 0), "mover": rows.get("mover", 0), "leaver": rows.get("leaver", 0),
                "directory": sum(v for k, v in rows.items() if k != "terminated"), "terminated": rows.get("terminated", 0)}
    return await cached(request, "identities", "counts", 30, load)


@router.get("")
async def list_identities(
    state: str = "all", q: str | None = Query(None, max_length=100), department_id: uuid.UUID | None = None,
    limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0), db: AsyncSession = Depends(get_db),
    _: Principal = Depends(require_permission("identities:read")),
):
    if state != "all" and state not in STATES:
        raise ApiError(422, "validation_error", "Invalid state filter.", fields={"state": "Unknown state"})
    cond = [Identity.lifecycle_state != "terminated"] if state == "all" else [Identity.lifecycle_state == state]
    if department_id:
        cond.append(Identity.department_id == department_id)
    if q:
        like = f"%{q.strip().lower()}%"
        cond.append(or_(func.lower(Identity.full_name).like(like), func.lower(Identity.email).like(like), func.lower(Identity.employee_id).like(like)))
    order = {"joiner": [Identity.start_date.desc(), Identity.full_name], "mover": [Identity.updated_at.desc()],
             "leaver": [Identity.end_date.asc()]}.get(state, [Identity.full_name])
    total = (await db.execute(select(func.count()).select_from(Identity).where(*cond))).scalar_one()
    rows = (await db.execute(select(Identity, Department.name, AccessProfile.name)
                             .outerjoin(Department, Department.id == Identity.department_id)
                             .outerjoin(AccessProfile, AccessProfile.id == Identity.access_profile_id)
                             .where(*cond).order_by(*order).limit(limit).offset(offset))).all()
    ids = [r[0].id for r in rows]
    depts = dict((await db.execute(select(Department.id, Department.name))).all())
    latest: dict = {}
    if ids:
        reqs = (await db.execute(select(LifecycleRequest).where(LifecycleRequest.identity_id.in_(ids),
                                                                LifecycleRequest.request_type.in_(("joiner", "mover", "leaver")))
                                 .order_by(LifecycleRequest.created_at.desc()))).scalars().all()
        for r in reqs:
            latest.setdefault(r.identity_id, r)
    deltas = await request_deltas(db, [r.id for r in latest.values()])
    ent_stats: dict = {}
    if ids and state == "leaver":
        for iid, st, n in (await db.execute(select(IdentityEntitlement.identity_id, IdentityEntitlement.status, func.count())
                                            .where(IdentityEntitlement.identity_id.in_(ids)).group_by(IdentityEntitlement.identity_id, IdentityEntitlement.status))).all():
            ent_stats.setdefault(iid, {})[st] = n
    today = datetime.now(timezone.utc).date()
    items = []
    for i, dept, prof in rows:
        r = latest.get(i.id)
        es = ent_stats.get(i.id, {})
        items.append({
            "id": i.id, "employee_id": i.employee_id, "name": i.full_name, "initials": _initials(i.full_name), "email": i.email,
            "department": dept, "job_title": i.job_title, "access_profile": prof, "identity_type": i.identity_type,
            "lifecycle_state": i.lifecycle_state, "risk_score": i.risk_score, "risk_level": stats.risk_level(i.risk_score),
            "start_date": i.start_date, "end_date": i.end_date, "last_authentication_at": i.last_authentication_at,
            "days_remaining": (i.end_date - today).days if i.end_date else None,
            "access": {"active": es.get("active", 0) + es.get("pending", 0), "revoked": es.get("revoked", 0)} if state == "leaver" else None,
            "request": None if not r else {
                "id": r.id, "ref": f"REQ-{r.ref_no}", "type": r.request_type, "status": r.status, "effective_date": r.effective_date,
                "from_department": depts.get(r.from_department_id), "to_department": depts.get(r.to_department_id),
                "added": deltas[r.id]["added"], "removed": deltas[r.id]["removed"], "created_at": r.created_at},
        })
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.get("/{identity_id}")
async def identity_detail(identity_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db),
                          _: Principal = Depends(require_permission("identities:read"))):
    async def load():
        row = (await db.execute(select(Identity, Department.name, AccessProfile.name)
                                .outerjoin(Department, Department.id == Identity.department_id)
                                .outerjoin(AccessProfile, AccessProfile.id == Identity.access_profile_id)
                                .where(Identity.id == identity_id))).first()
        if not row:
            return None
        i, dept, prof = row
        ents = (await db.execute(select(Entitlement.name, Entitlement.application, Entitlement.risk_level, IdentityEntitlement.status, IdentityEntitlement.expires_at)
                                 .join(IdentityEntitlement, IdentityEntitlement.entitlement_id == Entitlement.id)
                                 .where(IdentityEntitlement.identity_id == identity_id).order_by(Entitlement.name))).mappings().all()
        risk = (await db.execute(select(RiskAssessment).where(RiskAssessment.identity_id == identity_id)
                                 .order_by(RiskAssessment.assessed_at.desc()).limit(8))).scalars().all()
        reqs = (await db.execute(select(LifecycleRequest).where(LifecycleRequest.identity_id == identity_id)
                                 .order_by(LifecycleRequest.created_at.desc()).limit(6))).scalars().all()
        mgr = await db.get(Identity, i.manager_id) if i.manager_id else None
        return {"id": i.id, "employee_id": i.employee_id, "name": i.full_name, "email": i.email, "department": dept, "job_title": i.job_title,
                "access_profile": prof, "identity_type": i.identity_type, "lifecycle_state": i.lifecycle_state, "risk_score": i.risk_score,
                "risk_level": stats.risk_level(i.risk_score), "start_date": i.start_date, "end_date": i.end_date,
                "last_authentication_at": i.last_authentication_at, "manager": mgr.full_name if mgr else None, "is_demo": i.is_demo,
                "entitlements": [dict(e) for e in ents],
                "risk_history": [{"score": a.score, "level": a.level, "assessed_at": a.assessed_at, "triggers": [t["label"] for t in a.triggers]} for a in risk],
                "requests": [{"ref": f"REQ-{r.ref_no}", "type": r.request_type, "status": r.status, "created_at": r.created_at} for r in reqs]}
    data = await cached(request, "identities", f"detail:{identity_id}", 60, load)
    if data is None:
        raise ApiError(404, "not_found", "Identity not found.")
    return data


class IdentityIn(BaseModel):
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)
    email: EmailStr
    department_id: uuid.UUID
    access_profile_id: uuid.UUID
    start_date: date

    @field_validator("first_name", "last_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = " ".join(v.split())
        if not v:
            raise ValueError("Required")
        return v

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("start_date")
    @classmethod
    def _range(cls, v: date) -> date:
        today = datetime.now(timezone.utc).date()
        if v < today - timedelta(days=30) or v > today + timedelta(days=365):
            raise ValueError("Start date must be within the last 30 days and the next 12 months")
        return v


_RISK_POINTS = {"low": 2, "medium": 8, "high": 18, "critical": 40}


@router.post("", status_code=201)
async def create_identity(body: IdentityIn, request: Request, db: AsyncSession = Depends(get_db),
                          actor: Principal = Depends(require_permission("identities:write"))):
    settings = request.app.state.settings
    if settings.email_domains and body.email.rsplit("@", 1)[1] not in settings.email_domains:
        raise ApiError(422, "validation_error", "Please correct the highlighted fields.", fields={"email": "Use a corporate email address"})
    dept = await db.get(Department, body.department_id)
    prof = await db.get(AccessProfile, body.access_profile_id)
    if not dept:
        raise ApiError(422, "validation_error", "Unknown department.", fields={"department_id": "Unknown department"})
    if not prof:
        raise ApiError(422, "validation_error", "Unknown access profile.", fields={"access_profile_id": "Unknown access profile"})
    ents = (await db.execute(select(Entitlement).join(AccessProfileEntitlement, AccessProfileEntitlement.entitlement_id == Entitlement.id)
                             .where(AccessProfileEntitlement.access_profile_id == prof.id))).scalars().all()
    score = min(100, 5 + sum(_RISK_POINTS[e.risk_level] for e in ents))
    ident = Identity(employee_id=f"EMP-{secrets.token_hex(3).upper()}", full_name=f"{body.first_name} {body.last_name}", email=body.email,
                     department_id=dept.id, access_profile_id=prof.id, job_title=prof.name, lifecycle_state="joiner", risk_score=score,
                     start_date=body.start_date, is_demo=False)
    db.add(ident)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise ApiError(409, "email_exists", "An identity with this email already exists.", fields={"email": "Already exists"})
    assess = RiskAssessment(identity_id=ident.id, score=score, level=stats.risk_level(score), triggers=[])
    lreq = LifecycleRequest(identity_id=ident.id, request_type="joiner", status="pending_approval", to_department_id=dept.id,
                            requested_by=uuid.UUID(actor.id), requester_name=actor.full_name, effective_date=body.start_date)
    db.add_all([assess, lreq])
    await db.flush()
    for e in ents:
        db.add(LifecycleRequestEntitlement(request_id=lreq.id, entitlement_id=e.id, action="add"))
    assess.lifecycle_request_id = lreq.id
    db.add(ApprovalRequest(lifecycle_request_id=lreq.id, risk_assessment_id=assess.id, status="pending",
                           priority="urgent" if score >= 75 else "normal"))
    audit.record(db, request, "identity.create", actor_id=actor.id, actor_label=actor.email, target_type="identity", target_id=ident.id,
                 target_label=ident.email, details={"request": f"REQ-{lreq.ref_no}", "department": dept.name, "access_profile": prof.name})
    await db.commit()
    await invalidate(request)
    return {"id": ident.id, "name": ident.full_name, "request_ref": f"REQ-{lreq.ref_no}", "status": "pending_approval", "risk_score": score}


class DeprovisionIn(BaseModel):
    reason: str = Field(min_length=3, max_length=300)
    effective_date: date | None = None

    @field_validator("reason")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Give a reason")
        return v


@router.post("/{identity_id}/deprovision", status_code=202)
async def deprovision(identity_id: uuid.UUID, body: DeprovisionIn, request: Request, db: AsyncSession = Depends(get_db),
                      actor: Principal = Depends(require_permission("identities:write"))):
    """Request offboarding (Leaver). Always approval-gated: this only creates a pending request; nothing is revoked until an approver says yes
    (or, for a future effective date, until that date). Same policy path as the assistant."""
    ident = await db.get(Identity, identity_id)
    if not ident:
        raise ApiError(404, "not_found", "Identity not found.")
    if body.effective_date and body.effective_date < datetime.now(timezone.utc).date():
        raise ApiError(422, "validation_error", "The effective date cannot be in the past.", fields={"effective_date": "Cannot be in the past"})
    plan = await policy.build_plan(db, kind="leaver", identity=ident, effective_date=body.effective_date, requester_id=uuid.UUID(actor.id))
    if plan.decision != policy.APPROVAL:
        raise ApiError(409, "nothing_to_do", " ".join(plan.notes + plan.reasons) or "This identity cannot be offboarded.")
    out = await lifecycle.execute_plan(db, request, actor, plan, body.reason, via="api", justification=body.reason,
                                       audit_action="identity.deprovision_requested")
    await invalidate(request)
    return {"id": ident.id, "name": ident.full_name, "request_ref": out["ref"], "status": out["request_status"], "decision": out["decision"],
            "revokes": [l.name for l in plan.removes]}
