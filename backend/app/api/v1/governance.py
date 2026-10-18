import uuid
from datetime import date, datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import csrf
from app.core.deps import get_db, require_permission
from app.core.errors import ApiError
from app.models import CertificationCampaign, CertificationItem, Department, Entitlement, Identity, IdentityEntitlement
from app.services import audit, stats
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
