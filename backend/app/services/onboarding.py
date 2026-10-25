"""Joiner creation, shared by the onboarding form (POST /identities) and the agent's `provision_user` tool.

A joiner is always approval-gated: this creates the identity in state "joiner" plus a pending Joiner request whose entitlement
deltas are the access profile's entitlements. Nothing is granted until an approver says yes. The caller owns the commit.
"""
import secrets
import uuid
from datetime import date

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ApiError
from app.models import (AccessProfile, AccessProfileEntitlement, ApprovalRequest, Department, Entitlement, Identity, LifecycleRequest,
                        LifecycleRequestEntitlement, RiskAssessment)
from app.services import audit, stats
from app.services.accounts import Principal

RISK_POINTS = {"low": 2, "medium": 8, "high": 18, "critical": 40}


async def create_joiner(db: AsyncSession, request, actor: Principal, *, first_name: str, last_name: str, email: str,
                        dept: Department, prof: AccessProfile, start_date: date | None, audit_action: str = "identity.create",
                        extra_audit: dict | None = None) -> dict:
    ents = (await db.execute(select(Entitlement).join(AccessProfileEntitlement, AccessProfileEntitlement.entitlement_id == Entitlement.id)
                             .where(AccessProfileEntitlement.access_profile_id == prof.id))).scalars().all()
    score = min(100, 5 + sum(RISK_POINTS[e.risk_level] for e in ents))
    ident = Identity(employee_id=f"EMP-{secrets.token_hex(3).upper()}", full_name=f"{first_name} {last_name}", email=email,
                     department_id=dept.id, access_profile_id=prof.id, job_title=prof.name, lifecycle_state="joiner", risk_score=score,
                     start_date=start_date, is_demo=False)
    db.add(ident)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise ApiError(409, "email_exists", "An identity with this email already exists.", fields={"email": "Already exists"})
    assess = RiskAssessment(identity_id=ident.id, score=score, level=stats.risk_level(score), triggers=[])
    lreq = LifecycleRequest(identity_id=ident.id, request_type="joiner", status="pending_approval", to_department_id=dept.id,
                            requested_by=uuid.UUID(actor.id), requester_name=actor.full_name, effective_date=start_date)
    db.add_all([assess, lreq])
    await db.flush()
    for e in ents:
        db.add(LifecycleRequestEntitlement(request_id=lreq.id, entitlement_id=e.id, action="add"))
    assess.lifecycle_request_id = lreq.id
    db.add(ApprovalRequest(lifecycle_request_id=lreq.id, risk_assessment_id=assess.id, status="pending",
                           priority="urgent" if score >= 75 else "normal"))
    audit.record(db, request, audit_action, actor_id=actor.id, actor_label=actor.email, target_type="identity", target_id=ident.id,
                 target_label=ident.email, details={"request": f"REQ-{lreq.ref_no}", "department": dept.name, "access_profile": prof.name,
                                                    **(extra_audit or {})})
    return {"id": ident.id, "name": ident.full_name, "request_ref": f"REQ-{lreq.ref_no}", "status": "pending_approval", "risk_score": score}
