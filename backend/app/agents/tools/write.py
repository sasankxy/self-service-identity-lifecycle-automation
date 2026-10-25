"""Write tools, split in two phases so nothing changes without an explicit human confirm:

  prepare(ctx, args) -> Prepared   read-only: resolves the request and asks the policy engine for a Plan (the PDP)
  commit(ctx, args, prepared)      writes, in one transaction, through the SAME services the UI uses (lifecycle / onboarding)

The gateway calls prepare() again at commit time and never reuses an old Plan, so a decision cannot go stale or be forged.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import func, select

from app.agents.tools import schemas as S
from app.core.errors import ApiError
from app.models import AccessProfile, Identity
from app.services import directory, lifecycle, onboarding, policy


@dataclass
class Prepared:
    decision: str
    reasons: list[str]
    summary: dict
    target_id: uuid.UUID | None = None
    identity: Identity | None = None
    plan: policy.Plan | None = None
    extra: dict = field(default_factory=dict)


def plan_summary(plan: policy.Plan) -> dict:
    return {"kind": plan.kind, "identity": {"id": str(plan.identity.id), "name": plan.identity.full_name, "email": plan.identity.email},
            "from_department": plan.from_dept.name if plan.from_dept else None,
            "to_department": plan.to_dept.name if plan.to_dept else None, "access_profile": plan.profile.name if plan.profile else None,
            "add": [{"name": l.name, "application": l.application, "risk_level": l.risk_level, "decision": l.decision} for l in plan.adds],
            "remove": [l.name for l in plan.removes], "keeps": plan.keeps, "notes": plan.notes, "questions": plan.questions,
            "profile_options": [p.name for p in plan.profile_options], "choices": plan.choices,
            "effective_date": plan.effective_date.isoformat() if plan.effective_date else None}


async def _identity(ctx, identity_id: uuid.UUID) -> Identity:
    ident = await ctx.db.get(Identity, identity_id)
    if not ident:
        raise ApiError(404, "not_found", "Identity not found.")
    return ident


# ─────────────────────────── modify_user_access
async def prepare_modify(ctx, a: S.ModifyUserAccess) -> Prepared:
    ident = await _identity(ctx, a.identity_id)
    to_dept = await directory.dept_by_name(ctx.db, a.to_department) if a.to_department else None
    if a.change == "mover" and a.to_department and not to_dept:
        raise ApiError(422, "validation_error", "Unknown department.", fields={"to_department": "Unknown department"})
    prof = None
    if a.access_profile:
        prof = (await ctx.db.execute(select(AccessProfile).where(AccessProfile.department_id == (to_dept.id if to_dept else None),
                                                                 func.lower(AccessProfile.name) == a.access_profile.lower()))).scalar_one_or_none()
        if not prof:
            raise ApiError(422, "validation_error", "Unknown access profile for that department.", fields={"access_profile": "Unknown access profile"})
    plan = await policy.build_plan(ctx.db, kind=a.change, identity=ident, to_dept=to_dept if a.change == "mover" else None,
                                   applications=a.applications, roles=a.entitlements, effective_date=a.effective_date, date_text=a.date_text,
                                   access_profile=prof, requester_id=uuid.UUID(ctx.actor.id))
    return Prepared(plan.decision, list(plan.reasons), plan_summary(plan), ident.id, ident, plan)


async def commit_plan(ctx, prepared: Prepared, text: str, justification: str | None) -> dict:
    auto = prepared.decision == policy.AUTO
    return await lifecycle.execute_plan(ctx.db, ctx.request, ctx.actor, prepared.plan, text, via="agent", justification=justification,
                                        audit_action="agent.request_auto_approved" if auto else "agent.request_submitted")


async def commit_modify(ctx, a: S.ModifyUserAccess, prepared: Prepared) -> dict:
    return await commit_plan(ctx, prepared, ctx.user_text, a.justification or None)


# ─────────────────────────── deprovision_user (always APPROVAL: policy._leaver_plan)
async def prepare_deprovision(ctx, a: S.DeprovisionUser) -> Prepared:
    ident = await _identity(ctx, a.identity_id)
    plan = await policy.build_plan(ctx.db, kind="leaver", identity=ident, effective_date=a.effective_date, requester_id=uuid.UUID(ctx.actor.id))
    return Prepared(plan.decision, list(plan.reasons) + list(plan.notes), plan_summary(plan), ident.id, ident, plan)


async def commit_deprovision(ctx, a: S.DeprovisionUser, prepared: Prepared) -> dict:
    return await commit_plan(ctx, prepared, ctx.user_text or a.reason, a.reason)


# ─────────────────────────── provision_user (a joiner is always approval-gated)
async def prepare_provision(ctx, a: S.ProvisionUser) -> Prepared:
    dept = await directory.dept_by_name(ctx.db, a.department)
    if not dept:
        raise ApiError(422, "validation_error", "Unknown department.", fields={"department": "Unknown department"})
    prof = (await ctx.db.execute(select(AccessProfile).where(AccessProfile.department_id == dept.id,
                                                             func.lower(AccessProfile.name) == a.access_profile.lower()))).scalar_one_or_none()
    if not prof:
        raise ApiError(422, "validation_error", "Unknown access profile for that department.", fields={"access_profile": "Unknown access profile"})
    domains = ctx.settings.email_domains if ctx.settings else set()
    if domains and a.email.rsplit("@", 1)[1] not in domains:
        raise ApiError(422, "validation_error", "Use a corporate email address.", fields={"email": "Use a corporate email address"})
    exists = (await ctx.db.execute(select(Identity.id).where(func.lower(Identity.email) == a.email))).first()
    if exists:
        return Prepared(policy.DENY, ["An identity with this email already exists."], {"email": a.email})
    summary = {"kind": "joiner", "name": f"{a.first_name} {a.last_name}", "email": a.email, "department": dept.name, "access_profile": prof.name,
               "start_date": a.start_date.isoformat() if a.start_date else None}
    return Prepared(policy.APPROVAL, ["New identities are always reviewed by an approver before any access is granted."], summary,
                    extra={"dept": dept, "prof": prof})


async def commit_provision(ctx, a: S.ProvisionUser, prepared: Prepared) -> dict:
    out = await onboarding.create_joiner(ctx.db, ctx.request, ctx.actor, first_name=a.first_name, last_name=a.last_name, email=a.email,
                                         dept=prepared.extra["dept"], prof=prepared.extra["prof"], start_date=a.start_date,
                                         audit_action="agent.joiner_submitted", extra_audit={"trace_id": ctx.trace_id})
    await ctx.db.commit()
    return {"ref": out["request_ref"], "decision": policy.APPROVAL, "request_status": out["status"], "applied": False,
            "identity_id": str(out["id"])}
