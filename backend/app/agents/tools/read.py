"""Read-only tools. They never write, so the gateway runs them without confirmation (capability + permission still apply)."""
from __future__ import annotations

from sqlalchemy import func, select

from app.agents.tools import schemas as S
from app.models import (AccessProfile, AccessProfileEntitlement, ApprovalRequest, Department, Entitlement, Identity, IdentityEntitlement,
                        LifecycleRequest)
from app.services import directory, stats

LIVE = ("joiner", "active", "mover")


async def inspect_user_access(ctx, a: S.InspectUserAccess) -> dict:
    ident = await ctx.db.get(Identity, a.identity_id)
    return {"identity": {"id": str(ident.id), "name": ident.full_name, "employee_id": ident.employee_id},
            "access": await directory.entitlement_lines(ctx.db, ident.id, a.applications, a.entitlements)}


async def search_identities(ctx, a: S.SearchIdentities) -> dict:
    found = await directory.resolve_identities(ctx.db, ctx.actor, {"person": a.query})
    return {"matches": [{"id": str(i.id), "name": i.full_name, "email": i.email, "employee_id": i.employee_id,
                         "state": i.lifecycle_state} for i in found[:a.limit]], "total": len(found)}


async def get_identity_profile(ctx, a: S.GetIdentityProfile) -> dict:
    i = await ctx.db.get(Identity, a.identity_id)
    dept = await ctx.db.get(Department, i.department_id) if i.department_id else None
    prof = await ctx.db.get(AccessProfile, i.access_profile_id) if i.access_profile_id else None
    mgr = await ctx.db.get(Identity, i.manager_id) if i.manager_id else None
    return {"id": str(i.id), "name": i.full_name, "email": i.email, "employee_id": i.employee_id, "department": dept.name if dept else None,
            "access_profile": prof.name if prof else None, "manager": mgr.full_name if mgr else None, "state": i.lifecycle_state,
            "risk_score": i.risk_score, "risk_level": stats.risk_level(i.risk_score),
            "last_sign_in": i.last_authentication_at.isoformat() if i.last_authentication_at else None}


async def get_department_baseline(ctx, a: S.GetDepartmentBaseline) -> dict:
    dept = await directory.dept_by_name(ctx.db, a.department)
    rows = (await ctx.db.execute(
        select(AccessProfile.name, Entitlement.application, Entitlement.name, Entitlement.risk_level)
        .join(AccessProfileEntitlement, AccessProfileEntitlement.access_profile_id == AccessProfile.id)
        .join(Entitlement, Entitlement.id == AccessProfileEntitlement.entitlement_id)
        .where(AccessProfile.department_id == dept.id).order_by(AccessProfile.name, Entitlement.application, Entitlement.name))).all()
    profiles: dict[str, list[str]] = {}
    for p, app, name, risk in rows:
        profiles.setdefault(p, []).append(f"{name} ({app}) · {risk} risk")
    return {"department": dept.name, "profiles": profiles}


async def peer_access_stats(ctx, a: S.PeerAccessStats) -> dict:
    """Entitlements held by at least `min_share` of the department's live identities: the empirical 'normal' (Access Advisor input)."""
    dept = await directory.dept_by_name(ctx.db, a.department)
    n = (await ctx.db.execute(select(func.count()).select_from(Identity).where(
        Identity.department_id == dept.id, Identity.lifecycle_state.in_(LIVE)))).scalar_one()
    if not n:
        return {"department": dept.name, "population": 0, "common": []}
    rows = (await ctx.db.execute(
        select(Entitlement.name, Entitlement.application, Entitlement.risk_level, func.count(func.distinct(IdentityEntitlement.identity_id)))
        .join(IdentityEntitlement, IdentityEntitlement.entitlement_id == Entitlement.id)
        .join(Identity, Identity.id == IdentityEntitlement.identity_id)
        .where(Identity.department_id == dept.id, Identity.lifecycle_state.in_(LIVE), IdentityEntitlement.status == "active")
        .group_by(Entitlement.name, Entitlement.application, Entitlement.risk_level))).all()
    common = sorted(({"entitlement": e, "application": app, "risk_level": r, "share": round(c / n, 2)} for e, app, r, c in rows
                     if c / n >= a.min_share), key=lambda x: -x["share"])
    return {"department": dept.name, "population": n, "common": common}


async def list_pending_requests(ctx, a: S.ListPendingRequests) -> dict:
    rows = (await ctx.db.execute(
        select(LifecycleRequest.ref_no, LifecycleRequest.request_type, Identity.full_name, ApprovalRequest.priority, ApprovalRequest.requested_at)
        .join(ApprovalRequest, ApprovalRequest.lifecycle_request_id == LifecycleRequest.id)
        .join(Identity, Identity.id == LifecycleRequest.identity_id).where(ApprovalRequest.status == "pending")
        .order_by(ApprovalRequest.requested_at.desc()).limit(a.limit))).all()
    return {"pending": [{"ref": f"REQ-{n}", "type": t, "identity": name, "priority": p} for n, t, name, p, _ in rows]}


async def explain_entitlement_origin(ctx, a: S.ExplainEntitlementOrigin) -> dict:
    """Provenance of held access: profile grant vs. request (who asked, who approved, why), and whether it is baseline for the
    person's department. Read-only; this is the evidence the Investigator agent and the user see."""
    from app.models import User
    ident = await ctx.db.get(Identity, a.identity_id)
    q = (select(Entitlement, IdentityEntitlement).join(IdentityEntitlement, IdentityEntitlement.entitlement_id == Entitlement.id)
         .where(IdentityEntitlement.identity_id == ident.id, IdentityEntitlement.status.in_(("active", "pending"))))
    if a.entitlement:
        q = q.where(func.lower(Entitlement.name) == a.entitlement.lower())
    elif a.application:
        q = q.where(func.lower(Entitlement.application) == a.application.lower())
    rows = (await ctx.db.execute(q.order_by(Entitlement.application, Entitlement.name).limit(10))).all()
    baseline = set((await ctx.db.execute(
        select(AccessProfileEntitlement.entitlement_id).join(AccessProfile, AccessProfile.id == AccessProfileEntitlement.access_profile_id)
        .where(AccessProfile.department_id == ident.department_id))).scalars()) if ident.department_id else set()
    dept = await ctx.db.get(Department, ident.department_id) if ident.department_id else None
    out = []
    for e, ie in rows:
        item = {"entitlement": e.name, "application": e.application, "risk_level": e.risk_level, "status": ie.status,
                "granted_at": ie.granted_at.date().isoformat() if ie.granted_at else None,
                "expires_at": ie.expires_at.isoformat() if ie.expires_at else None, "in_department_baseline": e.id in baseline,
                "origin": "access_profile" if ie.source == "profile" else "request" if ie.source.startswith("request:") else ie.source}
        if ie.granted_by:
            u = await ctx.db.get(User, ie.granted_by)
            item["granted_by"] = u.email if u else None
        if ie.source.startswith("request:") and ie.source.split(":", 1)[1].isdigit():
            req = (await ctx.db.execute(select(LifecycleRequest).where(LifecycleRequest.ref_no == int(ie.source.split(":", 1)[1])))).scalar_one_or_none()
            if req:
                ap = (await ctx.db.execute(select(ApprovalRequest).where(ApprovalRequest.lifecycle_request_id == req.id))).scalars().first()
                approver = await ctx.db.get(User, ap.decided_by) if ap and ap.decided_by else None
                item["request"] = {"ref": f"REQ-{req.ref_no}", "type": req.request_type, "requested_by": req.requester_name,
                                   "justification": (req.justification or "")[:200], "status": req.status,
                                   "approved_by": approver.email if approver else ("policy engine" if ap and ap.status == "approved" else None),
                                   "decision_comment": (ap.decision_comment or "")[:200] if ap else None}
        out.append(item)
    return {"identity": {"id": str(ident.id), "name": ident.full_name}, "department": dept.name if dept else None, "entitlements": out}
