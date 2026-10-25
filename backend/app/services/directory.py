"""Read-only directory lookups shared by the rule-based assistant (api/v1/assistant.py) and the agent layer (app/agents).

Moved out of assistant.py unchanged so both front doors resolve people, departments and entitlements the same way.
Also holds the UI block helpers: the assistant and the agent return the same block format, so the frontend renders both.
"""
import re

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AccessProfile, Department, Entitlement, Identity, IdentityEntitlement, LifecycleRequest
from app.services import stats
from app.services.accounts import Principal


def kv(items): return {"type": "kv", "items": [[k, "—" if v is None else str(v)] for k, v in items]}
def text(t): return {"type": "text", "text": t}
def bullets(items): return {"type": "list", "items": items}
def head(t): return {"type": "heading", "text": t}


async def identity_card(db: AsyncSession, i: Identity) -> list[dict]:
    dept = await db.get(Department, i.department_id) if i.department_id else None
    prof = await db.get(AccessProfile, i.access_profile_id) if i.access_profile_id else None
    n_active = (await db.execute(select(func.count()).select_from(IdentityEntitlement).where(
        IdentityEntitlement.identity_id == i.id, IdentityEntitlement.status.in_(("active", "pending"))))).scalar_one()
    reqs = (await db.execute(select(LifecycleRequest.ref_no, LifecycleRequest.request_type, LifecycleRequest.status).where(
        LifecycleRequest.identity_id == i.id).order_by(LifecycleRequest.created_at.desc()).limit(3))).all()
    return [head(i.full_name), kv([
        ("Email", i.email), ("Department", dept.name if dept else None), ("Access profile", prof.name if prof else None),
        ("Lifecycle state", i.lifecycle_state), ("Risk score", f"{i.risk_score} / 100 ({stats.risk_level(i.risk_score)})"),
        ("Current entitlements", n_active), ("Recent requests", ", ".join(f"REQ-{n} {t} ({s})" for n, t, s in reqs) or "none")])]


async def resolve_identities(db: AsyncSession, actor: Principal, s: dict) -> list[Identity]:
    if s.get("employee_id"):
        cond = func.lower(Identity.employee_id) == s["employee_id"].lower()
    elif s.get("person"):
        parts = [p for p in re.findall(r"[a-z0-9.'-]+", s["person"].lower()) if len(p) >= 2]
        if not parts:
            return []
        cond = func.coalesce(func.lower(Identity.full_name), "").like(f"%{parts[0]}%")
        for p in parts:   # every name part must appear in the name or e-mail
            cond = cond & or_(func.lower(Identity.full_name).like(f"%{p}%"), func.lower(Identity.email).like(f"%{p}%"))
    elif s.get("subject_reference") == "SELF":
        cond = func.lower(Identity.email) == actor.email.lower()
    else:
        return []
    return list((await db.execute(select(Identity).where(cond).order_by(Identity.full_name).limit(25))).scalars().all())


async def entitlement_lines(db: AsyncSession, identity_id, apps: list[str] | None = None, roles: list[str] | None = None) -> list[str]:
    q = (select(Entitlement.application, Entitlement.name, Entitlement.risk_level, IdentityEntitlement.status)
         .join(IdentityEntitlement, IdentityEntitlement.entitlement_id == Entitlement.id)
         .where(IdentityEntitlement.identity_id == identity_id, IdentityEntitlement.status.in_(("active", "pending"))))
    if apps or roles:
        q = q.where(or_(func.lower(Entitlement.application).in_([a.lower() for a in apps or []]),
                        func.lower(Entitlement.name).in_([r.lower() for r in roles or []])))
    rows = (await db.execute(q.order_by(Entitlement.application, Entitlement.name))).all()
    lines = [f"{n} ({a}) · {r} risk" + (" · pending" if st == "pending" else "") for a, n, r, st in rows]
    return lines if len(lines) <= 12 else lines[:12] + [f"…and {len(lines) - 12} more"]


async def dept_by_name(db: AsyncSession, name: str | None) -> Department | None:
    return (await db.execute(select(Department).where(func.lower(Department.name) == name.lower()))).scalar_one_or_none() if name else None
