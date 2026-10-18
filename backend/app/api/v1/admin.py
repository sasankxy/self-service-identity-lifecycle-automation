"""Portal account administration: approval, rejection, suspension, role changes."""
import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import csrf
from app.core.deps import get_db, get_sessions, require_permission
from app.core.errors import ApiError
from app.core.rbac import PRIVILEGED_ROLES, ROLES
from app.models.auth import Role, User, UserRole
from app.schemas.auth import AdminUserOut, ApproveIn, RejectIn, SetRolesIn
from app.services import accounts, audit
from app.services.accounts import Principal
from app.services.sessions import SessionStore

router = APIRouter(prefix="/admin/users", tags=["admin"], dependencies=[Depends(csrf.csrf_protect)])


async def _roles_of(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    return sorted((await db.execute(
        select(Role.name).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )).scalars().all())


async def _out(db: AsyncSession, u: User) -> AdminUserOut:
    return AdminUserOut(id=u.id, email=u.email, full_name=u.full_name, status=u.status, roles=await _roles_of(db, u.id),
                        created_at=u.created_at, approved_at=u.approved_at, last_login_at=u.last_login_at)


async def _target(db: AsyncSession, user_id: uuid.UUID) -> User:
    u = await db.get(User, user_id)
    if not u:
        raise ApiError(404, "not_found", "User not found.")
    return u


def _check_assignable(actor: Principal, roles: list[str]) -> None:
    unknown = [r for r in roles if r not in ROLES]
    if unknown:
        raise ApiError(422, "validation_error", "Unknown role.", fields={"role": f"Unknown role: {unknown[0]}"})
    if PRIVILEGED_ROLES & set(roles) and not actor.can("roles:grant_privileged"):
        raise ApiError(403, "forbidden", "Only a Super Administrator can grant privileged roles.")


async def _guard_privileged_target(db: AsyncSession, actor: Principal, target: User) -> None:
    if PRIVILEGED_ROLES & set(await _roles_of(db, target.id)) and not actor.can("roles:grant_privileged"):
        raise ApiError(403, "forbidden", "Only a Super Administrator can modify privileged accounts.")


@router.get("")
async def list_users(status: str | None = None, q: str | None = None, limit: int = Query(25, ge=1, le=100),
                     offset: int = Query(0, ge=0), db: AsyncSession = Depends(get_db),
                     _: Principal = Depends(require_permission("users:read"))):
    stmt = select(User)
    if status:
        stmt = stmt.where(User.status == status)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(User.email).like(like), func.lower(User.full_name).like(like)))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(User.created_at.desc()).limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [await _out(db, u) for u in rows]}


@router.post("/{user_id}/approve", response_model=AdminUserOut)
async def approve(user_id: uuid.UUID, body: ApproveIn, request: Request, db: AsyncSession = Depends(get_db),
                  actor: Principal = Depends(require_permission("users:approve"))):
    _check_assignable(actor, [body.role])
    u = await _target(db, user_id)
    if str(u.id) == actor.id:
        raise ApiError(403, "forbidden", "You cannot approve your own account.")
    if u.status != "pending":
        raise ApiError(409, "invalid_state", f"Account is {u.status}, not pending.")
    u.status, u.approved_by, u.approved_at = "active", uuid.UUID(actor.id), func.now()
    await accounts.set_roles(db, u.id, [body.role], uuid.UUID(actor.id))
    audit.record(db, request, "user.approve", actor_id=actor.id, actor_label=actor.email, target_type="user",
                 target_id=u.id, severity="medium", details={"role": body.role, "email": u.email})
    await db.commit()
    await accounts.invalidate_principal(request.app.state.redis, u.id)
    await db.refresh(u)
    return await _out(db, u)


@router.post("/{user_id}/reject", response_model=AdminUserOut)
async def reject(user_id: uuid.UUID, body: RejectIn, request: Request, db: AsyncSession = Depends(get_db),
                 actor: Principal = Depends(require_permission("users:approve"))):
    u = await _target(db, user_id)
    if u.status != "pending":
        raise ApiError(409, "invalid_state", f"Account is {u.status}, not pending.")
    u.status, u.status_reason = "rejected", body.reason or None
    audit.record(db, request, "user.reject", actor_id=actor.id, actor_label=actor.email, target_type="user",
                 target_id=u.id, severity="low", details={"email": u.email, "reason": body.reason})
    await db.commit()
    await accounts.invalidate_principal(request.app.state.redis, u.id)
    return await _out(db, u)


@router.post("/{user_id}/suspend", response_model=AdminUserOut)
async def suspend(user_id: uuid.UUID, body: RejectIn, request: Request, db: AsyncSession = Depends(get_db),
                  actor: Principal = Depends(require_permission("users:approve")),
                  sessions: SessionStore = Depends(get_sessions)):
    u = await _target(db, user_id)
    if str(u.id) == actor.id:
        raise ApiError(403, "forbidden", "You cannot suspend your own account.")
    await _guard_privileged_target(db, actor, u)
    if u.status != "active":
        raise ApiError(409, "invalid_state", f"Account is {u.status}, not active.")
    u.status, u.status_reason = "suspended", body.reason or None
    audit.record(db, request, "user.suspend", actor_id=actor.id, actor_label=actor.email, target_type="user",
                 target_id=u.id, severity="high", details={"email": u.email, "reason": body.reason})
    await db.commit()
    await accounts.invalidate_principal(request.app.state.redis, u.id)
    await sessions.revoke_all(u.id)       # immediate: kills access and refresh tokens
    return await _out(db, u)


@router.post("/{user_id}/reactivate", response_model=AdminUserOut)
async def reactivate(user_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db),
                     actor: Principal = Depends(require_permission("users:approve"))):
    u = await _target(db, user_id)
    await _guard_privileged_target(db, actor, u)
    if u.status != "suspended":
        raise ApiError(409, "invalid_state", f"Account is {u.status}, not suspended.")
    u.status, u.status_reason = "active", None
    audit.record(db, request, "user.reactivate", actor_id=actor.id, actor_label=actor.email, target_type="user",
                 target_id=u.id, severity="medium", details={"email": u.email})
    await db.commit()
    await accounts.invalidate_principal(request.app.state.redis, u.id)
    return await _out(db, u)


@router.put("/{user_id}/roles", response_model=AdminUserOut)
async def set_roles(user_id: uuid.UUID, body: SetRolesIn, request: Request, db: AsyncSession = Depends(get_db),
                    actor: Principal = Depends(require_permission("users:manage_roles"))):
    _check_assignable(actor, body.roles)
    u = await _target(db, user_id)
    if str(u.id) == actor.id:
        raise ApiError(403, "forbidden", "You cannot change your own roles.")
    await _guard_privileged_target(db, actor, u)
    before = await _roles_of(db, u.id)
    await accounts.set_roles(db, u.id, body.roles, uuid.UUID(actor.id))
    audit.record(db, request, "user.roles_changed", actor_id=actor.id, actor_label=actor.email, target_type="user",
                 target_id=u.id, severity="high", details={"before": before, "after": sorted(body.roles)})
    await db.commit()
    await accounts.invalidate_principal(request.app.state.redis, u.id)
    return await _out(db, u)
