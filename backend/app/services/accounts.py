"""User lookup, role assignment, and the Redis cache-aside for principal metadata."""
import json
import uuid
from dataclasses import asdict, dataclass

from redis.asyncio import Redis
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.rbac import PERMISSIONS, ROLES
from app.models.auth import Permission, Role, RolePermission, User, UserRole


@dataclass
class Principal:
    id: str
    email: str
    full_name: str
    status: str
    roles: list[str]
    permissions: list[str]

    def can(self, perm: str) -> bool:
        return perm in self.permissions


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    return (await db.execute(select(User).where(func.lower(User.email) == email.lower()))).scalar_one_or_none()


async def _role_names_and_perms(db: AsyncSession, user_id: uuid.UUID) -> tuple[list[str], list[str]]:
    roles = (await db.execute(
        select(Role.name).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )).scalars().all()
    perms = (await db.execute(
        select(Permission.code).distinct()
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id)
    )).scalars().all()
    return sorted(roles), sorted(perms)


async def load_principal(db: AsyncSession, redis: Redis, settings: Settings, user_id: uuid.UUID) -> Principal | None:
    """Cache-aside. Contains NO secrets: no hash, no tokens. Redis errors propagate (fail closed)."""
    key = f"principal:{user_id}"
    cached = await redis.get(key)
    if cached:
        return Principal(**json.loads(cached))
    user = await db.get(User, user_id)
    if not user:
        return None
    roles, perms = await _role_names_and_perms(db, user_id)
    p = Principal(str(user.id), user.email, user.full_name, user.status, roles, perms)
    await redis.set(key, json.dumps(asdict(p)), ex=settings.principal_cache_ttl_seconds)
    return p


async def invalidate_principal(redis: Redis, user_id: uuid.UUID) -> None:
    await redis.delete(f"principal:{user_id}")


async def set_roles(db: AsyncSession, user_id: uuid.UUID, role_names: list[str], assigned_by: uuid.UUID | None) -> None:
    roles = (await db.execute(select(Role).where(Role.name.in_(role_names)))).scalars().all()
    await db.execute(delete(UserRole).where(UserRole.user_id == user_id))
    for r in roles:
        db.add(UserRole(user_id=user_id, role_id=r.id, assigned_by=assigned_by))


async def ensure_reference_data(db: AsyncSession) -> None:
    """Idempotently create roles, permissions and their mapping."""
    perms = {p.code: p for p in (await db.execute(select(Permission))).scalars()}
    for code, desc in PERMISSIONS.items():
        if code not in perms:
            perms[code] = Permission(code=code, description=desc)
            db.add(perms[code])
    roles = {r.name: r for r in (await db.execute(select(Role))).scalars()}
    for name, spec in ROLES.items():
        if name not in roles:
            roles[name] = Role(name=name, display_name=spec["display_name"], description=spec["description"])
            db.add(roles[name])
    await db.flush()
    existing = set((await db.execute(select(RolePermission.role_id, RolePermission.permission_id))).all())
    for name, spec in ROLES.items():
        for code in spec["permissions"]:
            pair = (roles[name].id, perms[code].id)
            if pair not in existing:
                db.add(RolePermission(role_id=pair[0], permission_id=pair[1]))
    await db.commit()
