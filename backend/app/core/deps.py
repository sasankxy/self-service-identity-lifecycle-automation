import uuid
from typing import AsyncIterator

from fastapi import Depends, Request
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.cookies import ACCESS_COOKIE
from app.core.errors import ApiError
from app.core.security import TokenError, decode_token
from app.services import accounts
from app.services.accounts import Principal
from app.services.ratelimit import RateLimiter
from app.services.sessions import SessionStore



def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session:
        yield session


def get_sessions(request: Request) -> SessionStore:
    return SessionStore(request.app.state.redis, request.app.state.settings)


def get_limiter(request: Request) -> RateLimiter:
    return RateLimiter(request.app.state.redis)


async def get_current_principal(
    request: Request, db: AsyncSession = Depends(get_db), sessions: SessionStore = Depends(get_sessions),
) -> Principal:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise ApiError(401, "not_authenticated", "Authentication required.")
    try:
        claims = decode_token(settings, token, "access")
    except TokenError as e:
        raise ApiError(401, e.code, "Session expired." if e.code == "token_expired" else "Invalid session.")
    try:
        if not await sessions.is_active(claims.sid, claims.sub):
            raise ApiError(401, "session_revoked", "Session is no longer valid.")
        principal = await accounts.load_principal(db, request.app.state.redis, settings, claims.sub)
    except RedisError:
        # Security-sensitive: never skip session validation when Redis is down.
        raise ApiError(503, "session_store_unavailable", "Authentication service temporarily unavailable.")
    if principal is None or principal.status != "active":
        raise ApiError(403, "account_inactive", "Your account is not active.")
    request.state.sid = claims.sid
    return principal


def require_permission(*codes: str):
    async def checker(principal: Principal = Depends(get_current_principal)) -> Principal:
        missing = [c for c in codes if not principal.can(c)]
        if missing:
            raise ApiError(403, "forbidden", "You do not have permission to perform this action.")
        return principal
    return checker
