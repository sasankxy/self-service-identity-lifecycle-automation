import time
from dataclasses import asdict

from fastapi import APIRouter, Depends, Request, Response
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import csrf
from app.core.cookies import ACCESS_COOKIE, REFRESH_COOKIE, clear_auth_cookies, set_cookie
from app.core.config import Settings
from app.core.deps import get_current_principal, get_db, get_limiter, get_sessions
from app.core.errors import ApiError
from app.core.rbac import DEFAULT_ROLE
from app.core.security import (
    TokenError, create_access_token, create_refresh_token, decode_token, hash_password,
    needs_rehash, verify_password,
)
from app.models.auth import User
from app.schemas.auth import LoginIn, MeOut, SignupIn
from app.services import accounts, audit
from app.services.accounts import Principal
from app.services.ratelimit import RateLimiter
from app.services.sessions import SessionStore
from sqlalchemy import func

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(csrf.csrf_protect)])
UNAVAILABLE = ApiError(503, "service_unavailable", "Service temporarily unavailable. Please try again shortly.")


def _set_csrf(resp: Response, s: Settings) -> str:
    token = csrf.issue_token(s)
    set_cookie(resp, s, csrf.CSRF_COOKIE, token, s.refresh_token_ttl_days * 86400, http_only=False)
    return token


def _set_access(resp: Response, s: Settings, user_id, sid: str) -> None:
    token, _ = create_access_token(s, user_id, sid)
    set_cookie(resp, s, ACCESS_COOKIE, token, s.access_token_ttl_minutes * 60)


def _set_refresh(resp: Response, s: Settings, user_id, sid: str, jti: str, exp: int) -> None:
    set_cookie(resp, s, REFRESH_COOKIE, create_refresh_token(s, user_id, sid, jti, exp),
                max(exp - int(time.time()), 1), path="/api/v1/auth")


# ------------------------------------------------------------------ endpoints
@router.get("/csrf")
async def get_csrf(request: Request, response: Response):
    return {"csrf_token": _set_csrf(response, request.app.state.settings)}


@router.post("/signup", status_code=201)
async def signup(body: SignupIn, request: Request, db: AsyncSession = Depends(get_db),
                 limiter: RateLimiter = Depends(get_limiter)):
    s: Settings = request.app.state.settings
    ip = audit.client_ip(request) or "unknown"
    try:
        ok, retry = await limiter.hit(f"signup:{ip}", s.signup_rate_limit_per_ip, s.signup_rate_limit_window_seconds)
    except RedisError:
        raise UNAVAILABLE
    if not ok:
        raise ApiError(429, "rate_limited", "Too many signup attempts. Try again later.", {"Retry-After": str(retry)})
    domain = body.email.rsplit("@", 1)[1]
    if s.email_domains and domain not in s.email_domains:
        raise ApiError(422, "validation_error", "Please correct the highlighted fields.",
                       fields={"email": "Use your corporate email address"})
    if await accounts.get_user_by_email(db, body.email):
        raise ApiError(409, "email_exists", "An account with this email already exists.")
    user = User(email=body.email, full_name=body.full_name, status="pending",
                password_hash=await hash_password(body.password))
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise ApiError(409, "email_exists", "An account with this email already exists.")
    await accounts.set_roles(db, user.id, [DEFAULT_ROLE], None)
    audit.record(db, request, "auth.signup", actor_id=user.id, actor_label=user.email,
                 target_type="user", target_id=user.id, details={"status": "pending"})
    await db.commit()
    return {"message": "Account created. An administrator must approve it before you can sign in."}


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db),
                limiter: RateLimiter = Depends(get_limiter), sessions: SessionStore = Depends(get_sessions)):
    s: Settings = request.app.state.settings
    ip = audit.client_ip(request) or "unknown"
    pair_key = f"login:{ip}:{body.email}"
    try:  # Redis is required for rate limiting and sessions: fail closed.
        ok1, retry1 = await limiter.hit(pair_key, s.login_rate_limit_per_email, s.login_rate_limit_window_seconds)
        ok2, retry2 = await limiter.hit(f"login:ip:{ip}", s.login_rate_limit_per_ip, s.login_rate_limit_window_seconds)
    except RedisError:
        raise UNAVAILABLE
    if not (ok1 and ok2):
        audit.record(db, request, "auth.login", actor_label=body.email, severity="medium", outcome="denied",
                     details={"reason": "rate_limited"})
        await db.commit()
        raise ApiError(429, "rate_limited", "Too many attempts. Please wait before trying again.",
                       {"Retry-After": str(max(retry1, retry2))})

    user = await accounts.get_user_by_email(db, body.email)   # PostgreSQL is authoritative
    valid = await verify_password(user.password_hash if user else None, body.password)
    if not valid:
        audit.record(db, request, "auth.login", actor_label=body.email, actor_id=user.id if user else None,
                     severity="low", outcome="failure", details={"reason": "bad_credentials"})
        await db.commit()
        raise ApiError(401, "invalid_credentials", "Invalid email or password.")

    # Credentials are correct: now it is safe to reveal account state.
    if user.status != "active":
        audit.record(db, request, "auth.login", actor_id=user.id, actor_label=user.email, severity="low",
                     outcome="denied", details={"reason": f"status_{user.status}"})
        await db.commit()
        if user.status == "pending":
            raise ApiError(403, "account_pending", "Your account is awaiting administrator approval.")
        raise ApiError(403, "account_disabled", "Your account is not active. Contact an administrator.")

    if needs_rehash(user.password_hash):
        user.password_hash = await hash_password(body.password)
    try:
        sid, jti, exp = await sessions.create(user.id, ip, request.headers.get("user-agent"))
        await accounts.invalidate_principal(request.app.state.redis, user.id)
        await limiter.reset(pair_key)
    except RedisError:
        raise UNAVAILABLE
    user.last_login_at = func.now()
    audit.record(db, request, "auth.login", actor_id=user.id, actor_label=user.email, target_type="user",
                 target_id=user.id, details={"session": sid[:6]})
    try:
        await db.commit()
    except Exception:
        await sessions.revoke(sid)
        raise
    principal = await accounts.load_principal(db, request.app.state.redis, s, user.id)
    _set_access(response, s, user.id, sid)
    _set_refresh(response, s, user.id, sid, jti, exp)
    csrf_token = _set_csrf(response, s)
    return {"user": asdict(principal), "csrf_token": csrf_token}


@router.post("/refresh")
async def refresh(request: Request, response: Response, db: AsyncSession = Depends(get_db),
                  sessions: SessionStore = Depends(get_sessions)):
    s: Settings = request.app.state.settings
    token = request.cookies.get(REFRESH_COOKIE)

    if not token:
        raise ApiError(401, "not_authenticated", "Authentication required.")
    try:
        claims = decode_token(s, token, "refresh")
    except TokenError as e:
        raise ApiError(401, e.code, "Session expired.", clear_cookies=True)
    try:
        user = await db.get(User, claims.sub)
        if not user or user.status != "active":
            await sessions.revoke(claims.sid)
            audit.record(db, request, "auth.refresh", actor_id=claims.sub, severity="medium", outcome="denied",
                         details={"reason": "account_inactive"})
            await db.commit()
            raise ApiError(401, "session_revoked", "Session is no longer valid.", clear_cookies=True)
        result, new_jti = await sessions.rotate(claims.sid, claims.jti)
    except RedisError:
        raise UNAVAILABLE
    if result.status == "reuse":
        audit.record(db, request, "auth.refresh_reuse_detected", actor_id=user.id, actor_label=user.email,
                     severity="high", outcome="denied", details={"session": claims.sid[:6]})
        await db.commit()
        raise ApiError(401, "session_revoked", "Session revoked for security reasons. Please sign in again.",
                       clear_cookies=True)
    if result.status == "missing":
        raise ApiError(401, "session_expired", "Session expired.", clear_cookies=True)
    _set_access(response, s, user.id, claims.sid)
    if result.status == "ok":
        _set_refresh(response, s, user.id, claims.sid, new_jti, result.expires_at)
    csrf_token = _set_csrf(response, s)
    return {"refreshed": True, "csrf_token": csrf_token}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db),
                 sessions: SessionStore = Depends(get_sessions)):
    s: Settings = request.app.state.settings
    sid, uid = None, None
    for name, typ in ((ACCESS_COOKIE, "access"), (REFRESH_COOKIE, "refresh")):
        tok = request.cookies.get(name)
        if tok:
            try:
                c = decode_token(s, tok, typ, verify_exp=False)  # signature still verified
                sid, uid = c.sid, c.sub
                break
            except TokenError:
                continue
    if sid:
        try:
            await sessions.revoke(sid)
        except RedisError:
            raise UNAVAILABLE
        audit.record(db, request, "auth.logout", actor_id=uid, target_type="user", target_id=uid)
        await db.commit()
    clear_auth_cookies(response, s)
    return {"logged_out": True}


@router.post("/logout-all")
async def logout_all(request: Request, response: Response, db: AsyncSession = Depends(get_db),
                     principal: Principal = Depends(get_current_principal),
                     sessions: SessionStore = Depends(get_sessions)):
    import uuid as _uuid
    n = await sessions.revoke_all(_uuid.UUID(principal.id))
    audit.record(db, request, "auth.logout_all", actor_id=principal.id, actor_label=principal.email,
                 target_type="user", target_id=principal.id, details={"sessions_revoked": n})
    await db.commit()
    clear_auth_cookies(response, request.app.state.settings)
    return {"logged_out": True, "sessions_revoked": n}


@router.get("/me", response_model=MeOut)
async def me(principal: Principal = Depends(get_current_principal)):
    return asdict(principal)
