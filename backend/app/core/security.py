"""Password hashing (Argon2id), password policy, and JWT helpers."""
import asyncio
import re
import secrets
import time
import uuid
from dataclasses import dataclass

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings

# argon2-cffi's PasswordHasher defaults to Argon2id (RFC 9106 low-memory profile).
_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))  # for constant-ish timing on unknown users


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(_ph.hash, password)


async def verify_password(stored_hash: str | None, password: str) -> bool:
    """Always performs one Argon2 verification, even for unknown users."""
    target = stored_hash or _DUMMY_HASH
    try:
        ok = await asyncio.to_thread(_ph.verify, target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return ok and stored_hash is not None


def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)


# ---------------------------------------------------------------- password policy
_COMMON = {
    "password1234", "password12345", "123456789012", "qwertyuiop12", "letmein12345",
    "administrator1", "welcome12345", "changeme1234", "iloveyou1234",
}


def password_problems(password: str, email: str = "", full_name: str = "", min_length: int = 12) -> list[str]:
    problems = []
    if len(password) < min_length:
        problems.append(f"at least {min_length} characters")
    if len(password) > 128:
        problems.append("at most 128 characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a symbol")
    low = password.lower()
    local = email.split("@")[0].lower() if email else ""
    if (len(local) >= 4 and local in low) or low in _COMMON:
        problems.append("must not be common or contain your email name")
    return problems


# ---------------------------------------------------------------- JWT
class TokenError(Exception):
    def __init__(self, code: str):
        self.code = code


@dataclass
class TokenClaims:
    sub: uuid.UUID
    sid: str
    jti: str
    type: str
    exp: int


def _encode(settings: Settings, claims: dict) -> str:
    return jwt.encode(claims, settings.signing_key(), algorithm=settings.jwt_algorithm)


def create_access_token(settings: Settings, user_id: uuid.UUID, sid: str) -> tuple[str, int]:
    now = int(time.time())
    exp = now + settings.access_token_ttl_minutes * 60
    token = _encode(settings, {
        "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "sub": str(user_id),
        "sid": sid, "jti": uuid.uuid4().hex, "type": "access",
        "iat": now, "nbf": now, "exp": exp,
    })
    return token, exp


def create_refresh_token(settings: Settings, user_id: uuid.UUID, sid: str, jti: str, exp: int) -> str:
    now = int(time.time())
    return _encode(settings, {
        "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "sub": str(user_id),
        "sid": sid, "jti": jti, "type": "refresh", "iat": now, "nbf": now, "exp": exp,
    })


def decode_token(settings: Settings, token: str, expected_type: str, verify_exp: bool = True) -> TokenClaims:
    try:
        data = jwt.decode(
            token,
            settings.verification_key(),
            algorithms=[settings.jwt_algorithm],         # pinned: no alg confusion, no "none"
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "nbf", "sub", "sid", "jti", "type"], "verify_exp": verify_exp},
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("token_expired")
    except jwt.PyJWTError:
        raise TokenError("token_invalid")
    if data.get("type") != expected_type:
        raise TokenError("token_invalid")
    try:
        sub = uuid.UUID(data["sub"])
    except ValueError:
        raise TokenError("token_invalid")
    return TokenClaims(sub=sub, sid=data["sid"], jti=data["jti"], type=data["type"], exp=int(data["exp"]))
