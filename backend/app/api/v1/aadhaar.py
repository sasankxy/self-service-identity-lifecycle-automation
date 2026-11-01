"""Aadhaar verification of joiners.

An admin creates a one-time link; the joiner opens it (no login), gives consent and uploads the card, so HR never handles the card.
The image is processed in memory and discarded (app/services/aadhaar.py). Only the outcome, masked number and a keyed hash are stored.
The token travels in a header so it does not appear in access logs, and only its hash is stored.
"""
import hashlib
import hmac
import secrets
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Header, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core import csrf
from app.core.deps import get_db, require_permission
from app.core.errors import ApiError
from app.models import Identity, IdentityVerification
from app.services import aadhaar, audit
from app.services.accounts import Principal
from app.services.ratelimit import RateLimiter

router = APIRouter(prefix="/identities", tags=["aadhaar"], dependencies=[Depends(csrf.csrf_protect)])
public = APIRouter(prefix="/public/aadhaar", tags=["aadhaar"])
LINK_TTL = timedelta(days=7)
MAX_ATTEMPTS = 5


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def summary(v: IdentityVerification | None) -> dict:
    if v is None:
        return {"status": "not_started"}
    return {"status": v.status, "masked_number": v.masked_number, "checks": v.checks, "attempts": v.attempts,
            "completed_at": v.completed_at, "link_expires_at": v.token_expires_at if v.token_hash else None}


class LinkIn(BaseModel):
    date_of_birth: date
    gender: Literal["M", "F", "T"] | None = None


@router.post("/{identity_id}/aadhaar/link", status_code=201)
async def create_link(identity_id: uuid.UUID, body: LinkIn, request: Request, db: AsyncSession = Depends(get_db),
                      actor: Principal = Depends(require_permission("identities:write"))):
    ident = await db.get(Identity, identity_id)
    if not ident:
        raise ApiError(404, "not_found", "Identity not found.")
    v = (await db.execute(select(IdentityVerification).where(IdentityVerification.identity_id == identity_id))).scalar_one_or_none()
    if v and v.status == "verified":
        raise ApiError(409, "already_verified", "This identity is already verified.")
    if v is None:
        v = IdentityVerification(identity_id=identity_id)
        db.add(v)
    token = secrets.token_urlsafe(32)
    v.status, v.attempts, v.checks, v.masked_number, v.number_hash, v.completed_at = "pending", 0, {}, None, None, None
    v.expected_dob, v.expected_gender, v.token_hash = body.date_of_birth, body.gender, _token_hash(token)
    v.token_expires_at = datetime.now(timezone.utc) + LINK_TTL
    audit.record(db, request, "identity.aadhaar_link_created", actor_id=actor.id, actor_label=actor.email, target_type="identity",
                 target_id=ident.id, target_label=ident.email, category="provisioning")
    await db.commit()
    return {"url": f"/verify.html#{token}", "expires_at": v.token_expires_at}


@router.get("/{identity_id}/aadhaar")
async def status(identity_id: uuid.UUID, db: AsyncSession = Depends(get_db), _: Principal = Depends(require_permission("identities:read"))):
    return summary((await db.execute(select(IdentityVerification).where(IdentityVerification.identity_id == identity_id))).scalar_one_or_none())


async def _by_token(db: AsyncSession, token: str | None) -> IdentityVerification:
    v = (await db.execute(select(IdentityVerification).where(IdentityVerification.token_hash == _token_hash(token or "")))).scalar_one_or_none()
    if not v or not v.token_expires_at or v.token_expires_at < datetime.now(timezone.utc):
        raise ApiError(404, "invalid_link", "This verification link is invalid or has expired. Ask your HR contact for a new one.")
    return v


@public.get("")
async def link_info(request: Request, x_verification_token: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    await _limit(request)
    v = await _by_token(db, x_verification_token)
    ident = await db.get(Identity, v.identity_id)
    return {"first_name": ident.full_name.split()[0], "status": v.status, "attempts_left": MAX_ATTEMPTS - v.attempts}


async def _limit(request: Request) -> None:
    ok, retry = await RateLimiter(request.app.state.redis).hit(f"aadhaar:{audit.client_ip(request) or 'unknown'}", 30, 3600)
    if not ok:
        raise ApiError(429, "rate_limited", "Too many attempts. Try again later.", headers={"Retry-After": str(retry)})


@public.post("")
async def upload(request: Request, file: UploadFile = File(...), consent: bool = Form(False), x_verification_token: str | None = Header(None),
                 db: AsyncSession = Depends(get_db)):
    await _limit(request)
    v = await _by_token(db, x_verification_token)
    if not consent:
        raise ApiError(422, "consent_required", "Please give consent before uploading your Aadhaar card.")
    if v.attempts >= MAX_ATTEMPTS:
        raise ApiError(429, "too_many_attempts", "Too many attempts on this link. Ask your HR contact for a new one.")
    image = await file.read(aadhaar.MAX_IMAGE_BYTES + 1)
    if len(image) > aadhaar.MAX_IMAGE_BYTES:
        raise ApiError(413, "too_large", "The image must be smaller than 5 MB.")
    ident = await db.get(Identity, v.identity_id)
    s = request.app.state.settings
    key = hmac.new(s.csrf_secret.encode(), b"identityos-aadhaar-v1", hashlib.sha256).digest()
    try:
        out = await run_in_threadpool(aadhaar.verify_image, image, expected_name=ident.full_name, expected_dob=v.expected_dob,
                                      expected_gender=v.expected_gender, hash_key=key, cert_path=s.aadhaar_uidai_cert_path)
    except ValueError:
        raise ApiError(422, "bad_image", "That file is not a readable image. Upload a clear JPG or PNG of your card.")
    finally:
        del image
    checks, final = out.checks, out.status
    if out.number_hash:
        other = (await db.execute(select(IdentityVerification.id).where(IdentityVerification.number_hash == out.number_hash,
                                                                        IdentityVerification.identity_id != v.identity_id))).first()
        if other:
            checks["duplicate"] = {"result": "fail", "detail": "This Aadhaar number is already linked to another identity."}
            final = "failed"
    v.attempts += 1
    v.status, v.checks, v.masked_number, v.number_hash, v.consent_at = final, checks, out.masked, out.number_hash, datetime.now(timezone.utc)
    v.completed_at = datetime.now(timezone.utc)
    if final != "failed":
        v.token_hash = None                      # one-time: verified or queued for human review
    audit.record(db, request, "identity.aadhaar_checked", actor_label=f"joiner:{ident.email}"[:320], target_type="identity", target_id=ident.id,
                 target_label=ident.email, category="provisioning", severity="medium" if final == "failed" else "info",
                 outcome="success" if final == "verified" else "flagged",
                 details={"status": final, "checks": {k: c["result"] for k, c in checks.items()}})
    await db.commit()
    # failed results tell the joiner only that it failed: per-check detail would help someone tune a forged card
    return {"status": final, "attempts_left": MAX_ATTEMPTS - v.attempts}
