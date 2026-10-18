"""Signed double-submit CSRF tokens + Origin checking for cookie-authenticated requests."""
import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import Request

from app.core.config import Settings
from app.core.errors import ApiError

CSRF_COOKIE = "identityos_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _sig(settings: Settings, nonce: str) -> str:
    return hmac.new(settings.csrf_secret.encode(), nonce.encode(), hashlib.sha256).hexdigest()


def issue_token(settings: Settings) -> str:
    nonce = secrets.token_urlsafe(24)
    return f"{nonce}.{_sig(settings, nonce)}"


def _valid(settings: Settings, token: str) -> bool:
    nonce, _, sig = token.partition(".")
    return bool(nonce and sig) and hmac.compare_digest(sig, _sig(settings, nonce))


def _origin_ok(request: Request, settings: Settings) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        ref = request.headers.get("referer")
        if not ref:
            return True  # non-browser client; the token check below still applies
        parts = urlsplit(ref)
        origin = f"{parts.scheme}://{parts.netloc}"
    own = f"{request.url.scheme}://{request.headers.get('host', '')}"
    return origin == own or origin in settings.cors_origins


async def csrf_protect(request: Request) -> None:
    if request.method in SAFE_METHODS:
        return
    settings: Settings = request.app.state.settings
    if not _origin_ok(request, settings):
        raise ApiError(403, "csrf_origin", "Cross-origin request blocked.")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get(CSRF_HEADER, "")
    if not cookie or not header or not hmac.compare_digest(cookie, header) or not _valid(settings, header):
        raise ApiError(403, "csrf_failed", "Missing or invalid CSRF token.")
