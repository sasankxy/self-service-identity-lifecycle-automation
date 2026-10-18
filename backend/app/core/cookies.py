"""Auth cookie helpers (HttpOnly access/refresh, readable CSRF cookie)."""
from fastapi import Response

from app.core.config import Settings

ACCESS_COOKIE = "identityos_at"
REFRESH_COOKIE = "identityos_rt"  # path-scoped to /api/v1/auth


def set_cookie(resp: Response, s: Settings, name: str, value: str, max_age: int, path: str = "/", http_only: bool = True):
    resp.set_cookie(name, value, max_age=max_age, path=path, httponly=http_only, secure=s.cookie_secure,
                    samesite=s.cookie_samesite, domain=s.cookie_domain)


def clear_auth_cookies(resp: Response, s: Settings) -> None:
    for name, path in ((ACCESS_COOKIE, "/"), (REFRESH_COOKIE, "/api/v1/auth")):
        resp.delete_cookie(name, path=path, domain=s.cookie_domain, secure=s.cookie_secure,
                           httponly=True, samesite=s.cookie_samesite)
