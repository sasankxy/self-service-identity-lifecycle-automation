from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.governance import AuditLog

_FORBIDDEN = ("password", "token", "secret", "hash", "authorization", "cookie")


def client_ip(request: Request) -> str | None:
    if request.app.state.settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


_CATEGORY = {"auth": "login", "user": "access_change", "approval": "approval", "identity": "provisioning",
             "governance": "access_change", "audit": "system", "risk": "risk_alert"}


def record(
    db: AsyncSession, request: Request, action: str, *, actor_id=None, actor_label: str = "anonymous",
    target_type: str | None = None, target_id=None, severity: str = "info", outcome: str = "success",
    details: dict | None = None, target_label: str | None = None, category: str | None = None,
) -> None:
    """Stage an audit row; the caller commits (so it shares the transaction of the change)."""
    safe = {k: v for k, v in (details or {}).items() if not any(f in k.lower() for f in _FORBIDDEN)}
    ip = client_ip(request)
    db.add(AuditLog(
        actor_user_id=actor_id, actor_label=actor_label[:320], action=action, target_type=target_type,
        target_id=str(target_id) if target_id else None, severity=severity, outcome=outcome,
        target_label=(target_label or (details or {}).get("email") or None),
        category=category or _CATEGORY.get(action.split(".")[0], "system"),
        ip_address=ip if ip and ip.replace(".", "").replace(":", "").isalnum() else None,
        user_agent=(request.headers.get("user-agent") or "")[:300] or None, details=safe,
    ))
