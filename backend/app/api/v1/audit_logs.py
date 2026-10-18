from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.common import csv_response
from app.core import csrf
from app.core.deps import get_db, require_permission
from app.models import AuditLog
from app.services import audit, stats
from app.services.accounts import Principal

router = APIRouter(prefix="/audit-logs", tags=["audit"], dependencies=[Depends(csrf.csrf_protect)])
CATEGORIES = ("provisioning", "access_change", "login", "risk_alert", "approval", "system")


def _conditions(category, severity, q, since, until):
    c = []
    if category:
        c.append(AuditLog.category == category)
    if severity:
        c.append(AuditLog.severity == severity)
    if since:
        c.append(AuditLog.occurred_at >= since)
    if until:
        c.append(AuditLog.occurred_at <= until)
    if q:
        like = f"%{q.strip().lower()}%"
        c.append(or_(func.lower(AuditLog.action).like(like), func.lower(AuditLog.actor_label).like(like), func.lower(func.coalesce(AuditLog.target_label, "")).like(like)))
    return c


def _row(a: AuditLog) -> dict:
    return {"id": a.id, "occurred_at": a.occurred_at, "event": stats.humanize_action(a.action), "action": a.action, "category": a.category,
            "actor": a.actor_label, "target": a.target_label, "severity": a.severity, "outcome": a.outcome, "is_demo": a.is_demo}


@router.get("")
async def list_logs(category: Literal["provisioning", "access_change", "login", "risk_alert", "approval", "system"] | None = None,
                    severity: Literal["info", "low", "medium", "high", "critical"] | None = None, q: str | None = Query(None, max_length=100),
                    since: datetime | None = None, until: datetime | None = None, limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0),
                    db: AsyncSession = Depends(get_db), _: Principal = Depends(require_permission("audit:read"))):
    cond = _conditions(category, severity, q, since, until)
    total = (await db.execute(select(func.count()).select_from(AuditLog).where(*cond))).scalar_one()
    rows = (await db.execute(select(AuditLog).where(*cond).order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc()).limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [_row(a) for a in rows]}


@router.get("/export")
async def export(request: Request, category: str | None = None, severity: str | None = None, q: str | None = Query(None, max_length=100),
                 db: AsyncSession = Depends(get_db), actor: Principal = Depends(require_permission("audit:read"))):
    if category and category not in CATEGORIES or severity and severity not in ("info", "low", "medium", "high", "critical"):
        return csv_response("audit-log", ["error"], [["invalid filter"]])
    cond = _conditions(category, severity, q, None, None)
    rows = (await db.execute(select(AuditLog).where(*cond).order_by(AuditLog.occurred_at.desc()).limit(10000))).scalars().all()
    audit.record(db, request, "audit.export", actor_id=actor.id, actor_label=actor.email, category="system", details={"rows": len(rows)})
    await db.commit()
    return csv_response("audit-log", ["Timestamp", "Event", "Category", "Actor", "Target", "Severity", "Outcome"],
                        [[a.occurred_at, stats.humanize_action(a.action), a.category, a.actor_label, a.target_label, a.severity, a.outcome] for a in rows])
