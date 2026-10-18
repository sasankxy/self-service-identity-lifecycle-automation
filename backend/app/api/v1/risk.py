from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.common import csv_response
from app.core import csrf
from app.core.deps import get_db, require_permission
from app.services import audit, stats
from app.services.accounts import Principal
from app.services.cache import cached

router = APIRouter(prefix="/risk", tags=["risk"], dependencies=[Depends(csrf.csrf_protect)])


@router.get("/summary")
async def summary(request: Request, db: AsyncSession = Depends(get_db), _: Principal = Depends(require_permission("risk:read"))):
    return await cached(request, "risk", "summary", 60, lambda: stats.risk_summary(db))


@router.get("/flagged")
async def flagged(limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0), db: AsyncSession = Depends(get_db),
                  _: Principal = Depends(require_permission("risk:read"))):
    total, items = await stats.flagged_identities(db, limit, offset)
    return {"total": total, "items": items}


@router.get("/flagged/export")
async def export(request: Request, db: AsyncSession = Depends(get_db), actor: Principal = Depends(require_permission("risk:read"))):
    total, items = await stats.flagged_identities(db, 5000, 0)
    audit.record(db, request, "risk.export", actor_id=actor.id, actor_label=actor.email, category="risk_alert", details={"rows": total})
    await db.commit()
    return csv_response("flagged-identities", ["Name", "Email", "Department", "Risk score", "Level", "Triggers", "Last review"],
                        [[i["name"], i["email"], i["department"], i["risk_score"], i["risk_level"], "; ".join(i["triggers"]), i["last_review"]] for i in items])
