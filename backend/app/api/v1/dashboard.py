from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db, require_permission
from app.services import stats
from app.services.cache import cached

router = APIRouter(prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(require_permission("dashboard:read"))])


@router.get("/summary")
async def summary(request: Request, db: AsyncSession = Depends(get_db)):
    return await cached(request, "dashboard", "summary", 30, lambda: stats.dashboard_summary(db))


@router.get("/trends")
async def trends(request: Request, db: AsyncSession = Depends(get_db)):
    return await cached(request, "dashboard", "trends", 60, lambda: stats.dashboard_trends(db))


@router.get("/activity")
async def activity(request: Request, db: AsyncSession = Depends(get_db)):
    return {"items": await cached(request, "dashboard", "activity", 15, lambda: stats.dashboard_activity(db))}
