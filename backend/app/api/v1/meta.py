from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db, require_permission
from app.models import AccessProfile, Department
from app.services.cache import cached

router = APIRouter(prefix="/meta", tags=["meta"], dependencies=[Depends(require_permission("identities:read"))])


@router.get("/lookups")
async def lookups(request: Request, db: AsyncSession = Depends(get_db)):
    async def load():
        d = (await db.execute(select(Department.id, Department.name).order_by(Department.name))).all()
        p = (await db.execute(select(AccessProfile.id, AccessProfile.name, AccessProfile.department_id).order_by(AccessProfile.name))).all()
        return {"departments": [{"id": i, "name": n} for i, n in d],
                "access_profiles": [{"id": i, "name": n, "department_id": dep} for i, n, dep in p]}
    return await cached(request, "meta", "lookups", 300, load)
