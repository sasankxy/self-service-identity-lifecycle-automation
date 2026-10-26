"""Audit-log integrity: verify the database-maintained hash chain (alembic 0004).

GET /audit-logs/integrity  -> {ok, checked, head: {chain_seq, row_hash}, breaks: [...]}

`head.row_hash` commits to the whole log up to that row. Recording it somewhere outside this database (a ticket, an e-mail, a
second system) lets a later check also prove that no rows were removed from the END of the log, which a chain alone cannot show.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import csrf
from app.core.deps import get_db, require_permission
from app.services.accounts import Principal

router = APIRouter(prefix="/audit-logs", tags=["audit"], dependencies=[Depends(csrf.csrf_protect)])


async def verify(db: AsyncSession, from_seq: int = 0, limit: int = 20) -> dict:
    breaks = (await db.execute(text("SELECT chain_seq, id, problem FROM audit_chain_breaks(:f) LIMIT :n"), {"f": from_seq, "n": limit})).all()
    checked = (await db.execute(text("SELECT count(*) FROM audit_logs WHERE chain_seq >= :f"), {"f": from_seq})).scalar_one()
    head = (await db.execute(text("SELECT chain_seq, row_hash FROM audit_logs WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1"))).first()
    return {"ok": not breaks, "checked": checked, "head": {"chain_seq": head[0], "row_hash": head[1]} if head else None,
            "breaks": [{"chain_seq": s, "id": i, "problem": p} for s, i, p in breaks]}


@router.get("/integrity")
async def integrity(from_seq: int = Query(0, ge=0), db: AsyncSession = Depends(get_db),
                    _: Principal = Depends(require_permission("audit:read"))):
    return await verify(db, from_seq)
