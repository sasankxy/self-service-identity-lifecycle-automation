import csv
import io
from datetime import datetime, timezone

from fastapi import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entitlement, LifecycleRequestEntitlement


def csv_response(filename: str, header: list[str], rows: list[list]) -> Response:
    """CSV with formula-injection protection (cells starting with = + - @ are neutralised)."""
    def safe(v):
        s = "" if v is None else (v.isoformat() if isinstance(v, datetime) else str(v))
        return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow([safe(c) for c in r])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}-{stamp}.csv"', "Cache-Control": "no-store"})


async def request_deltas(db: AsyncSession, request_ids: list) -> dict:
    """request_id -> {'added': [names], 'removed': [names]}"""
    out = {rid: {"added": [], "removed": []} for rid in request_ids}
    if not request_ids:
        return out
    rows = (await db.execute(
        select(LifecycleRequestEntitlement.request_id, LifecycleRequestEntitlement.action, Entitlement.name)
        .join(Entitlement, Entitlement.id == LifecycleRequestEntitlement.entitlement_id)
        .where(LifecycleRequestEntitlement.request_id.in_(request_ids)).order_by(Entitlement.name))).all()
    for rid, action, name in rows:
        out[rid]["added" if action == "add" else "removed"].append(name)
    return out
