"""Turns detections into governance findings, runs full scans, and re-checks a person after a move.

* sync_findings  open / refresh / auto-resolve findings so that they mirror what is detected *now* (idempotent).
* run_scan       the scheduled / manual / CLI scan: apply due requests, detect, sync, record the run. One scan at a time (Redis lock).
* recheck_identity  the mover-event trigger: after a department move is applied, re-run detection for that person only.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import GovernanceFinding, GovernanceScanRun, Identity
from app.services import audit, detection

log = logging.getLogger("identityos.governance")
LOCK_KEY = "governance:scan:lock"
LOCK_TTL_SECONDS = 600
ALERT_FROM = ("high", "critical")          # findings at or above this severity get their own risk_alert audit event


async def sync_findings(db: AsyncSession, detections: list[detection.Detection], *, scope_ids: set[uuid.UUID] | None, source: str,
                        request=None, now: datetime | None = None) -> tuple[list[GovernanceFinding], int]:
    """Make stored findings match `detections` (within `scope_ids`, or everything when None). Returns (newly opened or re-opened, auto-resolved count)."""
    now = now or datetime.now(timezone.utc)
    q = select(GovernanceFinding)
    if scope_ids is not None:
        q = q.where(GovernanceFinding.identity_id.in_(scope_ids))
    existing = {(f.rule, f.identity_id, f.subject_key): f for f in (await db.execute(q)).scalars()}
    current = {d.key: d for d in detections}
    opened: list[GovernanceFinding] = []
    for key, d in current.items():
        f = existing.get(key)
        if f is None:
            f = GovernanceFinding(kind=d.kind, rule=d.rule, identity_id=d.identity_id, subject_key=d.subject_key, severity=d.severity, status="open",
                                  title=d.title, details=d.details, source=source, first_detected_at=now, last_detected_at=now)
            db.add(f)
            opened.append(f)
        elif f.status == "resolved":                     # it came back
            f.status, f.resolved_at, f.severity, f.title, f.details, f.last_detected_at, f.source = "open", None, d.severity, d.title, d.details, now, source
            opened.append(f)
        else:                                            # still open (refresh) or still dismissed (stay dismissed)
            f.last_detected_at = now
            if f.status == "open":
                f.severity, f.title, f.details = d.severity, d.title, d.details
    resolved = 0
    for key, f in existing.items():
        if f.status == "open" and key not in current:
            f.status, f.resolved_at = "resolved", now
            resolved += 1
    await db.flush()
    for f in opened:
        if f.severity in ALERT_FROM:
            audit.record(db, request, "governance.finding_opened", actor_label="system", target_type="identity", target_id=f.identity_id,
                         target_label=f.title[:300], severity=f.severity, category="risk_alert", outcome="flagged",
                         details={"kind": f.kind, "rule": f.rule, "source": source})
    return opened, resolved


async def _open_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(GovernanceFinding).where(GovernanceFinding.status == "open"))).scalar_one()


async def run_scan(sessionmaker: async_sessionmaker, redis, *, trigger: str, request=None, actor=None) -> dict | None:
    """One full governance pass. Returns the run summary, or None when another scan holds the lock.
    Order matters: scheduled requests are applied first so the detection sees the state the directory is really in."""
    from app.services import lifecycle           # lazy: lifecycle imports this module for the mover trigger
    token = uuid.uuid4().hex
    try:
        got = await redis.set(LOCK_KEY, token, nx=True, ex=LOCK_TTL_SECONDS)
    except RedisError:
        got = True                               # Redis down: fail open, a duplicate scan is harmless (idempotent)
    if not got:
        return None
    started = datetime.now(timezone.utc)
    label = actor.email if actor else "system"
    try:
        async with sessionmaker() as db:
            applied = await lifecycle.apply_due_requests(db)
            detections, scanned = await detection.detect(db, now=started)
            opened, resolved = await sync_findings(db, detections, scope_ids=None, source="scheduled" if trigger == "scheduled" else "scan", request=request, now=started)
            open_total = await _open_count(db)
            finished = datetime.now(timezone.utc)
            run = GovernanceScanRun(started_at=started, finished_at=finished, trigger=trigger, status="ok", identities_scanned=scanned,
                                    opened=len(opened), resolved=resolved, open_total=open_total, applied_due=applied)
            db.add(run)
            audit.record(db, request, "governance.scan", actor_id=actor.id if actor else None, actor_label=label, category="risk_alert" if opened else "system",
                         severity="medium" if any(f.severity in ALERT_FROM for f in opened) else "info",
                         details={"trigger": trigger, "identities_scanned": scanned, "opened": len(opened), "resolved": resolved,
                                  "open_total": open_total, "applied_due_requests": applied})
            await db.commit()
            await db.refresh(run)
            return summarize(run)
    except Exception as e:
        log.exception("governance scan failed")
        try:
            async with sessionmaker() as db:
                db.add(GovernanceScanRun(started_at=started, finished_at=datetime.now(timezone.utc), trigger=trigger, status="failed", error=str(e)[:500]))
                await db.commit()
        except Exception:                        # pragma: no cover - never mask the original error
            log.exception("could not record the failed scan")
        raise
    finally:
        try:
            if await redis.get(LOCK_KEY) == token:
                await redis.delete(LOCK_KEY)
        except RedisError:                       # pragma: no cover
            pass


def summarize(run: GovernanceScanRun) -> dict:
    return {"id": run.id, "trigger": run.trigger, "status": run.status, "started_at": run.started_at, "finished_at": run.finished_at,
            "identities_scanned": run.identities_scanned, "opened": run.opened, "resolved": run.resolved, "open_total": run.open_total,
            "applied_due": run.applied_due, "error": run.error}


async def latest_run(db: AsyncSession) -> dict | None:
    run = (await db.execute(select(GovernanceScanRun).order_by(GovernanceScanRun.started_at.desc()).limit(1))).scalar_one_or_none()
    return summarize(run) if run else None


async def recheck_identity(db: AsyncSession, ident: Identity, *, reason: str) -> int:
    """Mover-event trigger: re-run detection for one person right after a change was applied, inside the caller's transaction.
    Runs in a SAVEPOINT and never raises: a failure here must not roll back (or block) the approval that triggered it."""
    try:
        async with db.begin_nested():
            await db.flush()                     # make the new department / entitlement statuses visible to the detection queries
            detections, _ = await detection.detect(db, identity_ids={ident.id})
            opened, resolved = await sync_findings(db, detections, scope_ids={ident.id}, source="mover_trigger")
            audit.record(db, None, "governance.mover_recheck", actor_label="system", target_type="identity", target_id=ident.id,
                         target_label=ident.email, category="risk_alert" if opened else "system", severity="medium" if opened else "info",
                         details={"reason": reason, "opened": len(opened), "resolved": resolved, "findings": [f.title for f in opened][:5]})
        return len(opened)
    except Exception:
        log.exception("mover re-check failed for %s", ident.id)
        return 0
