"""Background governance scheduler: every N minutes apply due requests, then scan for orphaned accounts and privilege creep.

Runs inside the API process (started from the app lifespan). Safe with several workers: a Redis lock (governance_scan.run_scan)
allows one scan at a time, and a worker skips its turn if a scan finished recently. Disable with GOVERNANCE_SCAN_INTERVAL_MINUTES=0;
it never runs when ENV=test. For cron-style deployments use `python -m scripts.run_scan` instead.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models import GovernanceScanRun
from app.services import governance_scan

log = logging.getLogger("identityos.governance")


async def _recent_run(app, within_s: float) -> bool:
    async with app.state.sessionmaker() as db:
        last = (await db.execute(select(GovernanceScanRun.finished_at).order_by(GovernanceScanRun.finished_at.desc()).limit(1))).scalar_one_or_none()
    return bool(last and last > datetime.now(timezone.utc) - timedelta(seconds=within_s))


async def scan_loop(app, interval_s: float, initial_delay_s: float = 0) -> None:
    await asyncio.sleep(initial_delay_s)
    while True:
        try:
            if await _recent_run(app, interval_s * 0.8):
                log.debug("governance scan skipped: another worker ran one recently")
            else:
                out = await governance_scan.run_scan(app.state.sessionmaker, app.state.redis, trigger="scheduled")
                if out:
                    log.info("governance scan: %s opened, %s resolved, %s open, %s scheduled request(s) applied",
                             out["opened"], out["resolved"], out["open_total"], out["applied_due"])
                if out and app.state.settings.agent_auto_remediate:      # opt-in: the governance agent proposes fixes for approval
                    from app.agents import governance, llm as agent_llm
                    agent_llm.start_turn(app.state.settings.agent_llm_max_calls * 10, 250.0)
                    await governance.remediate(app.state.sessionmaker, app.state.redis, app.state.settings,
                                               getattr(app.state, "agent_llm", None), limit=10)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("scheduled governance scan failed; will retry next interval")
        await asyncio.sleep(interval_s)


def start(app, settings) -> asyncio.Task | None:
    if settings.env == "test" or settings.governance_scan_interval_minutes <= 0:
        return None
    return asyncio.create_task(scan_loop(app, settings.governance_scan_interval_minutes * 60, settings.governance_scan_initial_delay_seconds),
                               name="governance-scan-loop")
