"""One governance pass from cron / CI (same code the in-app scheduler runs): apply due requests, then detect
orphaned accounts and privilege creep and update the findings.

    python -m scripts.run_scan
"""
import asyncio

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.services.governance_scan import run_scan


async def main() -> None:
    s = get_settings()
    engine = create_async_engine(s.database_url)
    redis = Redis.from_url(s.redis_url, decode_responses=True)
    try:
        out = await run_scan(async_sessionmaker(engine, expire_on_commit=False), redis, trigger="cli")
        print("another scan is already running" if out is None else
              f"scanned {out['identities_scanned']} identities: {out['opened']} opened, {out['resolved']} resolved, "
              f"{out['open_total']} open; {out['applied_due']} scheduled request(s) applied")
    finally:
        await redis.aclose()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
