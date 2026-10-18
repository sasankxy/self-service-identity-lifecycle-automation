"""Apply policy-approved requests whose effective date has arrived.  Run daily/hourly from cron:
    python -m scripts.apply_due
"""
import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.services.lifecycle import apply_due_requests


async def main() -> None:
    engine = create_async_engine(get_settings().database_url)
    async with async_sessionmaker(engine, expire_on_commit=False)() as db:
        print(f"applied {await apply_due_requests(db)} scheduled request(s)")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
