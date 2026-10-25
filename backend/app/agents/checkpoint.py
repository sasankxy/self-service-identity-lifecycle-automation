"""Checkpointer for the conversation graph: Postgres in dev/prod (conversations and pending confirmations survive restarts),
in-memory for tests or when explicitly configured. A Postgres failure at startup degrades to memory instead of taking the API down.
"""
from __future__ import annotations

import logging

from langgraph.checkpoint.memory import InMemorySaver

log = logging.getLogger("identityos.agent.checkpoint")


def psycopg_url(database_url: str) -> str:
    """SQLAlchemy URL (postgresql+asyncpg://...) -> libpq URL for psycopg. asyncpg's `ssl=` query flag becomes `sslmode=`."""
    url = database_url.replace("postgresql+asyncpg://", "postgresql://", 1).replace("postgresql+psycopg://", "postgresql://", 1)
    return url.replace("ssl=require", "sslmode=require")


async def open_checkpointer(settings):
    """Returns (checkpointer, closer). `closer` is an async callable to run at shutdown (or None)."""
    if settings.env == "test" or settings.agent_checkpointer == "memory":
        return InMemorySaver(), None
    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        from psycopg.rows import dict_row
        from psycopg_pool import AsyncConnectionPool
        pool = AsyncConnectionPool(psycopg_url(settings.database_url), min_size=1, max_size=5, open=False,
                                   kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row})
        await pool.open(wait=True, timeout=10)
        saver = AsyncPostgresSaver(pool)
        await saver.setup()               # idempotent: creates the checkpoint tables on first run
        log.info("agent checkpointer: postgres")
        return saver, pool.close
    except Exception:  # noqa: BLE001
        log.exception("Postgres checkpointer unavailable; agent conversations will be kept in memory only")
        return InMemorySaver(), None
