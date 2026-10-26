"""Per-user inbox of lifecycle-request outcomes ("REQ-5004 was approved"), delivered to the requester's chat.

Written after the deciding transaction commits (approvals API) and read by GET /agent/events. Redis list per user, newest first,
capped at 50 entries and 7 days. Best effort: a Redis failure never affects the decision itself.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from redis.exceptions import RedisError

log = logging.getLogger("identityos.request_events")
MAX_EVENTS, TTL_SECONDS = 50, 7 * 24 * 3600


def _key(user_id) -> str:
    return f"agent:events:{user_id}"


async def publish(redis, user_id, event: dict) -> None:
    if not user_id or redis is None:
        return
    try:
        payload = json.dumps({**event, "at": datetime.now(timezone.utc).isoformat()}, default=str)
        async with redis.pipeline(transaction=True) as p:
            p.lpush(_key(user_id), payload)
            p.ltrim(_key(user_id), 0, MAX_EVENTS - 1)
            p.expire(_key(user_id), TTL_SECONDS)
            await p.execute()
    except RedisError:
        log.warning("could not publish request event for %s", user_id)


async def drain(redis, user_id) -> list[dict]:
    """All undelivered events for the user, oldest first; they are removed as they are read."""
    try:
        async with redis.pipeline(transaction=True) as p:
            p.lrange(_key(user_id), 0, -1)
            p.delete(_key(user_id))
            raw, _ = await p.execute()
    except RedisError:
        return []
    out = []
    for item in reversed(raw or []):
        try:
            out.append(json.loads(item))
        except ValueError:
            continue
    return out
