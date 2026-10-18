"""Cache-aside for non-sensitive aggregates, with explicit TTLs and version-bump invalidation.

Key: cache:{ns}:{version}:{key}. Invalidation = INCR cachever:{ns}, which orphans every key of that namespace
at once (they expire by TTL). Reads degrade to the database if Redis is down; session checks never do (see deps).
"""
import json
import logging
from typing import Awaitable, Callable

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from redis.exceptions import RedisError

log = logging.getLogger("identityos.cache")
ALL_NAMESPACES = ("dashboard", "identities", "approvals", "risk", "governance", "audit", "meta")


async def cached(request: Request, ns: str, key: str, ttl: int, loader: Callable[[], Awaitable]):
    redis = request.app.state.redis
    try:
        ver = await redis.get(f"cachever:{ns}") or "0"
        ck = f"cache:{ns}:{ver}:{key}"
        hit = await redis.get(ck)
        if hit is not None:
            return json.loads(hit)
    except RedisError:
        log.warning("cache read failed for %s; serving from database", ns)
        return jsonable_encoder(await loader())
    data = jsonable_encoder(await loader())
    try:
        await redis.set(ck, json.dumps(data), ex=ttl)
    except RedisError:
        log.warning("cache write failed for %s", ns)
    return data


async def invalidate(request: Request, *namespaces: str) -> None:
    redis = request.app.state.redis
    try:
        async with redis.pipeline(transaction=False) as p:
            for ns in namespaces or ALL_NAMESPACES:
                p.incr(f"cachever:{ns}")
            await p.execute()
    except RedisError:
        log.warning("cache invalidation failed; stale data possible until TTL expiry")
