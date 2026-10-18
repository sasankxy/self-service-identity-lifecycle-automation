from redis.asyncio import Redis

_LUA = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {c, redis.call('TTL', KEYS[1])}
"""


class RateLimiter:
    """Fixed-window counter. Redis errors propagate so callers can fail closed."""

    def __init__(self, redis: Redis):
        self.r = redis
        self._script = redis.register_script(_LUA)

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        count, ttl = await self._script(keys=[f"rl:{key}"], args=[window])
        return int(count) <= limit, max(int(ttl), 1)

    async def reset(self, key: str) -> None:
        await self.r.delete(f"rl:{key}")
