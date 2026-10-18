"""Refresh-session store in Redis: rotation, reuse detection, revocation.

session:{sid}      hash  user_id, refresh_jti, prev_jti, rotated_at, created_at, expires_at, ip, ua
user_sessions:{u}  set   session ids for the user (for revoke-all)
A session key's existence IS the validity of both the access and refresh token.
"""
import secrets
import time
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis

from app.core.config import Settings

GRACE_SECONDS = 10  # tolerate parallel refreshes from the same browser

_ROTATE_LUA = """
local cur = redis.call('HMGET', KEYS[1], 'refresh_jti', 'created_at', 'prev_jti', 'rotated_at', 'expires_at')
if not cur[1] then return {0, 0} end
local now = tonumber(ARGV[3])
if cur[1] ~= ARGV[1] then
  if cur[3] and cur[3] == ARGV[1] and cur[4] and (now - tonumber(cur[4])) <= tonumber(ARGV[6]) then
    return {2, tonumber(cur[5])}
  end
  redis.call('DEL', KEYS[1]); return {-1, 0}
end
local abs_exp = tonumber(cur[2]) + tonumber(ARGV[5])
local new_exp = math.min(now + tonumber(ARGV[4]), abs_exp)
if new_exp <= now then redis.call('DEL', KEYS[1]); return {0, 0} end
redis.call('HSET', KEYS[1], 'prev_jti', ARGV[1], 'refresh_jti', ARGV[2], 'rotated_at', ARGV[3], 'expires_at', new_exp)
redis.call('EXPIREAT', KEYS[1], new_exp)
return {1, new_exp}
"""


@dataclass
class RotateResult:
    status: str          # ok | grace | reuse | missing
    expires_at: int = 0


class SessionStore:
    def __init__(self, redis: Redis, settings: Settings):
        self.r, self.s = redis, settings
        self._rotate = redis.register_script(_ROTATE_LUA)

    async def create(self, user_id: uuid.UUID, ip: str | None, ua: str | None) -> tuple[str, str, int]:
        sid, jti, now = secrets.token_urlsafe(18), uuid.uuid4().hex, int(time.time())
        exp = now + min(self.s.refresh_token_ttl_days, self.s.session_absolute_max_days) * 86400
        key = f"session:{sid}"
        async with self.r.pipeline(transaction=True) as p:
            p.hset(key, mapping={
                "user_id": str(user_id), "refresh_jti": jti, "created_at": now, "expires_at": exp,
                "ip": ip or "", "ua": (ua or "")[:200],
            })
            p.expireat(key, exp)
            p.sadd(f"user_sessions:{user_id}", sid)
            p.expire(f"user_sessions:{user_id}", self.s.session_absolute_max_days * 86400)
            await p.execute()
        return sid, jti, exp

    async def is_active(self, sid: str, user_id: uuid.UUID) -> bool:
        """Raises redis errors on purpose: callers must fail closed."""
        return (await self.r.hget(f"session:{sid}", "user_id")) == str(user_id)

    async def rotate(self, sid: str, old_jti: str) -> tuple[RotateResult, str]:
        new_jti, now = uuid.uuid4().hex, int(time.time())
        code, exp = await self._rotate(
            keys=[f"session:{sid}"],
            args=[old_jti, new_jti, now, self.s.refresh_token_ttl_days * 86400,
                  self.s.session_absolute_max_days * 86400, GRACE_SECONDS],
        )
        status = {1: "ok", 2: "grace", -1: "reuse", 0: "missing"}[int(code)]
        return RotateResult(status, int(exp)), new_jti

    async def revoke(self, sid: str) -> None:
        uid = await self.r.hget(f"session:{sid}", "user_id")
        async with self.r.pipeline(transaction=True) as p:
            p.delete(f"session:{sid}")
            if uid:
                p.srem(f"user_sessions:{uid}", sid)
            await p.execute()

    async def revoke_all(self, user_id: uuid.UUID) -> int:
        sids = await self.r.smembers(f"user_sessions:{user_id}")
        async with self.r.pipeline(transaction=True) as p:
            for sid in sids:
                p.delete(f"session:{sid}")
            p.delete(f"user_sessions:{user_id}")
            await p.execute()
        return len(sids)
