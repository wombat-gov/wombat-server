"""Small rate limiter for login attempts.

In-memory sliding window by default; Redis fixed-window when WOMBAT_REDIS_URL is
set, so multiple server replicas share the count. If Redis is configured but
unreachable, the limiter degrades to in-memory and logs once rather than
failing authentication entirely.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque

from wombat_server.config import settings

log = logging.getLogger(__name__)

try:  # Optional dependency: only needed for multi-replica deployments.
    import redis.asyncio as aioredis
except Exception:  # pragma: no cover - exercised only when the extra is absent
    aioredis = None


class RateLimiter:
    def __init__(self, name: str, limit: int, window_seconds: int) -> None:
        self.name = name
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        self._redis = None
        self._redis_failed = False
        if settings.wombat_redis_url and aioredis is not None:
            try:
                self._redis = aioredis.from_url(
                    settings.wombat_redis_url,
                    decode_responses=True,
                    socket_connect_timeout=1,
                    socket_timeout=1,
                )
            except Exception as exc:  # pragma: no cover
                log.warning("Redis rate limiter unavailable (%s); using in-memory.", exc)
                self._redis = None

    async def allow(self, key: str) -> bool:
        if self._redis is not None and not self._redis_failed:
            try:
                redis_key = f"wombat:ratelimit:{self.name}:{key}"
                count = await self._redis.incr(redis_key)
                if count == 1:
                    await self._redis.expire(redis_key, self.window)
                return int(count) <= self.limit
            except Exception as exc:  # pragma: no cover
                self._redis_failed = True
                log.warning("Redis rate limiter failed (%s); falling back to in-memory.", exc)

        now = time.monotonic()
        async with self._lock:
            bucket = self._hits[key]
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._hits.pop(key, None)
        if self._redis is not None and not self._redis_failed:
            try:
                await self._redis.delete(f"wombat:ratelimit:{self.name}:{key}")
            except Exception:  # pragma: no cover
                pass


login_ip_limiter = RateLimiter(
    "login-ip",
    settings.wombat_login_ip_limit,
    settings.wombat_login_ip_window_seconds,
)
