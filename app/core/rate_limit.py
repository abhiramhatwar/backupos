"""
Token-bucket rate limiter backed by Redis.

Each tenant gets a counter key that expires after 60 seconds.  On the first
request the counter is set to 1 with a 60-second TTL.  Subsequent requests
within that window increment the counter.  If the counter exceeds the
configured rate the request is rejected with HTTP 429.
"""
from __future__ import annotations

import redis.asyncio as aioredis
from fastapi import HTTPException


class RateLimiter:
    def __init__(self, redis_url: str, requests_per_minute: int = 60) -> None:
        self.redis: aioredis.Redis = aioredis.from_url(redis_url, decode_responses=True)
        self.rpm = requests_per_minute

    async def check(self, tenant_id: int) -> None:
        """
        Increment the request counter for *tenant_id*.  Raises HTTP 429 when
        the per-minute limit is exceeded.
        """
        key = f"rate_limit:{tenant_id}"
        count = await self.redis.incr(key)
        if count == 1:
            # First request in this window — set the TTL
            await self.redis.expire(key, 60)
        if count > self.rpm:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.rpm} requests per minute",
            )

    async def close(self) -> None:
        await self.redis.aclose()


# Singleton instance — initialised in app.main lifespan
rate_limiter: RateLimiter | None = None


async def enforce_rate_limit(tenant_id: int) -> None:
    """
    Enforce rate limiting for a tenant.  Call directly from route handlers
    after resolving the current tenant.  Silently skips if Redis is down.
    """
    if rate_limiter is None:
        return
    try:
        await rate_limiter.check(tenant_id)
    except HTTPException:
        raise
    except Exception:
        pass
