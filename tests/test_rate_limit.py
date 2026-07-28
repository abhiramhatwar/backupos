"""Unit tests for the token-bucket rate limiter."""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.core.rate_limit import RateLimiter, enforce_rate_limit

pytestmark = pytest.mark.asyncio


async def test_enforce_skips_when_limiter_is_none():
    with patch("app.core.rate_limit.rate_limiter", None):
        await enforce_rate_limit(tenant_id=1)  # must not raise


async def test_enforce_propagates_429():
    mock_limiter = AsyncMock()
    mock_limiter.check.side_effect = HTTPException(
        status_code=429, detail="Rate limit exceeded"
    )
    with patch("app.core.rate_limit.rate_limiter", mock_limiter):
        with pytest.raises(HTTPException) as exc_info:
            await enforce_rate_limit(tenant_id=42)

    assert exc_info.value.status_code == 429
    mock_limiter.check.assert_awaited_once_with(42)


async def test_enforce_swallows_redis_connection_error():
    mock_limiter = AsyncMock()
    mock_limiter.check.side_effect = ConnectionError("Redis down")
    with patch("app.core.rate_limit.rate_limiter", mock_limiter):
        await enforce_rate_limit(tenant_id=7)  # must not raise


async def test_enforce_swallows_generic_exception():
    mock_limiter = AsyncMock()
    mock_limiter.check.side_effect = RuntimeError("unexpected")
    with patch("app.core.rate_limit.rate_limiter", mock_limiter):
        await enforce_rate_limit(tenant_id=99)  # must not raise


async def test_rate_limiter_first_request_sets_ttl():
    mock_redis = AsyncMock()
    mock_redis.incr.return_value = 1

    limiter = RateLimiter.__new__(RateLimiter)
    limiter.redis = mock_redis
    limiter.rpm = 60

    await limiter.check(tenant_id=1)

    mock_redis.incr.assert_awaited_once_with("rate_limit:1")
    mock_redis.expire.assert_awaited_once_with("rate_limit:1", 60)


async def test_rate_limiter_subsequent_request_skips_ttl():
    mock_redis = AsyncMock()
    mock_redis.incr.return_value = 2  # not the first request in window

    limiter = RateLimiter.__new__(RateLimiter)
    limiter.redis = mock_redis
    limiter.rpm = 60

    await limiter.check(tenant_id=1)

    mock_redis.expire.assert_not_awaited()


async def test_rate_limiter_allows_exactly_at_limit():
    mock_redis = AsyncMock()
    mock_redis.incr.return_value = 60  # at the limit, not over

    limiter = RateLimiter.__new__(RateLimiter)
    limiter.redis = mock_redis
    limiter.rpm = 60

    await limiter.check(tenant_id=3)  # must not raise


async def test_rate_limiter_raises_429_when_exceeded():
    mock_redis = AsyncMock()
    mock_redis.incr.return_value = 61  # one over the limit

    limiter = RateLimiter.__new__(RateLimiter)
    limiter.redis = mock_redis
    limiter.rpm = 60

    with pytest.raises(HTTPException) as exc_info:
        await limiter.check(tenant_id=5)

    assert exc_info.value.status_code == 429


async def test_rate_limiter_uses_tenant_scoped_key():
    """Each tenant must have an isolated counter key."""
    mock_redis = AsyncMock()
    mock_redis.incr.return_value = 1

    limiter = RateLimiter.__new__(RateLimiter)
    limiter.redis = mock_redis
    limiter.rpm = 60

    await limiter.check(tenant_id=123)

    mock_redis.incr.assert_awaited_with("rate_limit:123")
