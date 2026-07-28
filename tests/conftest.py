"""
pytest fixtures for BackupOS tests.

Uses an in-memory SQLite database (via aiosqlite) so tests run without
a real PostgreSQL instance.
"""
import asyncio
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Override DATABASE_URL before the app is imported so settings picks it up
import os
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("CAS_STORE_PATH", "/tmp/backupos_test_cas")

from app.core.database import Base
from app.core.auth import hash_password, create_access_token
from app.models.tenant import Tenant

# ---------------------------------------------------------------------------
# In-memory async engine (SQLite via aiosqlite)
# ---------------------------------------------------------------------------
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DB_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)


# ---------------------------------------------------------------------------
# Patch app's database engine to use the test engine
# ---------------------------------------------------------------------------
import app.core.database as _db_module

_db_module.engine = test_engine
_db_module.AsyncSessionLocal = TestSessionLocal


async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with TestSessionLocal() as session:
        yield session


from app.core.database import get_db
from app.main import app

app.dependency_overrides[get_db] = _override_get_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop so all async fixtures share one loop."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def create_tables():
    """Create all tables once per test session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def test_tenant(db_session: AsyncSession):
    """Create a test tenant and return (tenant, jwt_token)."""
    tenant = Tenant(
        name="Test Tenant",
        email="test@example.com",
        hashed_password=hash_password("testpassword"),
        api_key="bos_test_api_key_12345",
        is_active=True,
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    token = create_access_token({"sub": str(tenant.id)})
    return tenant, token
