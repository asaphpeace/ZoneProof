"""
Shared test fixtures for Sentinel backend tests.

Requires a running Postgres instance. The test database is created/dropped
automatically. Set TEST_DATABASE_URL to override the default.

Default: postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_test
"""
import os
import uuid
from typing import AsyncGenerator

import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import pytest

from app.database import Base, get_db
from app.main import app
from app.rate_limit import limiter
from tests.factories import make_tenant, make_user


@pytest.fixture(autouse=True)
def _brand_mail_probe_is_offline(monkeypatch):
    """Brand Guard's email-intent probe (plan 2.3) reads DNS; no test may reach the real network by accident.
    Tests of the probe itself install their own fake."""
    from app.services import brand_guard_service

    async def offline(domain, mx_hosts):
        return None

    async def offline_one(arg):
        return None
    from app.services import brand_feeds

    async def no_feeds(db, **kw):
        return None
    monkeypatch.setattr(brand_feeds, "refresh", no_feeds)                         # public abuse feeds (plan 2.5)
    from app.services import brand_nrd
    monkeypatch.setattr(brand_nrd, "refresh", no_feeds)                           # new-registration lists (plan 2.6b)
    monkeypatch.setattr(brand_nrd.FEED, "days", {})
    monkeypatch.setattr(brand_guard_service, "_probe_mail", offline)
    monkeypatch.setattr(brand_guard_service, "_probe_hosting", offline_one)      # www CNAME lookups (plan 2.4)
    monkeypatch.setattr(brand_guard_service, "_ip_owner", offline_one)           # ASN lookups for campaign clustering (plan 2.4)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """
    The login/forgot-password/scan rate limits (see app/rate_limit.py) use
    in-memory storage keyed by client IP. Every test client in this suite
    connects from the same address, so without resetting between tests the
    whole suite shares one quota — a handful of tests in, anything calling
    /auth/token (including the auth_client fixture) starts getting a real
    429 instead of the response the test actually expects.
    """
    limiter.reset()
    yield

# ── Test DB URL ────────────────────────────────────────────────────────────────
TEST_DB_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_test",
)

# ── Engine (one per session) ───────────────────────────────────────────────────
test_engine = create_async_engine(TEST_DB_URL, echo=False, pool_pre_ping=True)
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)


@pytest_asyncio.fixture(scope="session")
async def create_tables():
    """Drop and recreate all tables once per test session. Request this fixture explicitly in DB tests."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(create_tables) -> AsyncGenerator[AsyncSession, None]:
    """
    Each test gets its own session wrapped in a SAVEPOINT that is rolled back
    after the test — keeping tests fully isolated without recreating tables.
    """
    async with test_engine.connect() as conn:
        await conn.begin()
        await conn.begin_nested()  # SAVEPOINT

        session = AsyncSession(bind=conn, expire_on_commit=False)

        yield session

        await session.close()
        await conn.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """ASGI test client with the test DB session injected."""
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def auth_client(client: AsyncClient, db_session: AsyncSession):
    """
    Pre-authenticated test client.

    Returns (client, tenant) where client already has the Authorization header
    set. Use this in any test that just needs a logged-in user without caring
    about the specific tenant details.

    For tests that need to control the tenant/user (e.g. workspace name
    assertions), create them manually via factories and log in explicitly.
    """
    tenant = await make_tenant(db_session, name="Test Workspace")
    await make_user(db_session, tenant, email=f"fixture-{uuid.uuid4().hex[:6]}@test.com", password="pass123")
    await db_session.flush()

    # Re-query to get the email we just generated
    from sqlalchemy import select
    from app.models.user import User
    result = await db_session.execute(
        select(User).where(User.tenant_id == tenant.id)
    )
    user = result.scalar_one()

    resp = await client.post(
        "/auth/token",
        data={"username": user.email, "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = resp.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client, tenant
