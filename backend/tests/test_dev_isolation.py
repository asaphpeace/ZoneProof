"""
Step 0.4 — dev hygiene. Covers: the optional DATABASE_SCHEMA engine setting,
dev_live.py's safety guard, schema isolation from the pytest tables, and that
Brand Guard's background work is opt-in so a shared backend isn't disturbed.
"""
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

import dev_live
from app import main as app_main
from app.config import settings
from app.database import Base, engine_connect_args
from tests.conftest import TEST_DB_URL


# ── engine_connect_args ──────────────────────────────────────────────────────

def test_empty_schema_leaves_behaviour_unchanged():
    assert engine_connect_args("") == {}


def test_schema_sets_search_path():
    assert engine_connect_args("dev_live") == {"server_settings": {"search_path": "dev_live"}}


@pytest.mark.parametrize("bad", ["Dev Live", "x; drop schema public", 'a"b', "1abc", "a-b", "x" * 64])
def test_invalid_schema_names_rejected(bad):
    with pytest.raises(ValueError):
        engine_connect_args(bad)


# ── dev_live safety guard ────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "postgresql+asyncpg://u:p@localhost:5432/sentinel_test",
    "postgresql+asyncpg://u:p@127.0.0.1/sentinel_dev",
])
def test_guard_allows_local_scratch_databases(url):
    dev_live.assert_safe_target(url)


@pytest.mark.parametrize("url", [
    "postgresql+asyncpg://u:p@localhost:5432/sentinel",            # the real dev DB
    "postgresql+asyncpg://u:p@db.example.com:5432/sentinel_test",  # not local
    "postgresql+asyncpg://u:p@localhost:5432/production",
])
def test_guard_refuses_real_or_remote_databases(url):
    with pytest.raises(SystemExit):
        dev_live.assert_safe_target(url)


# ── schema isolation (real Postgres) ─────────────────────────────────────────

async def test_schema_scoped_engine_is_isolated_from_public(create_tables):
    schema = "iso_probe"
    admin = create_async_engine(TEST_DB_URL)
    async with admin.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = create_async_engine(TEST_DB_URL, connect_args=engine_connect_args(schema))
    try:
        async with scoped.begin() as conn:
            assert (await conn.execute(text("select current_schema()"))).scalar() == schema
            await conn.execute(text("create table probe_rows (id int)"))
            await conn.execute(text("insert into probe_rows values (1)"))

        # What the pytest session does to `public`: drop and recreate every table.
        async with admin.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

        async with scoped.connect() as conn:
            assert (await conn.execute(text("select count(*) from probe_rows"))).scalar() == 1, \
                "live-verification data must survive the test suite's table resets"
    finally:
        await scoped.dispose()
        async with admin.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


# ── Brand Guard background work is opt-in ────────────────────────────────────

def test_brand_guard_is_off_by_default():
    assert settings.brand_guard_enabled is False


async def test_disabled_flag_makes_job_and_recovery_do_nothing(monkeypatch):
    monkeypatch.setattr(settings, "brand_guard_enabled", False)

    async def must_not_run(*a, **k):
        raise AssertionError("Brand Guard background work ran while disabled")

    from app.services import brand_guard_service
    monkeypatch.setattr(brand_guard_service, "scan_due_profiles", must_not_run)
    monkeypatch.setattr(brand_guard_service, "recover_interrupted_runs", must_not_run)

    await app_main._brand_guard_job()
    await app_main._brand_guard_recover_runs()


async def test_enabled_flag_runs_them(monkeypatch):
    monkeypatch.setattr(settings, "brand_guard_enabled", True)
    calls = []

    async def fake_scan(db):
        calls.append("scan")
        return 0

    async def fake_recover(db):
        calls.append("recover")
        return 0

    class _FakeSession:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *exc):
            return False

    from app import database
    from app.services import brand_guard_service
    monkeypatch.setattr(database, "AsyncSessionLocal", lambda: _FakeSession())
    monkeypatch.setattr(brand_guard_service, "scan_due_profiles", fake_scan)
    monkeypatch.setattr(brand_guard_service, "recover_interrupted_runs", fake_recover)

    await app_main._brand_guard_job()
    await app_main._brand_guard_recover_runs()
    assert calls == ["scan", "recover"]
