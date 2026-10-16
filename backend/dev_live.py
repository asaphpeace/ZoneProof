"""
Isolated environment for live (browser) verification.

The pytest suite drops and recreates every table in the test database's
`public` schema at the start and end of each run, so anything seeded there for
manual checking vanishes. This gives live verification its own Postgres
schema (`dev_live`) inside the same local database, which pytest never
touches, selected through the app's optional DATABASE_SCHEMA setting.

    python dev_live.py reset     # drop + recreate the schema, create tables, seed demo data
    python dev_live.py seed      # (re)seed demo data without dropping anything
    python dev_live.py serve     # run the API on :9931 against the schema (resets first if missing)
    python dev_live.py status    # what's in there
    python dev_live.py adduser you@example.com   # add an admin to the demo workspace with a generated password

The frontend dev server proxies /api to :9931 (see frontend/vite.config.ts), so
`serve` + the Vite server is the full local stack.

Safety: refuses to run unless the database host is local and the database name
contains "test" or "dev" — it can only ever drop the `dev_live` schema of a
scratch database, never a real one. Demo credentials are local-only values for
this scratch schema.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

SCHEMA = "dev_live"
PORT = 9931
DEFAULT_URL = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_test"
DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = "demo-pass-123"
DEMO_DOMAIN = "acmefinancial.co.za"
CREDENTIALS_FILE = "data/dev_live_users.txt"  # gitignored; generated passwords are written here, never printed


def assert_safe_target(url: str) -> None:
    """Exit unless `url` is a local scratch database (name contains test/dev)."""
    parsed = urlparse(url.replace("+asyncpg", ""))
    db = (parsed.path or "").lstrip("/")
    if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit(f"Refusing to run: database host {parsed.hostname!r} is not local.")
    if not re.search(r"(test|dev)", db):
        raise SystemExit(f"Refusing to run: database {db!r} doesn't look like a scratch database (name must contain 'test' or 'dev').")


def _configure_environment() -> str:
    url = os.environ.get("DEV_LIVE_DATABASE_URL", DEFAULT_URL)
    assert_safe_target(url)
    # Must be set before any `app` module is imported — settings are read at import.
    os.environ["DATABASE_URL"] = url
    os.environ["DATABASE_SCHEMA"] = SCHEMA
    os.environ["BRAND_GUARD_ENABLED"] = "true"  # opt-in flag: this environment exists to exercise Brand Guard
    return url


async def _reset(url: str) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.database import Base, engine_connect_args
    import app.models  # noqa: F401  (registers every table on Base.metadata)

    admin = create_async_engine(url)  # no search_path: needed to drop/create the schema itself
    async with admin.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE'))
        await conn.execute(text(f'CREATE SCHEMA "{SCHEMA}"'))
    await admin.dispose()

    scoped = create_async_engine(url, connect_args=engine_connect_args(SCHEMA))
    async with scoped.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await scoped.dispose()


async def _seed(url: str) -> None:
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    from app.database import engine_connect_args
    from app.models import Domain
    from app.models.user import Tenant, User
    from tests.factories import make_domain, make_tenant, make_user  # the project's own valid-row builders

    engine = create_async_engine(url, connect_args=engine_connect_args(SCHEMA))
    async with AsyncSession(engine, expire_on_commit=False) as db:
        if (await db.execute(select(User).where(User.email == DEMO_EMAIL))).scalar_one_or_none():
            print(f"Demo data already present ({DEMO_EMAIL}).")
        else:
            tenant = await make_tenant(db, name="Brand Guard Demo", plan="pro")
            await make_user(db, tenant, email=DEMO_EMAIL, password=DEMO_PASSWORD)
            domain = await make_domain(db, tenant, name=DEMO_DOMAIN)
            domain.ownership_verified = True
            await db.commit()
            print(f"Seeded tenant, user {DEMO_EMAIL}, verified domain {DEMO_DOMAIN}.")
    await engine.dispose()


async def _add_user(url: str, email: str) -> str:
    """Create an admin in the demo tenant with a random password. The password is written to
    CREDENTIALS_FILE (gitignored) — not printed — and verified against the stored hash."""
    import secrets
    from pathlib import Path

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    from app.database import engine_connect_args
    from app.models.user import Tenant, User
    from app.routers.auth import _verify
    from tests.factories import make_user

    email = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise SystemExit(f"{email!r} doesn't look like an email address.")

    password = secrets.token_urlsafe(12)
    engine = create_async_engine(url, connect_args=engine_connect_args(SCHEMA))
    try:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
                raise SystemExit(f"{email} already exists in {SCHEMA}.")
            tenant = (await db.execute(select(Tenant).where(Tenant.name == "Brand Guard Demo"))).scalar_one_or_none()
            if tenant is None:
                raise SystemExit("Demo workspace not found — run: python dev_live.py reset")
            user = await make_user(db, tenant, email=email, password=password)
            await db.commit()
            assert _verify(password, user.hashed_password), "stored hash does not verify"
    finally:
        await engine.dispose()

    path = Path(__file__).resolve().parent / CREDENTIALS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf8") as fh:
        fh.write(f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M}Z  schema={SCHEMA}  email={email}  password={password}\n")
    return str(path)


async def _schema_exists(url: str) -> bool:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(url)
    async with engine.connect() as conn:
        found = (await conn.execute(text("select 1 from pg_namespace where nspname = :n"), {"n": SCHEMA})).scalar()
    await engine.dispose()
    return bool(found)


async def _status(url: str) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(url)
    async with engine.connect() as conn:
        if not (await conn.execute(text("select 1 from pg_namespace where nspname = :n"), {"n": SCHEMA})).scalar():
            print(f"Schema {SCHEMA!r} does not exist. Run: python dev_live.py reset")
        else:
            tables = (await conn.execute(text("select count(*) from information_schema.tables where table_schema = :n"), {"n": SCHEMA})).scalar()
            users = (await conn.execute(text(f'select count(*) from "{SCHEMA}".users'))).scalar()
            print(f"Schema {SCHEMA!r}: {tables} tables, {users} user(s). API port {PORT}.")
    await engine.dispose()


def main(argv: list[str]) -> None:
    if len(argv) == 3 and argv[1] == "adduser":
        url = _configure_environment()
        path = asyncio.run(_add_user(url, argv[2]))
        print(f"Created {argv[2].strip().lower()} (admin, demo workspace) in schema {SCHEMA!r}.")
        print(f"Generated password saved to: {path}  (gitignored; not printed here)")
        return
    if len(argv) != 2 or argv[1] not in ("reset", "seed", "serve", "status"):
        raise SystemExit(__doc__)
    cmd = argv[1]
    url = _configure_environment()

    if cmd == "reset":
        asyncio.run(_reset(url))
        asyncio.run(_seed(url))
    elif cmd == "seed":
        asyncio.run(_seed(url))
    elif cmd == "status":
        asyncio.run(_status(url))
    elif cmd == "serve":
        if not asyncio.run(_schema_exists(url)):
            print(f"Schema {SCHEMA!r} missing — creating it first.")
            asyncio.run(_reset(url))
            asyncio.run(_seed(url))
        import uvicorn

        uvicorn.run("app.main:app", host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main(sys.argv)
