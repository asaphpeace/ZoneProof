"""
Runs integrations (V2 plan D1): connect, test, pull a feed, and say what happened.

Adapters (app/services/integrations) do the vendor talking. This module owns what
is the same for every vendor: credentials at rest, the manual run, the status
fields, and reducing any failure to a fixed kind so no vendor error text, host or
credential ever reaches a response or the stored row.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import IntegrationConnection, IntegrationFeed
from app.services import integrations, job_registry
from app.services.crypto_service import decrypt_secret, encrypt_secret

log = logging.getLogger(__name__)


class IntegrationError(ValueError):
    """The request cannot be honoured (unknown vendor, missing field). Safe to show."""


def _credentials(conn: IntegrationConnection) -> dict[str, str]:
    return json.loads(decrypt_secret(conn.encrypted_credentials))


async def create_connection(
    db: AsyncSession, tenant_id: uuid.UUID, vendor: str, label: str, credentials: dict[str, str]
) -> IntegrationConnection:
    adapter = integrations.get(vendor)
    if adapter is None:
        raise IntegrationError("Unknown integration")
    missing = [f for f in adapter.credential_fields if not (credentials.get(f) or "").strip()]
    if missing:
        raise IntegrationError("Missing: " + ", ".join(missing))
    # Keep only the fields the adapter declares: nothing else is stored.
    kept = {f: credentials[f].strip() for f in adapter.credential_fields}
    conn = IntegrationConnection(
        tenant_id=tenant_id, vendor=vendor, label=label.strip() or adapter.label,
        encrypted_credentials=encrypt_secret(json.dumps(kept)),
    )
    conn.feeds = [
        IntegrationFeed(feed_key=f.key, interval_seconds=f.default_interval_seconds) for f in adapter.feeds
    ]
    db.add(conn)
    await db.flush()
    return conn


async def get_connection(db: AsyncSession, tenant_id: uuid.UUID, connection_id: uuid.UUID) -> IntegrationConnection | None:
    return (await db.execute(
        select(IntegrationConnection).where(
            IntegrationConnection.id == connection_id, IntegrationConnection.tenant_id == tenant_id
        )
    )).scalar_one_or_none()


async def test_connection(db: AsyncSession, conn: IntegrationConnection) -> bool:
    adapter = integrations.get(conn.vendor)
    conn.last_tested_at = datetime.now(timezone.utc)
    try:
        if adapter is None:
            raise RuntimeError("adapter missing")
        await adapter.test(_credentials(conn))
        conn.status, conn.last_error_kind = "ok", None
    except Exception as e:
        log.warning("integration test failed (%s): %s", conn.vendor, type(e).__name__)
        conn.status, conn.last_error_kind = "failing", job_registry.classify(e)
    await db.flush()
    return conn.status == "ok"


async def run_feed(db: AsyncSession, conn: IntegrationConnection, feed: IntegrationFeed) -> bool:
    """Pull one feed now. Never raises: the outcome is on the feed row."""
    adapter = integrations.get(conn.vendor)
    feed.last_started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    try:
        if adapter is None:
            raise RuntimeError("adapter missing")
        result = await adapter.pull(_credentials(conn), feed.feed_key, feed.cursor, feed.last_finished)
        feed.last_ok, feed.last_error_kind = True, None
        feed.last_count, feed.cursor = result.count, result.cursor
        conn.status, conn.last_error_kind = "ok", None
    except Exception as e:
        log.warning("integration feed failed (%s/%s): %s", conn.vendor, feed.feed_key, type(e).__name__)
        feed.last_ok, feed.last_error_kind = False, job_registry.classify(e)
        conn.status, conn.last_error_kind = "failing", feed.last_error_kind
    feed.last_finished = datetime.now(timezone.utc)
    feed.last_duration_s = round(time.monotonic() - t0, 2)
    await db.flush()
    return bool(feed.last_ok)


def next_run(feed: IntegrationFeed) -> datetime | None:
    if not feed.enabled:
        return None
    if feed.last_finished is None:
        return datetime.now(timezone.utc)
    from datetime import timedelta
    return feed.last_finished + timedelta(seconds=feed.interval_seconds)


async def run_due(db: AsyncSession) -> int:
    """For the scheduler (wired when the first vendor exists): pull every enabled feed that is due."""
    now = datetime.now(timezone.utc)
    ran = 0
    for conn in (await db.execute(select(IntegrationConnection))).scalars().all():
        for feed in conn.feeds:
            due = next_run(feed)
            if feed.enabled and (feed.last_finished is None or (due is not None and due <= now)):
                await run_feed(db, conn, feed)
                ran += 1
    return ran
