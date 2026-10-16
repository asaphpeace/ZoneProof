"""Sending Brand Guard alerts and digests to a tenant's channels, and keeping a delivery log (plan step 8.7).

An alert is sent to a channel at most once (the log's unique key), never blocks or fails a scan (every error is caught and recorded), and a
channel that keeps failing is only recorded as failing, not retried in a loop: the next scan's dispatch tries again for alerts not yet logged
as sent. Customer-supplied URLs go through brand_notify's checks before any request is made."""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Alert, BrandCandidate, BrandNotifyChannel, BrandNotifyLog, BrandProfile
from app.services import brand_notify as bn
from app.services.crypto_service import decrypt_secret

log = logging.getLogger(__name__)
LOOKBACK = timedelta(hours=48)       # an alert older than this is never sent late
TIMEOUT = httpx.Timeout(8.0)
DIGEST_EVERY = timedelta(hours=24)
MAX_PER_PASS = 50                    # alerts per channel per dispatch, so one burst cannot flood a channel


def _link(path: str = "/brand-guard") -> str:
    return settings.app_base_url.rstrip("/") + path


def alert_dict(a: Alert) -> dict:
    return {"id": str(a.id), "severity": a.severity, "title": a.title, "body": a.body, "action": a.action, "created_at": a.created_at.isoformat() if a.created_at else ""}


async def deliver(db: AsyncSession, channel: BrandNotifyChannel, alert: dict, link: str | None = None) -> tuple[bool, str | None]:
    """Send one message. Returns (ok, error text safe to show). Never raises."""
    try:
        target = decrypt_secret(channel.target_enc)
        if channel.kind == "email":
            from app.services import email_service
            subject, html, text = bn.email_parts(alert, link)
            sent = await email_service.send_email(db, target, subject, html, text_body=text)
            return (True, None) if sent else (False, "The address is suppressed after an earlier bounce or complaint")
        host = (httpx.URL(target).host or "").lower()
        if not await bn.host_resolves_publicly(host):
            return False, "The address does not resolve to a public server"
        headers = {"Content-Type": "application/json", "User-Agent": "ZoneProof-Notifier/1"}
        if channel.kind == "slack":
            body = json.dumps(bn.slack_payload(alert, link)).encode()
        elif channel.kind == "teams":
            body = json.dumps(bn.teams_payload(alert, link)).encode()
        else:
            body = json.dumps(bn.webhook_payload(alert, link), sort_keys=True).encode()
            ts = str(int(time.time()))
            headers["X-ZoneProof-Timestamp"] = ts
            if channel.secret_enc:
                headers["X-ZoneProof-Signature"] = bn.sign(body, decrypt_secret(channel.secret_enc), ts)
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            r = await client.post(target, content=body, headers=headers)
        return (True, None) if 200 <= r.status_code < 300 else (False, f"The receiver answered HTTP {r.status_code}")
    except Exception as e:                              # a notification problem must never reach the caller
        log.info("Brand notification to channel %s failed: %s", channel.id, type(e).__name__)
        return False, f"Could not send ({type(e).__name__})"


def _record(db: AsyncSession, channel: BrandNotifyChannel, kind: str, alert_id, ok: bool, err: str | None, now: datetime) -> None:
    channel.last_status, channel.last_error, channel.last_sent_at = ("ok" if ok else "failed"), (err or "")[:300] or None, now
    db.add(BrandNotifyLog(id=uuid.uuid4(), tenant_id=channel.tenant_id, channel_id=channel.id, alert_id=alert_id, kind=kind, status="ok" if ok else "failed", error=(err or "")[:300] or None, sent_at=now))


async def dispatch_new(db: AsyncSession, tenant_id) -> int:
    """Send this tenant's recent brand alerts to every enabled channel that has not had them yet. Returns messages delivered. Never raises."""
    try:
        channels = (await db.execute(select(BrandNotifyChannel).where(BrandNotifyChannel.tenant_id == tenant_id, BrandNotifyChannel.enabled == True))).scalars().all()  # noqa: E712
        if not channels:
            return 0
        now = datetime.now(timezone.utc)
        alerts = (await db.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.category == "brand", Alert.created_at >= now - LOOKBACK).order_by(Alert.created_at))).scalars().all()
        sent = 0
        for ch in channels:
            done = {r[0] for r in (await db.execute(select(BrandNotifyLog.alert_id).where(BrandNotifyLog.channel_id == ch.id, BrandNotifyLog.status == "ok", BrandNotifyLog.alert_id.is_not(None)))).all()}
            todo = [a for a in alerts if a.id not in done and bn.passes(ch.min_severity, a.severity)][:MAX_PER_PASS]
            for a in todo:
                ok, err = await deliver(db, ch, alert_dict(a), _link())
                # a failed attempt is logged under a fresh row only once per pass; the unique key covers successes
                if ok:
                    _record(db, ch, "alert", a.id, True, None, now)
                    sent += 1
                else:
                    _record_failure_once(db, ch, a.id, err, now)
                    break                                    # a channel that is down gets one failure per pass, not fifty
        await db.commit()
        return sent
    except Exception:
        log.exception("Brand notification dispatch failed")
        await db.rollback()
        return 0


def _record_failure_once(db: AsyncSession, channel: BrandNotifyChannel, alert_id, err: str | None, now: datetime) -> None:
    channel.last_status, channel.last_error, channel.last_sent_at = "failed", (err or "")[:300] or None, now
    db.add(BrandNotifyLog(id=uuid.uuid4(), tenant_id=channel.tenant_id, channel_id=channel.id, alert_id=None, kind="alert", status="failed", error=(err or "")[:300] or None, sent_at=now))


_OPEN = ("new", "triaging", "suspicious", "monitoring")


async def digest_summary(db: AsyncSession, tenant_id) -> dict:
    """The numbers a daily summary needs, straight from the tenant's candidates (a lighter version of the home screen's summary)."""
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(BrandCandidate.status, BrandCandidate.due_at, BrandCandidate.first_seen_at).where(BrandCandidate.tenant_id == tenant_id))).all()
    return {
        "new_24h": sum(1 for _, _, seen in rows if seen and seen >= now - timedelta(hours=24)),
        "open_candidates": sum(1 for st, _, _ in rows if st in _OPEN),
        "confirmed": sum(1 for st, _, _ in rows if st == "confirmed"),
        "takedown": sum(1 for st, _, _ in rows if st == "takedown"),
        "overdue": sum(1 for st, due, _ in rows if st in ("confirmed", "takedown") and due is not None and due < now),
    }


async def send_due_digests(db: AsyncSession) -> int:
    """Scheduler entry: every tenant with a digest channel gets its summary at most once a day."""
    tenants = [r[0] for r in (await db.execute(select(BrandNotifyChannel.tenant_id).where(BrandNotifyChannel.digest == True, BrandNotifyChannel.enabled == True).distinct())).all()]  # noqa: E712
    n = 0
    for tid in tenants:
        brands = [r[0] for r in (await db.execute(select(BrandProfile.brand_name).where(BrandProfile.tenant_id == tid, BrandProfile.is_active == True))).all()]  # noqa: E712
        n += await send_digests(db, tid, ", ".join(brands[:3]) or "your brands", await digest_summary(db, tid))
    return n


async def send_digests(db: AsyncSession, tenant_id, brand: str, summary: dict) -> int:
    """Send the daily summary to digest channels that have not had one in 24 hours."""
    try:
        now = datetime.now(timezone.utc)
        channels = (await db.execute(select(BrandNotifyChannel).where(BrandNotifyChannel.tenant_id == tenant_id, BrandNotifyChannel.enabled == True, BrandNotifyChannel.digest == True))).scalars().all()  # noqa: E712
        n = 0
        for ch in channels:
            if ch.last_digest_at and now - ch.last_digest_at < DIGEST_EVERY:
                continue
            ok, err = await deliver(db, ch, bn.digest_alert(bn.digest(brand=brand, summary=summary, since=now - DIGEST_EVERY)), _link())
            ch.last_digest_at = now if ok else ch.last_digest_at
            _record(db, ch, "digest", None, ok, err, now)
            n += int(ok)
        await db.commit()
        return n
    except Exception:
        log.exception("Brand digest failed")
        await db.rollback()
        return 0
