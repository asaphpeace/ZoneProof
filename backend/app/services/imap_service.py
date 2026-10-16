"""
IMAP report ingestion service.

Flow:
  1. Connect to IMAP inbox (reports@mailsentry.co.za)
  2. Fetch unseen messages
  3. For each message:
     a. Extract slug from recipient subaddress (To:/Delivered-To: header)
     b. Resolve the slug against Domain.reporting_slug first (DMARC/
        TLS-RPT aggregate reports — the original use of this mailbox);
        if that doesn't match, try Tenant.phishing_report_slug instead
        (Phishing Simulation roadmap Phase 26 — an employee forwarding a
        real suspicious email). Same shared mailbox, same slug-in-
        recipient-address routing convention, two different tenant-
        scoped features hanging off it.
     c. Domain match: determine DMARC vs TLS-RPT from content-type/
        filename, parse, insert, rebuild aggregates.
        Tenant match: parse the forwarded message into a ReportedEmail
        row (app/services/email_ingestion_service.py) — no attachment
        type-sniffing needed, the whole message is the input.
     d. Mark message as seen once actually processed.
"""
from __future__ import annotations

import gzip
import io
import json
import logging
import zipfile
from datetime import datetime, timezone
from email import policy as email_policy
from email.parser import BytesParser
from typing import AsyncGenerator

import aioimaplib
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal
from app.services.dmarc_parser import parse_dmarc_xml
from app.services.tls_parser import parse_tls_json
from app.services.dmarc_service import rebuild_aggregates
from app.services.tls_service import rebuild_tls_aggregates
from app.services.email_ingestion_service import parse_reported_email

log = logging.getLogger(__name__)


async def _get_domain_by_slug(db: AsyncSession, slug: str):
    from sqlalchemy import select
    from app.models import Domain
    result = await db.execute(select(Domain).where(Domain.reporting_slug == slug))
    return result.scalar_one_or_none()


async def _get_tenant_by_report_slug(db: AsyncSession, slug: str):
    from sqlalchemy import select
    from app.models.user import Tenant
    result = await db.execute(select(Tenant).where(Tenant.phishing_report_slug == slug))
    return result.scalar_one_or_none()


def _extract_slug_from_to(to_header: str) -> str | None:
    """Extract slug from addresses like d4a9f2b1@mailsentry.co.za."""
    import re
    match = re.search(r"([a-f0-9]{8})@" + re.escape(settings.reporting_domain), to_header, re.I)
    return match.group(1) if match else None


def _decompress(data: bytes, filename: str) -> bytes:
    fname = filename.lower()
    if fname.endswith(".gz"):
        return gzip.decompress(data)
    if fname.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            inner = zf.namelist()[0]
            return zf.read(inner)
    return data


async def poll_inbox() -> None:
    """Connect to IMAP and process all unseen report emails."""
    if not settings.imap_password:
        log.info("IMAP: IMAP_PASSWORD is not set, skipping report ingestion")
        return

    imap = aioimaplib.IMAP4_SSL(host=settings.imap_host, port=settings.imap_port)
    await imap.wait_hello_from_server()
    login = await imap.login(settings.imap_user, settings.imap_password)
    if login.result != "OK":
        # Without this check a rejected login leaves the session in NONAUTH
        # and SELECT aborts with a confusing "illegal in state NONAUTH".
        log.error(
            "IMAP: login to %s as %s was rejected (%s) — check IMAP_USER/IMAP_PASSWORD",
            settings.imap_host, settings.imap_user, login.result,
        )
        try:
            await imap.logout()
        except Exception:
            pass
        return
    await imap.select("INBOX")

    _, data = await imap.search("UNSEEN")
    raw_uids = data[0].split() if data[0] else []
    uids = [u.decode() if isinstance(u, bytes) else u for u in raw_uids]
    log.info("IMAP: %d unseen messages", len(uids))

    for uid in uids:
        try:
            _, msg_data = await imap.fetch(uid, "(RFC822)")
            raw = msg_data[1]
            msg = BytesParser(policy=email_policy.default).parsebytes(raw)

            to_header = msg.get("To", "") + msg.get("Delivered-To", "")
            slug = _extract_slug_from_to(to_header)
            if not slug:
                log.warning("IMAP: no slug in To header '%s', skipping", to_header)
                continue

            async with AsyncSessionLocal() as db:
                domain = await _get_domain_by_slug(db, slug)
                if domain:
                    processed = await _process_dmarc_tls_attachments(db, domain, msg)
                else:
                    tenant = await _get_tenant_by_report_slug(db, slug)
                    if tenant:
                        await parse_reported_email(db, tenant, msg)
                        processed = True
                    else:
                        log.warning("IMAP: unknown slug %s, skipping", slug)
                        processed = False

                if processed:
                    await imap.store(uid, "+FLAGS", r"(\Seen)")

        except Exception:
            log.exception("IMAP: error processing uid %s", uid)

    await imap.logout()


async def _process_dmarc_tls_attachments(db: AsyncSession, domain, msg) -> bool:
    processed = False
    for part in msg.iter_attachments():
        ct = part.get_content_type()
        filename = part.get_filename() or ""
        payload = part.get_payload(decode=True)
        if not payload:
            continue

        # Determine report type
        is_dmarc = (
            "xml" in ct or
            filename.endswith((".xml.gz", ".xml.zip", ".xml"))
        )
        is_tls = (
            "tlsrpt" in ct or
            "json" in ct or
            filename.endswith((".json.gz", ".json.zip", ".json"))
        )

        if is_dmarc:
            raw_bytes = _decompress(payload, filename)
            report = await parse_dmarc_xml(db, domain, raw_bytes.decode("utf-8", errors="replace"))
            # Still mark the message seen on a duplicate — there's nothing
            # further to do with it, and leaving it unseen would just
            # cause the same duplicate-detection log line every poll cycle.
            if report is not None:
                await rebuild_aggregates(db, domain.id)
            processed = True

        elif is_tls:
            raw_bytes = _decompress(payload, filename)
            report = await parse_tls_json(db, domain, raw_bytes.decode("utf-8", errors="replace"))
            if report is not None:
                await rebuild_tls_aggregates(db, domain.id)
            processed = True

    return processed
