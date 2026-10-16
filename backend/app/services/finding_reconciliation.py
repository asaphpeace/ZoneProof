"""
Shared reconciliation logic for state-based scan passes (Prowler,
Cloudsplaining, Inspector, Lynis, Exposure) — every rescan used to just
insert a fresh batch of Finding/CloudPrivEscPath rows with zero awareness
of what the previous scan already persisted, so a persistent, unresolved
issue (the common case — most misconfigurations don't get fixed between
scans) re-accumulated a brand-new duplicate row every single time. On a
real test account this inflated one connection's finding count from 235
to 483 across a handful of rescans with no new issues, and the pattern
would grow unbounded on any account with a recurring scan schedule.

Deliberately NOT used for tier='oauth_risk'/'phishing'/'impersonation'/
'threat' findings — those represent discrete events (a campaign click, a
detected threat), not persistent configuration state, so accumulating one
row per occurrence is the correct behavior there, not this same bug.

reconcile() is generic over "the identity of a currently-detected issue"
via a caller-supplied key function, so each scan pass can express its own
correct identity (a Prowler finding's key includes the resource ARN a
check_id alone doesn't carry; a Lynis finding's key includes the host,
since the same generic Lynis test id can legitimately fire on two
different hosts under one engagement; Cloudsplaining and Exposure findings
are cheap to key directly).
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeVar

from sqlalchemy import ColumnElement, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding

T = TypeVar("T")


async def reconcile_findings(
    db: AsyncSession,
    *,
    engagement_id,
    scope: Sequence[ColumnElement[bool]],
    candidates: list[Finding],
    key_fn: Callable[[Finding], tuple],
) -> list[Finding]:
    """candidates are freshly-built Finding objects from this scan pass,
    NOT yet added to the session. scope further restricts which existing
    open Finding rows belong to this scan pass (e.g. Finding.tier=='cloud'
    and check_id not starting 'arn:', to keep Prowler's reconciliation from
    touching Inspector's rows even though both share tier='cloud').

    - A candidate whose key matches an existing open row: dropped, not
      re-inserted — the issue is still open, nothing changed.
    - A candidate with no match: added as a new open Finding.
    - An existing open row with no matching candidate: marked 'remediated'
      — this scan no longer detects it, so treat it as fixed rather than
      leaving a stale 'open' finding forever.

    Returns only the newly-inserted findings, matching what callers
    already did with the pre-reconciliation return value (the scan's own
    "what did this pass just discover" list) — existing open rows that
    matched are deliberately left untouched, including discovered_at.

    Three deliberate exceptions, all server-computed enrichment rather than
    user-facing history like discovered_at, so refreshing them on every
    scan is safe and correct — none ever touches status/discovered_at:

    - asset_id: a real bug found live — a Finding first created before its
      CloudAsset had been discovered yet (resource inventory, Phase 38a,
      runs first only on scans *after* it was added) got asset_id=None
      permanently, since a matched row was never revisited on later scans
      even once inventory caught up. That made a genuinely critical
      finding (an EC2 instance's SSH-exposed-to-Internet check) invisible
      in the Cloud Resource Explorer's per-resource finding badge, which
      joins on asset_id only.

    - extra/extra_populated_at: the same bug, found live again — every
      per-scanner enrichment field ever added (Prowler's compliance/
      categories/remediation_code/resource_metadata, Cloudsplaining's
      policy_document, etc.) landed only on a Finding's *first* discovery;
      a matched row on every rescan since kept whatever extra it had at
      creation, even after the extraction code was extended to capture
      more. Confirmed live against the real connected AWS account: the
      exact SSH-exposed finding named above still had extra=None weeks
      after Phase 36b started populating it, because it had never stopped
      matching on every rescan since before that phase existed. A scan
      pass that adds no new extra data for a given candidate (extra is
      None) leaves the existing row's extra untouched, same as asset_id's
      own None-guard — this only ever adds/refreshes real data, never
      erases it with a blank value.

    - exploitability/exploitability_scored_at: the exact same fix, applied
      pre-emptively this time rather than found live again — every scan
      pass now computes a real exploitability_service.py score for each
      candidate before it reaches this function, and a matched existing
      row needs the same refresh-on-match treatment or a scoring-formula
      improvement would only ever reach brand-new findings, never the
      already-persisted ones a real tenant's account is mostly made of."""
    existing = (
        await db.execute(
            select(Finding).where(Finding.engagement_id == engagement_id, Finding.status == "open", *scope)
        )
    ).scalars().all()

    existing_by_key = {key_fn(f): f for f in existing}
    candidates_by_key = {key_fn(c): c for c in candidates}
    candidate_keys = set(candidates_by_key.keys())

    new_findings = [c for c in candidates if key_fn(c) not in existing_by_key]
    for f in new_findings:
        db.add(f)

    enrichment_refreshed = False
    for key, existing_finding in existing_by_key.items():
        if key not in candidate_keys:
            existing_finding.status = "remediated"
        else:
            candidate = candidates_by_key[key]
            if candidate.asset_id is not None and existing_finding.asset_id != candidate.asset_id:
                existing_finding.asset_id = candidate.asset_id
                enrichment_refreshed = True
            if candidate.extra is not None and candidate.extra != existing_finding.extra:
                existing_finding.extra = candidate.extra
                existing_finding.extra_populated_at = candidate.extra_populated_at
                enrichment_refreshed = True
            if candidate.exploitability is not None and candidate.exploitability != existing_finding.exploitability:
                existing_finding.exploitability = candidate.exploitability
                existing_finding.exploitability_scored_at = candidate.exploitability_scored_at
                enrichment_refreshed = True

    if new_findings or enrichment_refreshed or any(key not in candidate_keys for key in existing_by_key):
        await db.commit()

    return new_findings
