"""
Detection Coverage — for each real IAM privilege-escalation path
(CloudPrivEscPath), whether the account's actual detection sources would
catch it being exploited. Not a new scan: reuses two things that already
exist and cost nothing extra to read —

1. Prowler's default ruleset already runs `cloudtrail_multi_region_enabled`
   and `guardduty_is_enabled` on every cloud scan (cloud_scan_service.py),
   persisted as ordinary open Finding rows when they FAIL. Prowler never
   persists a PASS row, so the absence of an open Finding for one of these
   check ids means the account passed it — the same "absence = enabled"
   convention this codebase already relies on elsewhere.
2. threat_detection_service.py's own reasoning about what actually gets
   logged: any IAM/management-plane API call is a CloudTrail *management
   event* by default, everywhere CloudTrail is turned on — multi-region is
   what determines whether a call from an unexpected region still lands in
   the trail.

Verdict is three-tier, not a bare yes/no:
- covered:    multi-region CloudTrail on AND GuardDuty on — the call would
              be logged *and* something is actively watching for it.
- partial:    multi-region CloudTrail on, GuardDuty off — the call would be
              logged, but nothing proactively alerts on it; only a manual
              log review or Sentinel's own threat_detection_service poll
              (a different, narrower signal) would ever surface it.
- blind_spot: multi-region CloudTrail off — the call might not even reach
              a trail if invoked from an unmonitored region.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CloudAccountConnection, CloudPrivEscPath, Finding

_CLOUDTRAIL_CHECK_ID = "cloudtrail_multi_region_enabled"
_GUARDDUTY_CHECK_ID = "guardduty_is_enabled"


async def compute_detection_coverage(db: AsyncSession, tenant_id: uuid.UUID) -> list[dict]:
    paths_result = await db.execute(
        select(CloudPrivEscPath).where(CloudPrivEscPath.tenant_id == tenant_id).order_by(CloudPrivEscPath.discovered_at.desc())
    )
    paths = paths_result.scalars().all()
    if not paths:
        return []

    # Real per-account fix (Coverage Map roadmap Phase 35b): CloudTrail/
    # GuardDuty posture used to be computed once, tenant-wide, and applied
    # identically to every path — a tenant with 2+ connected AWS accounts
    # got one account's posture bled onto every other account's paths.
    # Each CloudPrivEscPath carries its own cloud_account_connection_id;
    # that connection's own engagement_id is what its Prowler Finding rows
    # were written under (cloud_scan_service.py sets engagement_id=engagement.id
    # at every Finding-creation site, and the connection resolves to that
    # same engagement), so join through that instead of tenant_id.
    connection_ids = {path.cloud_account_connection_id for path in paths}
    connections_result = await db.execute(
        select(CloudAccountConnection).where(CloudAccountConnection.id.in_(connection_ids))
    )
    engagement_id_by_connection_id = {c.id: c.engagement_id for c in connections_result.scalars().all()}

    failed_result = await db.execute(
        select(Finding.engagement_id, Finding.check_id).where(
            Finding.tenant_id == tenant_id, Finding.tier == "cloud", Finding.status == "open",
            Finding.check_id.in_([_CLOUDTRAIL_CHECK_ID, _GUARDDUTY_CHECK_ID]),
        )
    )
    failed_checks_by_engagement: dict[uuid.UUID | None, set[str]] = {}
    for engagement_id, check_id in failed_result.all():
        failed_checks_by_engagement.setdefault(engagement_id, set()).add(check_id)

    results = []
    for path in paths:
        engagement_id = engagement_id_by_connection_id.get(path.cloud_account_connection_id)
        failed_checks = failed_checks_by_engagement.get(engagement_id, set())
        cloudtrail_multi_region_enabled = _CLOUDTRAIL_CHECK_ID not in failed_checks
        guardduty_enabled = _GUARDDUTY_CHECK_ID not in failed_checks

        if not cloudtrail_multi_region_enabled:
            verdict, reason = "blind_spot", (
                "CloudTrail is not enabled across all regions on this account (Prowler check "
                f"'{_CLOUDTRAIL_CHECK_ID}' is failing). An action in this path's technique chain, "
                "called from a region without an active trail, would not be logged at all."
            )
        elif not guardduty_enabled:
            verdict, reason = "partial", (
                "CloudTrail is enabled across all regions, so every action in this path's technique "
                "chain would be logged as a management event regardless of region. But GuardDuty is "
                f"not enabled (Prowler check '{_GUARDDUTY_CHECK_ID}' is failing) — nothing proactively "
                "alerts on it; it would only surface via manual log review."
            )
        else:
            verdict, reason = "covered", (
                "CloudTrail is enabled across all regions and GuardDuty is enabled — every action in "
                "this path's technique chain would be logged, and GuardDuty's anomaly detection is "
                "actively watching this account for suspicious activity."
            )

        results.append({
            "priv_esc_path_id": str(path.id),
            "source_principal_arn": path.source_principal_arn,
            "target_principal_arn": path.target_principal_arn,
            "technique_chain": path.technique_chain,
            "severity": path.severity,
            "verdict": verdict,
            "reason": reason,
            "cloudtrail_multi_region_enabled": cloudtrail_multi_region_enabled,
            "guardduty_enabled": guardduty_enabled,
            "discovered_at": path.discovered_at.isoformat(),
        })
    return results
