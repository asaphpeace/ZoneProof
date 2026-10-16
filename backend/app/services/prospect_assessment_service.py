"""
Real, passive, consent-free security posture snapshot for a domain the
tenant does NOT own — backs the "Prospect Assessment" sales tool.

Reuses the exact real DNS/HTTPS primitives V1's own Email Authentication
Defense already trusts for onboarded domains — dmarc_service.check_dmarc_dns,
spf_composer.fetch_spf_record/parse_spf_record, tls_service.check_mta_sts_dns
/fetch_mta_sts_policy — and posture_service.compute_posture's real scoring
engine, rather than inventing a parallel one. Every one of these reads
either public DNS records or a domain's public /.well-known/mta-sts.txt
file — the same category of lookup any public tool (mxtoolbox, dmarcian's
free checker) already performs for any domain with no consent required,
since it's all public data. Deliberately does NOT do anything V1/Command
gates behind ownership_verified (active subdomain probing, TCP port scans
in exposure_scan_service.py) — those are a real consent boundary this tool
must not cross for a domain we have no relationship with.

dmarc_comp/tls_pass_pct/min_cert_days are always None here — those need a
connected account (aggregate report data, live TLS handshake stats,
certificate probing), not something guessable from outside. The resulting
score is honestly partial, not padded to look complete.

Replaced a version of this feature that fabricated a "risk score" purely
from a checksum of the domain string — found during a promise-vs-delivery
audit, since this exact tool's own UI copy says "Generate a branded risk
report for the sales call" with a "Book Remediation Call" CTA, i.e. it was
built to be shown to a real prospect.
"""
from __future__ import annotations

from app.services.dmarc_service import check_dmarc_dns
from app.services.posture_service import compute_posture
from app.services.spf_composer import fetch_spf_record, parse_spf_record
from app.services.tls_service import check_mta_sts_dns, fetch_mta_sts_policy

_DMARC_STAGES = {"reject", "quarantine", "none"}
_TLS_STAGES = {"enforce", "testing"}

# What this tool can't see without a connected account — shown as an
# honest "connect for the full picture" CTA instead of fabricated numbers.
NOT_ASSESSED = [
    "Cloud Misconfiguration Defense",
    "Third-Party OAuth App Risk",
    "Identity & Credential Hygiene",
]


def _dmarc_stage_from_policy(policy: str | None) -> str:
    return policy if policy in _DMARC_STAGES else "none"


def _tls_stage_from_mode(mode: str | None) -> str:
    return mode if mode in _TLS_STAGES else "none"


async def assess_domain(domain_name: str) -> dict:
    """A real, honestly-partial posture snapshot for domain_name — every
    field traces back to an actual DNS/HTTPS lookup made just now. Each
    underlying check (check_dmarc_dns/fetch_spf_record/check_mta_sts_dns)
    already catches DNS failures internally and returns a safe "not
    found" default, so a domain that doesn't resolve at all degrades to
    an honest all-checks-failed result rather than raising."""
    dmarc = await check_dmarc_dns(domain_name)
    dmarc_stage = _dmarc_stage_from_policy(dmarc["policy"]) if dmarc["exists"] else "none"

    spf_record = await fetch_spf_record(domain_name)
    spf_qualifier = None
    if spf_record:
        _, spf_qualifier = parse_spf_record(spf_record)

    mta_sts_dns = await check_mta_sts_dns(domain_name)
    tls_stage = "none"
    mta_sts_mode = None
    if mta_sts_dns["exists"]:
        mta_sts_policy = await fetch_mta_sts_policy(domain_name)
        mta_sts_mode = mta_sts_policy.get("mode")
        tls_stage = _tls_stage_from_mode(mta_sts_mode)

    posture = compute_posture(
        dmarc_stage=dmarc_stage, dmarc_comp=None,
        tls_stage=tls_stage, tls_pass_pct=None,
        min_cert_days=None,
    )

    return {
        "domain": domain_name,
        "score": posture["score"],
        "grade": posture["grade"],
        "grade_color": posture["color"],
        "checks": [
            {
                "label": "Email Authentication (DMARC)",
                "found": dmarc["exists"],
                "detail": (
                    f"DMARC record found — policy is p={dmarc_stage}."
                    if dmarc["exists"]
                    else "No DMARC record found — spoofed email using this domain isn't blocked at all."
                ),
            },
            {
                "label": "Sender Policy (SPF)",
                "found": spf_record is not None,
                "detail": (
                    f"SPF record found — ends {spf_qualifier}."
                    if spf_record
                    else "No SPF record found."
                ),
            },
            {
                "label": "Mail Transport Security (MTA-STS)",
                "found": mta_sts_dns["exists"],
                "detail": (
                    f"MTA-STS policy found — mode is {mta_sts_mode or 'unknown'}."
                    if mta_sts_dns["exists"]
                    else "No MTA-STS record found — mail delivery has no downgrade/interception protection."
                ),
            },
        ],
        "not_assessed": NOT_ASSESSED,
    }
