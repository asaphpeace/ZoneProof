"""
Compute overall security posture and letter grade for a domain,
and aggregate a portfolio-level Sentinel Score for the tenant.
"""
from __future__ import annotations

from dataclasses import dataclass


# ── Per-domain grade thresholds (used for DomainTable grade badges) ──────────

GRADE_THRESHOLDS = [
    # (min_score, grade, color)
    # DMARC pillar is worth 65 pts max; a domain reaches B on DMARC alone at p=reject+100%
    (95, "A+", "#34e0a1"),
    (85, "A",  "#34e0a1"),
    (62, "B",  "#2ee6c5"),
    (42, "C",  "#f5c542"),
    (25, "D",  "#f5a23d"),
    (0,  "F",  "#ff4d6d"),
]

# ── Sentinel Score grade bands ───────────────────────────────────────────────

SENTINEL_BANDS = [
    (90, "A", "#34e0a1", "Fully protected"),
    (75, "B", "#5b6ef5", "Strong posture"),
    (55, "C", "#f5c542", "Partial coverage"),
    (35, "D", "#ff8c42", "Significant gaps"),
    (0,  "F", "#ff4d6d", "At risk"),
]


# ── Per-domain sub-scores ─────────────────────────────────────────────────────

def _dmarc_score(stage: str, comp: float | None) -> float:
    """0–65 points for DMARC (used for per-domain grade).
    Stage: reject=40, quarantine=28, monitor=12, none=0
    Compliance %: up to 25 additional pts.
    A domain at p=reject with 100% compliance scores 65/100 on this pillar alone — enough for grade B.
    """
    stage_pts = {"reject": 40, "quarantine": 28, "monitor": 12, "none": 0}.get(stage, 0)
    comp_pts = (comp or 0) / 100 * 25
    return stage_pts + comp_pts


def _tls_score(stage: str, pass_pct: float | None) -> float:
    """0–25 points for TLS / MTA-STS (used for per-domain grade).
    Stage: enforce=20, testing=12, none=0 — absence no longer fatal.
    Pass quality: up to 5 additional pts.
    """
    stage_pts = {"enforce": 20, "testing": 12, "none": 0}.get(stage, 0)
    pass_pts = (pass_pct or 0) / 100 * 5
    return stage_pts + pass_pts


def _cert_score(min_days: int | None) -> float:
    """0–10 points for certificate health (used for per-domain grade).
    Reduced from 20 — cert issues matter but shouldn't be the deciding factor.
    None means no cert data (no MTA-STS), treated as 0 rather than penalised separately.
    """
    if min_days is None:
        return 0
    if min_days < 0:
        return 0
    if min_days < 7:
        return 2
    if min_days < 30:
        return 6
    return 10


def compute_posture(
    dmarc_stage: str,
    dmarc_comp: float | None,
    tls_stage: str,
    tls_pass_pct: float | None,
    min_cert_days: int | None,
) -> dict:
    score = (
        _dmarc_score(dmarc_stage, dmarc_comp)
        + _tls_score(tls_stage, tls_pass_pct)
        + _cert_score(min_cert_days)
    )
    score = min(100, score)
    for threshold, grade, color in GRADE_THRESHOLDS:
        if score >= threshold:
            return {"score": round(score, 1), "grade": grade, "color": color}
    return {"score": 0, "grade": "F", "color": "#ff4d6d"}


# ── Sentinel Score pillars ────────────────────────────────────────────────────
# Max points: DMARC 60 + TLS 25 + Certs 15 = 100

def _sentinel_dmarc_pts(stage: str) -> float:
    """0–60 pts: DMARC enforcement stage."""
    return {"reject": 60, "quarantine": 40, "monitor": 20, "none": 0}.get(stage or "none", 0)


def _sentinel_tls_pts(stage: str, pass_pct: float | None) -> float:
    """0–25 pts: MTA-STS enforcement + TLS pass quality."""
    if stage == "enforce":
        return 25 if (pass_pct or 0) >= 99 else 18
    if stage == "testing":
        return 10
    return 0


def _sentinel_cert_pts(min_days: int | None, cert_status: str | None) -> float:
    """0–15 pts: certificate health."""
    if cert_status == "expired":
        return 0
    if cert_status == "critical" or (min_days is not None and min_days < 7):
        return 2
    if cert_status == "expiring_soon" or (min_days is not None and min_days < 30):
        return 8
    return 15


@dataclass
class DomainSentinelInput:
    dmarc_stage: str
    tls_stage: str
    tls_pass_pct: float | None
    min_cert_days: int | None
    cert_status: str | None
    volume: int   # mail volume — used for weighting


@dataclass
class SentinelResult:
    score: int                  # 0–100 portfolio score
    grade: str                  # A / B / C / D / F
    grade_color: str
    grade_label: str
    pillar_dmarc: float         # portfolio-weighted DMARC points (0–60, email-auth pillar's own 100-scale)
    pillar_tls: float           # portfolio-weighted TLS points   (0–25,     "        "        "    )
    pillar_certs: float         # portfolio-weighted cert points  (0–15,     "        "        "    )
    volume_weighted: bool       # True if volume data was available
    pillar_cloud_posture: float | None  # 0–100 on Cloud Posture's own scale; None if no connected cloud account
    pillar_human_risk: float | None = None  # 0–100 on Human Risk's own scale; None if no phishing campaign history
    pillar_verified_exploitability: float | None = None  # 0–100 real per-Finding exploitability rollup; None if nothing scored yet
    pillar_brand_exposure: float | None = None  # 0–100 look-alike domain exposure (brand_exposure.py); None if no active, scanned brand


# ── Cross-domain composite weights (ARCHITECTURE.md Section 8) ───────────────
# Full target: Email Auth 20 / Cloud Posture 15 / External Exposure 15 /
# Credential Hygiene 10 / Human Risk 15 / Verified Exploitability 25 = 100.
# Verified Exploitability now exists (exploitability_service.py). Email
# Auth, Cloud Posture, Human Risk, and now Verified Exploitability exist
# today (Tier 2, External Exposure/Credential Hygiene as standalone
# pillars, isn't built) — renormalized across whatever signals are actually
# available below, so adding a tier later is a matter of adding one more
# term to the sum, not a rewrite. This is why _EMAIL_AUTH_WEIGHT/
# _CLOUD_POSTURE_WEIGHT/_HUMAN_RISK_WEIGHT aren't used as raw percentages
# directly.
_EMAIL_AUTH_WEIGHT = 20
_CLOUD_POSTURE_WEIGHT = 15
_HUMAN_RISK_WEIGHT = 15
_BRAND_EXPOSURE_WEIGHT = 15      # same as Human Risk; None-means-absent, so it only counts for a tenant that uses Brand Guard
# The term this comment named but never had data for, until
# exploitability_service.py's real per-Finding scoring shipped.
_VERIFIED_EXPLOITABILITY_WEIGHT = 25


def compute_sentinel_score(
    domains: list[DomainSentinelInput],
    cloud_posture_score: float | None = None,
    human_risk_score: float | None = None,
    verified_exploitability_score: float | None = None,
    brand_exposure_score: float | None = None,
) -> SentinelResult:
    """
    Compute a volume-weighted portfolio Sentinel Score (0–100).
    Falls back to simple average when no domain has volume data.

    cloud_posture_score: 0-100, from cloud_scan_service's tenant-wide
    Cloud-Posture computation (BUILD_PLAN.md Phase 1 step 10). None means
    the tenant has no connected cloud account — in that case this returns
    exactly what it always has, unchanged, so shipping this doesn't quietly
    move an existing V1-only customer's score the day it deploys. Once a
    cloud account connects, the composite blends both signals, renormalized
    over whichever weights are actually available (see _EMAIL_AUTH_WEIGHT /
    _CLOUD_POSTURE_WEIGHT above).

    human_risk_score: 0-100, from phishing_service's tenant-wide Human Risk
    computation (Coverage Map plan phishing transformation, Phase 9). Same
    None-means-absent convention as cloud_posture_score — a tenant with no
    phishing campaign history sees no change to their score at all.

    verified_exploitability_score: 0-100, from exploitability_service's
    compute_tenant_verified_exploitability_score() — the real per-Finding
    exploitability rollup (CVSS/EPSS/exploit-available for CVEs, real
    reachability/policy-scope signals for everything else). Same
    None-means-absent convention: a tenant with no scored open findings
    yet sees no change to their score, never a fabricated perfect 100.
    """
    if not domains:
        return SentinelResult(
            score=0, grade="F", grade_color="#ff4d6d", grade_label="At risk",
            pillar_dmarc=0, pillar_tls=0, pillar_certs=0, volume_weighted=False,
            pillar_cloud_posture=cloud_posture_score, pillar_human_risk=human_risk_score,
            pillar_verified_exploitability=verified_exploitability_score, pillar_brand_exposure=brand_exposure_score,
        )

    total_volume = sum(d.volume for d in domains)
    use_weights = total_volume > 0

    weighted_dmarc = 0.0
    weighted_tls   = 0.0
    weighted_certs = 0.0

    for d in domains:
        w = d.volume / total_volume if use_weights else 1 / len(domains)
        weighted_dmarc += _sentinel_dmarc_pts(d.dmarc_stage) * w
        weighted_tls   += _sentinel_tls_pts(d.tls_stage, d.tls_pass_pct) * w
        weighted_certs += _sentinel_cert_pts(d.min_cert_days, d.cert_status) * w

    email_auth_score_0_100 = weighted_dmarc + weighted_tls + weighted_certs  # already 0-100 (60+25+15)

    weighted_terms = [(email_auth_score_0_100, _EMAIL_AUTH_WEIGHT)]
    if cloud_posture_score is not None:
        weighted_terms.append((cloud_posture_score, _CLOUD_POSTURE_WEIGHT))
    if human_risk_score is not None:
        weighted_terms.append((human_risk_score, _HUMAN_RISK_WEIGHT))
    if verified_exploitability_score is not None:
        weighted_terms.append((verified_exploitability_score, _VERIFIED_EXPLOITABILITY_WEIGHT))
    if brand_exposure_score is not None:
        weighted_terms.append((brand_exposure_score, _BRAND_EXPOSURE_WEIGHT))

    weight_sum = sum(w for _, w in weighted_terms)
    raw = sum(s * (w / weight_sum) for s, w in weighted_terms)

    score = min(100, max(0, round(raw)))

    grade, color, label = "F", "#ff4d6d", "At risk"
    for threshold, g, c, lbl in SENTINEL_BANDS:
        if score >= threshold:
            grade, color, label = g, c, lbl
            break

    return SentinelResult(
        score=score,
        grade=grade,
        grade_color=color,
        grade_label=label,
        pillar_dmarc=round(weighted_dmarc, 1),
        pillar_tls=round(weighted_tls, 1),
        pillar_certs=round(weighted_certs, 1),
        volume_weighted=use_weights,
        pillar_cloud_posture=round(cloud_posture_score, 1) if cloud_posture_score is not None else None,
        pillar_human_risk=round(human_risk_score, 1) if human_risk_score is not None else None,
        pillar_verified_exploitability=round(verified_exploitability_score, 1) if verified_exploitability_score is not None else None,
        pillar_brand_exposure=round(brand_exposure_score, 1) if brand_exposure_score is not None else None,
    )
