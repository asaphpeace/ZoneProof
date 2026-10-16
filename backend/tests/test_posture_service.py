"""
compute_sentinel_score's Cloud Posture blending (BUILD_PLAN.md Phase 1 step
10 / ARCHITECTURE.md Section 8's cross-domain composite score, renormalized
across whichever category weights actually exist today).

Key requirement: a tenant with no connected cloud account must get back
literally the same score as before this feature existed -- shipping this
must not quietly move an existing V1-only customer's number.
"""
from app.services.posture_service import DomainSentinelInput, compute_sentinel_score

_PERFECT_DOMAIN = DomainSentinelInput(
    dmarc_stage="reject", tls_stage="enforce", tls_pass_pct=100,
    min_cert_days=90, cert_status="ok", volume=1000,
)


def test_no_cloud_posture_arg_matches_pre_command_behavior_exactly():
    with_default = compute_sentinel_score([_PERFECT_DOMAIN])
    explicit_none = compute_sentinel_score([_PERFECT_DOMAIN], cloud_posture_score=None)

    assert with_default.score == explicit_none.score == 100
    assert with_default.pillar_cloud_posture is None
    assert explicit_none.pillar_cloud_posture is None


def test_perfect_cloud_posture_keeps_a_perfect_email_score_at_100():
    result = compute_sentinel_score([_PERFECT_DOMAIN], cloud_posture_score=100)
    assert result.score == 100
    assert result.pillar_cloud_posture == 100


def test_bad_cloud_posture_pulls_down_an_otherwise_perfect_email_score():
    perfect_email_only = compute_sentinel_score([_PERFECT_DOMAIN])
    blended = compute_sentinel_score([_PERFECT_DOMAIN], cloud_posture_score=0)

    assert perfect_email_only.score == 100
    # Cloud Posture is 15 of the 35 available weight points (20 email + 15
    # cloud) once it's present -- a 0 cloud score should knock the blended
    # score down by roughly 15/35 ~= 43%, not by some arbitrary amount.
    assert blended.score < perfect_email_only.score
    assert 55 <= blended.score <= 60


def test_cloud_posture_score_is_rounded_and_passed_through_unchanged():
    result = compute_sentinel_score([_PERFECT_DOMAIN], cloud_posture_score=72.456)
    assert result.pillar_cloud_posture == 72.5


def test_empty_domain_list_still_reports_cloud_posture_if_given():
    result = compute_sentinel_score([], cloud_posture_score=80)
    assert result.score == 0  # no email-auth signal at all -- unchanged existing behavior
    assert result.pillar_cloud_posture == 80


# ── Human Risk pillar (Coverage Map plan phishing transformation, Phase 9) ──
# Same "None must match pre-existing behavior exactly" requirement as Cloud
# Posture above -- a tenant with no phishing campaign history must see no
# change to their score at all.

def test_no_human_risk_arg_matches_pre_phase9_behavior_exactly():
    with_default = compute_sentinel_score([_PERFECT_DOMAIN])
    explicit_none = compute_sentinel_score([_PERFECT_DOMAIN], human_risk_score=None)

    assert with_default.score == explicit_none.score == 100
    assert with_default.pillar_human_risk is None
    assert explicit_none.pillar_human_risk is None


def test_perfect_human_risk_keeps_a_perfect_email_score_at_100():
    result = compute_sentinel_score([_PERFECT_DOMAIN], human_risk_score=100)
    assert result.score == 100
    assert result.pillar_human_risk == 100


def test_bad_human_risk_pulls_down_an_otherwise_perfect_email_score():
    perfect_email_only = compute_sentinel_score([_PERFECT_DOMAIN])
    blended = compute_sentinel_score([_PERFECT_DOMAIN], human_risk_score=0)

    assert perfect_email_only.score == 100
    # Human Risk is 15 of the 35 available weight points (20 email + 15
    # human risk) once it's present -- a 0 score should knock the blended
    # score down by roughly 15/35 ~= 43%, not by some arbitrary amount.
    assert blended.score < perfect_email_only.score
    assert 55 <= blended.score <= 60


def test_human_risk_score_is_rounded_and_passed_through_unchanged():
    result = compute_sentinel_score([_PERFECT_DOMAIN], human_risk_score=63.789)
    assert result.pillar_human_risk == 63.8


def test_cloud_posture_and_human_risk_blend_together_when_both_present():
    # 20 email + 15 cloud + 15 human risk = 50 total weight points.
    result = compute_sentinel_score([_PERFECT_DOMAIN], cloud_posture_score=100, human_risk_score=100)
    assert result.score == 100
    assert result.pillar_cloud_posture == 100
    assert result.pillar_human_risk == 100

    result_bad_human = compute_sentinel_score([_PERFECT_DOMAIN], cloud_posture_score=100, human_risk_score=0)
    assert result_bad_human.score < 100
    # human risk is 15 of 50 points here -- a 0 should cost ~30%, not ~43%.
    assert 68 <= result_bad_human.score <= 73


def test_empty_domain_list_still_reports_human_risk_if_given():
    result = compute_sentinel_score([], human_risk_score=40)
    assert result.score == 0  # no email-auth signal at all -- unchanged existing behavior
    assert result.pillar_human_risk == 40


# ── Verified Exploitability pillar (exploitability_service.py) — the term
# this file's own module comment named and reserved (ARCHITECTURE.md
# Section 8) since before it had any real data behind it. Same "None must
# match pre-existing behavior exactly" requirement as the two pillars above.

def test_no_verified_exploitability_arg_matches_pre_existing_behavior_exactly():
    with_default = compute_sentinel_score([_PERFECT_DOMAIN])
    explicit_none = compute_sentinel_score([_PERFECT_DOMAIN], verified_exploitability_score=None)

    assert with_default.score == explicit_none.score == 100
    assert with_default.pillar_verified_exploitability is None
    assert explicit_none.pillar_verified_exploitability is None


def test_perfect_verified_exploitability_keeps_a_perfect_email_score_at_100():
    result = compute_sentinel_score([_PERFECT_DOMAIN], verified_exploitability_score=100)
    assert result.score == 100
    assert result.pillar_verified_exploitability == 100


def test_bad_verified_exploitability_pulls_down_an_otherwise_perfect_email_score():
    perfect_email_only = compute_sentinel_score([_PERFECT_DOMAIN])
    blended = compute_sentinel_score([_PERFECT_DOMAIN], verified_exploitability_score=0)

    assert perfect_email_only.score == 100
    # Verified Exploitability is 25 of the 45 available weight points (20
    # email + 25 exploitability) once it's present -- a 0 score should
    # knock the blended score down by roughly 25/45 ~= 56%, not an
    # arbitrary amount.
    assert blended.score < perfect_email_only.score
    assert 42 <= blended.score <= 47


def test_verified_exploitability_score_is_rounded_and_passed_through_unchanged():
    result = compute_sentinel_score([_PERFECT_DOMAIN], verified_exploitability_score=81.234)
    assert result.pillar_verified_exploitability == 81.2


def test_all_three_optional_pillars_blend_together_when_present():
    # 20 email + 15 cloud + 15 human risk + 25 exploitability = 75 total.
    result = compute_sentinel_score(
        [_PERFECT_DOMAIN], cloud_posture_score=100, human_risk_score=100, verified_exploitability_score=100,
    )
    assert result.score == 100
    assert result.pillar_verified_exploitability == 100

    result_bad_exploitability = compute_sentinel_score(
        [_PERFECT_DOMAIN], cloud_posture_score=100, human_risk_score=100, verified_exploitability_score=0,
    )
    assert result_bad_exploitability.score < 100
    # exploitability is 25 of 75 points here -- a 0 should cost ~33%, not
    # the ~56% it costs when it's the only optional pillar present.
    assert 63 <= result_bad_exploitability.score <= 70


def test_empty_domain_list_still_reports_verified_exploitability_if_given():
    result = compute_sentinel_score([], verified_exploitability_score=55)
    assert result.score == 0  # no email-auth signal at all -- unchanged existing behavior
    assert result.pillar_verified_exploitability == 55
