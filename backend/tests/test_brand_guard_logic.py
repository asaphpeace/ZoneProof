"""
Pure-logic tests for Brand Guard discovery + scoring — no DB, no network.
The scorer's job is noise control, so most of these pin down what must NOT be
flagged as well as what must.
"""
from datetime import datetime, timedelta, timezone

from app.services import brand_discovery_service as disc
from app.services.brand_scoring_service import assess_candidate

NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)
PRIMARY = "acmefinancial.co.za"
TOKENS = ["acmefinancial"]


def _assess(domain, *, enrichment=None, official=None, klass=None):
    return assess_candidate(
        domain, primary_domain=PRIMARY, official_domains=official or [], brand_tokens=TOKENS,
        discovery_class=klass, enrichment=enrichment or {}, now=NOW,
    )


# ── discovery ────────────────────────────────────────────────────────────────

def test_split_registrable_handles_second_level_za():
    assert disc.split_registrable("acme.co.za") == ("acme", "co.za")
    assert disc.split_registrable("www.acme.com") == ("acme", "com")


def test_skeleton_collapses_confusables():
    assert disc.skeleton("acmefinancia1") == disc.skeleton("acmefinancial")
    assert disc.skeleton("rnicrosoft") == disc.skeleton("microsoft")
    assert disc.skeleton("acmеfinancial") == disc.skeleton("acmefinancial")  # Cyrillic е


def test_edit_distance_counts_transposition_once():
    assert disc.edit_distance("acme", "acem") == 1
    assert disc.edit_distance("acme", "acme") == 0


def test_generate_candidates_covers_each_class_and_excludes_self():
    out = disc.generate_candidates(PRIMARY, "Acme Financial", ["pay"])
    assert PRIMARY not in out
    assert out["acmefinancia1.co.za"] == "homoglyph"
    assert out["login-acmefinancial.co.za"] == "combosquat"
    assert out["acmefinancial.com"] == "tld_swap"
    assert out["acmefinancal.co.za"] == "typo"
    assert any(d.startswith("xn--") for d in out), "IDN homoglyphs must be emitted as punycode"
    assert len(out) <= disc.MAX_CANDIDATES


def test_generate_candidates_refuses_tiny_brands():
    assert disc.generate_candidates("ab.com") == {}


def test_ct_fingerprint_refuses_short_tokens():
    assert disc.matches_brand_fingerprint("secure-acmefinancial-login.com", TOKENS) == "acmefinancial"
    assert disc.matches_brand_fingerprint("unrelated.com", TOKENS) is None
    assert disc.matches_brand_fingerprint("abcdef.com", ["abc"]) is None


# ── scoring ──────────────────────────────────────────────────────────────────

def test_customer_owned_domain_is_never_a_threat():
    a = _assess("acmefinancial.com", official=["acmefinancial.com"], enrichment={"has_a": True, "has_mx": True})
    assert a.suggested_status == "customer_owned"
    assert a.identity_score == 0 and a.abuse_score == 0 and not a.should_alert


def test_fresh_live_homoglyph_is_suspicious_and_alerts():
    a = _assess("acmefinancia1.co.za", klass="homoglyph", enrichment={
        "has_a": True, "has_mx": True, "registered_at": (NOW - timedelta(days=3)).isoformat(),
    })
    assert a.threat_class == "homoglyph"
    # Liveness carries no weight (measured, brand_eval.abuse_lr); this alerts because of the stated CLASS PRIOR for a visually identical
    # name, which is labelled an assumption in the evidence.
    assert a.suggested_status == "suspicious" and a.should_alert and a.urgency == "high"
    sig = {s.signal: s for s in a.signals}
    assert {"homoglyph", "new_registration", "mx_live", "dns_live", "class_prior"} <= set(sig)
    assert sig["dns_live"].weight == 0.0 and sig["class_prior"].data["basis"] == "expert" and "ASSUMPTION" in sig["class_prior"].summary


def test_fresh_live_ordinary_lookalike_without_abuse_evidence_is_watched_not_alerted():
    """The measured half of the story: liveness alone is not abuse evidence, so a live typo of the brand is something to watch."""
    a = _assess("acmefinancal.co.za", klass="typo", enrichment={
        "has_a": True, "has_mx": True, "registered_at": (NOW - timedelta(days=3)).isoformat(),
    })
    assert a.suggested_status != "suspicious" and not a.should_alert
    assert "class_prior" not in {s.signal for s in a.signals}


def test_fresh_live_homoglyph_with_real_abuse_evidence_scores_higher_still():
    base = _assess("acmefinancia1.co.za", klass="homoglyph", enrichment={"has_a": True, "has_mx": True, "registered_at": (NOW - timedelta(days=3)).isoformat()})
    listed = _assess("acmefinancia1.co.za", klass="homoglyph", enrichment={
        "has_a": True, "has_mx": True, "registered_at": (NOW - timedelta(days=3)).isoformat(),
        "feeds": [{"feed": "phishunt", "label": "phishunt.io", "first_seen": "2026-10-01", "same_site": False, "detail": {"other_flags": 0}}],
    })
    assert listed.abuse_score > base.abuse_score and listed.should_alert


def test_old_established_lookalike_is_not_flagged():
    """Identity similarity alone must not create an alert — a 5-year-old domain
    that merely resembles the brand is overwhelmingly an unrelated business."""
    a = _assess("acmefinancal.co.za", klass="typo", enrichment={
        "has_a": True, "registered_at": (NOW - timedelta(days=2000)).isoformat(),
    })
    assert not a.should_alert
    assert a.suggested_status == "monitoring"


def test_unresolving_lookalike_stays_low_abuse():
    a = _assess("acmefinancial.org", klass="tld_swap", enrichment={})
    assert a.abuse_score == 0
    assert not a.should_alert


def test_identity_and_abuse_are_independent():
    parked = _assess("acmefinancia1.co.za", klass="homoglyph", enrichment={"has_a": False, "has_mx": False})
    assert parked.identity_score >= 60
    assert parked.abuse_score < 30


def test_combosquat_with_lure_word_and_ct_cert():
    a = _assess("secure-acmefinancial-login.com", enrichment={
        "has_a": True, "ct_hit": True, "ct_cert_issued_at": (NOW - timedelta(hours=2)).isoformat(),
        "registered_at": (NOW - timedelta(days=1)).isoformat(),
    })
    names = {s.signal for s in a.signals}
    assert {"keyword_combo", "ct_certificate", "credential_lure_word", "recent_certificate"} <= names
    assert a.impact == "high"
    assert a.should_alert


def test_every_signal_has_summary_text():
    a = _assess("acmefinancia1.co.za", klass="homoglyph", enrichment={"has_a": True})
    assert a.signals and all(s.summary for s in a.signals)


def test_ct_poll_interval_is_configurable_with_a_floor(monkeypatch):
    from datetime import timedelta
    from app.config import settings
    from app.services import brand_guard_service as svc
    assert svc._ct_poll_interval() == timedelta(hours=6)
    monkeypatch.setattr(settings, "brand_guard_ct_poll_minutes", 60)
    assert svc._ct_poll_interval() == timedelta(hours=1)
    monkeypatch.setattr(settings, "brand_guard_ct_poll_minutes", 1)
    assert svc._ct_poll_interval() == timedelta(minutes=15)
