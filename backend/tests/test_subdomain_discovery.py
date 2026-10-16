"""
Unit tests for the pure hostname-matching helper in subdomain_discovery_service.py.
The merge/sort/DB-backed parts (discover_subdomains) need a real session and
are exercised manually against the running app, not here — this covers the
one piece of logic that's easy to get subtly wrong: matching a hostname to
its parent domain without false positives on lookalike domains.
"""
import inspect

from app.services.subdomain_discovery_service import _is_subdomain, discover_subdomains, _ACTIVE_CANDIDATES


def test_direct_subdomain_matches():
    assert _is_subdomain("mail.example.com", "example.com") is True


def test_root_domain_itself_does_not_match():
    assert _is_subdomain("example.com", "example.com") is False


def test_lookalike_domain_does_not_match():
    """notexample.com must not be treated as a subdomain of example.com."""
    assert _is_subdomain("notexample.com", "example.com") is False


def test_sibling_domain_does_not_match():
    assert _is_subdomain("example.org", "example.com") is False


def test_case_and_trailing_dot_are_normalized():
    assert _is_subdomain("Mail.Example.com.", "example.com") is True


def test_nested_subdomain_matches():
    assert _is_subdomain("a.b.mail.example.com", "example.com") is True


# ── Active-probing gate (Part 1 source #4) ───────────────────────────────────

def test_active_probing_defaults_to_off():
    """allow_active must default to False — callers (e.g. a future /scan
    integration) that forget to pass it explicitly must not get active probing."""
    sig = inspect.signature(discover_subdomains)
    assert sig.parameters["allow_active"].default is False


def test_active_candidate_wordlist_stays_small_and_email_relevant():
    """Guards against this quietly growing into a generic brute-force list.
    Raised from 15 to 75 on 2026-10-15 for the bounded email-scoped list; the
    stricter content checks live in test_subdomain_sources.py."""
    assert len(_ACTIVE_CANDIDATES) <= 75
    assert "mail" in _ACTIVE_CANDIDATES
    assert "mta-sts" in _ACTIVE_CANDIDATES
