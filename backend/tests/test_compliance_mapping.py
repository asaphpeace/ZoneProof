"""
compliance_mapping.py reads real JSON files Prowler itself ships inside its
isolated venv (.venv-prowler) — these tests exercise that real data, not a
mock, since the whole point of this module is "don't hand-maintain a
crosswalk, load Prowler's own." Skipped if Prowler isn't installed in this
environment (matches the skip pattern already used for other
Prowler-binary-dependent tests).
"""
import pytest

from app.services import compliance_mapping


def _prowler_installed() -> bool:
    return compliance_mapping._find_prowler_compliance_dir() is not None


@pytest.mark.skipif(not _prowler_installed(), reason="Prowler not installed in .venv-prowler")
def test_cis_controls_for_a_real_known_check():
    controls = compliance_mapping.cis_controls_for_check("iam_root_mfa_enabled")
    assert controls  # at least one real CIS control maps to this check
    assert all(isinstance(c, str) for c in controls)


@pytest.mark.skipif(not _prowler_installed(), reason="Prowler not installed in .venv-prowler")
def test_attack_techniques_for_a_real_known_check():
    techniques = compliance_mapping.attack_techniques_for_check("iam_root_mfa_enabled")
    assert techniques
    assert all("id" in t and t["id"].startswith("T") for t in techniques)


def test_cis_controls_for_unknown_check_returns_empty():
    assert compliance_mapping.cis_controls_for_check("this_check_does_not_exist_xyz") == []


def test_attack_techniques_for_unknown_check_returns_empty():
    assert compliance_mapping.attack_techniques_for_check("this_check_does_not_exist_xyz") == []


def test_lookups_handle_none_check_id_gracefully():
    assert compliance_mapping.cis_controls_for_check(None) == []
    assert compliance_mapping.attack_techniques_for_check(None) == []


def test_lookups_return_empty_when_compliance_dir_not_found(monkeypatch):
    monkeypatch.setattr(compliance_mapping, "_find_prowler_compliance_dir", lambda: None)
    compliance_mapping._load_cis_check_map.cache_clear()
    compliance_mapping._load_attack_check_map.cache_clear()
    try:
        assert compliance_mapping.cis_controls_for_check("iam_root_mfa_enabled") == []
        assert compliance_mapping.attack_techniques_for_check("iam_root_mfa_enabled") == []
    finally:
        compliance_mapping._load_cis_check_map.cache_clear()
        compliance_mapping._load_attack_check_map.cache_clear()
