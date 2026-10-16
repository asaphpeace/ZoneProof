"""
CIS AWS Foundations Benchmark control numbers and MITRE ATT&CK technique IDs
for Prowler-sourced findings — loaded directly from the JSON crosswalk files
Prowler itself ships (…/prowler/compliance/aws/{cis_5.0_aws,mitre_attack_aws}
.json) inside its isolated venv, not hand-maintained here. This is genuine,
Prowler-curated crosswalk data, not a guess — see BUILD_PLAN.md.

Scope: this only ever matches Prowler's own check_id values (e.g.
"iam_root_mfa_enabled"). Amazon Inspector findings key on a finding ARN,
Lynis findings on a Lynis test ID, and Exposure findings on our own
EXPOSURE-* ids — none of those exist in Prowler's crosswalk, so lookups for
them correctly return empty rather than a false match.

Loaded lazily and cached at module scope. If the venv/files aren't present
(Prowler never installed in this environment), lookups just return empty
results rather than raising — compliance tagging is enrichment, never
something that should break a scan pass or a findings list.
"""
import functools
import json
import logging
from pathlib import Path

from app.config import settings

_log = logging.getLogger(__name__)


def _find_prowler_compliance_dir() -> Path | None:
    try:
        venv_root = Path(settings.command_prowler_bin).resolve().parents[1]
    except IndexError:
        return None
    # Try the standard venv layout directly before falling back to a
    # recursive glob. `.venv-prowler` contains boto3/botocore's full
    # per-service JSON model tree (tens of thousands of files) — a
    # recursive Path.glob("**/...") walks all of it in pure Python with no
    # OS-level shortcut, synchronously, inside this async request handler.
    # Measured to block the entire event loop for minutes on Windows the
    # first time this ran (this function is @lru_cache'd, so it only fires
    # once per process, but that one time froze every concurrent request —
    # found by a real findings list hanging, not assumed from the code).
    windows_layout = venv_root / "Lib" / "site-packages" / "prowler" / "compliance" / "aws"
    if windows_layout.is_dir():
        return windows_layout
    posix_matches = list(venv_root.glob("lib/python*/site-packages/prowler/compliance/aws"))
    if posix_matches:
        return posix_matches[0]
    # Last resort for a non-standard layout — same expensive walk as
    # before, but only reached if neither known layout matched.
    matches = list(venv_root.glob("**/prowler/compliance/aws"))
    return matches[0] if matches else None


@functools.lru_cache(maxsize=1)
def _load_cis_check_map() -> dict[str, list[str]]:
    """check_id -> list of CIS AWS Foundations Benchmark control ids, e.g. ["1.5"]."""
    compliance_dir = _find_prowler_compliance_dir()
    if not compliance_dir:
        return {}
    cis_file = compliance_dir / "cis_5.0_aws.json"
    if not cis_file.exists():
        return {}
    try:
        data = json.loads(cis_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        _log.warning("Could not load CIS compliance mapping from %s", cis_file)
        return {}

    mapping: dict[str, list[str]] = {}
    for req in data.get("Requirements", []):
        control_id = req.get("Id")
        if not control_id:
            continue
        for check_id in req.get("Checks", []):
            mapping.setdefault(check_id, []).append(control_id)
    return mapping


@functools.lru_cache(maxsize=1)
def _load_attack_check_map() -> dict[str, list[dict]]:
    """check_id -> list of {id, name, tactics} MITRE ATT&CK technique dicts."""
    compliance_dir = _find_prowler_compliance_dir()
    if not compliance_dir:
        return {}
    attack_file = compliance_dir / "mitre_attack_aws.json"
    if not attack_file.exists():
        return {}
    try:
        data = json.loads(attack_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        _log.warning("Could not load MITRE ATT&CK compliance mapping from %s", attack_file)
        return {}

    mapping: dict[str, list[dict]] = {}
    for req in data.get("Requirements", []):
        technique_id = req.get("Id")
        if not technique_id:
            continue
        technique = {"id": technique_id, "name": req.get("Name"), "tactics": req.get("Tactics", [])}
        for check_id in req.get("Checks", []):
            mapping.setdefault(check_id, []).append(technique)
    return mapping


def cis_controls_for_check(check_id: str | None) -> list[str]:
    if not check_id:
        return []
    return _load_cis_check_map().get(check_id, [])


def attack_techniques_for_check(check_id: str | None) -> list[dict]:
    if not check_id:
        return []
    return _load_attack_check_map().get(check_id, [])
