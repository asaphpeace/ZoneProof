"""
Sentinel Command Tier 0 — Host & Server Security, VPS/SSH half.

Two things are genuinely, empirically verified here: SSH keypair generation
(real cryptography, no mocking) and the Lynis report.dat parser (given a
hand-authored sample). The exact remote Lynis CLI invocation and real-world
report.dat shape are NOT verified against a real Lynis run — see
host_scan_service.py's module docstring for why (no safe way to install and
exercise the real binary in this environment).
"""
import base64
import hashlib
import io

import paramiko

from app.services.host_scan_service import (
    _docker_container_severity,
    _parse_docker_inventory,
    _parse_lynis_report,
    generate_ssh_keypair,
)


def test_generate_ssh_keypair_produces_a_loadable_ed25519_key():
    private_pem, public_openssh, fingerprint = generate_ssh_keypair()

    assert private_pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert public_openssh.startswith("ssh-ed25519 ")
    assert fingerprint.startswith("SHA256:")

    # Round-trips through paramiko exactly the way the real connect() path does.
    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(private_pem))
    assert pkey.get_name() == "ssh-ed25519"

    # Matches the standard ssh-keygen -lf computation: SHA256 of the public
    # key's raw wire-format blob, base64, no padding.
    blob = base64.b64decode(public_openssh.split()[1])
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    assert fingerprint == expected


def test_generate_ssh_keypair_produces_unique_keys_each_call():
    _, pub1, fp1 = generate_ssh_keypair()
    _, pub2, fp2 = generate_ssh_keypair()
    assert pub1 != pub2
    assert fp1 != fp2


_SAMPLE_LYNIS_REPORT = """
lynis_version=3.0.9
os_name=Linux
warning[]=SSH-7408|Root can directly login via SSH|-|
suggestion[]=AUTH-9328|Default umask in /etc/login.defs is not configured|-|
warning[]=FIRE-4590|No firewall software installed|-|
hardening_index=64|70
"""


def test_parse_lynis_report_extracts_warnings_and_suggestions():
    results = _parse_lynis_report(_SAMPLE_LYNIS_REPORT)
    assert len(results) == 3

    warnings = [r for r in results if r["severity"] == "high"]
    suggestions = [r for r in results if r["severity"] == "medium"]
    assert len(warnings) == 2
    assert len(suggestions) == 1

    ssh_finding = next(r for r in warnings if r["check_id"] == "SSH-7408")
    assert "Root can directly login" in ssh_finding["title"]
    assert ssh_finding["detail"].startswith("SSH-7408|")


def test_parse_lynis_report_handles_empty_and_malformed_input():
    assert _parse_lynis_report("") == []
    assert _parse_lynis_report("not lynis output at all\nrandom garbage") == []
    assert _parse_lynis_report("warning[]=\nwarning[]=|") == []


# ── Close scan-data gaps for the attack simulation engine: Lynis' own real
# severity rating (previously never read — every warning/suggestion got a
# fake binary guess), and its vulnerable-package detection (previously
# discarded entirely). Field layout verified against a real community
# report.dat parser, not guessed. ──

def test_parse_lynis_report_uses_lynis_own_severity_when_populated():
    # Real severity in the 3rd field: C/S -> critical, H -> high (same as
    # today's default for a warning, but for the RIGHT reason now), M ->
    # medium, L/I -> low.
    report = (
        "warning[]=SSH-7408|Root can directly login via SSH|C|\n"
        "suggestion[]=AUTH-9328|Default umask not configured|L|\n"
    )
    results = _parse_lynis_report(report)
    ssh = next(r for r in results if r["check_id"] == "SSH-7408")
    auth = next(r for r in results if r["check_id"] == "AUTH-9328")
    assert ssh["severity"] == "critical"
    assert auth["severity"] == "low"


def test_parse_lynis_report_falls_back_to_default_when_lynis_severity_is_blank():
    # "-" is real, common Lynis output (not every check populates
    # severity) — must fall back to the existing per-kind default, never
    # crash or silently drop the finding.
    report = "warning[]=FIRE-4590|No firewall software installed|-|\n"
    [result] = _parse_lynis_report(report)
    assert result["severity"] == "high"


def test_parse_lynis_report_extracts_vulnerable_packages():
    report = "vulnerable_package[]=openssl-1.0.1|CVE info here|\n"
    [result] = _parse_lynis_report(report)
    assert result["check_id"] == "lynis_vulnerable_package_openssl-1.0.1"
    assert "openssl-1.0.1" in result["title"]
    assert result["severity"] == "high"


def test_parse_lynis_report_disambiguates_multiple_vulnerable_packages():
    # Distinct check_ids — must not collide in reconcile_findings' own
    # (check_id, resource_uid) dedup key the way a single shared check_id
    # would.
    report = (
        "vulnerable_package[]=openssl-1.0.1|-|\n"
        "vulnerable_package[]=curl-7.29|-|\n"
    )
    results = _parse_lynis_report(report)
    assert {r["check_id"] for r in results} == {
        "lynis_vulnerable_package_openssl-1.0.1", "lynis_vulnerable_package_curl-7.29",
    }


# ── Docker container inventory (tightly-scoped sudoers `docker ps`) ───────
# Fixture shape modeled on a real, live-captured `docker ps --no-trunc`
# run against the real SEDAC-DEV instance during this session's own
# sudoers debugging — includes the real "Up 2 months (healthy)" STATUS
# value with an embedded space, the exact case that breaks a naive
# whitespace-split parser.

_SAMPLE_DOCKER_PS_OUTPUT = (
    'CONTAINER ID    IMAGE           COMMAND               CREATED        STATUS                  PORTS                               NAMES\n'
    'abc123def456    sedna-backend   "uvicorn app.main"    2 months ago   Up 2 months             8000/tcp                            sedna-backend-1\n'
    'def456abc789    sedna-web       "caddy run"           2 months ago   Up 2 months             0.0.0.0:80->80/tcp, :::80->80/tcp   sedna-web-1\n'
    '789abc123def0   postgres:16     "docker-entrypoint"   2 months ago   Up 2 months (healthy)   5432/tcp                            sedna-db-1'
)


def test_parse_docker_inventory_extracts_all_real_containers():
    results = _parse_docker_inventory(_SAMPLE_DOCKER_PS_OUTPUT)
    assert len(results) == 3
    names = {r["name"] for r in results}
    assert names == {"sedna-backend-1", "sedna-web-1", "sedna-db-1"}


def test_parse_docker_inventory_handles_status_value_with_embedded_space():
    # "Up 2 months (healthy)" has two internal spaces — a naive
    # whitespace split would misread this as extra columns; position-
    # based parsing must not.
    results = _parse_docker_inventory(_SAMPLE_DOCKER_PS_OUTPUT)
    db = next(r for r in results if r["name"] == "sedna-db-1")
    assert db["status"] == "Up 2 months (healthy)"
    assert db["image"] == "postgres:16"
    assert db["ports"] == "5432/tcp"


def test_parse_docker_inventory_captures_published_ports_with_commas():
    results = _parse_docker_inventory(_SAMPLE_DOCKER_PS_OUTPUT)
    web = next(r for r in results if r["name"] == "sedna-web-1")
    assert web["ports"] == "0.0.0.0:80->80/tcp, :::80->80/tcp"


def test_parse_docker_inventory_handles_empty_and_malformed_input():
    assert _parse_docker_inventory("") == []
    assert _parse_docker_inventory("not docker output at all\nrandom garbage") == []


def test_docker_container_severity_medium_for_a_published_port():
    assert _docker_container_severity("0.0.0.0:80->80/tcp, :::80->80/tcp") == "medium"
    assert _docker_container_severity(":::443->443/tcp") == "medium"


def test_docker_container_severity_low_for_internal_only():
    assert _docker_container_severity("8000/tcp") == "low"
    assert _docker_container_severity("") == "low"
