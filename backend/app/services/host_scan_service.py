"""
Sentinel Command Tier 0 — Host & Server Security, VPS/SSH half.

Amazon Inspector (cloud_scan_service.py) only ever sees AWS EC2 instances
through the cloud control plane. This module covers everything else: a
plain VPS on any provider (or no provider at all), reached over SSH and
audited with Lynis (CISOfy's open-source system-hardening scanner).

Credential model, per HostConnection's own docstring: we generate our own
SSH keypair per connection and the customer installs only the public key on
a scoped read-only audit user they create themselves. We never hold the
customer's SSH credential — same "no stored secret" property
CloudAccountConnection's AWS role-assumption already has. Our own private
key (the one thing we do generate and must keep) is Fernet-encrypted at
rest via crypto_service.

Trust boundary the other direction: the SERVER's SSH host key is pinned
trust-on-first-use (HostConnection.host_key_fingerprint) on the first
successful verify, and every connection after that must match it. A silent
host-key change is either a legitimate host rebuild or a MITM, and this
product's whole premise is not guessing which without telling anyone.

KNOWN LIMITATION: the exact Lynis CLI invocation and report.dat format below
are written to Lynis's publicly documented conventions, not empirically
verified against a real Lynis run — this Windows dev environment has no
safe way to install and exercise the real Lynis binary (see BUILD_PLAN.md's
note on this). generate_ssh_keypair() and the report.dat *parser* (given a
sample report) are both real, tested code; only the exact remote command
line and Lynis's real-world output shape are unverified. Confirm against a
real Lynis run before trusting this in production.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import logging
import uuid
from datetime import datetime, timezone

import paramiko
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Engagement, Finding, HostConnection
from app.services.crypto_service import decrypt_secret
from app.services.exploitability_service import score_and_stamp
from app.services.finding_reconciliation import reconcile_findings

_log = logging.getLogger(__name__)

_SSH_CONNECT_TIMEOUT = 15
_SSH_COMMAND_TIMEOUT = 300

# Lynis' two-tier finding model: warnings are things it found wrong,
# suggestions are hardening recommendations. These are the fallback
# defaults used only when Lynis's own severity field (see
# _LYNIS_SEVERITY_MAP below) is empty for a given line — which is common,
# not a sign of a parsing bug — never when it's actually populated.
_LYNIS_WARNING_SEVERITY = "high"
_LYNIS_SUGGESTION_SEVERITY = "medium"

# Lynis' own real severity rating — the 3rd pipe-delimited field on
# warning[]/suggestion[] lines — verified against a real community
# report.dat parser (d4t4king/lynis-report-converter), not guessed: C/S
# map to this product's "critical", H to "high", M to "medium", L/I to
# "low". A blank or "-" value (common — Lynis doesn't always populate
# this) falls through to the two defaults above instead of guessing.
_LYNIS_SEVERITY_MAP = {
    "C": "critical", "S": "critical",
    "H": "high",
    "M": "medium",
    "L": "low", "I": "low",
}


def _fingerprint(key_blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")


def generate_ssh_keypair() -> tuple[str, str, str]:
    """Returns (private_key_pem, public_key_openssh, fingerprint). Ed25519 —
    smaller keys, faster, and the modern default (OpenSSH itself has
    recommended Ed25519 over RSA since 6.5)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8") + " sentinel-command"

    key_blob = base64.b64decode(public_openssh.split()[1])
    fingerprint = _fingerprint(key_blob)

    return private_pem, public_openssh, fingerprint


def _load_private_key(pem: str) -> paramiko.PKey:
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))


def _connect(connection: HostConnection) -> paramiko.SSHClient:
    """Raises on any failure — caller decides what that means for status."""
    pkey = _load_private_key(decrypt_secret(connection.encrypted_private_key))

    client = paramiko.SSHClient()
    # We verify the host key ourselves, against our own pin, right after
    # connecting — not paramiko's own known_hosts mechanism, which has
    # nothing to pin against on a fresh server and no persistence across
    # our stateless app processes anyway.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=connection.hostname_or_ip,
        port=connection.ssh_port,
        username=connection.ssh_username,
        pkey=pkey,
        timeout=_SSH_CONNECT_TIMEOUT,
        banner_timeout=_SSH_CONNECT_TIMEOUT,
        auth_timeout=_SSH_CONNECT_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


class HostKeyMismatchError(Exception):
    """The server's SSH host key doesn't match what we pinned on first
    connect. Could be a legitimate host rebuild; could be a MITM. Either
    way this is a decision for the customer, not something to silently
    proceed past."""


def _check_host_key(client: paramiko.SSHClient, connection: HostConnection) -> str:
    transport = client.get_transport()
    remote_key = transport.get_remote_server_key()
    remote_fp = _fingerprint(remote_key.asbytes())

    if connection.host_key_fingerprint and connection.host_key_fingerprint != remote_fp:
        raise HostKeyMismatchError(
            f"Host key changed since first connect: pinned={connection.host_key_fingerprint} now={remote_fp}"
        )
    return remote_fp


def _verify_sync(connection: HostConnection) -> str:
    """Runs the blocking paramiko connect + a trivial command, off the
    event loop (see verify_host_connection). Returns the confirmed host key
    fingerprint on success; raises on any failure."""
    client = _connect(connection)
    try:
        fingerprint = _check_host_key(client, connection)
        _, stdout, _ = client.exec_command("echo sentinel-ok", timeout=_SSH_CONNECT_TIMEOUT)
        stdout.channel.recv_exit_status()
        return fingerprint
    finally:
        client.close()


async def verify_host_connection(db: AsyncSession, connection: HostConnection) -> bool:
    try:
        fingerprint = await asyncio.to_thread(_verify_sync, connection)
    except HostKeyMismatchError as e:
        _log.warning("Host connection verify failed (host key mismatch): connection_id=%s error=%s", connection.id, e)
        connection.status = "error"
        await db.commit()
        return False
    except Exception as e:
        # paramiko raises a wide variety of exception types for the many
        # ways an SSH connect can fail (auth, network, protocol) — none of
        # them indicate a bug in this code, all of them mean "could not
        # verify," so they're handled uniformly rather than enumerated.
        _log.warning("Host connection verify failed: connection_id=%s error=%s", connection.id, e)
        connection.status = "error"
        await db.commit()
        return False

    if connection.host_key_fingerprint is None:
        connection.host_key_fingerprint = fingerprint  # TOFU pin
    connection.status = "connected"
    connection.connected_at = datetime.now(timezone.utc)
    await db.commit()
    return True


# ── Lynis scan pass ──────────────────────────────────────────────────────────

# Deliberately no sudo: the customer creates a scoped, unprivileged audit
# user (same "least privilege" shape as the AWS read-only role), so this
# runs in Lynis' own unprivileged mode — fewer checks than a root run, but
# consistent with never asking for more access than we need. --quick skips
# the interactive pauses Lynis normally has between test categories.
_LYNIS_REMOTE_COMMAND = (
    "REPORT_FILE=$(mktemp) && "
    "lynis audit system --quick --no-colors --report-file \"$REPORT_FILE\" > /dev/null 2>&1; "
    "cat \"$REPORT_FILE\" 2>/dev/null; "
    "rm -f \"$REPORT_FILE\""
)


def _run_lynis_sync(connection: HostConnection) -> str:
    client = _connect(connection)
    try:
        _check_host_key(client, connection)
        _, stdout, _ = client.exec_command(_LYNIS_REMOTE_COMMAND, timeout=_SSH_COMMAND_TIMEOUT)
        report = stdout.read().decode("utf-8", errors="replace")
        stdout.channel.recv_exit_status()
        return report
    finally:
        client.close()


def _parse_lynis_report(report_text: str) -> list[dict]:
    """Lynis' report.dat is a flat key=value file; repeated findings use a
    `key[]=` array marker and pipe-delimited fields. Unknown/malformed
    lines are skipped rather than raising — a partially-parseable report
    is still useful, and a scan pass failing outright over one odd line
    would be worse than a few missed findings.

    warning[]/suggestion[] fields: TEST-ID|description|severity|solution
    — verified against a real community report.dat parser
    (d4t4king/lynis-report-converter), not guessed. severity (3rd field)
    is Lynis' own rating when populated (common not to be — falls back to
    the per-kind default in that case, see _LYNIS_SEVERITY_MAP above).

    vulnerable_package[]: a real, separate Lynis field (its
    vulnerable-software-detection check) this parser never read before —
    each becomes its own Finding, check_id disambiguated by package name
    so multiple vulnerable packages on one host don't collide in
    reconcile_findings' (check_id, resource_uid) dedup key."""
    results: list[dict] = []
    for line in report_text.splitlines():
        line = line.strip()
        if line.startswith("warning[]=") or line.startswith("suggestion[]="):
            kind, _, value = line.partition("=")
            default_severity = _LYNIS_WARNING_SEVERITY if kind == "warning[]" else _LYNIS_SUGGESTION_SEVERITY
            fields = value.split("|")
            if not fields or not fields[0]:
                continue
            test_id = fields[0]
            description = fields[1] if len(fields) > 1 and fields[1] else test_id
            raw_severity = fields[2].strip().upper() if len(fields) > 2 else ""
            severity = _LYNIS_SEVERITY_MAP.get(raw_severity, default_severity)
            results.append({
                "check_id": test_id,
                "title": description,
                "detail": value,
                "severity": severity,
            })
        elif line.startswith("vulnerable_package[]="):
            _, _, value = line.partition("=")
            fields = value.split("|")
            if not fields or not fields[0]:
                continue
            package = fields[0]
            results.append({
                "check_id": f"lynis_vulnerable_package_{package}",
                "title": f"Vulnerable package detected: {package}",
                "detail": value,
                "severity": "high",
            })
    return results


async def run_lynis_scan(
    db: AsyncSession, engagement: Engagement, connection: HostConnection,
    error_detail: dict | None = None,
) -> list[Finding] | None:
    """Returns None (not []) on failure — see cloud_scan_service
    .run_prowler_scan's docstring for why that distinction matters. An
    empty report_text is itself treated as a failure (most likely lynis
    isn't installed on the target — the remote command swallows that as a
    silent no-op) rather than "scan ran, host is spotless": a real
    report.dat always has some content (lynis_version=, os_name=, ...)
    even when it finds zero warnings/suggestions.

    error_detail — same convention as cloud_scan_service.run_prowler_scan's
    own error_detail param: a real bug found live (connection.last_scan_error
    always read the generic "Lynis scan failed" no matter which of these
    three distinct, individually-diagnosable causes actually happened — the
    real reason only ever reached the server log, never the user)."""
    try:
        report_text = await asyncio.to_thread(_run_lynis_sync, connection)
    except HostKeyMismatchError as e:
        _log.warning("Lynis scan skipped (host key mismatch): connection_id=%s error=%s", connection.id, e)
        if error_detail is not None:
            error_detail["message"] = "Host key changed since this connection was last verified — re-verify to accept the new key, or investigate if you didn't rebuild/replace this server."
        return None
    except Exception as e:
        _log.warning("Lynis scan failed: connection_id=%s error=%s", connection.id, e)
        if error_detail is not None:
            error_detail["message"] = f"Could not connect or run the audit command: {e}"
        return None

    if not report_text.strip():
        _log.warning("Lynis scan produced no output: connection_id=%s (is lynis installed on the target?)", connection.id)
        if error_detail is not None:
            error_detail["message"] = "Lynis produced no output — confirm lynis is installed on the target and available on the audit user's PATH (no sudo required)."
        return None

    parsed = _parse_lynis_report(report_text)
    candidates: list[Finding] = [
        Finding(
            id=uuid.uuid4(),
            tenant_id=connection.tenant_id,
            engagement_id=engagement.id,
            asset_id=None,
            tier="host",
            severity=row["severity"],
            title=row["title"],
            status="open",
            check_id=row["check_id"],
            resource_uid=connection.hostname_or_ip,
            detail=row["detail"],
        )
        for row in parsed
    ]
    for c in candidates:
        score_and_stamp(c)

    # resource_uid is the host, not just check_id — one engagement can
    # cover multiple HostConnections, and Lynis test ids (e.g. "SSH-7408")
    # are generic, not per-host, so the same test firing on two different
    # hosts under one engagement must not be treated as the same finding.
    return await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "host"],
        candidates=candidates,
        key_fn=lambda f: (f.check_id, f.resource_uid),
    )


# ── Docker container inventory ────────────────────────────────────────────

# Deliberately no --format flag: a real, live-confirmed sudo gotcha —
# curly-brace Go-template syntax in a sudoers Cmnd_Spec silently fails to
# match at invocation time even when `sudo -l` displays it as an apparent
# exact match (sudo's fnmatch-style command matching, not a bug in this
# code). The sudoers grant is scoped to exactly this one command, nothing
# else — no `docker inspect` (dumps env vars, a real secret-leakage risk)
# and no `docker exec` (arbitrary code execution).
_DOCKER_PS_COMMAND = "sudo -n /usr/bin/docker ps --no-trunc"

_DOCKER_PS_HEADERS = ["CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"]


def _run_docker_inventory_sync(connection: HostConnection) -> tuple[str, int]:
    """Runs in a thread, mirrors _run_lynis_sync exactly — same _connect/
    _check_host_key reuse. Returns (output, exit_status): the real exit
    code is what distinguishes "sudo/docker not usable" from "zero
    containers running," which a bare empty-output check can't (unlike
    Lynis's report.dat, a healthy `docker ps` with nothing running is
    legitimately empty output at exit 0)."""
    client = _connect(connection)
    try:
        _check_host_key(client, connection)
        _, stdout, _ = client.exec_command(_DOCKER_PS_COMMAND, timeout=_SSH_COMMAND_TIMEOUT)
        output = stdout.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        return output, exit_status
    finally:
        client.close()


def _parse_docker_inventory(output: str) -> list[dict]:
    """Parses `docker ps --no-trunc`'s plain default tabular output —
    position-based column parsing using the real header row's own column
    start offsets, not a naive whitespace split: a real value like STATUS
    ("Up 2 hours") legitimately contains single spaces that would
    otherwise be misread as column boundaries. The standard robust
    technique for `ps`-style fixed-column-position (not fixed-width)
    output. An unexpected header shape degrades to [] rather than
    guessing at misaligned data."""
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        return []
    header = lines[0]
    offsets: list[tuple[str, int]] = []
    for name in _DOCKER_PS_HEADERS:
        idx = header.find(name)
        if idx == -1:
            return []
        offsets.append((name, idx))

    results: list[dict] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        fields: dict[str, str] = {}
        for i, (name, start) in enumerate(offsets):
            end = offsets[i + 1][1] if i + 1 < len(offsets) else len(line)
            fields[name] = line[start:end].strip()
        results.append({
            "id": fields.get("CONTAINER ID", ""),
            "name": fields.get("NAMES", ""),
            "image": fields.get("IMAGE", ""),
            "status": fields.get("STATUS", ""),
            "ports": fields.get("PORTS", ""),
        })
    return results


def _docker_container_severity(ports: str) -> str:
    """A real, parseable signal from Docker's own Ports column — "medium"
    when a container is actually published to all interfaces (0.0.0.0 or
    the IPv6 equivalent :::), the same real distinction this session's own
    security-group exposure work already established; "low" (never
    silently dropped) for a container that's real but internal-only —
    still worth knowing, just not itself internet-reachable."""
    return "medium" if ("0.0.0.0:" in ports or ":::" in ports) else "low"


async def run_docker_inventory_scan(
    db: AsyncSession, engagement: Engagement, connection: HostConnection,
    error_detail: dict | None = None,
) -> list[Finding] | None:
    """Additive to run_lynis_scan, never a substitute — independent
    failure here must never flip the whole host connection to "failed"
    when Lynis itself succeeded (see rescan_host_connection). Returns None
    only when sudo/docker genuinely isn't usable (non-zero exit or a
    raised exception) — a real empty container list at exit 0 is a valid,
    honest result, not a failure."""
    try:
        output, exit_status = await asyncio.to_thread(_run_docker_inventory_sync, connection)
    except HostKeyMismatchError as e:
        _log.warning("Docker inventory scan skipped (host key mismatch): connection_id=%s error=%s", connection.id, e)
        if error_detail is not None:
            error_detail["message"] = "Host key changed since this connection was last verified — re-verify to accept the new key."
        return None
    except Exception as e:
        _log.warning("Docker inventory scan failed: connection_id=%s error=%s", connection.id, e)
        if error_detail is not None:
            error_detail["message"] = f"Could not connect or run the docker inventory command: {e}"
        return None

    if exit_status != 0:
        _log.info("Docker inventory scan: sudo/docker not usable: connection_id=%s exit_status=%s", connection.id, exit_status)
        if error_detail is not None:
            error_detail["message"] = (
                "Docker inventory command failed — confirm the sentinel-audit-docker sudoers rule is installed, "
                "the docker path matches, and Docker is installed on the target."
            )
        return None

    parsed = _parse_docker_inventory(output)
    candidates: list[Finding] = [
        Finding(
            id=uuid.uuid4(),
            tenant_id=connection.tenant_id,
            engagement_id=engagement.id,
            asset_id=None,
            tier="host",
            severity=_docker_container_severity(row["ports"]),
            title=f"Docker container running: {row['name']} ({row['image']})",
            status="open",
            check_id=f"docker_container_{row['name']}",
            resource_uid=connection.hostname_or_ip,
            detail=f"Status: {row['status']} | Ports: {row['ports'] or 'none published'} | ID: {row['id']}",
        )
        for row in parsed
    ]
    for c in candidates:
        score_and_stamp(c)

    # Deliberately its own, narrower scope than run_lynis_scan's — a real
    # correctness risk found during planning: reusing Lynis's own
    # scope=[tier=='host'] here would mark every existing Lynis finding
    # "remediated" the moment this ran (anything in scope with no
    # matching candidate gets closed). check_id prefix keeps the two
    # passes' reconciliation completely disjoint, same convention Prowler/
    # Inspector already use to share tier='cloud' safely.
    return await reconcile_findings(
        db, engagement_id=engagement.id,
        scope=[Finding.tier == "host", Finding.check_id.like("docker_container_%")],
        candidates=candidates,
        key_fn=lambda f: (f.check_id, f.resource_uid),
    )


async def rescan_host_connection(db: AsyncSession, engagement: Engagement, connection: HostConnection) -> None:
    """Same per-action Emergency Stop enforcement as cloud_scan_service
    .rescan_connection — re-checks engagement.status immediately before the
    scan, not just once at the top, since revoke() needs to actually stop
    new work from starting."""
    await db.refresh(engagement)
    if engagement.status != "active":
        _log.info("Skipping host rescan — engagement no longer active: engagement_id=%s status=%s", engagement.id, engagement.status)
        return

    # Same transient "running:lynis" marker cloud_scan_service uses — a real
    # Lynis-over-SSH pass takes real time, and a poller should be able to
    # show that, not just a static "Running…" label.
    connection.last_scan_status = "running:lynis"
    await db.commit()

    detail: dict = {}
    result = await run_lynis_scan(db, engagement, connection, error_detail=detail)
    connection.last_scanned_at = datetime.now(timezone.utc)
    if result is None:
        connection.last_scan_status = "failed"
        connection.last_scan_error = detail.get("message") or "Lynis scan failed"
    else:
        connection.last_scan_status = "success"
        connection.last_scan_error = None

    # Independent of Lynis's own result above — a Docker-inventory failure
    # (e.g. the sudoers rule genuinely isn't installed on some other host)
    # must never flip an otherwise-successful Lynis scan to "failed"; it's
    # logged here, not surfaced as the whole connection's error.
    docker_detail: dict = {}
    docker_result = await run_docker_inventory_scan(db, engagement, connection, error_detail=docker_detail)
    if docker_result is None:
        _log.info("Docker inventory scan did not run: connection_id=%s reason=%s", connection.id, docker_detail.get("message"))

    await db.commit()


async def rescan_all_due_host_connections(db: AsyncSession) -> int:
    """Batch entry point for the recurring scheduler job — mirrors
    cloud_scan_service.rescan_all_due_connections."""
    result = await db.execute(
        select(HostConnection, Engagement)
        .join(Engagement, HostConnection.engagement_id == Engagement.id)
        .where(HostConnection.status == "connected", Engagement.status == "active")
    )
    rows = result.all()
    for connection, engagement in rows:
        try:
            await rescan_host_connection(db, engagement, connection)
        except Exception:
            _log.exception("Scheduled host rescan failed: connection_id=%s", connection.id)
    return len(rows)
