"""
Sentinel Command Tier 0 — HostConnection lifecycle (SSH/Lynis, VPS half of
Host & Server Security). paramiko's real network layer is never exercised
here — _connect() is monkeypatched to a fake SSH client, since there's no
real SSH server to test against in this environment. generate_ssh_keypair()
itself IS real (see test_host_scan_service.py); only the network I/O is faked.
"""
import json

from tests.factories import make_tenant, make_user


class _FakeKey:
    def __init__(self, key_bytes: bytes):
        self._key_bytes = key_bytes

    def asbytes(self):
        return self._key_bytes


class _FakeTransport:
    def __init__(self, key_bytes: bytes):
        self._key_bytes = key_bytes

    def get_remote_server_key(self):
        return _FakeKey(self._key_bytes)


class _FakeChannel:
    def recv_exit_status(self):
        return 0


class _FakeStdout:
    def __init__(self, data: bytes = b""):
        self._data = data
        self.channel = _FakeChannel()

    def read(self):
        return self._data


class _FakeSSHClient:
    def __init__(self, host_key_bytes: bytes = b"fake-host-key-v1", lynis_output: bytes = b""):
        self._host_key_bytes = host_key_bytes
        self._lynis_output = lynis_output

    def get_transport(self):
        return _FakeTransport(self._host_key_bytes)

    def exec_command(self, command, timeout=None):
        return None, _FakeStdout(self._lynis_output), _FakeStdout(b"")

    def close(self):
        pass


async def _create_connection(client):
    resp = await client.post("/host-connections", json={
        "hostname_or_ip": "10.0.0.5", "ssh_port": 22, "ssh_username": "sentinel-audit",
    })
    assert resp.status_code == 200
    return resp.json()


async def test_create_connection_returns_generated_public_key(auth_client):
    client, _tenant = auth_client
    setup = await _create_connection(client)
    assert setup["status"] == "pending_verification"
    assert setup["public_key"].startswith("ssh-ed25519 ")
    assert setup["public_key_fingerprint"].startswith("SHA256:")
    assert len(setup["instructions"]) == 3


async def test_verify_connection_succeeds_and_pins_host_key(auth_client, monkeypatch):
    monkeypatch.setattr(
        "app.services.host_scan_service._connect",
        lambda connection: _FakeSSHClient(),
    )
    client, _tenant = auth_client
    setup = await _create_connection(client)

    resp = await client.post(f"/host-connections/{setup['id']}/verify")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "connected"
    assert body["host_key_fingerprint"] is not None
    assert body["connected_at"] is not None


async def test_verify_connection_fails_gracefully_on_connect_error(auth_client, monkeypatch):
    def _raise(connection):
        raise TimeoutError("no route to host")

    monkeypatch.setattr("app.services.host_scan_service._connect", _raise)
    client, _tenant = auth_client
    setup = await _create_connection(client)

    resp = await client.post(f"/host-connections/{setup['id']}/verify")
    assert resp.status_code == 400

    list_resp = await client.get("/host-connections")
    assert list_resp.json()[0]["status"] == "error"


async def test_list_connections_surfaces_engagement_status(auth_client, monkeypatch, db_session):
    """Real bug found live: a connection can be genuinely SSH-verified
    ("connected") while its own Engagement is still stuck at draft — e.g.
    Dropbox Sign wasn't configured — and the frontend had no way to tell
    that apart from a fully scan-ready connection. list_connections must
    surface the real engagement status, not just the connection's own."""
    monkeypatch.setattr("app.services.host_scan_service._connect", lambda connection: _FakeSSHClient())
    client, tenant = auth_client
    setup = await _create_connection(client)
    await client.post(f"/host-connections/{setup['id']}/verify")

    resp = await client.post("/engagements", json={"tier": "host", "host_connection_ids": [setup["id"]]})
    assert resp.status_code == 200
    engagement = resp.json()

    list_resp = await client.get("/host-connections")
    body = list_resp.json()[0]
    assert body["engagement_id"] == engagement["id"]
    assert body["engagement_status"] == "draft"  # never requested/approved yet — exactly the stuck state

    from app.models import Engagement
    eng_row = await db_session.get(Engagement, engagement["id"])
    eng_row.status = "active"
    await db_session.commit()

    list_resp = await client.get("/host-connections")
    assert list_resp.json()[0]["engagement_status"] == "active"


async def test_reverify_detects_host_key_change(auth_client, monkeypatch):
    """First verify pins the host key (TOFU). A later connect presenting a
    DIFFERENT host key — a rebuilt server, or a MITM — must be refused, not
    silently accepted and re-pinned."""
    client, _tenant = auth_client
    setup = await _create_connection(client)

    monkeypatch.setattr(
        "app.services.host_scan_service._connect",
        lambda connection: _FakeSSHClient(host_key_bytes=b"original-host-key"),
    )
    first = await client.post(f"/host-connections/{setup['id']}/verify")
    assert first.status_code == 200
    pinned_fp = first.json()["host_key_fingerprint"]

    monkeypatch.setattr(
        "app.services.host_scan_service._connect",
        lambda connection: _FakeSSHClient(host_key_bytes=b"a-completely-different-key"),
    )
    second = await client.post(f"/host-connections/{setup['id']}/verify")
    assert second.status_code == 400

    list_resp = await client.get("/host-connections")
    body = list_resp.json()[0]
    assert body["status"] == "error"
    assert body["host_key_fingerprint"] == pinned_fp  # pin itself is untouched by the failed attempt


async def test_rescan_now_rejects_unconnected_connection(auth_client):
    client, _tenant = auth_client
    setup = await _create_connection(client)

    resp = await client.post(f"/host-connections/{setup['id']}/rescan")
    assert resp.status_code == 400


async def test_rescan_now_runs_lynis_and_persists_host_tier_findings(auth_client, monkeypatch):
    sample_report = (
        "warning[]=SSH-7408|Root can directly login via SSH|-|\n"
        "suggestion[]=AUTH-9328|Default umask is not configured|-|\n"
    )

    def _fake_connect(connection):
        return _FakeSSHClient(lynis_output=sample_report.encode("utf-8"))

    monkeypatch.setattr("app.services.host_scan_service._connect", _fake_connect)

    client, _tenant = auth_client
    setup = await _create_connection(client)
    await client.post(f"/host-connections/{setup['id']}/verify")

    engagement_resp = await client.post(
        "/engagements", json={"tier": "host", "host_connection_ids": [setup["id"]]}
    )
    engagement_id = engagement_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    resp = await client.post(f"/host-connections/{setup['id']}/rescan")
    assert resp.status_code == 200
    assert resp.json()["last_scanned_at"] is not None

    findings_resp = await client.get(f"/engagements/{engagement_id}/findings")
    findings = findings_resp.json()
    assert len(findings) == 2
    assert {f["tier"] for f in findings} == {"host"}
    severities = {f["check_id"]: f["severity"] for f in findings}
    assert severities["SSH-7408"] == "high"
    assert severities["AUTH-9328"] == "medium"


async def test_rescan_does_not_duplicate_a_persistent_finding_on_rescan(auth_client, monkeypatch):
    sample_report = "warning[]=SSH-7408|Root can directly login via SSH|-|\n"

    def _fake_connect(connection):
        return _FakeSSHClient(lynis_output=sample_report.encode("utf-8"))

    monkeypatch.setattr("app.services.host_scan_service._connect", _fake_connect)

    client, _tenant = auth_client
    setup = await _create_connection(client)
    await client.post(f"/host-connections/{setup['id']}/verify")
    engagement_resp = await client.post("/engagements", json={"tier": "host", "host_connection_ids": [setup["id"]]})
    engagement_id = engagement_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    await client.post(f"/host-connections/{setup['id']}/rescan")
    await client.post(f"/host-connections/{setup['id']}/rescan")

    findings = (await client.get(f"/engagements/{engagement_id}/findings")).json()
    assert len(findings) == 1


async def test_rescan_marks_a_resolved_host_finding_remediated(auth_client, monkeypatch):
    sample_report = "warning[]=SSH-7408|Root can directly login via SSH|-|\n"
    monkeypatch.setattr(
        "app.services.host_scan_service._connect",
        lambda connection: _FakeSSHClient(lynis_output=sample_report.encode("utf-8")),
    )

    client, _tenant = auth_client
    setup = await _create_connection(client)
    await client.post(f"/host-connections/{setup['id']}/verify")
    engagement_resp = await client.post("/engagements", json={"tier": "host", "host_connection_ids": [setup["id"]]})
    engagement_id = engagement_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    await client.post(f"/host-connections/{setup['id']}/rescan")

    monkeypatch.setattr(
        "app.services.host_scan_service._connect",
        lambda connection: _FakeSSHClient(lynis_output=b"lynis_version=3.1.4\n"),  # issue no longer reproduces
    )
    await client.post(f"/host-connections/{setup['id']}/rescan")

    findings = (await client.get(f"/engagements/{engagement_id}/findings")).json()
    assert len(findings) == 1
    assert findings[0]["status"] == "remediated"


async def test_rescan_now_rejects_when_engagement_not_active(auth_client, monkeypatch):
    monkeypatch.setattr("app.services.host_scan_service._connect", lambda connection: _FakeSSHClient())
    client, _tenant = auth_client
    setup = await _create_connection(client)
    await client.post(f"/host-connections/{setup['id']}/verify")

    # Note: no engagement created/approved at all — connection has no
    # engagement_id, same "no authorization on file" refusal as cloud's
    # equivalent test.
    resp = await client.post(f"/host-connections/{setup['id']}/rescan")
    assert resp.status_code == 400


async def test_connections_are_isolated_by_tenant(auth_client, client, db_session):
    owner_client, _owner_tenant = auth_client
    setup = await _create_connection(owner_client)

    other_tenant = await make_tenant(db_session, name="Other Workspace")
    await make_user(db_session, other_tenant, email="other-host@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token",
        data={"username": "other-host@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    other_client = client
    other_client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    list_resp = await other_client.get("/host-connections")
    assert list_resp.json() == []

    verify_resp = await other_client.post(f"/host-connections/{setup['id']}/verify")
    assert verify_resp.status_code == 404


# ── last_scan_status tracking — a failed rescan must not look like a clean one ──

async def test_rescan_marks_failed_when_lynis_produces_no_output(auth_client, monkeypatch):
    """Empty report_text (e.g. lynis isn't installed on the target) must
    surface as a failed scan, not as 'ran cleanly, host is spotless.'"""
    client, _tenant = auth_client
    setup = await _create_connection(client)

    monkeypatch.setattr(
        "app.services.host_scan_service._connect",
        lambda connection: _FakeSSHClient(lynis_output=b""),
    )
    await client.post(f"/host-connections/{setup['id']}/verify")

    engagement_resp = await client.post(
        "/engagements", json={"tier": "host", "host_connection_ids": [setup["id"]]}
    )
    await client.post(f"/engagements/{engagement_resp.json()['id']}/approve")

    resp = await client.post(f"/host-connections/{setup['id']}/rescan")
    assert resp.status_code == 200
    assert resp.json()["last_scan_status"] == "failed"
    # Real bug found live: this used to always read the generic "Lynis scan
    # failed" no matter the cause — now the specific, actionable reason
    # (from host_scan_service.run_lynis_scan's error_detail) reaches the
    # connection row, not just the server log.
    assert "installed" in resp.json()["last_scan_error"].lower()


async def test_rescan_error_names_the_real_connection_failure(auth_client, monkeypatch):
    """A real SSH/connect-level failure (distinct from the empty-output
    case above) must surface ITS OWN specific reason too, not the same
    generic string both causes used to share."""
    client, _tenant = auth_client
    setup = await _create_connection(client)

    def _raise(connection):
        raise TimeoutError("no route to host")
    monkeypatch.setattr("app.services.host_scan_service._connect", lambda connection: _FakeSSHClient())
    await client.post(f"/host-connections/{setup['id']}/verify")

    engagement_resp = await client.post(
        "/engagements", json={"tier": "host", "host_connection_ids": [setup["id"]]}
    )
    await client.post(f"/engagements/{engagement_resp.json()['id']}/approve")

    monkeypatch.setattr("app.services.host_scan_service._connect", _raise)
    resp = await client.post(f"/host-connections/{setup['id']}/rescan")
    assert resp.status_code == 200
    assert resp.json()["last_scan_status"] == "failed"
    assert "no route to host" in resp.json()["last_scan_error"]


async def test_rescan_marks_success_when_lynis_report_has_zero_findings(auth_client, monkeypatch):
    """A real report.dat with content but no warning[]/suggestion[] lines
    (a genuinely hardened host) must still register as success, distinct
    from the empty-output failure case above."""
    client, _tenant = auth_client
    setup = await _create_connection(client)

    clean_report = "lynis_version=3.0.9\nos_name=Linux\nhardening_index=95|100\n"
    monkeypatch.setattr(
        "app.services.host_scan_service._connect",
        lambda connection: _FakeSSHClient(lynis_output=clean_report.encode("utf-8")),
    )
    await client.post(f"/host-connections/{setup['id']}/verify")

    engagement_resp = await client.post(
        "/engagements", json={"tier": "host", "host_connection_ids": [setup["id"]]}
    )
    await client.post(f"/engagements/{engagement_resp.json()['id']}/approve")

    resp = await client.post(f"/host-connections/{setup['id']}/rescan")
    assert resp.status_code == 200
    assert resp.json()["last_scan_status"] == "success"
    assert resp.json()["last_scan_error"] is None


# ── PATCH /host-connections/{id} — display_name ─────────────────────────────

async def test_rename_host_connection_sets_and_clears_display_name(auth_client):
    """display_name is the one piece of "environment" identity nothing in
    SSH/hostname data can supply on its own — a human judgment call, so it
    needs its own editable field. Explicit null clears it back to the
    derived hostname label, not just omission."""
    client, _tenant = auth_client
    setup = await _create_connection(client)

    resp = await client.patch(f"/host-connections/{setup['id']}", json={"display_name": "Mail server — Production"})
    assert resp.status_code == 200
    assert resp.json()["display_name"] == "Mail server — Production"

    resp = await client.patch(f"/host-connections/{setup['id']}", json={"display_name": None})
    assert resp.status_code == 200
    assert resp.json()["display_name"] is None


async def test_rename_host_connection_is_audit_logged(auth_client, db_session):
    client, tenant = auth_client
    setup = await _create_connection(client)

    await client.patch(f"/host-connections/{setup['id']}", json={"display_name": "Mail server — Production"})

    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry
    result = await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.tenant_id == tenant.id, AuditLogEntry.action == "host_connection.renamed")
    )
    entry = result.scalars().one()
    assert entry.before == {"display_name": None}
    assert entry.after == {"display_name": "Mail server — Production"}
