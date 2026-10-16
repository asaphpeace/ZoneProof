import json
import uuid
from datetime import datetime, timezone

from app.models import BrandProfile
from app.services import brand_evidence_pack as ep
from tests.test_brand_graph import cand
from tests.test_brand_guard_api import _pro_profile

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def _pack(**over):
    kw = dict(
        brand={"name": "Acme", "official_domains": ["acme.co.za"]},
        candidate={"domain": "acme-pay.xyz", "domain_unicode": "acme-pay.xyz", "verdict": "Watch", "why": "w", "decision": None, "stage": "Resolving", "first_seen_at": "2026-10-01T00:00:00+00:00", "last_seen_at": "2026-10-05T00:00:00+00:00", "sources": ["permutation"]},
        evidence=[{"signal": "dns_live", "summary": "Resolves <b>now</b>", "weight": 0, "observed_at": "2026-10-05T11:00:00+00:00", "data": {"a": ["1.2.3.4"]}}],
        timeline=[{"at": "2026-10-04T00:00:00+00:00", "summary": "Went live"}],
        threat={"impact": {"text": "It could serve a website."}, "narrative": {"steps": [{"text": "Registered it.", "status": "observed", "note": ""}], "summary": "Seen: 1 of 1 steps.", "caveat": "c"}},
        campaign=None, generated_at=NOW, generated_by="Ann",
    )
    kw.update(over)
    return ep.build(**kw)


def test_the_hash_verifies_and_any_change_breaks_it():
    p = _pack()
    assert ep.verify(p) and len(p["integrity"]["hash"]) == 64
    p["evidence"][0]["summary"] = "tampered"
    assert not ep.verify(p)
    p2 = _pack()
    p2["integrity"]["hash"] = "0" * 64
    assert not ep.verify(p2)


def test_the_hash_is_stable_across_key_order_and_changes_with_content():
    assert _pack()["integrity"]["hash"] == _pack()["integrity"]["hash"]
    assert _pack(generated_by="Bob")["integrity"]["hash"] != _pack()["integrity"]["hash"]
    p = _pack()
    reordered = {k: p[k] for k in reversed(list(p))}
    assert ep.verify(reordered)


def test_the_pack_lists_what_it_did_not_check_and_what_the_hash_does_not_prove():
    p = _pack()
    assert p["not_checked"] and "does not prove" in p["limits"]


def test_html_escapes_untrusted_text_and_carries_the_hash_and_the_gaps():
    h = ep.render_html(_pack())
    assert "<b>now</b>" not in h and "&lt;b&gt;now&lt;/b&gt;" in h          # evidence text can be attacker-controlled
    assert _pack()["integrity"]["hash"] in h and "What was not checked" in h and "Registered it." in h


async def _case(client, tenant, db_session):
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    row = cand(profile, "acme-pay.xyz", status="new", a=["1.2.3.4"])
    db_session.add(row)
    await db_session.commit()
    return str(row.id)


async def test_api_json_pack_verifies_and_is_audited(auth_client, db_session):
    client, tenant = auth_client
    cid = await _case(client, tenant, db_session)
    r = await client.get(f"/brand-guard/candidates/{cid}/evidence-pack?format=json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    pack = json.loads(r.text)
    assert ep.verify(pack) and pack["subject"]["domain"] == "acme-pay.xyz" and pack["brand"]["name"]
    assert str(pack["integrity"]["hash"])[:8] in r.headers["content-disposition"]


async def test_api_rejects_unknown_format_and_other_tenants_candidates(auth_client, db_session):
    client, tenant = auth_client
    cid = await _case(client, tenant, db_session)
    assert (await client.get(f"/brand-guard/candidates/{cid}/evidence-pack?format=docx")).status_code == 422
    assert (await client.get(f"/brand-guard/candidates/{uuid.uuid4()}/evidence-pack")).status_code == 404


async def test_api_pdf_pack_is_a_pdf_and_the_export_is_in_the_audit_log(auth_client, db_session):
    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry as AuditLog
    client, tenant = auth_client
    cid = await _case(client, tenant, db_session)
    r = await client.get(f"/brand-guard/candidates/{cid}/evidence-pack?format=pdf")
    assert r.status_code == 200 and r.content[:4] == b"%PDF" and r.headers["content-type"] == "application/pdf"
    rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "brand_guard.evidence_pack_exported"))).scalars().all()
    assert len(rows) == 1 and rows[0].target_label == "acme-pay.xyz" and rows[0].after["format"] == "pdf"
