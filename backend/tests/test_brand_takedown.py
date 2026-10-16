from datetime import datetime, timezone

import pytest

from app.services import brand_takedown as td

RDAP = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]], "entities": [
    {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@reg.example"], ["tel", {}, "uri", "tel:+1.5550100"]]]}]}]}
IPRDAP = {"name": "NET-1", "entities": [{"roles": ["registrant"], "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "noc@host.example"]]]}]}]}


def test_abuse_contact_is_found_even_when_nested_and_missing_is_empty():
    assert td.abuse_contacts(RDAP) == {"emails": ["abuse@reg.example"], "phones": ["+1.5550100"], "name": None}
    assert td.abuse_contacts(IPRDAP)["emails"] == ["noc@host.example"] and td.abuse_contacts(IPRDAP)["name"] == "NET-1"
    assert td.abuse_contacts({}) == {"emails": [], "phones": [], "name": None}
    assert td.abuse_contacts({"entities": [None, "x", {"roles": None}]})["emails"] == []      # malformed input does not raise


def test_registrar_name():
    assert td.registrar_name(RDAP) == "Example Registrar" and td.registrar_name({}) is None


@pytest.mark.parametrize("ip,ok", [("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False), ("169.254.1.1", False), ("fe80::1", False), ("nope", False)])
def test_only_public_addresses_are_looked_up(ip, ok):
    assert td.is_public_ip(ip) is ok


def test_cloudflare_detection():
    assert td.uses_cloudflare(["ada.ns.cloudflare.com."]) and not td.uses_cloudflare(["ns1.example.com"]) and not td.uses_cloudflare(None)


def _r(**kw):
    base = dict(domain="acme-pay.xyz", registrar="Example Registrar", registrar_abuse=td.abuse_contacts(RDAP), host_abuse=td.abuse_contacts(IPRDAP), host_ip="1.2.3.4", nameservers=["ada.ns.cloudflare.com"])
    base.update(kw)
    return td.routes(**base)


def test_routes_are_ordered_registrar_cdn_host_and_label_certainty():
    r = _r()
    assert [x["kind"] for x in r] == ["registrar", "cdn", "host"]
    assert r[0]["target"] == "abuse@reg.example" and all(x["certainty"] == "discovered" for x in r)
    assert r[1]["target"] == td.CLOUDFLARE_ABUSE_FORM and r[1]["how"] == "form"


def test_missing_contacts_become_suggested_manual_routes_never_invented():
    r = _r(registrar_abuse={}, host_abuse={}, nameservers=[])
    assert [x["kind"] for x in r] == ["registrar", "host"] and all(x["how"] == "manual" and x["certainty"] == "suggested" and x["target"] == "" for x in r)


def test_za_domains_get_a_suggested_registry_route_with_no_made_up_contact():
    r = _r(domain="acme.co.za", registrar_abuse={}, host_abuse=None, host_ip=None, nameservers=[])
    assert r[0]["kind"] == "za_registry" and r[0]["certainty"] == "suggested" and r[0]["target"] == "" and "confirm" in r[0]["note"]


def test_draft_is_factual_names_the_recipient_type_and_includes_the_hash_only_when_given():
    route = _r()[0]
    d = td.draft(domain="acme-pay.xyz", brand="Acme", official_domains=["acme.co.za"], observations=["Resolves to 1.2.3.4", "Registered 2 days ago"], pack_hash="ab" * 32, route=route, sender_name="Ann", generated_at=datetime(2026, 10, 5, tzinfo=timezone.utc))
    assert d["subject"] == "Abuse report: acme-pay.xyz impersonating Acme" and "registrar" in d["body"] and "Registered 2 days ago" in d["body"] and "ab" * 32 in d["body"] and d["body"].rstrip().endswith("Ann")
    assert "SHA-256" not in td.draft(domain="d", brand="b", official_domains=[], observations=[], pack_hash=None, route=route, sender_name="A", generated_at=datetime(2026, 10, 5))["body"]


def test_status_flow_only_allows_forward_steps_and_reverting_a_draft():
    assert td.can_move("draft", "approved") and td.can_move("approved", "sent") and td.can_move("approved", "draft") and td.can_move("sent", "removed")
    assert not td.can_move("draft", "sent")                 # nothing is sent without approval
    assert not td.can_move("removed", "draft") and not td.can_move("sent", "draft")


def test_mailto_encodes_the_text():
    assert td.mailto("a@b.c", "x y", "l1\nl2") == "mailto:a@b.c?subject=x%20y&body=l1%0Al2"


# -- API --------------------------------------------------------------------
import uuid

from app.models import BrandProfile
from tests.test_brand_graph import cand
from tests.test_brand_guard_api import _pro_profile

ROUTE = {"kind": "registrar", "label": "Registrar (X)", "how": "email", "target": "abuse@reg.example", "certainty": "discovered", "note": ""}


async def _case(client, tenant, db_session):
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    row = cand(profile, "acme-pay.xyz", status="confirmed", a=["1.2.3.4"])
    db_session.add(row)
    await db_session.commit()
    return str(row.id)


async def test_api_routes_use_discovery_and_send_nothing(auth_client, db_session, monkeypatch):
    from app.services import brand_takedown_discovery as disc
    client, tenant = auth_client
    cid = await _case(client, tenant, db_session)
    seen = {}

    async def fake(domain, enrichment):
        seen["domain"] = domain
        return [ROUTE]
    monkeypatch.setattr(disc, "discover", fake)
    r = (await client.get(f"/brand-guard/candidates/{cid}/takedown-routes")).json()
    assert r["routes"] == [ROUTE] and seen["domain"] == "acme-pay.xyz"


async def test_draft_edit_approve_send_outcome_flow_with_gates_and_audit(auth_client, db_session):
    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry
    client, tenant = auth_client
    cid = await _case(client, tenant, db_session)
    t = (await client.post(f"/brand-guard/candidates/{cid}/takedowns", json={"route": ROUTE})).json()
    assert t["status"] == "draft" and t["mailto"] is None and "acme-pay.xyz" in t["subject"] and t["allowed_next"] == ["approved"]
    tid = t["id"]
    # nothing can be sent without approval
    assert (await client.post(f"/brand-guard/takedowns/{tid}/status", json={"status": "sent"})).status_code == 409
    edited = (await client.patch(f"/brand-guard/takedowns/{tid}", json={"subject": "S", "body": "B"})).json()
    assert edited["subject"] == "S"
    ap = (await client.post(f"/brand-guard/takedowns/{tid}/status", json={"status": "approved"})).json()
    assert ap["approved_at"] and ap["mailto"].startswith("mailto:abuse@reg.example")
    assert (await client.patch(f"/brand-guard/takedowns/{tid}", json={"subject": "x", "body": "y"})).status_code == 409   # approved text is frozen
    sent = (await client.post(f"/brand-guard/takedowns/{tid}/status", json={"status": "sent"})).json()
    assert sent["sent_at"]
    done = (await client.post(f"/brand-guard/takedowns/{tid}/status", json={"status": "removed", "note": "registrar suspended it"})).json()
    assert done["status"] == "removed" and done["outcome_note"] == "registrar suspended it" and done["allowed_next"] == []
    assert len((await client.get(f"/brand-guard/candidates/{cid}/takedowns")).json()) == 1
    actions = {a.action for a in (await db_session.execute(select(AuditLogEntry))).scalars().all()}
    assert {"brand_guard.takedown_drafted", "brand_guard.takedown_approved", "brand_guard.takedown_sent", "brand_guard.takedown_removed"} <= actions
    lines = [e["summary"] for e in (await client.get(f"/brand-guard/candidates/{cid}/timeline")).json()["events"]]
    assert any("takedown request" in l and "removed" in l for l in lines)


async def test_api_rejects_bad_routes_and_other_tenants(auth_client, db_session):
    client, tenant = auth_client
    cid = await _case(client, tenant, db_session)
    assert (await client.post(f"/brand-guard/candidates/{cid}/takedowns", json={"route": {**ROUTE, "target": "no-at-sign"}})).status_code == 422
    assert (await client.post(f"/brand-guard/candidates/{cid}/takedowns", json={"route": {**ROUTE, "kind": "bogus"}})).status_code == 422
    assert (await client.post(f"/brand-guard/candidates/{uuid.uuid4()}/takedowns", json={"route": ROUTE})).status_code == 404
    assert (await client.post(f"/brand-guard/takedowns/{uuid.uuid4()}/status", json={"status": "approved"})).status_code == 404


def test_the_complaint_speaks_about_the_brand_in_the_third_person():
    d = td.draft(domain="d.xyz", brand="Acme", official_domains=["acme.com"], observations=["Contains your brand name 'acme'.", "A name that is not yours.", "reported by your team"], pack_hash=None,
                 route={"kind": "registrar"}, sender_name="Ann", generated_at=datetime(2026, 10, 5, tzinfo=timezone.utc))
    assert "your" not in d["body"].split("What we have observed")[1].split("We ask")[0].lower()
    assert "the Acme brand name" in d["body"] and "not Acme's" in d["body"]


# ── E5: a complaint may only state what a third party can check ───────────────

def _ev(signal, summary="s", observed_at="2026-10-05T10:00:00+00:00", weight=10):
    return {"signal": signal, "summary": summary, "observed_at": observed_at, "weight": weight}


def test_complaint_never_carries_private_or_inferred_lines():
    private = ["reported_by_employee", "reported_brand_mention", "same_network_as_spoofer", "linked_to_known_bad",
               "mirrors_mail_provider", "copied_dkim_key", "same_nameservers", "same_hosting_ip", "defensive_mail_posture", "popular_site"]
    evidence = [_ev(s, summary=f"private {s}") for s in private] + [_ev("page_password_form", "Asks for a password")]
    obs, level = td.claims(evidence)
    assert obs == ["Asks for a password"]
    assert level == "page_evidence"
    assert not any("private" in o for o in obs)


def test_page_and_blocklist_lines_come_first_and_set_the_level():
    obs, level = td.claims([_ev("new_registration", "Registered 2 days ago"), _ev("on_phishing_feed", "Listed on a public phishing feed")])
    assert obs[0] == "Listed on a public phishing feed" and level == "page_evidence"


def test_name_and_registration_only_is_labelled_name_only():
    obs, level = td.claims([_ev("homoglyph", "Looks like acme"), _ev("new_registration", "Registered 2 days ago")])
    assert level == "name_only" and len(obs) == 2


def test_a_line_without_a_time_or_summary_is_not_a_claim():
    obs, level = td.claims([_ev("page_password_form", "x", observed_at=None), _ev("page_copies_wording", "")])
    assert obs == [] and level == "name_only"


def test_duplicate_lines_are_stated_once_and_capped():
    obs, _ = td.claims([_ev("page_password_form", "same")] * 3 + [_ev("homoglyph", f"n{i}") for i in range(12)])
    assert obs.count("same") == 1 and len(obs) == 8


def test_draft_without_observations_says_the_page_was_not_captured_and_invents_nothing():
    route = _r()[0]
    body = td.draft(domain="acme-pay.xyz", brand="Acme", official_domains=["acme.co.za"], observations=[], pack_hash=None,
                    route=route, sender_name="Ann", generated_at=datetime(2026, 10, 5, tzinfo=timezone.utc))["body"]
    assert "not captured the content" in body
    assert "no specific observations" not in body
    assert "What we have observed" not in body
    assert "login" not in body.lower() and "password" not in body.lower()


async def test_viewer_cannot_draft_edit_or_approve(client, db_session):
    from tests.factories import make_tenant, make_user
    tenant = await make_tenant(db_session, name="Takedown Roles", plan="pro")
    await make_user(db_session, tenant, email="admin-td@test.com", password="pass123", role="admin")
    await make_user(db_session, tenant, email="viewer-td@test.com", password="pass123", role="viewer")
    await db_session.flush()

    async def login(email):
        r = await client.post("/auth/token", data={"username": email, "password": "pass123"},
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
        client.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})

    await login("admin-td@test.com")
    cid = await _case(client, tenant, db_session)
    t = (await client.post(f"/brand-guard/candidates/{cid}/takedowns", json={"route": ROUTE})).json()
    assert t["evidence_level"] == "name_only"

    await login("viewer-td@test.com")
    assert (await client.post(f"/brand-guard/candidates/{cid}/takedowns", json={"route": ROUTE})).status_code == 403
    assert (await client.patch(f"/brand-guard/takedowns/{t['id']}", json={"subject": "S", "body": "B"})).status_code == 403
    assert (await client.post(f"/brand-guard/takedowns/{t['id']}/status", json={"status": "approved"})).status_code == 403
    # reading is still allowed
    assert (await client.get(f"/brand-guard/candidates/{cid}/takedowns")).status_code == 200


async def test_single_admin_can_approve_their_own_draft_and_it_is_recorded(auth_client, db_session):
    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry
    client, tenant = auth_client
    cid = await _case(client, tenant, db_session)
    t = (await client.post(f"/brand-guard/candidates/{cid}/takedowns", json={"route": ROUTE})).json()
    ap = await client.post(f"/brand-guard/takedowns/{t['id']}/status", json={"status": "approved"})
    assert ap.status_code == 200
    entry = next(a for a in (await db_session.execute(select(AuditLogEntry))).scalars().all() if a.action == "brand_guard.takedown_approved")
    assert (entry.after or {}).get("self_approved") is True
