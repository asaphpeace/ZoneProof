import json
from datetime import datetime, timezone

import pytest

from app.services import brand_blocklist as bl

WHEN = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)


def test_clean_keeps_only_valid_hostnames_sorted_unique_lowercase():
    assert bl.clean(["B.example.com.", "a.example.com", "a.example.com", " c.xyz "]) == ["a.example.com", "b.example.com", "c.xyz"]


@pytest.mark.parametrize("bad", ["", "no-dot", "a b.com", "a.com\nNew-Item evil", 'a.com"; rm', "-a.com", "a..com", "x" * 64 + ".com", "a.c", "ü.com", "a.com;b.com", "$(x).com"])
def test_clean_drops_anything_that_could_break_or_inject_into_a_config_line(bad):
    assert bl.clean([bad]) == []


def test_clean_ignores_non_strings():
    assert bl.clean([None, 5, "ok.xyz"]) == ["ok.xyz"]            # type: ignore[list-item]


def test_plain_and_csv():
    assert bl.plain(["b.xyz", "a.xyz"]) == "a.xyz\nb.xyz\n"
    assert bl.csv(["a.xyz"]) == "domain\na.xyz\n"


def test_microsoft_script_blocks_urls_and_senders_and_never_runs_unclean_input():
    s = bl.microsoft_365(["a.xyz", 'evil.com"; Remove-Item x'], "Acme", WHEN)
    assert s.count("New-TenantAllowBlockListItems") == 2 and '-ListType Url -Block -Entries "a.xyz"' in s and "-ListType Sender -Block" in s and "Remove-Item" not in s
    assert "Review before running" in s
    assert "No confirmed look-alikes" in bl.microsoft_365([], "Acme", WHEN) and "New-Tenant" not in bl.microsoft_365([], "Acme", WHEN)


def test_rpz_answers_nxdomain_for_the_name_and_everything_under_it():
    z = bl.rpz(["a.xyz"], "Acme", WHEN)
    assert "a.xyz CNAME ." in z and "*.a.xyz CNAME ." in z and "20261006" in z and z.startswith("; ZoneProof")


def test_chrome_policy_is_valid_json_with_the_documented_key():
    assert json.loads(bl.chrome_policy(["b.xyz", "a.xyz"])) == {"URLBlocklist": ["a.xyz", "b.xyz"]}


@pytest.mark.parametrize("fmt", list(bl.FORMATS))
def test_every_format_renders(fmt):
    assert bl.render(fmt, ["a.xyz"], "Acme", WHEN)


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        bl.render("bogus", [], "A", WHEN)


def test_report_link_prefills_only_where_documented_and_always_gives_the_text_to_paste():
    g = bl.report_link("google_safe_browsing", "a.xyz")
    assert g["url"].startswith("https://safebrowsing.google.com/") and "url=http%3A%2F%2Fa.xyz" in g["url"] and g["paste"] == "http://a.xyz"
    m = bl.report_link("microsoft", "a.xyz")
    assert "?" not in m["url"] and m["paste"] == "http://a.xyz"


def test_submission_flow():
    assert bl.can_move_submission("submitted", "listed") and bl.can_move_submission("declined", "submitted")
    assert not bl.can_move_submission("listed", "declined") and not bl.can_move_submission("submitted", "submitted")


# -- API --------------------------------------------------------------------
import uuid

from app.models import BrandProfile
from tests.test_brand_graph import cand
from tests.test_brand_guard_api import _pro_profile


async def _two(client, tenant, db_session):
    profile = await db_session.get(BrandProfile, uuid.UUID(await _pro_profile(client, tenant, db_session)))
    rows = [cand(profile, "acme-a.xyz", status="confirmed"), cand(profile, "acme-b.xyz", status="takedown"), cand(profile, "acme-c.xyz", status="suspicious"), cand(profile, "acme-d.xyz", status="false_positive")]
    db_session.add_all(rows)
    await db_session.commit()
    return profile, [str(r.id) for r in rows]


async def test_api_blocklist_exports_only_confirmed_unless_asked_for_likely(auth_client, db_session):
    client, tenant = auth_client
    profile, _ = await _two(client, tenant, db_session)
    r = await client.get("/brand-guard/blocklist?format=plain")
    assert r.text == "acme-a.xyz\nacme-b.xyz\n" and r.headers["x-entry-count"] == "2" and "content-disposition" not in r.headers
    likely = await client.get(f"/brand-guard/blocklist?format=plain&include=likely&profile_id={profile.id}")
    assert likely.text == "acme-a.xyz\nacme-b.xyz\nacme-c.xyz\n"            # never the false positive
    assert "acme-d.xyz" not in (await client.get("/brand-guard/blocklist?format=csv&include=likely")).text


async def test_api_download_is_audited_and_preview_is_not(auth_client, db_session):
    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry
    client, tenant = auth_client
    await _two(client, tenant, db_session)
    await client.get("/brand-guard/blocklist?format=m365")
    assert (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.action == "brand_guard.blocklist_exported"))).scalars().all() == []
    r = await client.get("/brand-guard/blocklist?format=m365&download=true")
    assert "attachment" in r.headers["content-disposition"] and "New-TenantAllowBlockListItems" in r.text
    rows = (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.action == "brand_guard.blocklist_exported"))).scalars().all()
    assert len(rows) == 1 and rows[0].after["count"] == 2


async def test_api_blocklist_rejects_unknown_format_include_and_other_tenants_brand(auth_client, db_session):
    client, tenant = auth_client
    await _two(client, tenant, db_session)
    assert (await client.get("/brand-guard/blocklist?format=bogus")).status_code == 422
    assert (await client.get("/brand-guard/blocklist?include=everything")).status_code == 422
    assert (await client.get(f"/brand-guard/blocklist?profile_id={uuid.uuid4()}")).status_code == 404


async def test_api_report_links_and_submission_tracking(auth_client, db_session):
    client, tenant = auth_client
    _, ids = await _two(client, tenant, db_session)
    links = (await client.get(f"/brand-guard/candidates/{ids[0]}/report-links")).json()
    assert {l["service"] for l in links} == set(bl.SERVICES) and all(l["submission"] is None and l["paste"] == "http://acme-a.xyz" for l in links)
    s = (await client.post(f"/brand-guard/candidates/{ids[0]}/submissions", json={"service": "netcraft"})).json()
    assert s["status"] == "submitted" and s["allowed_next"] == ["listed", "declined"]
    assert (await client.post(f"/brand-guard/candidates/{ids[0]}/submissions", json={"service": "netcraft"})).status_code == 409      # once per service
    assert (await client.post(f"/brand-guard/candidates/{ids[0]}/submissions", json={"service": "nope"})).status_code == 422
    done = (await client.post(f"/brand-guard/submissions/{s['id']}/status", json={"status": "listed", "note": "live"})).json()
    assert done["status"] == "listed" and done["note"] == "live" and done["allowed_next"] == []
    assert (await client.post(f"/brand-guard/submissions/{s['id']}/status", json={"status": "declined"})).status_code == 409
    again = (await client.get(f"/brand-guard/candidates/{ids[0]}/report-links")).json()
    assert [l["submission"]["status"] for l in again if l["submission"]] == ["listed"]


async def test_api_submissions_are_tenant_scoped(auth_client, db_session):
    client, tenant = auth_client
    await _two(client, tenant, db_session)
    assert (await client.get(f"/brand-guard/candidates/{uuid.uuid4()}/report-links")).status_code == 404
    assert (await client.post(f"/brand-guard/submissions/{uuid.uuid4()}/status", json={"status": "listed"})).status_code == 404
