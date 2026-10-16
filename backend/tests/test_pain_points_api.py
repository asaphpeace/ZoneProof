"""
PAIN_POINT_RESOLUTION_PLAN.md Pain 3 and Pain 4, through the HTTP layer.

The rules themselves are covered in test_verdict_service.py and
test_recommendation_engine.py. These confirm the results actually reach the
API a page reads: the DKIM-failure hypotheses on a DMARC source row, and the
per-source readiness list on the dry-run endpoint.
"""
from tests.factories import make_dmarc_aggregate, make_domain


async def _agg(db, domain, org, ip, total, fail, classification):
    return await make_dmarc_aggregate(
        db, domain, days_ago=3, source_org=org, source_ip=ip,
        total_count=total, pass_count=total - fail, fail_count=fail,
        disposition="none", classification=classification,
    )


# ── Pain 4: per-source readiness ─────────────────────────────────────────────

async def test_simulate_policy_returns_every_sources_readiness_blockers_first(auth_client, db_session):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="ready.test", dmarc_stage="monitor")
    await _agg(db_session, domain, "Google", "10.0.0.1", 2000, 0, "authorized")
    await _agg(db_session, domain, "SendGrid", "10.0.0.2", 500, 100, "authorized")
    await _agg(db_session, domain, "Unknown host", "10.0.0.3", 400, 400, "spoof")
    await _agg(db_session, domain, "Tiny sender", "10.0.0.4", 3, 3, "authorized")
    await db_session.commit()

    r = await client.get(f"/domains/{domain.id}/simulate-policy")
    assert r.status_code == 200
    rows = {x["source_org"]: x["status"] for x in r.json()["source_readiness"]}
    assert rows == {
        "SendGrid": "blocking",              # authorized and failing: this is what stops enforcement
        "Unknown host": "will_be_blocked",   # not ours, failing: exactly what enforcement is for
        "Google": "ready",
        "Tiny sender": "below_floor",        # too small a share to gate on, shown for transparency
    }
    order = [x["status"] for x in r.json()["source_readiness"]]
    assert order[0] == "blocking" and order[-1] == "below_floor"


async def test_simulate_policy_refuses_when_there_is_nothing_to_simulate(auth_client, db_session):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="done.test", dmarc_stage="reject")
    r = await client.get(f"/domains/{domain.id}/simulate-policy")
    assert r.status_code == 400
    assert "Nothing to simulate" in r.json()["detail"]


async def test_simulate_policy_is_scoped_to_the_workspace(auth_client, db_session):
    from tests.factories import make_tenant
    client, _ = auth_client
    other = await make_tenant(db_session, name="Someone Else")
    theirs = await make_domain(db_session, other, name="theirs.test", dmarc_stage="monitor")
    assert (await client.get(f"/domains/{theirs.id}/simulate-policy")).status_code == 404


# ── Pain 3: DKIM failure hypotheses reach the drill-down ─────────────────────

def _details(body):
    return [d for s in body["sources"] for ip in s["ips"] for d in ip["auth_details"]]


async def test_failed_dkim_detail_carries_ranked_hypotheses_to_the_api(auth_client, db_session):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="dkim.test", dmarc_stage="monitor")
    agg = await _agg(db_session, domain, "Mailer", "10.0.0.9", 300, 300, "unauthorized")
    agg.dkim_result, agg.dkim_aligned = "fail", False
    agg.spf_result, agg.spf_aligned = "fail", False
    agg.envelope_from = "bounce.forwarder.example"          # differs from the header-from: forwarding's hallmark
    agg.dkim_domain = "dkim.test"
    await db_session.commit()

    body = (await client.get(f"/domains/{domain.id}/dmarc?days=30")).json()
    failing = [d for d in _details(body) if d["dmarc_result"] == "fail"]
    assert failing, "the failing row should be present"
    hyps = failing[0]["dkim_failure_hypotheses"]
    assert [h["id"] for h in hyps] == ["transit_modification", "key_mismatch"]
    assert hyps[0]["confidence"] > hyps[1]["confidence"]
    assert hyps[0]["fix"] != hyps[1]["fix"]


async def test_passing_detail_has_no_hypotheses(auth_client, db_session):
    client, tenant = auth_client
    domain = await make_domain(db_session, tenant, name="fine.test", dmarc_stage="monitor")
    agg = await _agg(db_session, domain, "Google", "10.0.0.8", 300, 0, "authorized")
    agg.dkim_result, agg.dkim_aligned = "pass", True
    agg.spf_result, agg.spf_aligned = "pass", True
    agg.dkim_domain = "fine.test"
    await db_session.commit()

    body = (await client.get(f"/domains/{domain.id}/dmarc?days=30")).json()
    assert all(d["dkim_failure_hypotheses"] == [] for d in _details(body))
