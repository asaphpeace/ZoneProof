"""MSP view of Brand Guard (plan 8.4): a roll-up across clients, and a white-label evidence pack for a client's look-alike."""
import json
import uuid
from datetime import datetime, timedelta, timezone

from app.models import BrandCandidate, BrandProfile
from app.models.user import Tenant
from app.services import brand_evidence_pack as ep
from tests.factories import make_domain, make_tenant, make_user
from tests.test_msp import _login_as


async def _msp(client, db_session, plan="msp"):
    t = await make_tenant(db_session, name="Zeta MSP", plan=plan)
    t.brand_name = "Zeta Secure"
    await make_user(db_session, t, email=f"owner-{uuid.uuid4().hex[:6]}@example.com", password="pass123")
    await db_session.flush()
    return t


async def _client_with_brand(db_session, msp, name, *, statuses=(), overdue=0):
    c = Tenant(id=uuid.uuid4(), name=name, plan="free", parent_tenant_id=msp.id)
    db_session.add(c)
    await db_session.flush()
    await make_user(db_session, c, email=f"u-{uuid.uuid4().hex[:6]}@example.com", password="pass123")
    d = await make_domain(db_session, c, name=f"{name.lower()}.co.za")
    prof = BrandProfile(id=uuid.uuid4(), tenant_id=c.id, domain_id=d.id, brand_name=name, keywords=[], official_domains=[])
    db_session.add(prof)
    await db_session.flush()
    now = datetime.now(timezone.utc)
    for i, st in enumerate(statuses):
        db_session.add(BrandCandidate(
            id=uuid.uuid4(), tenant_id=c.id, profile_id=prof.id, candidate_domain=f"{name.lower()}-{i}.xyz", status=st, stage="resolving", enrichment={"a": ["1.2.3.4"]},
            first_seen_at=now, due_at=(now - timedelta(hours=1)) if (i < overdue and st in ("confirmed", "takedown")) else None,
        ))
    await db_session.commit()
    return c


async def test_rollup_needs_the_msp_plan(auth_client):
    client, _ = auth_client
    r = await client.get("/msp/brand-guard")
    assert r.status_code == 403


async def test_rollup_counts_per_client_and_puts_the_most_urgent_first(client, db_session):
    msp = await _msp(client, db_session)
    quiet = await _client_with_brand(db_session, msp, "Quiet", statuses=("false_positive",))
    busy = await _client_with_brand(db_session, msp, "Busy", statuses=("confirmed", "confirmed", "takedown", "suspicious", "new"), overdue=2)
    await _client_with_brand(db_session, msp, "Mid", statuses=("suspicious", "suspicious"))
    from sqlalchemy import select
    from app.models import User
    owner = (await db_session.execute(select(User).where(User.tenant_id == msp.id))).scalars().first()
    await _login_as(client, owner.email)
    r = (await client.get("/msp/brand-guard")).json()
    assert [c["name"] for c in r["clients"]] == ["Busy", "Mid", "Quiet"]
    b = r["clients"][0]
    assert (b["brands"], b["confirmed"], b["takedown"], b["overdue"], b["needs_attention"]) == (1, 2, 1, 2, 2)
    assert r["totals"]["brands"] == 3 and r["totals"]["overdue"] == 2 and r["totals"]["confirmed"] == 2


async def test_rollup_never_shows_another_msps_clients(client, db_session):
    mine = await _msp(client, db_session)
    other = await make_tenant(db_session, name="Other MSP", plan="msp")
    await _client_with_brand(db_session, other, "Theirs", statuses=("confirmed",))
    from sqlalchemy import select
    from app.models import User
    owner = (await db_session.execute(select(User).where(User.tenant_id == mine.id))).scalars().first()
    await _login_as(client, owner.email)
    assert (await client.get("/msp/brand-guard")).json() == {"clients": [], "totals": {"brands": 0, "needs_attention": 0, "confirmed": 0, "takedown": 0, "overdue": 0}}


async def _login_owner(client, db_session, msp):
    from sqlalchemy import select
    from app.models import User
    owner = (await db_session.execute(select(User).where(User.tenant_id == msp.id))).scalars().first()
    await _login_as(client, owner.email)


async def test_white_label_pack_is_presented_as_the_msp_and_audited_against_the_msp(client, db_session):
    from sqlalchemy import select
    from app.models.audit_log import AuditLogEntry
    msp = await _msp(client, db_session)
    c = await _client_with_brand(db_session, msp, "Clientco", statuses=("confirmed",))
    await _login_owner(client, db_session, msp)
    cases = (await client.get(f"/msp/clients/{c.id}/brand-guard/cases")).json()
    assert [x["domain"] for x in cases] == ["clientco-0.xyz"]
    r = await client.get(f"/msp/clients/{c.id}/brand-guard/candidates/{cases[0]['id']}/evidence-pack?format=json")
    assert r.status_code == 200
    pack = json.loads(r.text)
    assert ep.verify(pack) and pack["issuer"] == {"name": "Zeta Secure"} and pack["brand"]["name"] == "Clientco"
    assert pack["generated_by"] != ""
    rows = (await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.action == "msp.client_evidence_pack_exported"))).scalars().all()
    assert len(rows) == 1 and rows[0].tenant_id == msp.id and "Clientco" in rows[0].target_label
    pdf = await client.get(f"/msp/clients/{c.id}/brand-guard/candidates/{cases[0]['id']}/evidence-pack?format=pdf")
    assert pdf.content[:4] == b"%PDF"


async def test_white_label_pack_needs_the_feature_and_refuses_other_msps_clients_and_candidates(client, db_session):
    msp = await _msp(client, db_session)
    other = await make_tenant(db_session, name="Other MSP", plan="msp")
    theirs = await _client_with_brand(db_session, other, "Theirs", statuses=("confirmed",))
    mine = await _client_with_brand(db_session, msp, "Mine", statuses=("confirmed",))
    await _login_owner(client, db_session, msp)
    their_cand = (await db_session.execute(__import__("sqlalchemy").select(BrandCandidate).where(BrandCandidate.tenant_id == theirs.id))).scalars().first()
    my_cand = (await db_session.execute(__import__("sqlalchemy").select(BrandCandidate).where(BrandCandidate.tenant_id == mine.id))).scalars().first()
    assert (await client.get(f"/msp/clients/{theirs.id}/brand-guard/candidates/{their_cand.id}/evidence-pack?format=json")).status_code == 404
    assert (await client.get(f"/msp/clients/{theirs.id}/brand-guard/cases")).status_code == 404
    # a candidate of a different tenant, requested through MY client's path, must not leak either
    assert (await client.get(f"/msp/clients/{mine.id}/brand-guard/candidates/{their_cand.id}/evidence-pack?format=json")).status_code == 404
    assert (await client.get(f"/msp/clients/{mine.id}/brand-guard/candidates/{my_cand.id}/evidence-pack?format=docx")).status_code == 422
