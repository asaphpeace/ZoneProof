"""
Router-level tests for POST /prospect-assessment — auth + input validation
+ rate-limit wiring, not the detection logic itself (see
test_prospect_assessment_service.py for that).
"""
from app.routers import prospect as router_module


async def test_requires_auth(client):
    resp = await client.post("/prospect-assessment", json={"domain": "example.com"})
    assert resp.status_code == 401


async def test_rejects_a_domain_with_no_dot(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/prospect-assessment", json={"domain": "notadomain"})
    assert resp.status_code == 400


async def test_rejects_an_empty_domain(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/prospect-assessment", json={"domain": "   "})
    assert resp.status_code == 400


async def test_returns_the_real_service_result(auth_client, monkeypatch):
    client, _tenant = auth_client

    async def fake_assess(domain):
        return {
            "domain": domain, "score": 60.0, "grade": "C", "grade_color": "#f5c542",
            "checks": [{"label": "Email Authentication (DMARC)", "found": True, "detail": "DMARC record found — policy is p=reject."}],
            "not_assessed": ["Cloud Misconfiguration Defense", "Third-Party OAuth App Risk", "Identity & Credential Hygiene"],
        }

    monkeypatch.setattr(router_module, "assess_domain", fake_assess)

    resp = await client.post("/prospect-assessment", json={"domain": "Example.COM"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["domain"] == "example.com"  # lowercased/stripped before hitting the service
    assert body["grade"] == "C"
    assert body["not_assessed"] == [
        "Cloud Misconfiguration Defense", "Third-Party OAuth App Risk", "Identity & Credential Hygiene",
    ]


async def test_rate_limited_at_three_per_minute(auth_client, monkeypatch):
    client, _tenant = auth_client

    async def fake_assess(domain):
        return {
            "domain": domain, "score": 0.0, "grade": "F", "grade_color": "#ff4d6d",
            "checks": [], "not_assessed": [],
        }

    monkeypatch.setattr(router_module, "assess_domain", fake_assess)

    statuses = []
    for _ in range(4):
        resp = await client.post("/prospect-assessment", json={"domain": "example.com"})
        statuses.append(resp.status_code)

    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429
