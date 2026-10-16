"""C8: liveness stays trivial; readiness reflects the database."""
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_liveness_and_readiness_ok():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/health")).json() == {"status": "ok"}
        r = await c.get("/health/ready")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readiness_is_503_when_database_is_down(monkeypatch):
    import app.database as database

    class Down:
        def connect(self):
            raise ConnectionError("db down at 10.0.0.5")

    monkeypatch.setattr(database, "engine", Down())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/health/ready")
    assert r.status_code == 503 and "10.0.0.5" not in r.text
