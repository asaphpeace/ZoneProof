"""C2: secrets from a managed store at start-up, and the production start-up guard."""
import json

import pytest

from app.services.secrets_loader import (
    DEV_SECRET_KEY,
    SecretsError,
    enforce_production_guard,
    fetch_secret_json,
    overrides_from_secret,
    production_problems,
)

GOOD_KEY = "k" * 40
GOOD_DB = "postgresql+asyncpg://zp:a-long-random-password@db.internal:5432/zoneproof"


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.asked = response, error, []

    def get_secret_value(self, SecretId):
        self.asked.append(SecretId)
        if self.error:
            raise self.error
        return self.response


def factory(client, seen=None):
    def make(service, **kwargs):
        if seen is not None:
            seen.update(service=service, **kwargs)
        return client
    return make


# ── reading the secret ───────────────────────────────────────────────────────

def test_reads_one_json_secret_and_lowercases_keys():
    client = FakeClient({"SecretString": json.dumps({"SECRET_KEY": "abc", "SENDGRID_API_KEY": "SG.x", "N": None})})
    seen = {}
    data = fetch_secret_json("zp/prod", "eu-west-1", client_factory=factory(client, seen))
    assert data == {"secret_key": "abc", "sendgrid_api_key": "SG.x", "n": ""}
    assert client.asked == ["zp/prod"]
    assert seen == {"service": "secretsmanager", "region_name": "eu-west-1"}


def test_unreadable_secret_stops_start_up_without_leaking_details():
    client = FakeClient(error=RuntimeError("arn:aws:secretsmanager:...:secret:zp/prod-AbC123 access denied"))
    with pytest.raises(SecretsError) as e:
        fetch_secret_json("zp/prod", client_factory=factory(client))
    assert "RuntimeError" in str(e.value) and "AbC123" not in str(e.value)


@pytest.mark.parametrize("response", [{}, {"SecretString": ""}, {"SecretString": "not json"}, {"SecretString": "[1, 2]"}])
def test_secrets_that_are_not_a_json_object_are_refused(response):
    with pytest.raises(SecretsError):
        fetch_secret_json("zp/prod", client_factory=factory(FakeClient(response)))


# ── what gets applied ────────────────────────────────────────────────────────

def test_environment_wins_and_unknown_keys_are_reported_by_name_only():
    secret = {"secret_key": "from-store", "sendgrid_api_key": "SG.store", "not_a_setting": "hunter2"}
    known = {"secret_key", "sendgrid_api_key"}
    apply, ignored = overrides_from_secret(secret, known, environ={"SENDGRID_API_KEY": "SG.env"})
    assert apply == {"secret_key": "from-store"}
    assert ignored == ["not_a_setting"]


# ── the production guard ─────────────────────────────────────────────────────

def test_development_is_never_blocked():
    assert production_problems(environment="development", secret_key=DEV_SECRET_KEY,
                               database_url="postgresql+asyncpg://sentinel:sentinel@localhost/x") == []


@pytest.mark.parametrize("env", ["production", "PRODUCTION", " prod "])
def test_production_with_the_public_key_is_refused(env):
    with pytest.raises(SecretsError, match="public development default"):
        enforce_production_guard(environment=env, secret_key=DEV_SECRET_KEY, database_url=GOOD_DB)


def test_production_with_a_short_key_or_default_database_password_is_refused():
    assert any("shorter" in p for p in production_problems(environment="production", secret_key="short", database_url=GOOD_DB))
    problems = production_problems(environment="production", secret_key=GOOD_KEY,
                                   database_url="postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinel")
    assert problems == ["DATABASE_URL uses the default database password"]


def test_production_with_real_values_starts():
    enforce_production_guard(environment="production", secret_key=GOOD_KEY, database_url=GOOD_DB)


# ── load_settings end to end ─────────────────────────────────────────────────

def test_load_settings_fills_unset_values_from_the_secret_and_env_still_wins(monkeypatch):
    from app import config
    from app.services import secrets_loader

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRETS_PROVIDER", "aws")
    monkeypatch.setenv("AWS_SECRET_ID", "zp/prod")
    monkeypatch.setenv("SECRET_KEY", "")                       # compose passes unset values as empty
    monkeypatch.setenv("DATABASE_URL", GOOD_DB)
    monkeypatch.setenv("SENDGRID_API_KEY", "SG.from-env")
    monkeypatch.setattr(secrets_loader, "fetch_secret_json",
                        lambda secret_id, region="": {"secret_key": GOOD_KEY, "sendgrid_api_key": "SG.store", "junk": "x"})
    s = config.load_settings()
    assert s.secret_key == GOOD_KEY and s.sendgrid_api_key == "SG.from-env"


def test_load_settings_refuses_production_on_defaults(monkeypatch):
    from app import config

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("SECRETS_PROVIDER", raising=False)
    monkeypatch.setenv("SECRET_KEY", DEV_SECRET_KEY)
    with pytest.raises(SecretsError):
        config.load_settings()


def test_provider_without_a_secret_id_stops_start_up(monkeypatch):
    from app import config

    monkeypatch.setenv("SECRETS_PROVIDER", "aws")
    monkeypatch.delenv("AWS_SECRET_ID", raising=False)
    with pytest.raises(SecretsError, match="AWS_SECRET_ID"):
        config.load_settings()
