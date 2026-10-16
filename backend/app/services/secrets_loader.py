"""
Secrets from a managed store at start-up (V2 plan C2).

With SECRETS_PROVIDER=aws and AWS_SECRET_ID set, one JSON secret in AWS Secrets
Manager is read once when the process starts and its keys fill the settings.
Anything set in the environment wins, so a single value can still be overridden
by hand, and nothing changes when the provider is not configured.

The secret is one JSON object whose keys are setting names (upper or lower
case): {"SECRET_KEY": "...", "SENDGRID_API_KEY": "...", "DATABASE_URL": "..."}.
Unknown keys are ignored and reported by name only; values are never logged.

Also holds the production guard: a process that says it is production refuses to
start with the public development signing key or the default database password.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable

log = logging.getLogger(__name__)

DEV_SECRET_KEY = "dev-secret-change-in-production"
MIN_SECRET_KEY_LENGTH = 32
_PRODUCTION = {"production", "prod"}


class SecretsError(RuntimeError):
    """The managed store was configured but could not be read. Start-up stops: running on defaults would be worse."""


def fetch_secret_json(
    secret_id: str,
    region: str = "",
    *,
    client_factory: Callable[..., Any] | None = None,
) -> dict[str, str]:
    """Read one Secrets Manager secret holding a JSON object. Raises SecretsError, never returns partial data."""
    try:
        if client_factory is None:
            import boto3
            client_factory = boto3.client
        kwargs = {"region_name": region} if region else {}
        client = client_factory("secretsmanager", **kwargs)
        raw = client.get_secret_value(SecretId=secret_id).get("SecretString")
    except Exception as e:
        # The exception type is enough to act on; the message can carry the secret's ARN or request details.
        raise SecretsError(f"Could not read secret '{secret_id}' from AWS Secrets Manager ({type(e).__name__})") from None
    if not raw:
        raise SecretsError(f"Secret '{secret_id}' has no SecretString (binary secrets are not supported)")
    try:
        data = json.loads(raw)
    except ValueError:
        raise SecretsError(f"Secret '{secret_id}' is not valid JSON; expected an object of setting names to values") from None
    if not isinstance(data, dict):
        raise SecretsError(f"Secret '{secret_id}' must be a JSON object of setting names to values")
    return {str(k).lower(): "" if v is None else str(v) for k, v in data.items()}


def overrides_from_secret(
    secret: dict[str, str],
    known_fields: set[str],
    environ: dict[str, str] | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Which secret values to apply: known setting names the environment has not set. Also returns ignored key names."""
    # An empty value (compose passes unset variables through as "") counts as not set.
    env = {k.lower() for k, v in (os.environ if environ is None else environ).items() if v}
    apply, ignored = {}, []
    for key, value in secret.items():
        if key not in known_fields:
            ignored.append(key)
        elif key not in env:
            apply[key] = value
    return apply, sorted(ignored)


def production_problems(*, environment: str, secret_key: str, database_url: str) -> list[str]:
    """What stops a production process from starting. Empty list means fine (or not production)."""
    if environment.strip().lower() not in _PRODUCTION:
        return []
    problems = []
    if secret_key == DEV_SECRET_KEY:
        problems.append("SECRET_KEY is the public development default; tokens could be forged by anyone who reads the source")
    elif len(secret_key) < MIN_SECRET_KEY_LENGTH:
        problems.append(f"SECRET_KEY is shorter than {MIN_SECRET_KEY_LENGTH} characters")
    # sqlalchemy URL: scheme://user:password@host/db
    creds = database_url.split("://", 1)[-1].split("@", 1)[0]
    if "@" in database_url.split("://", 1)[-1] and ":" in creds and creds.split(":", 1)[1] == "sentinel":
        problems.append("DATABASE_URL uses the default database password")
    return problems


def enforce_production_guard(*, environment: str, secret_key: str, database_url: str) -> None:
    problems = production_problems(environment=environment, secret_key=secret_key, database_url=database_url)
    if problems:
        raise SecretsError(
            "Refusing to start with ENVIRONMENT=" + environment + ": " + "; ".join(problems)
            + ". Set real values (environment or the managed secret), or set ENVIRONMENT=development for local work."
        )
