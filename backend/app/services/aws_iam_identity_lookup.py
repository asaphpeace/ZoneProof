"""
Best-effort AWS IAM-user-to-email resolution via a conventional tag
(Coverage Map plan phishing transformation, Phase 7) — the fallback for
principals `_extract_sso_session_email()` in threat_detection_service.py
can't resolve (no CloudTrail AssumedRole activity yet, or the account
doesn't use SSO/IAM Identity Center).

IAM Users only, deliberately — a Role can be assumed by many different
humans, so a role-level tag can never honestly represent one person's
email the way a user-level tag can.
"""
from __future__ import annotations

import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.config import settings

_log = logging.getLogger(__name__)

_EMAIL_TAG_KEYS = {"email", "Email", "EMAIL", "e-mail", "E-mail"}


def lookup_iam_user_email_tag(role_arn: str, external_id: str, user_name: str) -> str | None:
    """Assumes the connection's already-granted read-only role (same
    pattern as every other AWS call in this codebase) and reads the IAM
    user's own tags for a conventional Email tag key. Never raises — a
    missing permission or an untagged user is a normal, expected outcome,
    not a failure worth surfacing as one."""
    try:
        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="sentinel-command-iam-identity-lookup",
            ExternalId=external_id, DurationSeconds=900,
        )["Credentials"]
        iam = boto3.client(
            "iam",
            region_name=settings.command_aws_default_region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        tags = iam.list_user_tags(UserName=user_name).get("Tags", [])
    except (ClientError, BotoCoreError) as e:
        _log.info("IAM user email-tag lookup failed (non-fatal): user_name=%s error=%s", user_name, e)
        return None

    for tag in tags:
        if tag.get("Key") in _EMAIL_TAG_KEYS and tag.get("Value"):
            return tag["Value"].strip().lower()
    return None
