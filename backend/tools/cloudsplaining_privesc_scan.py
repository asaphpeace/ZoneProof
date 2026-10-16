"""
Runs inside backend/.venv-iam-tools (not the app's own venv — see
requirements-tools.txt for why Cloudsplaining/PMapper are isolated).

Assumes the target role, downloads the account's IAM authorization details,
and emits a flat JSON array of privilege-escalation findings to stdout —
deliberately NOT reusing Cloudsplaining's own nested export format (findings
are keyed by policy ID with role *names* under AttachedTo, not principal
ARNs directly; verified empirically against a real fixture while building
this, not assumed from docs).

Usage:
    python cloudsplaining_privesc_scan.py --role-arn <arn> --external-id <id>

Output shape:
    {
      "priv_esc_paths": [{"principal_arn": "...", "escalation_type": "...", "actions": [...], "policy_document": {...} | null}, ...],
      "policy_risk_findings": [{"principal_arn": "...", "category": "...", "actions": [...], "policy_document": {...} | null}, ...],
    }

policy_document is the real Cloudsplaining-computed IAM policy JSON (the
actual Resource/Condition scope per statement) — previously computed but
never read by this script, so "Resource: *" and a single scoped bucket
looked identical downstream. null when Cloudsplaining didn't attach one
for that policy.
"""
from __future__ import annotations

import argparse
import json
import sys

import boto3
from cloudsplaining.scan.authorization_details import AuthorizationDetails
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS

_POLICY_SECTIONS = ("inline_policies", "customer_managed_policies", "aws_managed_policies")

# The 4 Cloudsplaining risk categories computed for every policy alongside
# PrivilegeEscalation but never previously read at all (Phase 36 AWS
# data-discard audit) — confirmed against cloudsplaining/scan/inline_policy.py
# and policy_document.py this session. Unlike PrivilegeEscalation's own
# `findings` (a list of {"type", "actions"} dicts), these 4 categories'
# `findings` are plain lists of action strings — verified, not assumed
# symmetric with PrivilegeEscalation's shape.
_RISK_CATEGORIES = ("DataExfiltration", "ResourceExposure", "ServiceWildcard", "CredentialsExposure")


def _assume_role_session(role_arn: str, external_id: str) -> boto3.Session:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="sentinel-command-cloudsplaining",
        ExternalId=external_id,
        DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _fetch_authorization_details(session: boto3.Session) -> dict:
    iam = session.client("iam")
    merged = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        for key in merged:
            merged[key].extend(page.get(key, []))
    return merged


def _arn_by_name(results: dict) -> dict:
    # AttachedTo carries all three principal kinds Cloudsplaining tracks —
    # verified against cloudsplaining's own inline_policy.py/managed_policy_
    # detail.py, which build {"roles": [...], "groups": [...], "users": [...]}
    # for every policy. An earlier version of this script only read
    # AttachedTo["roles"], silently dropping any privilege-escalation policy
    # attached directly to a user or group — a real detection gap found by
    # testing against a deliberately over-permissioned IAM user rather than
    # assumed from the roles-only case working. Users in particular are the
    # common case for smaller accounts (this product's actual target market
    # per BUILD_PLAN.md) that haven't adopted role-based access.
    return {
        "roles": {r["name"]: r["arn"] for r in results["roles"].values()},
        "users": {u["name"]: u["arn"] for u in results["users"].values()},
        "groups": {g["name"]: g["arn"] for g in results["groups"].values()},
    }


def find_privilege_escalation_paths(results: dict) -> list[dict]:
    arn_by_name = _arn_by_name(results)

    paths = []
    for section in _POLICY_SECTIONS:
        for policy in results.get(section, {}).values():
            privesc = policy.get("PrivilegeEscalation", {})
            findings = privesc.get("findings") or []
            if not findings:
                continue
            severity = privesc.get("severity", "high")  # Cloudsplaining rates this category "high" as of writing
            attached_to = policy.get("AttachedTo", {})
            for principal_kind, name_to_arn in arn_by_name.items():
                for principal_name in attached_to.get(principal_kind, []):
                    principal_arn = name_to_arn.get(principal_name)
                    if not principal_arn:
                        continue
                    policy_name = policy.get("PolicyName")
                    policy_arn = policy.get("Arn") or policy.get("PolicyArn")
                    for finding in findings:
                        paths.append({
                            "principal_arn": principal_arn,
                            "escalation_type": finding.get("type"),
                            "actions": finding.get("actions", []),
                            "severity": severity,
                            "policy_name": policy_name,
                            "policy_arn": policy_arn,
                            # Real statement-level Resource/Condition scope
                            # Cloudsplaining already computes but this
                            # script never read — "Resource: *" and a
                            # single scoped bucket look identical without
                            # this (Phase: close scan-data gaps for the
                            # attack simulation engine).
                            "policy_document": policy.get("PolicyDocument"),
                        })
    return paths


def find_iam_policy_risk_findings(results: dict) -> list[dict]:
    """The 4 risk categories Cloudsplaining computes per-policy alongside
    PrivilegeEscalation but that this codebase previously discarded
    entirely — a policy with real, severe DataExfiltration or
    CredentialsExposure risk produced zero findings before this. Same
    principal-resolution walk as find_privilege_escalation_paths, since
    these aren't escalation *paths* (no source->target chain) — they
    become Finding rows, not CloudPrivEscPath rows, in the caller."""
    arn_by_name = _arn_by_name(results)

    findings = []
    for section in _POLICY_SECTIONS:
        for policy in results.get(section, {}).values():
            attached_to = policy.get("AttachedTo", {})
            policy_name = policy.get("PolicyName")
            policy_arn = policy.get("Arn") or policy.get("PolicyArn")
            for category in _RISK_CATEGORIES:
                category_result = policy.get(category) or {}
                actions = category_result.get("findings") or []
                if not actions:
                    continue
                severity = category_result.get("severity", "medium")
                for principal_kind, name_to_arn in arn_by_name.items():
                    for principal_name in attached_to.get(principal_kind, []):
                        principal_arn = name_to_arn.get(principal_name)
                        if not principal_arn:
                            continue
                        findings.append({
                            "principal_arn": principal_arn,
                            "category": category,
                            "actions": actions,
                            "severity": severity,
                            "policy_name": policy_name,
                            "policy_arn": policy_arn,
                            "policy_document": policy.get("PolicyDocument"),
                        })
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--external-id", required=True)
    args = parser.parse_args()

    session = _assume_role_session(args.role_arn, args.external_id)
    account_details = _fetch_authorization_details(session)
    auth_details = AuthorizationDetails(account_details, DEFAULT_EXCLUSIONS)
    priv_esc_paths = find_privilege_escalation_paths(auth_details.results)
    policy_risk_findings = find_iam_policy_risk_findings(auth_details.results)

    json.dump({"priv_esc_paths": priv_esc_paths, "policy_risk_findings": policy_risk_findings}, sys.stdout)


if __name__ == "__main__":
    main()
