"""
Tests for cloudsplaining_privesc_scan.py's role-name -> ARN cross-
referencing logic. Requires `cloudsplaining` itself, which only exists in
backend/.venv-iam-tools — NOT part of the main app test suite (see
tests/test_cloudsplaining_scan.py for the plumbing tests that do run there).

Run manually from backend/:
    .venv-iam-tools/Scripts/python -m pytest tools/test_cloudsplaining_privesc_scan.py

Fixtures below are real get_account_authorization_details()-shaped input,
verified against actual Cloudsplaining output while building the script
(see its module docstring) — not guessed from documentation.
"""
from cloudsplaining.scan.authorization_details import AuthorizationDetails
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS

from cloudsplaining_privesc_scan import find_iam_policy_risk_findings, find_privilege_escalation_paths


def test_resolves_role_name_to_arn_for_a_known_escalation():
    fixture = {
        "UserDetailList": [], "GroupDetailList": [],
        "RoleDetailList": [{
            "RoleName": "escalatable-role", "RoleId": "AROATEST123",
            "Arn": "arn:aws:iam::123456789012:role/escalatable-role", "Path": "/",
            "CreateDate": "2026-01-01T00:00:00Z",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
            "InstanceProfileList": [],
            "RolePolicyList": [{
                "PolicyName": "escalation-policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["iam:CreatePolicyVersion", "iam:PassRole"],
                        "Resource": "*",
                    }],
                },
            }],
            "AttachedManagedPolicies": [], "Tags": [], "RoleLastUsed": {},
        }],
        "Policies": [],
    }

    auth_details = AuthorizationDetails(fixture, DEFAULT_EXCLUSIONS)
    paths = find_privilege_escalation_paths(auth_details.results)

    assert len(paths) == 1
    assert paths[0]["principal_arn"] == "arn:aws:iam::123456789012:role/escalatable-role"
    assert paths[0]["escalation_type"] == "CreateNewPolicyVersion"
    assert paths[0]["severity"] == "high"
    # The policy that actually grants the escalating permissions — real
    # evidence for the attack-path graph's drill-down panel, not just the
    # abstract technique name.
    assert paths[0]["policy_name"] == "escalation-policy"
    # Real statement-level Resource/Condition scope — previously computed
    # by Cloudsplaining but never read by this script. "Resource": "*"
    # here is exactly the kind of unconstrained scope the attack
    # simulation engine needs to tell apart from a policy scoped to one
    # specific bucket/table/etc.
    assert paths[0]["policy_document"]["Statement"][0]["Resource"] == "*"
    assert "iam:PassRole" in paths[0]["policy_document"]["Statement"][0]["Action"]


def test_resolves_user_name_to_arn_for_a_known_escalation():
    # Real gap found while testing against a deliberately over-permissioned
    # IAM user rather than assumed: the original version of this function
    # only read AttachedTo["roles"], silently dropping any escalation
    # policy attached directly to a user — the common case for smaller
    # accounts that haven't adopted role-based access (this product's
    # actual target market per BUILD_PLAN.md).
    fixture = {
        "RoleDetailList": [], "GroupDetailList": [],
        "UserDetailList": [{
            "UserName": "escalatable-user", "UserId": "AIDATEST789",
            "Arn": "arn:aws:iam::123456789012:user/escalatable-user", "Path": "/",
            "CreateDate": "2026-01-01T00:00:00Z",
            "UserPolicyList": [{
                "PolicyName": "escalation-policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                        "Resource": "*",
                    }],
                },
            }],
            "AttachedManagedPolicies": [], "GroupList": [], "Tags": [],
        }],
        "Policies": [],
    }

    auth_details = AuthorizationDetails(fixture, DEFAULT_EXCLUSIONS)
    paths = find_privilege_escalation_paths(auth_details.results)

    # Granting both CreatePolicyVersion and SetDefaultPolicyVersion trips
    # two distinct Cloudsplaining escalation types, not one.
    assert len(paths) == 2
    assert all(p["principal_arn"] == "arn:aws:iam::123456789012:user/escalatable-user" for p in paths)
    assert {p["escalation_type"] for p in paths} == {"CreateNewPolicyVersion", "SetExistingDefaultPolicyVersion"}


def test_empty_for_a_role_with_no_escalation_potential():
    fixture = {
        "UserDetailList": [], "GroupDetailList": [],
        "RoleDetailList": [{
            "RoleName": "read-only-role", "RoleId": "AROATEST456",
            "Arn": "arn:aws:iam::123456789012:role/read-only-role", "Path": "/",
            "CreateDate": "2026-01-01T00:00:00Z",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
            "InstanceProfileList": [],
            "RolePolicyList": [{
                "PolicyName": "read-only-policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}],
                },
            }],
            "AttachedManagedPolicies": [], "Tags": [], "RoleLastUsed": {},
        }],
        "Policies": [],
    }

    auth_details = AuthorizationDetails(fixture, DEFAULT_EXCLUSIONS)
    assert find_privilege_escalation_paths(auth_details.results) == []


def test_find_iam_policy_risk_findings_flags_unconstrained_data_exfiltration_actions():
    # Phase 36 AWS data-discard audit: DataExfiltration/ResourceExposure/
    # ServiceWildcard/CredentialsExposure are computed by Cloudsplaining for
    # every policy alongside PrivilegeEscalation but were never read at all
    # before this. s3:GetObject with no resource constraint is a real,
    # documented DataExfiltration trigger (cloudsplaining/shared/constants.py
    # READ_ONLY_DATA_EXFILTRATION_ACTIONS), not a synthetic example.
    fixture = {
        "UserDetailList": [], "GroupDetailList": [],
        "RoleDetailList": [{
            "RoleName": "over-permissioned-role", "RoleId": "AROATEST999",
            "Arn": "arn:aws:iam::123456789012:role/over-permissioned-role", "Path": "/",
            "CreateDate": "2026-01-01T00:00:00Z",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
            "InstanceProfileList": [],
            "RolePolicyList": [{
                "PolicyName": "unconstrained-s3-read",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
                },
            }],
            "AttachedManagedPolicies": [], "Tags": [], "RoleLastUsed": {},
        }],
        "Policies": [],
    }

    auth_details = AuthorizationDetails(fixture, DEFAULT_EXCLUSIONS)
    findings = find_iam_policy_risk_findings(auth_details.results)

    data_exfil = [f for f in findings if f["category"] == "DataExfiltration"]
    assert len(data_exfil) == 1
    assert data_exfil[0]["principal_arn"] == "arn:aws:iam::123456789012:role/over-permissioned-role"
    assert "s3:GetObject" in data_exfil[0]["actions"]
    assert data_exfil[0]["policy_name"] == "unconstrained-s3-read"
    assert data_exfil[0]["policy_document"]["Statement"][0]["Resource"] == "*"
    # ServiceWildcard/ResourceExposure/CredentialsExposure genuinely don't
    # apply to this narrow single-action policy — confirming the function
    # doesn't fabricate categories that don't actually fire.
    assert {f["category"] for f in findings} == {"DataExfiltration"}


def test_find_iam_policy_risk_findings_empty_for_a_read_only_constrained_policy():
    fixture = {
        "UserDetailList": [], "GroupDetailList": [],
        "RoleDetailList": [{
            "RoleName": "constrained-role", "RoleId": "AROATEST888",
            "Arn": "arn:aws:iam::123456789012:role/constrained-role", "Path": "/",
            "CreateDate": "2026-01-01T00:00:00Z",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
            "InstanceProfileList": [],
            "RolePolicyList": [{
                "PolicyName": "constrained-s3-read",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::specific-bucket/*"}],
                },
            }],
            "AttachedManagedPolicies": [], "Tags": [], "RoleLastUsed": {},
        }],
        "Policies": [],
    }

    auth_details = AuthorizationDetails(fixture, DEFAULT_EXCLUSIONS)
    assert find_iam_policy_risk_findings(auth_details.results) == []
