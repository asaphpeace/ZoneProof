"""
Curated "how to fix this" remediation text for IAM privilege-escalation
edges (CloudPrivEscPath) and OAuth-grant edges (OAuthGrant) — the graph's
own edges (and Simulate-the-Fix's simulated paths) already say WHAT the
technique is (escalation_type/technique_chain) and its MITRE tag
(attack_technique_mapping.py), but never a concrete instruction for what to
actually go change in AWS/Entra ID. Same posture as
attack_technique_mapping.py's own docstring: a reasonable, curated
best-effort mapping built from AWS/Microsoft's own published guidance for
each technique, not a source-verified data file — confirm before treating
it as authoritative remediation advice for a specific customer environment.

Keyed the same way IamPathEvidence.vue's own (frontend-only, narrower)
ESCALATION_LABELS/ACTION_REASONS maps are — escalation_type first (the most
specific, Cloudsplaining-classified case), falling back to the first action
in technique_chain, lowercased. Deliberately server-side (unlike the
frontend's plain-language "why" sentence) so the same real text is
available everywhere an edge/path is rendered — GraphView.vue's evidence
panel and SimulateFixView.vue's — without duplicating the map twice.
"""

_ESCALATION_TYPE_REMEDIATION: dict[str, str] = {
    "CreateNewPolicyVersion": (
        "Remove iam:CreatePolicyVersion (and iam:SetDefaultPolicyVersion) from this principal's own "
        "permissions, or attach a permissions boundary that blocks it from modifying IAM policies at all."
    ),
    "SetExistingDefaultPolicyVersion": (
        "Remove iam:SetDefaultPolicyVersion from this principal, or restrict it with a Resource condition "
        "so it can't target policies attached to itself."
    ),
    "CreateEC2WithExistingIP": (
        "Remove ec2:RunInstances + iam:PassRole from this principal together, or add an "
        "iam:PassedToService/Resource condition to iam:PassRole limiting it to a fixed allow-list of "
        "instance profiles it's actually meant to launch."
    ),
    "PassExistingRoleToNewLambdaThenInvoke": (
        "Remove iam:PassRole + lambda:CreateFunction/InvokeFunction from this principal together, or add "
        "an iam:PassedToService condition to iam:PassRole restricting which roles it can hand to Lambda."
    ),
    "RunsAsRole": (
        "Ensure this instance's attached IAM role follows least privilege — anything the role can do, an "
        "attacker who compromises the instance (SSRF against IMDS, remote code execution, etc.) inherits "
        "too. Review its attached policies and remove anything the workload doesn't actually need."
    ),
    "InternetExposed": (
        "Restrict this resource's security group ingress rules to known, trusted CIDR ranges instead of "
        "0.0.0.0/0. If public access is genuinely required, front it with a WAF or load balancer rather "
        "than exposing the resource directly."
    ),
    "LateralMovement": (
        "Scope this security group's ingress rule to the specific port and protocol actually required "
        "between these two resources, or remove it entirely and route the access through a bastion host "
        "or AWS Systems Manager Session Manager instead of direct instance-to-instance network access."
    ),
    "CanAccessData": (
        "Scope this principal's S3 statements to only the specific buckets/prefixes actually required, "
        "removing any wildcard Resource grant. Note this reflects the identity policy only — a bucket "
        "policy or Organizations SCP/RCP could independently restrict this further and should be checked "
        "before assuming this access is fully blocked by any other means."
    ),
}

_IAM_ACTION_REMEDIATION: dict[str, str] = {
    "iam:passrole": (
        "Add an iam:PassedToService or Resource condition to this PassRole permission so it can only be "
        "used for specific, intended roles — not any role in the account."
    ),
    "iam:createaccesskey": (
        "Remove iam:CreateAccessKey for other users from this principal, or scope it to the principal's "
        "own keys only (a Resource condition matching ${aws:username})."
    ),
    "iam:createloginprofile": "Remove iam:CreateLoginProfile for other users from this principal, or scope it to self-service only.",
    "iam:updateloginprofile": "Remove iam:UpdateLoginProfile for other users from this principal, or scope it to self-service only.",
    "sts:assumerole": (
        "Tighten the target role's own trust policy so only the intended principals can assume it, and "
        "remove broad sts:AssumeRole (Resource: *) from this principal."
    ),
    "iam:createpolicyversion": "Remove iam:CreatePolicyVersion from this principal, or attach a permissions boundary blocking self-modification of policies.",
    "iam:setdefaultpolicyversion": "Remove iam:SetDefaultPolicyVersion from this principal, or attach a permissions boundary blocking self-modification of policies.",
    "iam:attachuserpolicy": "Remove iam:AttachUserPolicy from this principal, or restrict it with an iam:PolicyARN condition to a fixed allow-list of policies.",
    "iam:attachrolepolicy": "Remove iam:AttachRolePolicy from this principal, or restrict it with an iam:PolicyARN condition to a fixed allow-list of policies.",
    "iam:attachgrouppolicy": "Remove iam:AttachGroupPolicy from this principal, or restrict it with an iam:PolicyARN condition to a fixed allow-list of policies.",
    "iam:putuserpolicy": "Remove iam:PutUserPolicy (inline-policy write) from this principal — inline policy authorship is rarely needed and is a direct self-escalation vector.",
    "iam:putrolepolicy": "Remove iam:PutRolePolicy (inline-policy write) from this principal — inline policy authorship is rarely needed and is a direct self-escalation vector.",
    "iam:updateassumerolepolicy": (
        "Remove iam:UpdateAssumeRolePolicy from this principal — letting it rewrite a role's trust policy "
        "lets it grant itself (or anyone) the ability to assume that role."
    ),
    "lambda:createfunction": "Remove lambda:CreateFunction from this principal, or restrict iam:PassRole so it can't hand an over-permissioned execution role to a new function.",
    "lambda:invokefunction": "Restrict which functions this principal can invoke (a Resource condition), or remove the function's own over-permissioned execution role.",
    "lambda:updatefunctioncode": "Remove lambda:UpdateFunctionCode from this principal, or restrict it to functions whose execution role isn't more privileged than this principal.",
    "ec2:runinstances": "Restrict this principal's ec2:RunInstances to a fixed allow-list of instance profiles via an iam:PassedToService/Resource condition.",
    "cloudformation:createstack": "Remove cloudformation:CreateStack from this principal, or restrict it via an iam:PassRole condition so it can't provision resources under a more privileged role.",
}

_OAUTH_SCOPE_REMEDIATION: dict[str, str] = {
    "mail.read": "Confirm this app's mailbox read access is still required; revoke the grant in the Entra ID admin center if not, or narrow it to Mail.Read.Shared.",
    "mail.readwrite": "Confirm this app's mailbox access is still required; revoke the grant if not, or narrow it from ReadWrite to Read-only if the app doesn't actually need to modify mail.",
    "mail.send": "Confirm this app genuinely needs to send mail as this account; revoke the grant if not — Mail.Send is commonly abused for internal spearphishing.",
    "files.readwrite.all": "Narrow this scope to specific sites/drives if the app supports it (Files.ReadWrite instead of .All), or revoke the grant if broad access isn't required.",
    "sites.readwrite.all": "Narrow this scope to specific SharePoint sites if the app supports it, or revoke the grant if tenant-wide access isn't required.",
    "directory.readwrite.all": "This is a tenant-wide directory-write scope — confirm it's genuinely required for this app's function and revoke if not; prefer a narrower delegated scope where the provider offers one.",
    "user.readwrite.all": "This scope lets the app read and modify any user account in the directory — confirm it's genuinely required and revoke if not.",
}

_DEFAULT_REMEDIATION = (
    "Review the specific permissions in this chain and remove or scope down whichever ones aren't "
    "strictly required for this principal's actual job — no specific remediation template exists yet "
    "for this exact combination."
)


def remediation_for_edge(escalation_type: str | None, technique_chain: list[str]) -> str:
    """The one function both graph_service.py (live edges) and the
    /graph/simulate router (simulated paths) call, so the same real text
    shows up everywhere an edge/path is rendered. escalation_type (when
    Cloudsplaining classified one) is the most specific case; otherwise
    falls back to the first action/scope in technique_chain — matches the
    same precedence IamPathEvidence.vue's own frontend plain-language
    mapping already uses for its "why" sentence."""
    if escalation_type and escalation_type in _ESCALATION_TYPE_REMEDIATION:
        return _ESCALATION_TYPE_REMEDIATION[escalation_type]
    if not technique_chain:
        return _DEFAULT_REMEDIATION
    key = technique_chain[0].lower()
    if key in _IAM_ACTION_REMEDIATION:
        return _IAM_ACTION_REMEDIATION[key]
    if key in _OAUTH_SCOPE_REMEDIATION:
        return _OAUTH_SCOPE_REMEDIATION[key]
    return _DEFAULT_REMEDIATION
