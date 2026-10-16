"""
MITRE ATT&CK technique tags for IAM privilege-escalation actions
(CloudPrivEscPath.technique_chain, from Cloudsplaining's Rhino Security Labs
-derived methodology). Distinct from compliance_mapping.py's crosswalk,
which is real data Prowler ships — Cloudsplaining doesn't ship an ATT&CK
crosswalk of its own, so this is a curated mapping built from ATT&CK's own
published technique descriptions (Cloud IaaS/Privilege Escalation tactic),
not a guessed one, but also not a source-verified data file the way
compliance_mapping.py's is. Treat it as a reasonable best-effort tag, not an
authoritative crosswalk — confirm before quoting it as compliance evidence.

Keyed on the AWS IAM action, lowercased, matching how technique_chain
entries are already stored (see cloud_scan_service.run_priv_esc_analysis
and tools/cloudsplaining_privesc_scan.py).
"""

_IAM_ACTION_ATTACK_MAP: dict[str, dict] = {
    "iam:passrole": {
        "id": "T1548.005", "name": "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
    },
    "iam:createpolicyversion": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:setdefaultpolicyversion": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:attachuserpolicy": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:attachrolepolicy": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:attachgrouppolicy": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:putuserpolicy": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:putrolepolicy": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:updateassumerolepolicy": {
        "id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "iam:createaccesskey": {
        "id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials",
        "tactics": ["Persistence"],
    },
    "iam:createloginprofile": {
        "id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials",
        "tactics": ["Persistence"],
    },
    "iam:updateloginprofile": {
        "id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials",
        "tactics": ["Persistence"],
    },
    "sts:assumerole": {
        "id": "T1078.004", "name": "Valid Accounts: Cloud Accounts",
        "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    },
    "lambda:createfunction": {
        "id": "T1651", "name": "Cloud Administration Command",
        "tactics": ["Execution"],
    },
    "lambda:invokefunction": {
        "id": "T1651", "name": "Cloud Administration Command",
        "tactics": ["Execution"],
    },
    "lambda:updatefunctioncode": {
        "id": "T1651", "name": "Cloud Administration Command",
        "tactics": ["Execution"],
    },
    "ec2:runinstances": {
        "id": "T1651", "name": "Cloud Administration Command",
        "tactics": ["Execution"],
    },
    "cloudformation:createstack": {
        "id": "T1651", "name": "Cloud Administration Command",
        "tactics": ["Execution"],
    },
}

_DEFAULT_TECHNIQUE = {
    "id": "T1078.004", "name": "Valid Accounts: Cloud Accounts",
    "tactics": ["Privilege Escalation"],
}


_OAUTH_SCOPE_ATTACK_MAP: dict[str, dict] = {
    # Microsoft Graph delegated permission strings, lowercased — matches the
    # oauth2PermissionGrants.scope values oauth_app_risk_service.py stores.
    # Same curated-not-source-verified posture as the IAM map above: neither
    # Microsoft nor Google ships an official scope-to-ATT&CK crosswalk.
    "mail.read": {"id": "T1114.003", "name": "Email Collection: Email Forwarding Rule", "tactics": ["Collection"]},
    "mail.readwrite": {"id": "T1114.003", "name": "Email Collection: Email Forwarding Rule", "tactics": ["Collection"]},
    "mail.send": {"id": "T1534", "name": "Internal Spearphishing", "tactics": ["Lateral Movement"]},
    "files.readwrite.all": {"id": "T1530", "name": "Data from Cloud Storage", "tactics": ["Collection"]},
    "sites.readwrite.all": {"id": "T1530", "name": "Data from Cloud Storage", "tactics": ["Collection"]},
    "directory.readwrite.all": {"id": "T1098", "name": "Account Manipulation", "tactics": ["Persistence"]},
    "user.readwrite.all": {"id": "T1098", "name": "Account Manipulation", "tactics": ["Persistence"]},
}

_DEFAULT_OAUTH_TECHNIQUE = {
    "id": "T1528", "name": "Steal Application Access Token", "tactics": ["Credential Access"],
}


def attack_techniques_for_oauth_scopes(scopes: list[str]) -> list[dict]:
    """OAuth-scope counterpart to attack_techniques_for_actions above — kept
    as a separate function rather than reusing that one, since its default
    fallback (an IAM-specific technique) would be a wrong tag for a scope
    with no specific mapping. T1528 (Steal Application Access Token) is the
    generic technique this whole feature is an instance of, so it's the
    right fallback here, not the IAM one."""
    seen_ids: set[str] = set()
    techniques: list[dict] = []
    for scope in scopes:
        technique = _OAUTH_SCOPE_ATTACK_MAP.get(scope.lower(), _DEFAULT_OAUTH_TECHNIQUE)
        if technique["id"] not in seen_ids:
            seen_ids.add(technique["id"])
            techniques.append(technique)
    return techniques or [_DEFAULT_OAUTH_TECHNIQUE]


def attack_techniques_for_actions(actions: list[str]) -> list[dict]:
    """One technique per distinct mapped action, in first-seen order. Any
    action with no specific mapping falls back to the general cloud
    privilege-escalation technique rather than being silently dropped —
    every CloudPrivEscPath edge should carry at least one tag."""
    seen_ids: set[str] = set()
    techniques: list[dict] = []
    for action in actions:
        technique = _IAM_ACTION_ATTACK_MAP.get(action.lower(), _DEFAULT_TECHNIQUE)
        if technique["id"] not in seen_ids:
            seen_ids.add(technique["id"])
            techniques.append(technique)
    return techniques or [_DEFAULT_TECHNIQUE]


def attack_techniques_for_runs_as() -> list[dict]:
    """RUNS_AS (graph_service.py) isn't an abused API action like the two
    functions above tag — it's a structural fact (this compute resource
    executes as this IAM role), so there's no per-action lookup table here,
    just the same accurate fixed tag: an attacker who compromises the
    resource inherits the role's access via valid cloud credentials."""
    return [_DEFAULT_TECHNIQUE]


_EXPOSURE_TECHNIQUE = {
    "id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["Initial Access"],
}


def attack_techniques_for_internet_exposure() -> list[dict]:
    """EXPOSED_TO_INTERNET (graph_service.py) is initial access via a real
    reachability fact, not credential reuse — a distinct fixed tag from
    RUNS_AS's T1078.004, since this is how an attacker FIRST reaches a
    resource, not what they inherit once they're on it."""
    return [_EXPOSURE_TECHNIQUE]


_LATERAL_MOVEMENT_TECHNIQUE = {
    "id": "T1021", "name": "Remote Services", "tactics": ["Lateral Movement"],
}


def attack_techniques_for_lateral_movement() -> list[dict]:
    """LATERAL_MOVEMENT (graph_service.py) — a real security-group rule
    letting one instance reach another over the network, distinct from
    both RUNS_AS (identity inheritance) and EXPOSED_TO_INTERNET (initial
    access) — this is movement AFTER an attacker already has a foothold."""
    return [_LATERAL_MOVEMENT_TECHNIQUE]
    return techniques or [_DEFAULT_TECHNIQUE]


_CAN_ACCESS_TECHNIQUE = {
    "id": "T1530", "name": "Data from Cloud Storage", "tactics": ["Collection"],
}


def attack_techniques_for_can_access() -> list[dict]:
    """CAN_ACCESS (graph_service.py) — a real, confirmed identity-policy
    grant onto a tagged crown-jewel resource (iam:SimulatePrincipalPolicy,
    resource_inventory_service.py), distinct from every edge above: this
    is what an attacker DOES once they hold the identity, not how they got
    it or moved to it."""
    return [_CAN_ACCESS_TECHNIQUE]
