from pydantic import BaseModel


class GraphNodeOut(BaseModel):
    id: str
    label: str
    hue: str
    detail: str
    discovered: str
    # principal (default, an IAM/human identity) | third_party_app
    # (OAUTH_APP_RISK_DESIGN.md Section 6) | cloud_resource | host — the
    # latter two are real findings with no edge in or out, never a
    # fabricated relationship to anything else (see graph_service.py's
    # module docstring).
    kind: str = "principal"
    # Open tier='credential' Findings whose resource_uid ARN-matches this
    # node's own id (Phase 36f) — 0 for a node with none, and always 0 for
    # a non-IAM node (email/app ids aren't ARN-matchable). The graph's own
    # edges stay privesc/OAuth-only; this is metadata on an existing node,
    # never a new edge.
    open_credential_findings: int = 0
    # The subset of open_credential_findings above that comes from
    # Cloudsplaining's DataExfiltration/ResourceExposure/ServiceWildcard/
    # CredentialsExposure categories (check_id prefixed "cloudsplaining_")
    # — real "can act catastrophically without ever escalating privileges"
    # risk, as distinct from routine password/MFA/access-key hygiene
    # findings that also live under the blended count above. 0/None for a
    # node with none.
    open_policy_risk_findings: int = 0
    policy_risk_worst_severity: str | None = None
    # Generic real-findings badge for kind="cloud_resource"/"host" nodes —
    # deliberately separate from the two IAM-specific fields above (those
    # stay principal-scoped, unchanged). 0/None for every other node kind.
    open_findings: int = 0
    findings_worst_severity: str | None = None
    # Customer/heuristic "this asset matters" signal (CloudAsset.
    # is_high_value) — False for any node not backed by a real CloudAsset
    # (principals, third-party apps, the "internet" node). Distinct from
    # graph_service.py's own unrelated "crown jewel cards" (_compute_targets)
    # concept — that means "any node reached by >=1 edge", pure topology.
    is_high_value: bool = False


class GraphAttackTechniqueOut(BaseModel):
    id: str
    name: str | None = None
    tactics: list[str] = []


class GraphExposedPortOut(BaseModel):
    port: int | None = None
    protocol: str | None = None
    cidr: str


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    severity: str
    technique_chain: list[str]
    attack_techniques: list[GraphAttackTechniqueOut]
    discovered: str
    # priv_esc | oauth_grant | runs_as — explicit discriminator. Before
    # runs_as existed, an edge's kind was only inferable from which
    # optional fields below were populated (IAM-only vs left None); that
    # implicit convention breaks once two different edge kinds both leave
    # the same fields None, so this is set explicitly at every edge-append
    # call site rather than left to infer.
    edge_type: str = "priv_esc"
    # Only populated for IAM privilege-escalation edges (CloudPrivEscPath) —
    # None for OAuth-grant edges, which don't have a Cloudsplaining
    # escalation classification, an IAM policy, or a priv-esc-path row
    # behind them (Simulate-the-Fix's priv_esc_path_ids fallback needs
    # priv_esc_path_id for a path with no resolved policy_arn).
    escalation_type: str | None = None
    policy_name: str | None = None
    policy_arn: str | None = None
    priv_esc_path_id: str | None = None
    # open | retest_closed (Phase 39a "severed" edges) — OAuth-grant edges
    # are always "open" (OAuthGrant has no revoked/closed concept today).
    status: str = "open"
    # Relative time the re-scan reconciliation verified this edge closed
    # (CloudPrivEscPath.closed_at) — None while status="open" or for an
    # OAuth-grant edge (never closes today).
    closed: str | None = None
    # Curated "how to fix this" text (privesc_remediation_mapping.py) — real
    # for every edge, IAM or OAuth; never absent, since the mapping always
    # has a generic fallback rather than leaving this field empty.
    remediation: str
    # Real security-group rule evidence for exposed_to_internet edges only
    # (graph_service.py's _compute_ec2_internet_exposed_ports) — EVERY real
    # matched port/protocol/CIDR rule, not just the one that drove
    # severity (a real gap this session found: keeping only the single
    # worst match silently dropped an instance's other real open ports).
    # [] for every other edge type, and for a Finding-only exposure with
    # no matching raw-internet SG rule (honest "no port-level evidence").
    exposed_ports: list[GraphExposedPortOut] = []


class GraphTargetOut(BaseModel):
    """Phase 39a — a "crown jewel" card: any node reached by at least one
    edge. worst_severity is None when every path reaching it is severed
    (real "contained" state), not when there's simply no data."""
    node_id: str
    open_path_count: int
    closed_path_count: int
    worst_severity: str | None = None


class GraphChokepointOut(BaseModel):
    """Phase 39a — the policy shared by the most currently-open paths,
    reusing simulate_fix()'s own grouping. Absent entirely (not a
    zero-valued object) when no policy_arn is shared by more than one
    open path."""
    policy_arn: str
    policy_name: str | None = None
    closes_count: int
    total_open_count: int


class GraphScopeOut(BaseModel):
    """Phase 39b — real read-only/scope data, replacing the kind of
    active-exploitation-engine chrome (Pause/Emergency Stop/Exploit Cap)
    this product never had a real basis for. read_only is a static fact
    about this product's architecture (assumed-role reads only), not a
    toggle."""
    read_only: bool = True
    connected_accounts: int = 0
    iam_principals: int = 0


class GraphViewingOut(BaseModel):
    """Real scan-selector support — which single connection the response is
    narrowed to, or absent entirely for the default tenant-wide blend
    across every connected account/OAuth tenant. label is the same real
    display_name-or-derived-identity text used elsewhere (findings.py's
    own _cloud_connection_label), never a placeholder."""
    id: str
    provider: str
    label: str


class TenantGraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    last_analyzed: str | None = None
    sources: list[str] = []
    targets: list[GraphTargetOut] = []
    chokepoint: GraphChokepointOut | None = None
    scope: GraphScopeOut = GraphScopeOut()
    viewing: GraphViewingOut | None = None


class SimulateFixRequest(BaseModel):
    # Which policy(ies) to hypothetically fix — the primary, fan-out-capable
    # key. priv_esc_path_ids is the fallback for paths with no resolved
    # policy_arn (simulated individually, no sibling fan-out).
    policy_arns: list[str] = []
    priv_esc_path_ids: list[str] = []


class SimulatedPathOut(BaseModel):
    id: str
    source_principal_arn: str
    target_principal_arn: str
    technique_chain: list[str]
    attack_techniques: list[GraphAttackTechniqueOut] = []
    severity: str
    policy_name: str | None = None
    policy_arn: str | None = None
    remediation: str


class SimulateFixResponse(BaseModel):
    would_close: list[SimulatedPathOut]
