from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.graph import SimulateFixRequest, SimulateFixResponse, SimulatedPathOut, TenantGraphOut
from app.services.advisor_service import (
    _advisor_cache,
    _cache_key,
    compute_fingerprint,
    generate_fix_verification_summary,
    generate_graph_insight,
    generate_kill_chain_narrative,
    is_unchanged,
    remember_fingerprint,
)
from app.services.attack_technique_mapping import attack_techniques_for_actions
from app.services.graph_service import (
    _compute_kill_chains,
    build_tenant_privesc_graph,
    get_fix_verifications,
    simulate_fix,
)
from app.services.privesc_remediation_mapping import remediation_for_edge

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("", response_model=TenantGraphOut)
async def get_tenant_graph(
    connection_id: str | None = Query(None, description="Narrow the graph to one connected AWS account, OAuth tenant, or host connection — absent for the default tenant-wide blend"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Real IAM Privilege-Escalation Graph, third-party OAuth app risk, and
    standalone real-findings nodes (cloud misconfiguration + host/VPS) for
    the current tenant — see graph_service.py's module docstring for what's
    a real edge vs. a standalone node. Returns empty nodes/edges (not an
    error) if nothing has been discovered yet."""
    data = await build_tenant_privesc_graph(db, user.tenant_id, connection_id)
    return TenantGraphOut(**data)


@router.get("/insight")
async def get_graph_insight(
    connection_id: str | None = Query(None, description="Same scan-selector scope as GET /graph — keeps the AI Analyst's narration matched to what's on screen"),
    cached_only: bool = Query(False),
    force: bool = Query(False, description="Bypass the unchanged-data guard — used by the explicit Regenerate button"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Phase 39c — the Attack Path Graph's "AI Analyst" — same fingerprint-
    gated caching as GET /advisor/cert-summary and /dns-summary, so a plain
    page reload doesn't re-call Claude unless the graph's own chokepoint/
    target data actually changed since the last call. The cache key's own
    domain_id_or_name slot carries connection_id, so switching scan scope
    is never served a stale message cached for a different connection."""
    cache_key = _cache_key(str(user.tenant_id), "graph_insight", connection_id)
    if cached_only:
        cached = _advisor_cache.get(cache_key)
        if cached:
            return cached

    graph = await build_tenant_privesc_graph(db, user.tenant_id, connection_id)
    open_path_count = sum(1 for e in graph["edges"] if e.get("status", "open") == "open")
    fingerprint_payload = {"targets": graph["targets"], "chokepoint": graph["chokepoint"], "open_path_count": open_path_count}
    fingerprint = compute_fingerprint(fingerprint_payload)
    if not force and is_unchanged(cache_key, fingerprint):
        cached = _advisor_cache.get(cache_key)
        if cached:
            return cached

    result = await generate_graph_insight(
        node_count=len(graph["nodes"]), edge_count=len(graph["edges"]),
        open_path_count=open_path_count, targets=graph["targets"], chokepoint=graph["chokepoint"],
    )
    _advisor_cache[cache_key] = result
    remember_fingerprint(cache_key, fingerprint)
    return result


@router.get("/kill-chains")
async def get_kill_chains(
    connection_id: str | None = Query(None, description="Same scan-selector scope as GET /graph"),
    cached_only: bool = Query(False),
    force: bool = Query(False, description="Bypass the unchanged-data guard — used by the explicit Regenerate button"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The Kill Chain Narrative — real, ordered entry-to-outcome hop
    sequences (graph_service._compute_kill_chains) synthesized into one
    compelling, true story per real outcome. Same fingerprint-gated
    caching as GET /graph/insight, separate cache namespace so the two
    never collide or overwrite each other."""
    cache_key = _cache_key(str(user.tenant_id), "kill_chains", connection_id)
    if cached_only:
        cached = _advisor_cache.get(cache_key)
        if cached:
            return cached

    graph = await build_tenant_privesc_graph(db, user.tenant_id, connection_id)
    kill_chains = await _compute_kill_chains(db, graph["nodes"], graph["edges"])
    fingerprint = compute_fingerprint({"kill_chains": kill_chains})
    if not force and is_unchanged(cache_key, fingerprint):
        cached = _advisor_cache.get(cache_key)
        if cached:
            return cached

    narrative = await generate_kill_chain_narrative(kill_chains)
    result = {"chains": kill_chains, **narrative}
    _advisor_cache[cache_key] = result
    remember_fingerprint(cache_key, fingerprint)
    return result


@router.get("/fix-verification")
async def get_fix_verification(
    cached_only: bool = Query(False),
    force: bool = Query(False, description="Bypass the unchanged-data guard — used by the explicit Regenerate button"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The objective, re-scan-verified counterpart to Simulate-the-Fix's
    hypothetical "would close" prediction — every group here is real
    CloudPrivEscPath.status="retest_closed" data (set mechanically by the
    reconciliation step in cloud_scan_service.py when a re-scan no longer
    finds the path), not a projection. The LLM only narrates this already-
    settled fact (generate_fix_verification_summary), it never determines
    it — same fingerprint-gated caching as GET /graph/insight."""
    cache_key = _cache_key(str(user.tenant_id), "fix_verification", None)
    if cached_only:
        cached = _advisor_cache.get(cache_key)
        if cached:
            return {"verifications": cached["verifications"], **cached["summary"]}

    verifications = await get_fix_verifications(db, user.tenant_id)
    fingerprint = compute_fingerprint(verifications)
    if not force and is_unchanged(cache_key, fingerprint):
        cached = _advisor_cache.get(cache_key)
        if cached:
            return {"verifications": cached["verifications"], **cached["summary"]}

    summary = await generate_fix_verification_summary(verifications)
    _advisor_cache[cache_key] = {"verifications": verifications, "summary": summary}
    remember_fingerprint(cache_key, fingerprint)
    return {"verifications": verifications, **summary}


@router.post("/simulate", response_model=SimulateFixResponse)
async def simulate_graph_fix(
    payload: SimulateFixRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Simulate-the-Fix: a pure hypothetical read — nothing is changed in
    AWS or in the database. See graph_service.simulate_fix for how the
    "would close" set is derived."""
    paths = await simulate_fix(
        db, user.tenant_id, policy_arns=payload.policy_arns, priv_esc_path_ids=payload.priv_esc_path_ids,
    )
    return SimulateFixResponse(would_close=[
        SimulatedPathOut(
            id=str(p.id), source_principal_arn=p.source_principal_arn, target_principal_arn=p.target_principal_arn,
            technique_chain=p.technique_chain, attack_techniques=attack_techniques_for_actions(p.technique_chain),
            severity=p.severity, policy_name=p.policy_name, policy_arn=p.policy_arn,
            remediation=remediation_for_edge(p.escalation_type, p.technique_chain),
        )
        for p in paths
    ])
