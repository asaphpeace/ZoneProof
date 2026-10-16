"""
Shared Finding -> FindingOut serialization — factored out of
app/routers/engagement.py's list_findings so the new tenant-wide GET
/findings (app/routers/findings.py) doesn't duplicate the attack-technique/
CIS-control resolution logic (three different vocabularies depending on
tier — see _attack_techniques' own docstring below for why that can't be a
single flat crosswalk).
"""
from app.models import Finding, OAuthGrant
from app.schemas.finding import AttackTechniqueOut, FindingOut
from app.services import compliance_mapping
from app.services.attack_technique_mapping import attack_techniques_for_actions, attack_techniques_for_oauth_scopes


def _attack_techniques(f: Finding, scopes_by_app_client_id: dict[str, list[str]]) -> list[AttackTechniqueOut]:
    # tier='threat' findings key check_id on a raw IAM action (e.g.
    # "iam:PassRole"), not one of Prowler's own check ids — a different
    # vocabulary, so compliance_mapping's Prowler-sourced crosswalk would
    # never match it. attack_technique_mapping is the curated IAM-action
    # mapping built for exactly this (see ITDR_DESIGN.md and
    # attack_technique_mapping.py's own docstring on why it's a different
    # confidence tier than Prowler's data).
    if f.tier == "threat" and f.check_id:
        return [AttackTechniqueOut(**t) for t in attack_techniques_for_actions([f.check_id])]
    if f.tier == "oauth_risk" and f.check_id in scopes_by_app_client_id:
        return [AttackTechniqueOut(**t) for t in attack_techniques_for_oauth_scopes(scopes_by_app_client_id[f.check_id])]
    return [AttackTechniqueOut(**t) for t in compliance_mapping.attack_techniques_for_check(f.check_id)]


def finding_to_out(
    f: Finding, scopes_by_app_client_id: dict[str, list[str]],
    connection_id: str | None = None, connection_label: str | None = None,
    connection_display_name: str | None = None, resource_tags: dict[str, str] | None = None,
) -> FindingOut:
    return FindingOut(
        id=str(f.id), engagement_id=str(f.engagement_id), asset_id=str(f.asset_id) if f.asset_id else None,
        tier=f.tier, severity=f.severity, title=f.title, status=f.status,
        check_id=f.check_id, resource_uid=f.resource_uid, detail=f.detail, remediation_guidance=f.remediation_guidance,
        discovered_at=f.discovered_at.isoformat(),
        cis_controls=compliance_mapping.cis_controls_for_check(f.check_id),
        attack_techniques=_attack_techniques(f, scopes_by_app_client_id),
        occurrence_count=f.occurrence_count, affected_resources=f.affected_resources,
        region=f.region, extra=f.extra,
        connection_id=connection_id, connection_label=connection_label,
        connection_display_name=connection_display_name, resource_tags=resource_tags or {},
    )
