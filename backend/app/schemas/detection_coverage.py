from pydantic import BaseModel


class DetectionCoverageEdgeOut(BaseModel):
    priv_esc_path_id: str
    source_principal_arn: str
    target_principal_arn: str
    technique_chain: list[str]
    severity: str
    verdict: str  # covered | partial | blind_spot
    reason: str
    cloudtrail_multi_region_enabled: bool
    guardduty_enabled: bool
    discovered_at: str
