from pydantic import BaseModel


class EngagementCreate(BaseModel):
    tier: str  # cloud | host | exposure | credential | phishing | reachability | exploit
    domain_id: str | None = None
    scope: dict = {}
    # tier='cloud' only — which connections this engagement authorizes scans
    # against. Sets CloudAccountConnection.engagement_id on each, which is
    # what the rescan scheduler joins on.
    cloud_account_connection_ids: list[str] = []
    # tier='host' only — same shape as cloud_account_connection_ids, for
    # HostConnection's SSH/Lynis rescan scheduler join.
    host_connection_ids: list[str] = []


class EngagementOut(BaseModel):
    id: str
    tier: str
    domain_id: str | None
    scope: dict
    status: str
    approved_at: str | None
    expires_at: str | None
    created_at: str
    roe_signature_request_id: str | None = None
    roe_doc_url: str | None = None


class RequestSignaturePayload(BaseModel):
    # Defaults to the calling user's own identity if omitted — the common
    # case is the tenant admin authorizing work on their own infrastructure.
    # An override is allowed for the rare case where a different named
    # signatory (not the person operating Command) is the real authority.
    signer_name: str | None = None
    signer_email: str | None = None


class EngagementScheduleUpdate(BaseModel):
    # PATCH semantics — only the fields sent are changed. phishing-tier
    # only, and only while status == 'active' (see the router docstring
    # for the real compliance reasoning: a genuinely signed ROE states the
    # cadence in the document itself, so changing it here after a real
    # signature is a real, audited divergence from what was authorized —
    # not something this endpoint pretends isn't happening).
    cadence_days: int | None = None
    recurring: bool | None = None
    landing_page_id: str | None = None
