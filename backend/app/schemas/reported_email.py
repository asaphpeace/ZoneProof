from pydantic import BaseModel


class ReportedEmailOut(BaseModel):
    id: str
    received_at: str
    reporter_hash: str | None
    original_subject: str | None
    original_from: str | None
    original_from_domain: str | None
    original_date: str | None
    body_text_excerpt: str | None
    urls_found: list[str]
    is_original_message_attached: bool
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str | None
    auth_results_raw: str | None
    disposition: str
    disposition_note: str | None
    disposition_at: str | None
    url_risk: list[dict] | None = None
    url_risk_scored_at: str | None = None


class UpdateDispositionRequest(BaseModel):
    disposition: str  # confirmed_malicious | false_positive | already_known | new
    note: str | None = None


class UnmaskReporterOut(BaseModel):
    email: str
