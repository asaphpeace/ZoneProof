from __future__ import annotations
import re
from pydantic import BaseModel, field_validator
from datetime import datetime

# RFC 1035 label rules: letters/digits/hyphens, no leading/trailing hyphen
# per label, each label 1-63 chars, total length <= 253. Deliberately
# stricter than what DNS resolvers tolerate, since this string also gets
# embedded unescaped into URLs (mta-sts.{name}) and HTML emails — see
# PAIN_POINT_RESOLUTION_PLAN.md audit findings.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def _validate_hostname(name: str) -> str:
    name = name.strip().lower().rstrip(".")
    if not _HOSTNAME_RE.match(name):
        raise ValueError(f"'{name}' is not a valid domain name")
    return name


class DomainCreate(BaseModel):
    names: list[str]  # one or more domains

    @field_validator("names")
    @classmethod
    def _validate_names(cls, v: list[str]) -> list[str]:
        return [_validate_hostname(n) for n in v]


class DomainOut(BaseModel):
    id: str
    domain: str
    dmarc_stage: str
    mta_sts_stage: str
    dmarc_record_published: bool
    tlsrpt_record_published: bool
    mta_sts_published: bool
    ownership_verified: bool
    reporting_address: str
    mta_sts_hosting_mode: str
    added_at: datetime
    # Derived, not stored — the most specific other monitored domain this one
    # is a subdomain of, if any. Lets the Domains page relate a discovered
    # subdomain (added via "Monitor this") back to its parent.
    parent_domain: str | None = None

    model_config = {"from_attributes": True}


class OwnershipVerifyOut(BaseModel):
    domain: str
    verified: bool
    method: str | None       # dmarc_rua | tlsrpt_rua | None
    record_found: str | None
    message: str


class DomainDetail(DomainOut):
    dmarc_policy: str | None
    dmarc_pct: int | None
    mta_sts_policy_id: str | None
    last_checked_at: datetime | None


class WizardStep2Out(BaseModel):
    """Result of DMARC DNS check for a domain during wizard."""
    domain: str
    already_exists: bool = False   # domain is already actively monitored
    dmarc_exists: bool
    current_record: str | None
    generated_record: str
    record_host: str
    reporting_address: str


class WizardStep3Out(BaseModel):
    """TLS onboarding info for a domain."""
    domain: str
    tlsrpt_record: str
    tlsrpt_host: str
    mta_sts_dns_record: str
    mta_sts_dns_host: str
    mta_sts_policy: str
    policy_url: str
    reporting_address: str
    # Managed-hosting alternative (PAIN_POINT_RESOLUTION_PLAN.md Pain 5) —
    # the CNAME target if the customer chooses Sentinel-hosted instead of
    # self-hosting the policy file. Always populated; only used by the UI
    # when the customer picks that option.
    mta_sts_cname_target: str
    mta_sts_cname_host: str


class RecommendationOut(BaseModel):
    """One outcome from the rule-based recommendation engine for this domain."""
    direction: str          # advance | hold | regression
    severity: str            # info | warn | critical
    category: str             # dmarc | tls | cert
    title: str
    body: str
    blocking_reason: str | None = None


class SourceImpactOut(BaseModel):
    source_org: str
    classification: str
    affected_count: int


class SourceReadinessOut(BaseModel):
    """One row in the Enforcement Readiness checklist — PAIN_POINT_RESOLUTION_PLAN.md Pain 4."""
    source_org: str
    classification: str
    total_count: int
    fail_count: int
    status: str   # ready | blocking | will_be_blocked | below_floor


class RegistrarInstructionsOut(BaseModel):
    """Curated, provider-specific DNS publishing steps — Part 1 Phase 1 of GUIDED_ONBOARDING_PLAN.md."""
    key: str
    name: str
    steps: list[str]
    help_url: str | None
    nameservers: list[str]


class DnsLiveCheckOut(BaseModel):
    """Cheap, no-DB-write DNS check used for live confirmation polling while
    publishing instructions are on screen — distinct from /sync-dns, which
    also runs ownership verification and AI risk assessment and is too
    heavy to call every few seconds."""
    exists: bool


class EmailInstructionsIn(BaseModel):
    to_email: str
    record_type: str   # dmarc | mta-sts | tlsrpt


class DiscoveredSubdomainOut(BaseModel):
    """
    A subdomain found via passive sources (own DMARC data, cert SANs, CT
    logs) — see subdomain_discovery_service.py. Never from active probing.
    """
    hostname: str
    sources: list[str]            # dmarc | cert | ct, may be more than one
    sends_mail: bool
    mail_volume: int
    already_monitored: bool
    # PAIN_POINT_RESOLUTION_PLAN.md Pain 6 — monitor | exclude | inherited_sp,
    # or None if not yet decided. A mail-sending subdomain with None here is
    # what blocks DMARC advancement (see recommendation_engine.py).
    disposition: str | None = None
    disposition_reason: str | None = None



class SubdomainCoverageOut(BaseModel):
    """
    What the parent DMARC policy does to a subdomain nobody listed. Needs no
    enumeration: unlisted subdomains inherit sp= (or p=, or np= where published).
    """
    dmarc_found: bool
    policy: str | None = None
    subdomain_policy: str | None = None
    np_policy: str | None = None
    effective_subdomain_policy: str | None = None
    level: str                    # protected | partial | open
    summary: str


class DiscoveredSubdomainsOut(BaseModel):
    """
    Discovery result plus the state of each source, so "none found" can be told
    apart from "a source could not be asked" (for example a certificate-log
    timeout). Source states: ok | cached | timed_out | failed |
    skipped_unverified | wildcard_filtered.
    """
    subdomains: list[DiscoveredSubdomainOut]
    sources: dict[str, str]
    coverage: SubdomainCoverageOut | None = None

class SubdomainDispositionIn(BaseModel):
    hostname: str
    disposition: str   # monitor | exclude | inherited_sp
    reason: str | None = None


class SimulationOut(BaseModel):
    """
    Dry-run preview of advancing to the next DMARC stage, computed against
    already-collected aggregate traffic — answers "will this break my email?"
    before the user touches DNS.
    """
    target_stage: str
    total_volume: int
    affected_volume: int
    affected_pct: float
    safe: bool
    by_classification: dict[str, int]
    authorized_sources_affected: list[SourceImpactOut]
    source_readiness: list[SourceReadinessOut] = []
