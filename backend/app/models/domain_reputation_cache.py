"""
Shared, tenant-agnostic cache of real per-domain reputation signals for
link_risk_service.py (Phishing Simulation roadmap Phase 32 — the
composite link risk score built on top of Phase 26's Real-Threat Reports
triage feature).

Deliberately has NO tenant_id: a domain's registration age and Google Web
Risk status are public facts about the internet, not tenant data, so
sharing one row across every tenant that has ever seen a URL on that
domain is a real efficiency win (cuts external API calls, keeps this
product well inside Web Risk's free monthly tier) with no privacy
implication.

domain_registered_at/domain_age_source are genuinely cacheable — a
domain's creation date doesn't change (see link_risk_service.py's
_DOMAIN_AGE_CACHE_TTL_DAYS for why it's still refreshed periodically
rather than cached forever: ownership can transfer). web_risk_last_verdict
is the opposite: informational/last-known-value only, NEVER trusted as
authoritative for a fresh scoring decision, because Google's threat lists
can flip within hours — every real scoring pass calls Web Risk live per
exact URL regardless of this column's age. See link_risk_service.py's
module docstring for the full reasoning.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class DomainReputationCache(Base):
    __tablename__ = "domain_reputation_cache"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    apex_domain: Mapped[str] = mapped_column(String(253), unique=True, index=True)

    domain_registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    domain_age_source: Mapped[str | None] = mapped_column(String(20), nullable=True)  # "rdap" | "za_whois" | None
    domain_age_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    web_risk_last_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)  # "match" | "clean" | None
    web_risk_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Cached purely to avoid recomputing a pure lookup-table read every
    # time; not itself a network-derived fact, so it has no TTL/refresh
    # logic of its own — link_risk_service just overwrites it each pass.
    tld_reputation_delta: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
