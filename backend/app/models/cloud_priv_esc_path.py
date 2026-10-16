import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CloudPrivEscPath(Base):
    """One discovered IAM privilege-escalation chain from Cloudsplaining/
    PMapper analysis — the cloud-account counterpart to Tier 4's network
    reachability edges. Append-only per scan: a path that disappears on
    re-scan (remediated) is left in place and a corresponding Finding is
    marked retest_closed, rather than deleting the historical record —
    mirrors how DmarcRecord/TlsReport keep history instead of overwriting."""

    __tablename__ = "cloud_priv_esc_paths"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    cloud_account_connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cloud_account_connections.id", ondelete="CASCADE"), index=True
    )

    source_principal_arn: Mapped[str] = mapped_column(String(2048))
    target_principal_arn: Mapped[str] = mapped_column(String(2048))  # often the account's admin role/user
    technique_chain: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # e.g. ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]

    # Cloudsplaining's own classification of *which* escalation technique
    # this is (e.g. "PassExistingRoleToNewLambdaThenInvoke") and the real
    # policy that grants it — both already computed by the tool script but
    # previously discarded on the way into this table. Real evidence for
    # the attack-path drill-down panel, not just an action-name list.
    escalation_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    policy_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    policy_arn: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    severity: Mapped[str] = mapped_column(String(20))  # critical | high | medium | low

    # Real per-source detail this codebase previously discarded — currently
    # just the real Cloudsplaining PolicyDocument (which resources/
    # conditions the granting statement actually applies to; "Resource: *"
    # vs one scoped bucket is a real, large exploitability difference this
    # table couldn't represent before). Same JSONB-blob-over-typed-columns
    # convention as Finding.extra, for the same reason — no DB join/index
    # needed on this, just heterogeneous per-source context.
    extra: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Was truly append-only until now — every rescan re-inserted every
    # currently-active path with no awareness of what a previous scan
    # already found, the exact "483 duplicate rows" bug already fixed for
    # Finding (see finding_reconciliation.py) but never applied here.
    # retest_closed means "this path was open on a previous scan and is no
    # longer detected" — the row stays for history, mirroring how
    # DmarcRecord/TlsReport/Finding all keep history instead of deleting.
    status: Mapped[str] = mapped_column(String(20), default="open")
    # open | retest_closed

    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Set the moment a re-scan's reconciliation flips this row to
    # retest_closed (_reconcile_priv_esc_paths, cloud_scan_service.py) —
    # None while status="open". Lets Simulate-the-Fix state an exact,
    # objective verification time ("closed by re-scan on {date}") instead
    # of a vague "closed at some point" claim.
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped["Engagement"] = relationship()  # type: ignore[name-defined]
    connection: Mapped["CloudAccountConnection"] = relationship()  # type: ignore[name-defined]
