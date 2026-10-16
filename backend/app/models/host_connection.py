import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class HostConnection(Base):
    """Read-only SSH access into a customer's server — any provider, or no
    cloud provider at all (a plain VPS with no cloud API surface, the
    original gap this was built for: Prowler/Cloudsplaining only ever see
    the cloud control plane, never the instance OS).

    Distinct credential model from CloudAccountConnection: we generate our
    OWN SSH keypair per connection and the customer installs only the
    PUBLIC key, on a scoped read-only audit user they create themselves —
    we never hold the customer's actual SSH credential, same "no stored
    secret" property CloudAccountConnection's AWS role-assumption already
    has. Our own private key (the one piece we do generate and must keep)
    is Fernet-encrypted at rest, same pattern as Azure/GCP creds."""

    __tablename__ = "host_connections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    # Same lazy-link pattern as CloudAccountConnection.engagement_id — set
    # when an Engagement (tier='host') covering this connection is created,
    # not at connection-creation time. See that model's docstring for why.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True, index=True
    )

    hostname_or_ip: Mapped[str] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_username: Mapped[str] = mapped_column(String(64))  # the scoped read-only audit user the customer creates

    # We generate this keypair ourselves; only the public key is ever shown
    # to the customer (to install), never the private key. The private key
    # is the one secret we do hold, encrypted at rest.
    encrypted_private_key: Mapped[str] = mapped_column(String)
    public_key: Mapped[str] = mapped_column(String(1024))  # OpenSSH format, shown to customer to install
    public_key_fingerprint: Mapped[str] = mapped_column(String(128))  # shown for verification without re-displaying the full key

    # Trust-on-first-use pin of the SERVER's SSH host key (distinct from the
    # keypair above, which is OUR identity to the server). Set on the first
    # successful verify; every connect after that compares against it and
    # refuses to proceed on a mismatch instead of silently reconnecting —
    # a changed host key is either a legitimate host rebuild or a MITM, and
    # a security product shouldn't guess which without telling anyone.
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="pending_verification")
    # pending_verification | connected | revoked | error

    # Same rationale as CloudAccountConnection.display_name — a hostname/IP
    # is a real, stable technical fact but says nothing about what the
    # machine actually IS ("mail-prod-01" vs "203.0.113.10"). Null by
    # default; GET /findings and the connections list fall back to the raw
    # hostname_or_ip when unset.
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)

    connected_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Same rationale as CloudAccountConnection.last_scan_status — a Lynis
    # run that fails (SSH error, host key mismatch, Lynis missing on the
    # target) must not look identical to a clean run that found nothing.
    last_scan_status: Mapped[str] = mapped_column(String(40), default="never_run")
    # never_run | success | failed | running:lynis (transient, see host_scan_service.py)
    last_scan_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
    engagement: Mapped["Engagement | None"] = relationship()  # type: ignore[name-defined]
