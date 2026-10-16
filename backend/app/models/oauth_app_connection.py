import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class OAuthAppConnection(Base):
    """Read-only access into a customer's Microsoft 365/Entra ID (and later
    Google Workspace) tenant, for Third-Party OAuth App Risk
    (OAUTH_APP_RISK_DESIGN.md). Same shape-family as CloudAccountConnection
    and HostConnection — connecting (handing over a credential) and
    authorizing scans against it (the Engagement consent gate) are
    deliberately separate steps, same as those two.

    Unlike AWS's role-assumption model, Microsoft Graph has no equivalent
    "assume a role, no secret stored" mechanism for this use case — the
    customer's App Registration client secret genuinely has to be held,
    encrypted at rest via crypto_service.py, same as HostConnection's SSH
    private key."""

    __tablename__ = "oauth_app_connections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    # Nullable until an Engagement is created, same reasoning as
    # CloudAccountConnection.engagement_id — the scheduler joins on this to
    # find only connections with a currently-active authorization.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True, index=True
    )

    provider: Mapped[str] = mapped_column(String(20))  # microsoft365 (google_workspace, later)

    # Microsoft 365 / Entra ID — an App Registration the customer creates
    # themselves, granted read-only application permissions
    # (Application.Read.All, DelegatedPermissionGrant.Read.All, User.Read.All)
    # and admin-consented once. ms_tenant_id is the customer's own Entra
    # directory id — distinct from tenant_id above (Sentinel's own tenant).
    ms_tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ms_client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encrypted_client_secret: Mapped[str | None] = mapped_column(String, nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="pending_verification")
    # pending_verification | connected | revoked | error

    connected_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_status: Mapped[str] = mapped_column(String(20), default="never_run")
    # never_run | success | failed
    last_scan_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
    engagement: Mapped["Engagement | None"] = relationship()  # type: ignore[name-defined]


class OAuthGrant(Base):
    """One discovered (app, grantee) OAuth permission grant — the graph
    edge (OAUTH_APP_RISK_DESIGN.md Section 3.2/6). Append-only per scan,
    same "never deleted, retest_closed on remediation" philosophy
    CloudPrivEscPath already documents for itself."""

    __tablename__ = "oauth_grants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("oauth_app_connections.id", ondelete="CASCADE"), index=True
    )

    grantee_principal: Mapped[str] = mapped_column(String(320))  # the human who granted access — an email
    app_name: Mapped[str] = mapped_column(String(300))
    app_client_id: Mapped[str] = mapped_column(String(64))  # the real dedup key; names collide, ids don't

    # Graph's servicePrincipal.verifiedPublisher — null when the app has no
    # verified publisher at all (a real, meaningful risk signal on its own:
    # an unverified app requesting broad scopes is more suspicious than a
    # verified one), not just missing data.
    publisher_verified: Mapped[bool] = mapped_column(default=False)
    publisher_name: Mapped[str | None] = mapped_column(String(300), nullable=True)

    scopes: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # provider-native scope/permission strings, e.g. Graph API "Mail.Read"

    risk_tier: Mapped[str] = mapped_column(String(20))  # critical | high | medium | low
    granted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # nullable — Microsoft Graph's oauth2PermissionGrants doesn't reliably
    # surface exact grant dates; don't imply precision the source lacks.
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
    engagement: Mapped["Engagement"] = relationship()  # type: ignore[name-defined]
    connection: Mapped["OAuthAppConnection"] = relationship()
