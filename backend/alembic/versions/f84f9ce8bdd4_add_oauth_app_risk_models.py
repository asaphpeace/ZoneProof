"""add oauth app risk models

Revision ID: f84f9ce8bdd4
Revises: 8ac1d5b933e8
Create Date: 2026-07-21 08:44:46.153991

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'f84f9ce8bdd4'
down_revision: Union[str, None] = '8ac1d5b933e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('oauth_app_connections',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('engagement_id', sa.UUID(), nullable=True),
    sa.Column('provider', sa.String(length=20), nullable=False),
    sa.Column('ms_tenant_id', sa.String(length=64), nullable=True),
    sa.Column('ms_client_id', sa.String(length=64), nullable=True),
    sa.Column('encrypted_client_secret', sa.String(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('connected_by_user_id', sa.UUID(), nullable=True),
    sa.Column('connected_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_scan_status', sa.String(length=20), nullable=False),
    sa.Column('last_scan_error', sa.String(length=1000), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['connected_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_oauth_app_connections_engagement_id'), 'oauth_app_connections', ['engagement_id'], unique=False)
    op.create_index(op.f('ix_oauth_app_connections_tenant_id'), 'oauth_app_connections', ['tenant_id'], unique=False)
    op.create_table('oauth_grants',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('engagement_id', sa.UUID(), nullable=False),
    sa.Column('connection_id', sa.UUID(), nullable=False),
    sa.Column('grantee_principal', sa.String(length=320), nullable=False),
    sa.Column('app_name', sa.String(length=300), nullable=False),
    sa.Column('app_client_id', sa.String(length=64), nullable=False),
    sa.Column('scopes', postgresql.ARRAY(sa.String()), nullable=False),
    sa.Column('risk_tier', sa.String(length=20), nullable=False),
    sa.Column('granted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['connection_id'], ['oauth_app_connections.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_oauth_grants_connection_id'), 'oauth_grants', ['connection_id'], unique=False)
    op.create_index(op.f('ix_oauth_grants_engagement_id'), 'oauth_grants', ['engagement_id'], unique=False)
    op.create_index(op.f('ix_oauth_grants_tenant_id'), 'oauth_grants', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_oauth_grants_tenant_id'), table_name='oauth_grants')
    op.drop_index(op.f('ix_oauth_grants_engagement_id'), table_name='oauth_grants')
    op.drop_index(op.f('ix_oauth_grants_connection_id'), table_name='oauth_grants')
    op.drop_table('oauth_grants')
    op.drop_index(op.f('ix_oauth_app_connections_tenant_id'), table_name='oauth_app_connections')
    op.drop_index(op.f('ix_oauth_app_connections_engagement_id'), table_name='oauth_app_connections')
    op.drop_table('oauth_app_connections')
