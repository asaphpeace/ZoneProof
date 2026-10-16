"""add host connections for ssh based scanning

New Host & Server Security position, VPS/SSH half — any server, any
provider, no cloud API needed. We generate our own SSH keypair per
connection (encrypted_private_key here); only the public key is ever shown
to the customer. Autogenerate again flagged the same unrelated pre-existing
drift on dmarc_reports/tls_reports/users/service_accounts seen in every
migration so far — excluded, still out of scope.

Revision ID: 1bd12fdcd1eb
Revises: fd299b96f8f7
Create Date: 2026-07-11
"""
from alembic import op
import sqlalchemy as sa

revision = '1bd12fdcd1eb'
down_revision = 'fd299b96f8f7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('host_connections',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('engagement_id', sa.UUID(), nullable=True),
    sa.Column('hostname_or_ip', sa.String(length=255), nullable=False),
    sa.Column('ssh_port', sa.Integer(), nullable=False),
    sa.Column('ssh_username', sa.String(length=64), nullable=False),
    sa.Column('encrypted_private_key', sa.String(), nullable=False),
    sa.Column('public_key', sa.String(length=1024), nullable=False),
    sa.Column('public_key_fingerprint', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('connected_by_user_id', sa.UUID(), nullable=True),
    sa.Column('connected_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['connected_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_host_connections_engagement_id'), 'host_connections', ['engagement_id'], unique=False)
    op.create_index(op.f('ix_host_connections_tenant_id'), 'host_connections', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_host_connections_tenant_id'), table_name='host_connections')
    op.drop_index(op.f('ix_host_connections_engagement_id'), table_name='host_connections')
    op.drop_table('host_connections')
