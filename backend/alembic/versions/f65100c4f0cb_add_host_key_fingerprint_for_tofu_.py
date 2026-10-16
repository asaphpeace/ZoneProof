"""add host key fingerprint for TOFU pinning

TOFU-pin the SSH server's own host key (distinct from the keypair Sentinel
generates as ITS identity to the server) so a later host-key change gets
flagged as a possible MITM instead of silently reconnecting. Autogenerate
again flagged the same unrelated pre-existing drift on
dmarc_reports/tls_reports/users/service_accounts seen in every migration
this session — excluded, still out of scope.

Revision ID: f65100c4f0cb
Revises: 1bd12fdcd1eb
Create Date: 2026-07-12
"""
from alembic import op
import sqlalchemy as sa

revision = 'f65100c4f0cb'
down_revision = '1bd12fdcd1eb'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('host_connections', sa.Column('host_key_fingerprint', sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column('host_connections', 'host_key_fingerprint')
