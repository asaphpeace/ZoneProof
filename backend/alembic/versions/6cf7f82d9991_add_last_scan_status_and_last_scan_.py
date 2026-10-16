"""add last_scan_status and last_scan_error to connections

A scan that fails must not look identical to a scan that ran cleanly and
found nothing — only FAIL findings are persisted, so an empty Finding list
is inherently ambiguous. server_default backfills existing rows (there are
already real connections in dev) as 'never_run', matching the Python-side
default. Autogenerate again flagged the same unrelated pre-existing drift
on dmarc_reports/tls_reports/users/service_accounts seen in every migration
this session — excluded, still out of scope.

Revision ID: 6cf7f82d9991
Revises: f65100c4f0cb
Create Date: 2026-07-12
"""
from alembic import op
import sqlalchemy as sa

revision = '6cf7f82d9991'
down_revision = 'f65100c4f0cb'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('cloud_account_connections', sa.Column('last_scan_status', sa.String(length=20), nullable=False, server_default='never_run'))
    op.add_column('cloud_account_connections', sa.Column('last_scan_error', sa.String(length=1000), nullable=True))
    op.add_column('host_connections', sa.Column('last_scan_status', sa.String(length=20), nullable=False, server_default='never_run'))
    op.add_column('host_connections', sa.Column('last_scan_error', sa.String(length=1000), nullable=True))


def downgrade() -> None:
    op.drop_column('host_connections', 'last_scan_error')
    op.drop_column('host_connections', 'last_scan_status')
    op.drop_column('cloud_account_connections', 'last_scan_error')
    op.drop_column('cloud_account_connections', 'last_scan_status')
