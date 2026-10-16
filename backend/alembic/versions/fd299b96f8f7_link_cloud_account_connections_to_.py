"""link cloud account connections to engagements

engagement_id lets the rescan scheduler join directly to find connections
with a currently-active authorization, instead of matching against
Engagement.scope's JSONB list. Autogenerate also flagged unrelated
pre-existing drift on dmarc_reports/tls_reports/users/service_accounts
(same partial-index/nullability differences seen in the last two
migrations) — excluded here again, still out of scope.

Revision ID: fd299b96f8f7
Revises: d8d42a912e06
Create Date: 2026-07-10
"""
from alembic import op
import sqlalchemy as sa

revision = 'fd299b96f8f7'
down_revision = 'd8d42a912e06'
branch_labels = None
depends_on = None

_FK_NAME = 'fk_cloud_account_connections_engagement_id_engagements'


def upgrade() -> None:
    op.add_column('cloud_account_connections', sa.Column('engagement_id', sa.UUID(), nullable=True))
    op.create_index(
        op.f('ix_cloud_account_connections_engagement_id'),
        'cloud_account_connections', ['engagement_id'], unique=False,
    )
    op.create_foreign_key(
        _FK_NAME, 'cloud_account_connections', 'engagements',
        ['engagement_id'], ['id'], ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint(_FK_NAME, 'cloud_account_connections', type_='foreignkey')
    op.drop_index(op.f('ix_cloud_account_connections_engagement_id'), table_name='cloud_account_connections')
    op.drop_column('cloud_account_connections', 'engagement_id')
