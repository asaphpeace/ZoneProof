"""add reported_emails table and tenant phishing_report_slug

Revision ID: 5e1a7c3f9b26
Revises: 3c8f5a1d7e92
Create Date: 2026-09-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '5e1a7c3f9b26'
down_revision: Union[str, None] = '3c8f5a1d7e92'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('phishing_report_slug', sa.String(length=64), nullable=True))
    op.create_unique_constraint('uq_tenants_phishing_report_slug', 'tenants', ['phishing_report_slug'])

    op.create_table('reported_emails',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('reporter_hash', sa.String(length=64), nullable=True),
    sa.Column('original_subject', sa.String(length=500), nullable=True),
    sa.Column('original_from', sa.String(length=320), nullable=True),
    sa.Column('original_from_domain', sa.String(length=253), nullable=True),
    sa.Column('original_date', sa.DateTime(timezone=True), nullable=True),
    sa.Column('body_text_excerpt', sa.Text(), nullable=True),
    sa.Column('urls_found', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('is_original_message_attached', sa.Boolean(), nullable=False),
    sa.Column('spf_result', sa.String(length=20), nullable=True),
    sa.Column('dkim_result', sa.String(length=20), nullable=True),
    sa.Column('dmarc_result', sa.String(length=20), nullable=True),
    sa.Column('auth_results_raw', sa.Text(), nullable=True),
    sa.Column('disposition', sa.String(length=30), nullable=False),
    sa.Column('disposition_note', sa.String(length=1000), nullable=True),
    sa.Column('disposition_by_user_id', sa.UUID(), nullable=True),
    sa.Column('disposition_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['disposition_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_reported_emails_tenant_id'), 'reported_emails', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_reported_emails_tenant_id'), table_name='reported_emails')
    op.drop_table('reported_emails')
    op.drop_constraint('uq_tenants_phishing_report_slug', 'tenants', type_='unique')
    op.drop_column('tenants', 'phishing_report_slug')
