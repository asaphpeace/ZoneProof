"""add domain_reputation_cache and reported_emails link risk columns

Revision ID: a1c9f4e2b8d3
Revises: 5e1a7c3f9b26
Create Date: 2026-09-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a1c9f4e2b8d3'
down_revision: Union[str, None] = '5e1a7c3f9b26'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('domain_reputation_cache',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('apex_domain', sa.String(length=253), nullable=False),
    sa.Column('domain_registered_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('domain_age_source', sa.String(length=20), nullable=True),
    sa.Column('domain_age_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('web_risk_last_verdict', sa.String(length=20), nullable=True),
    sa.Column('web_risk_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('tld_reputation_delta', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_domain_reputation_cache_apex_domain'), 'domain_reputation_cache', ['apex_domain'], unique=True)

    op.add_column('reported_emails', sa.Column('url_risk', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('reported_emails', sa.Column('url_risk_scored_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('reported_emails', 'url_risk_scored_at')
    op.drop_column('reported_emails', 'url_risk')

    op.drop_index(op.f('ix_domain_reputation_cache_apex_domain'), table_name='domain_reputation_cache')
    op.drop_table('domain_reputation_cache')
