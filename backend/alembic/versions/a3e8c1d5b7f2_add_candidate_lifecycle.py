"""add candidate lifecycle: stage columns, observations, events

Revision ID: a3e8c1d5b7f2
Revises: f7c2a9d4e1b6
Create Date: 2026-10-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a3e8c1d5b7f2'
down_revision: Union[str, None] = 'f7c2a9d4e1b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_BACKFILL_STAGE_SQL = """
    UPDATE brand_candidates SET stage = CASE
        WHEN enrichment->>'ct_hit' = 'true' THEN 'certified'
        WHEN enrichment->>'has_mx' = 'true' THEN 'mail_enabled'
        WHEN enrichment->>'has_a' = 'true' THEN 'resolving'
        ELSE 'registered'
    END
"""


def upgrade() -> None:
    op.add_column('brand_candidates', sa.Column('stage', sa.String(16), nullable=False, server_default='registered'))
    op.add_column('brand_candidates', sa.Column('stage_changed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('brand_candidates', sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('brand_candidates', sa.Column('lifecycle', postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))

    # Candidates saved before this migration had signs of life by construction (only live or registered
    # names were kept), so the column default of 'registered' would wrongly label them dormant until their
    # brand is next scanned. Backfill the stage from what each row already recorded. `lifecycle` stays empty:
    # the next scan treats it as a first observation and fills in the history.
    op.execute(_BACKFILL_STAGE_SQL)

    op.create_table(
        'brand_candidate_observations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('candidate_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_candidates.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('stage', sa.String(16), nullable=False),
        sa.Column('registered', sa.Boolean(), nullable=True),
        sa.Column('resolving', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('mail', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('certified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('ns', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('registered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('source', sa.String(20), nullable=False, server_default='scan'),
    )
    op.create_index('ix_brand_candidate_observations_candidate_id', 'brand_candidate_observations', ['candidate_id'])
    op.create_index('ix_brand_candidate_observations_tenant_id', 'brand_candidate_observations', ['tenant_id'])
    op.create_index('ix_bc_obs_candidate_time', 'brand_candidate_observations', ['candidate_id', 'observed_at'])

    op.create_table(
        'brand_candidate_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('candidate_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_candidates.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(24), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('payload', postgresql.JSONB(), nullable=False, server_default='{}'),
    )
    op.create_index('ix_brand_candidate_events_candidate_id', 'brand_candidate_events', ['candidate_id'])
    op.create_index('ix_brand_candidate_events_tenant_id', 'brand_candidate_events', ['tenant_id'])
    op.create_index('ix_bc_events_candidate_time', 'brand_candidate_events', ['candidate_id', 'occurred_at'])


def downgrade() -> None:
    op.drop_table('brand_candidate_events')
    op.drop_table('brand_candidate_observations')
    op.drop_column('brand_candidates', 'lifecycle')
    op.drop_column('brand_candidates', 'last_observed_at')
    op.drop_column('brand_candidates', 'stage_changed_at')
    op.drop_column('brand_candidates', 'stage')
