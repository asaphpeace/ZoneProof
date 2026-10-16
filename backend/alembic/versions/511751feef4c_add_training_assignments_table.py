"""add training assignments table

Revision ID: 511751feef4c
Revises: 9a7bec3f97e9
Create Date: 2026-09-15 09:21:50.768265

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '511751feef4c'
down_revision: Union[str, None] = '9a7bec3f97e9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('training_assignments',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('campaign_id', sa.UUID(), nullable=False),
    sa.Column('recipient_hash', sa.String(length=64), nullable=False),
    sa.Column('lure_category', sa.String(length=50), nullable=False),
    sa.Column('trigger_event_type', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('reflection_response', sa.String(length=50), nullable=True),
    sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['campaign_id'], ['phishing_campaigns.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'campaign_id', 'recipient_hash', name='uq_training_assignment_recipient'),
    )
    op.create_index(op.f('ix_training_assignments_campaign_id'), 'training_assignments', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_training_assignments_tenant_id'), 'training_assignments', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_training_assignments_tenant_id'), table_name='training_assignments')
    op.drop_index(op.f('ix_training_assignments_campaign_id'), table_name='training_assignments')
    op.drop_table('training_assignments')
