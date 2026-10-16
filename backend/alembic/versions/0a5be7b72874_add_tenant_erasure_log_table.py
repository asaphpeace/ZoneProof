"""add tenant erasure log table

Revision ID: 0a5be7b72874
Revises: 1771c4c78969
Create Date: 2026-09-15 18:56:50.374974

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0a5be7b72874'
down_revision: Union[str, None] = '1771c4c78969'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('tenant_erasure_log',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('tenant_name', sa.String(length=200), nullable=False),
    sa.Column('deleted_by_email', sa.String(length=320), nullable=False),
    sa.Column('domain_count', sa.Integer(), nullable=False),
    sa.Column('user_count', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tenant_erasure_log_tenant_id'), 'tenant_erasure_log', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_tenant_erasure_log_tenant_id'), table_name='tenant_erasure_log')
    op.drop_table('tenant_erasure_log')
