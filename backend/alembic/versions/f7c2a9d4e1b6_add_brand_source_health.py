"""add brand source health

Revision ID: f7c2a9d4e1b6
Revises: e5b1f3a7c2d9
Create Date: 2026-09-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f7c2a9d4e1b6'
down_revision: Union[str, None] = 'e5b1f3a7c2d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_source_health',
        sa.Column('source', sa.String(40), primary_key=True),
        sa.Column('label', sa.String(120), nullable=False),
        sa.Column('status', sa.String(10), nullable=False, server_default='healthy'),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_failure_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('last_latency_ms', sa.Integer(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('brand_source_health')
