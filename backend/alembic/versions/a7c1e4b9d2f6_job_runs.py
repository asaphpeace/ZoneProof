"""persist background job history (V2 plan G2)

Revision ID: a7c1e4b9d2f6
Revises: e5a9c3d7f1b2
Create Date: 2026-10-16 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'a7c1e4b9d2f6'
down_revision: Union[str, None] = 'e5a9c3d7f1b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'job_runs',
        sa.Column('job_key', sa.String(64), primary_key=True),
        sa.Column('runs', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_started', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_finished', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_ok', sa.Boolean(), nullable=True),
        sa.Column('last_failure_kind', sa.String(24), nullable=True),
        sa.Column('last_duration_s', sa.Float(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('job_runs')
