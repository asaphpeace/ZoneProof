"""add the live certificate stream worker's read positions

Revision ID: a4c8e2d6b1f3
Revises: f1b4d6a8c3e2
Create Date: 2026-10-02 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a4c8e2d6b1f3'
down_revision: Union[str, None] = 'f1b4d6a8c3e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ct_stream_cursors',
        sa.Column('log_id', sa.String(255), primary_key=True),
        sa.Column('next_index', sa.BigInteger(), nullable=False),
        sa.Column('tree_size', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('lag_seconds', sa.Float(), nullable=True),
        sa.Column('entries_seen', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('entries_skipped', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('names_matched', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('ct_stream_cursors')
