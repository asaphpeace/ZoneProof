"""add cloud_priv_esc_paths.closed_at

Revision ID: c2d8e6f0a1b5
Revises: f3b7c1e9d4a2
Create Date: 2026-09-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c2d8e6f0a1b5'
down_revision: Union[str, None] = 'f3b7c1e9d4a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('cloud_priv_esc_paths', sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('cloud_priv_esc_paths', 'closed_at')
