"""add status to cloud_priv_esc_paths for reconciliation

Revision ID: e3ed250e0693
Revises: f12939886456
Create Date: 2026-09-14 08:44:04.731198

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e3ed250e0693'
down_revision: Union[str, None] = 'f12939886456'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default so existing rows (from scans run before this column
    # existed) backfill to 'open' rather than failing the NOT NULL add.
    op.add_column('cloud_priv_esc_paths', sa.Column('status', sa.String(length=20), nullable=False, server_default='open'))


def downgrade() -> None:
    op.drop_column('cloud_priv_esc_paths', 'status')
