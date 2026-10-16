"""add publisher verification fields to oauth_grants

Revision ID: f12939886456
Revises: a7fcc3199888
Create Date: 2026-09-14 07:52:08.661909

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f12939886456'
down_revision: Union[str, None] = 'a7fcc3199888'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default so existing rows (from scans run before this column
    # existed) backfill to False rather than failing the NOT NULL add.
    op.add_column('oauth_grants', sa.Column('publisher_verified', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('oauth_grants', sa.Column('publisher_name', sa.String(length=300), nullable=True))


def downgrade() -> None:
    op.drop_column('oauth_grants', 'publisher_name')
    op.drop_column('oauth_grants', 'publisher_verified')
