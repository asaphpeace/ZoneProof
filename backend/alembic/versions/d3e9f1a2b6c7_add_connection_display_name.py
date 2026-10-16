"""add display_name to cloud_account_connections and host_connections

Revision ID: d3e9f1a2b6c7
Revises: c2d8e6f0a1b5
Create Date: 2026-09-25 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd3e9f1a2b6c7'
down_revision: Union[str, None] = 'c2d8e6f0a1b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('cloud_account_connections', sa.Column('display_name', sa.String(length=200), nullable=True))
    op.add_column('host_connections', sa.Column('display_name', sa.String(length=200), nullable=True))


def downgrade() -> None:
    op.drop_column('host_connections', 'display_name')
    op.drop_column('cloud_account_connections', 'display_name')
