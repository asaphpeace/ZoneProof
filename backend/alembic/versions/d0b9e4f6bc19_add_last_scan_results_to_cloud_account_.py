"""add last_scan_results to cloud_account_connections

Revision ID: d0b9e4f6bc19
Revises: f84f9ce8bdd4
Create Date: 2026-09-11 14:23:12.528009

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'd0b9e4f6bc19'
down_revision: Union[str, None] = 'f84f9ce8bdd4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'cloud_account_connections',
        sa.Column('last_scan_results', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
    )


def downgrade() -> None:
    op.drop_column('cloud_account_connections', 'last_scan_results')
