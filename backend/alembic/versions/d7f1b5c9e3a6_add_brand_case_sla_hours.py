"""store the allowance a case deadline was set with

Revision ID: d7f1b5c9e3a6
Revises: c6e0a4b8d2f5
Create Date: 2026-10-05 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'd7f1b5c9e3a6'
down_revision: Union[str, None] = 'c6e0a4b8d2f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('brand_candidates', sa.Column('sla_hours', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('brand_candidates', 'sla_hours')
