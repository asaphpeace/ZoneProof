"""add shared brand registration cache

Revision ID: c2d7a4e9b1f5
Revises: a3e8c1d5b7f2
Create Date: 2026-10-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c2d7a4e9b1f5'
down_revision: Union[str, None] = 'a3e8c1d5b7f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_registration_cache',
        sa.Column('apex_domain', sa.String(253), primary_key=True),
        sa.Column('registered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('found', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('source', sa.String(20), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('brand_registration_cache')
