"""add brand fingerprint and trademarks to brand profiles

Revision ID: d8f3a5c1e7b2
Revises: c2d7a4e9b1f5
Create Date: 2026-10-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'd8f3a5c1e7b2'
down_revision: Union[str, None] = 'c2d7a4e9b1f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('brand_profiles', sa.Column('trademarks', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.add_column('brand_profiles', sa.Column('fingerprint', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('brand_profiles', sa.Column('fingerprint_built_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('brand_profiles', 'fingerprint_built_at')
    op.drop_column('brand_profiles', 'fingerprint')
    op.drop_column('brand_profiles', 'trademarks')
