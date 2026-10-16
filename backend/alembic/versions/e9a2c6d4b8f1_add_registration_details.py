"""add registry details to the shared registration cache

Revision ID: e9a2c6d4b8f1
Revises: d8f3a5c1e7b2
Create Date: 2026-10-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e9a2c6d4b8f1'
down_revision: Union[str, None] = 'd8f3a5c1e7b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('brand_registration_cache', sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('brand_registration_cache', 'details')
