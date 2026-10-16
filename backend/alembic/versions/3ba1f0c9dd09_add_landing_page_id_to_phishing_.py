"""add landing_page_id to phishing campaigns

Revision ID: 3ba1f0c9dd09
Revises: 511751feef4c
Create Date: 2026-09-15 09:34:53.160195

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3ba1f0c9dd09'
down_revision: Union[str, None] = '511751feef4c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('phishing_campaigns', sa.Column('landing_page_id', sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column('phishing_campaigns', 'landing_page_id')
