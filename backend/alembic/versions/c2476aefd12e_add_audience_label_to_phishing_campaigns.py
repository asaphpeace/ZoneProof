"""add audience_label to phishing_campaigns

Revision ID: c2476aefd12e
Revises: d14eddd6a899
Create Date: 2026-09-15 13:45:23.408604

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c2476aefd12e'
down_revision: Union[str, None] = 'd14eddd6a899'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('phishing_campaigns', sa.Column('audience_label', sa.String(length=200), nullable=True))


def downgrade() -> None:
    op.drop_column('phishing_campaigns', 'audience_label')
