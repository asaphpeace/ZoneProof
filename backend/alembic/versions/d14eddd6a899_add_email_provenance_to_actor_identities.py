"""add email provenance to actor identities

Revision ID: d14eddd6a899
Revises: 3ba1f0c9dd09
Create Date: 2026-09-15 10:00:28.616560

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd14eddd6a899'
down_revision: Union[str, None] = '3ba1f0c9dd09'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('actor_identities', sa.Column('email_provenance', sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column('actor_identities', 'email_provenance')
