"""add resource_uid to findings for reconciliation

Revision ID: c562d49e1286
Revises: d0b9e4f6bc19
Create Date: 2026-09-11 15:47:42.809832

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c562d49e1286'
down_revision: Union[str, None] = 'd0b9e4f6bc19'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('resource_uid', sa.String(length=2048), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'resource_uid')
