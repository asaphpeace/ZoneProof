"""add findings.region and findings.extra (JSONB)

Revision ID: f3b7c1e9d4a2
Revises: a1c9f4e2b8d3
Create Date: 2026-09-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'f3b7c1e9d4a2'
down_revision: Union[str, None] = 'a1c9f4e2b8d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('region', sa.String(length=30), nullable=True))
    op.create_index(op.f('ix_findings_region'), 'findings', ['region'], unique=False)

    op.add_column('findings', sa.Column('extra', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('findings', sa.Column('extra_populated_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'extra_populated_at')
    op.drop_column('findings', 'extra')

    op.drop_index(op.f('ix_findings_region'), table_name='findings')
    op.drop_column('findings', 'region')
