"""add brand case workflow columns (assignee, due, resolved)

Revision ID: c6e0a4b8d2f5
Revises: b5d9f3a7c1e4
Create Date: 2026-10-03 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'c6e0a4b8d2f5'
down_revision: Union[str, None] = 'b5d9f3a7c1e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('brand_candidates', sa.Column('assignee_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True))
    op.add_column('brand_candidates', sa.Column('due_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('brand_candidates', sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_brand_candidates_assignee_user_id', 'brand_candidates', ['assignee_user_id'])


def downgrade() -> None:
    op.drop_index('ix_brand_candidates_assignee_user_id', table_name='brand_candidates')
    op.drop_column('brand_candidates', 'resolved_at')
    op.drop_column('brand_candidates', 'due_at')
    op.drop_column('brand_candidates', 'assignee_user_id')
