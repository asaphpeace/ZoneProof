"""add email_suppressions table

Revision ID: 1771c4c78969
Revises: c2476aefd12e
Create Date: 2026-09-15 18:23:29.093584

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '1771c4c78969'
down_revision: Union[str, None] = 'c2476aefd12e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('email_suppressions',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('reason', sa.String(length=20), nullable=False),
    sa.Column('detail', sa.String(length=500), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_suppressions_email'), 'email_suppressions', ['email'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_email_suppressions_email'), table_name='email_suppressions')
    op.drop_table('email_suppressions')
