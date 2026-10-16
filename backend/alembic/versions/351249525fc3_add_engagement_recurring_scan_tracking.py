"""add engagement recurring scan tracking

Revision ID: 351249525fc3
Revises: 1a1aa3632727
Create Date: 2026-07-18 10:58:17.091367

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '351249525fc3'
down_revision: Union[str, None] = '1a1aa3632727'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('engagements', sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('engagements', sa.Column('last_scan_status', sa.String(length=20), server_default='never_run', nullable=False))
    op.add_column('engagements', sa.Column('last_scan_error', sa.String(length=1000), nullable=True))


def downgrade() -> None:
    op.drop_column('engagements', 'last_scan_error')
    op.drop_column('engagements', 'last_scan_status')
    op.drop_column('engagements', 'last_scanned_at')
