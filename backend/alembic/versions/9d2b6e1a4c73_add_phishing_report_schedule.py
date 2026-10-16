"""add phishing report schedule columns

Revision ID: 9d2b6e1a4c73
Revises: 7f3a9c2e5b41
Create Date: 2026-09-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '9d2b6e1a4c73'
down_revision: Union[str, None] = '7f3a9c2e5b41'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('phishing_report_schedule', sa.String(length=20), nullable=False, server_default='off'))
    op.add_column('tenants', sa.Column('last_phishing_report_sent_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('tenants', 'last_phishing_report_sent_at')
    op.drop_column('tenants', 'phishing_report_schedule')
