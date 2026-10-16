"""add phishing body html sent and tenant phishing paused

Revision ID: 9a7bec3f97e9
Revises: 70bdcba91aae
Create Date: 2026-09-14 19:19:46.238954

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a7bec3f97e9'
down_revision: Union[str, None] = '70bdcba91aae'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('phishing_campaigns', sa.Column('body_html_sent', sa.Text(), nullable=True))
    op.add_column('tenants', sa.Column('phishing_paused', sa.Boolean(), server_default='false', nullable=False))


def downgrade() -> None:
    op.drop_column('tenants', 'phishing_paused')
    op.drop_column('phishing_campaigns', 'body_html_sent')
