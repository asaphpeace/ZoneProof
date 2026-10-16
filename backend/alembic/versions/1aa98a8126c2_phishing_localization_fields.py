"""phishing localization fields

Revision ID: 1aa98a8126c2
Revises: 5195e95231d0
Create Date: 2026-09-15 19:18:57.772346

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '1aa98a8126c2'
down_revision: Union[str, None] = '5195e95231d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('phishing_campaigns', sa.Column('subject_sent_by_locale', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('phishing_campaigns', sa.Column('body_html_sent_by_locale', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('phishing_events', sa.Column('locale', sa.String(length=10), nullable=True))
    op.add_column('tenants', sa.Column('default_locale', sa.String(length=10), server_default='en', nullable=False))


def downgrade() -> None:
    op.drop_column('tenants', 'default_locale')
    op.drop_column('phishing_events', 'locale')
    op.drop_column('phishing_campaigns', 'body_html_sent_by_locale')
    op.drop_column('phishing_campaigns', 'subject_sent_by_locale')
