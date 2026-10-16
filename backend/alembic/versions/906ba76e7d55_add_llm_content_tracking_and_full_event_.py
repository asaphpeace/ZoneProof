"""add llm content tracking and full event evidence to phishing

Revision ID: 906ba76e7d55
Revises: e3ed250e0693
Create Date: 2026-09-14 09:05:58.294008

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '906ba76e7d55'
down_revision: Union[str, None] = 'e3ed250e0693'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('phishing_campaigns', sa.Column('llm_generated', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('phishing_campaigns', sa.Column('subject_sent', sa.String(length=500), nullable=True))
    op.add_column('phishing_campaigns', sa.Column('dmarc_context', sa.String(length=500), nullable=True))
    op.add_column('phishing_events', sa.Column('ip_address', sa.String(length=45), nullable=True))
    op.add_column('phishing_events', sa.Column('user_agent', sa.String(length=500), nullable=True))
    op.add_column('phishing_events', sa.Column('destination_url', sa.String(length=500), nullable=True))


def downgrade() -> None:
    op.drop_column('phishing_events', 'destination_url')
    op.drop_column('phishing_events', 'user_agent')
    op.drop_column('phishing_events', 'ip_address')
    op.drop_column('phishing_campaigns', 'dmarc_context')
    op.drop_column('phishing_campaigns', 'subject_sent')
    op.drop_column('phishing_campaigns', 'llm_generated')
