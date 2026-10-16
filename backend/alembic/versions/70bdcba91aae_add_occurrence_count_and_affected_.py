"""add occurrence_count and affected_resources to findings for regional dedup

Revision ID: 70bdcba91aae
Revises: 906ba76e7d55
Create Date: 2026-09-14 12:40:06.890590

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '70bdcba91aae'
down_revision: Union[str, None] = '906ba76e7d55'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Scoped to just this migration's actual change (occurrence_count/
# affected_resources on findings) — autogenerate also picked up unrelated
# pre-existing drift (dmarc_reports/tls_reports/users index drops,
# service_accounts NOT NULL) that predates this work and hasn't been
# separately reviewed, same as every other migration this session.


def upgrade() -> None:
    op.add_column('findings', sa.Column('occurrence_count', sa.Integer(), server_default='1', nullable=False))
    op.add_column('findings', sa.Column('affected_resources', postgresql.ARRAY(sa.String()), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'affected_resources')
    op.drop_column('findings', 'occurrence_count')
