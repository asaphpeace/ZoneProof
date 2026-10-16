"""add escalation_type and policy name/arn to cloud_priv_esc_paths

Revision ID: 79d7f8c61066
Revises: c562d49e1286
Create Date: 2026-09-14 07:24:39.421042

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '79d7f8c61066'
down_revision: Union[str, None] = 'c562d49e1286'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Scoped to just this migration's actual change — autogenerate also
    # picked up unrelated pre-existing drift (index drops on dmarc_reports/
    # tls_reports/users, a NOT NULL tightening on service_accounts) that
    # predates this work and hasn't been separately reviewed; left out
    # deliberately rather than folded in silently.
    op.add_column('cloud_priv_esc_paths', sa.Column('escalation_type', sa.String(length=200), nullable=True))
    op.add_column('cloud_priv_esc_paths', sa.Column('policy_name', sa.String(length=300), nullable=True))
    op.add_column('cloud_priv_esc_paths', sa.Column('policy_arn', sa.String(length=2048), nullable=True))


def downgrade() -> None:
    op.drop_column('cloud_priv_esc_paths', 'policy_arn')
    op.drop_column('cloud_priv_esc_paths', 'policy_name')
    op.drop_column('cloud_priv_esc_paths', 'escalation_type')
