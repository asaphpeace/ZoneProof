"""widen last_scan_status to fit transient running: markers

Revision ID: a7fcc3199888
Revises: 79d7f8c61066
Create Date: 2026-09-14 07:35:13.146595

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a7fcc3199888'
down_revision: Union[str, None] = '79d7f8c61066'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Scoped to just this migration's actual change — see 79d7f8c61066 for
    # why the unrelated autogenerate-detected drift is deliberately excluded.
    op.alter_column('cloud_account_connections', 'last_scan_status',
               existing_type=sa.VARCHAR(length=20),
               type_=sa.String(length=40),
               existing_nullable=False,
               existing_server_default=sa.text("'never_run'::character varying"))
    op.alter_column('host_connections', 'last_scan_status',
               existing_type=sa.VARCHAR(length=20),
               type_=sa.String(length=40),
               existing_nullable=False,
               existing_server_default=sa.text("'never_run'::character varying"))


def downgrade() -> None:
    op.alter_column('host_connections', 'last_scan_status',
               existing_type=sa.String(length=40),
               type_=sa.VARCHAR(length=20),
               existing_nullable=False,
               existing_server_default=sa.text("'never_run'::character varying"))
    op.alter_column('cloud_account_connections', 'last_scan_status',
               existing_type=sa.String(length=40),
               type_=sa.VARCHAR(length=20),
               existing_nullable=False,
               existing_server_default=sa.text("'never_run'::character varying"))
