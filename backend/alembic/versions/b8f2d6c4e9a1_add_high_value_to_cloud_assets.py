"""add high-value tagging to cloud_assets

Revision ID: b8f2d6c4e9a1
Revises: a7c3e9f1d4b6
Create Date: 2026-09-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b8f2d6c4e9a1'
down_revision: Union[str, None] = 'a7c3e9f1d4b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FK_NAME = 'fk_cloud_assets_high_value_set_by_user_id_users'


def upgrade() -> None:
    op.add_column('cloud_assets', sa.Column('is_high_value', sa.Boolean(), nullable=True))
    op.add_column('cloud_assets', sa.Column('high_value_set_by_user_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('cloud_assets', sa.Column('high_value_set_at', sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key(
        _FK_NAME, 'cloud_assets', 'users',
        ['high_value_set_by_user_id'], ['id'], ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint(_FK_NAME, 'cloud_assets', type_='foreignkey')
    op.drop_column('cloud_assets', 'high_value_set_at')
    op.drop_column('cloud_assets', 'high_value_set_by_user_id')
    op.drop_column('cloud_assets', 'is_high_value')
