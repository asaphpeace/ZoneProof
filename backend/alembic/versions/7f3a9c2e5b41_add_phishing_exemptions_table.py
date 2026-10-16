"""add phishing_exemptions table

Revision ID: 7f3a9c2e5b41
Revises: 44c2eb186e47
Create Date: 2026-09-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '7f3a9c2e5b41'
down_revision: Union[str, None] = '44c2eb186e47'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('phishing_exemptions',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('reason', sa.String(length=500), nullable=True),
    sa.Column('created_by_user_id', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'email', name='uq_phishing_exemption_tenant_email'),
    )
    op.create_index(op.f('ix_phishing_exemptions_tenant_id'), 'phishing_exemptions', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_phishing_exemptions_tenant_id'), table_name='phishing_exemptions')
    op.drop_table('phishing_exemptions')
