"""add phishing custom templates

Revision ID: 44c2eb186e47
Revises: 1aa98a8126c2
Create Date: 2026-09-16 09:31:17.573780

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '44c2eb186e47'
down_revision: Union[str, None] = '1aa98a8126c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('phishing_custom_templates',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('label', sa.String(length=200), nullable=False),
    sa.Column('category', sa.String(length=50), nullable=False),
    sa.Column('subject', sa.String(length=500), nullable=False),
    sa.Column('body_html', sa.Text(), nullable=False),
    sa.Column('difficulty', sa.String(length=10), nullable=False),
    sa.Column('from_email', sa.String(length=320), nullable=True),
    sa.Column('display_name', sa.String(length=200), nullable=True),
    sa.Column('include_attachments', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_phishing_custom_templates_tenant_id'), 'phishing_custom_templates', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_phishing_custom_templates_tenant_id'), table_name='phishing_custom_templates')
    op.drop_table('phishing_custom_templates')
