"""add training course library

Revision ID: 3c8f5a1d7e92
Revises: 9d2b6e1a4c73
Create Date: 2026-09-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '3c8f5a1d7e92'
down_revision: Union[str, None] = '9d2b6e1a4c73'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('training_courses',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('description', sa.String(length=1000), nullable=True),
    sa.Column('category', sa.String(length=100), nullable=False),
    sa.Column('created_by_user_id', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_training_courses_tenant_id'), 'training_courses', ['tenant_id'], unique=False)

    op.create_table('training_course_modules',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('course_id', sa.UUID(), nullable=False),
    sa.Column('order_index', sa.Integer(), nullable=False),
    sa.Column('format', sa.String(length=20), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('content', sa.String(length=20000), nullable=True),
    sa.Column('duration_minutes', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['course_id'], ['training_courses.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_training_course_modules_tenant_id'), 'training_course_modules', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_training_course_modules_course_id'), 'training_course_modules', ['course_id'], unique=False)

    op.create_table('training_course_assignments',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('course_id', sa.UUID(), nullable=False),
    sa.Column('recipient_hash', sa.String(length=64), nullable=False),
    sa.Column('access_token', sa.String(length=64), nullable=False),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('campaign_id', sa.UUID(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('completed_module_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('module_responses', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('reminder_count', sa.Integer(), nullable=False),
    sa.Column('last_reminder_sent_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['course_id'], ['training_courses.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['campaign_id'], ['phishing_campaigns.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'course_id', 'recipient_hash', name='uq_course_assignment_recipient'),
    )
    op.create_index(op.f('ix_training_course_assignments_tenant_id'), 'training_course_assignments', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_training_course_assignments_course_id'), 'training_course_assignments', ['course_id'], unique=False)
    op.create_index(op.f('ix_training_course_assignments_access_token'), 'training_course_assignments', ['access_token'], unique=True)

    op.add_column('tenants', sa.Column('auto_assign_training_course_id', sa.UUID(), nullable=True))
    op.add_column('tenants', sa.Column('training_reminder_interval_days', sa.Integer(), server_default='14', nullable=False))
    op.add_column('tenants', sa.Column('training_reminder_max_count', sa.Integer(), server_default='2', nullable=False))
    op.create_foreign_key(
        'fk_tenants_auto_assign_training_course_id', 'tenants', 'training_courses',
        ['auto_assign_training_course_id'], ['id'], ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint('fk_tenants_auto_assign_training_course_id', 'tenants', type_='foreignkey')
    op.drop_column('tenants', 'training_reminder_max_count')
    op.drop_column('tenants', 'training_reminder_interval_days')
    op.drop_column('tenants', 'auto_assign_training_course_id')

    op.drop_index(op.f('ix_training_course_assignments_access_token'), table_name='training_course_assignments')
    op.drop_index(op.f('ix_training_course_assignments_course_id'), table_name='training_course_assignments')
    op.drop_index(op.f('ix_training_course_assignments_tenant_id'), table_name='training_course_assignments')
    op.drop_table('training_course_assignments')

    op.drop_index(op.f('ix_training_course_modules_course_id'), table_name='training_course_modules')
    op.drop_index(op.f('ix_training_course_modules_tenant_id'), table_name='training_course_modules')
    op.drop_table('training_course_modules')

    op.drop_index(op.f('ix_training_courses_tenant_id'), table_name='training_courses')
    op.drop_table('training_courses')
