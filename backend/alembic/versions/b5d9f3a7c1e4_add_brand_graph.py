"""add the brand evidence graph (nodes and edges)

Revision ID: b5d9f3a7c1e4
Revises: a4c8e2d6b1f3
Create Date: 2026-10-03 03:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b5d9f3a7c1e4'
down_revision: Union[str, None] = 'a4c8e2d6b1f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'brand_graph_nodes',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('key', sa.String(300), nullable=False),
        sa.Column('label', sa.String(300), nullable=False),
        sa.Column('attrs', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('profile_id', 'kind', 'key', name='uq_brand_graph_nodes_profile_kind_key'),
    )
    op.create_index('ix_brand_graph_nodes_tenant_id', 'brand_graph_nodes', ['tenant_id'])
    op.create_index('ix_brand_graph_nodes_profile_id', 'brand_graph_nodes', ['profile_id'])
    op.create_table(
        'brand_graph_edges',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_profiles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('src_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_graph_nodes.id', ondelete='CASCADE'), nullable=False),
        sa.Column('dst_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('brand_graph_nodes.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(24), nullable=False),
        sa.Column('attrs', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('profile_id', 'src_id', 'dst_id', 'kind', name='uq_brand_graph_edges'),
    )
    for col in ('tenant_id', 'profile_id', 'src_id', 'dst_id'):
        op.create_index(f'ix_brand_graph_edges_{col}', 'brand_graph_edges', [col])


def downgrade() -> None:
    for col in ('dst_id', 'src_id', 'profile_id', 'tenant_id'):
        op.drop_index(f'ix_brand_graph_edges_{col}', table_name='brand_graph_edges')
    op.drop_table('brand_graph_edges')
    op.drop_index('ix_brand_graph_nodes_profile_id', table_name='brand_graph_nodes')
    op.drop_index('ix_brand_graph_nodes_tenant_id', table_name='brand_graph_nodes')
    op.drop_table('brand_graph_nodes')
