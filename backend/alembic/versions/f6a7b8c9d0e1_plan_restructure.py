"""plan_type, feature registry, simplify plans

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-06-23 16:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('plan_type', sa.String(length=32), nullable=False, server_default='professional'))
        batch_op.drop_column('monthly_price')
        batch_op.drop_column('annual_price')
        batch_op.drop_column('trial_days')
        batch_op.drop_column('limits')
        batch_op.drop_column('addons')
        batch_op.drop_column('msp_tiers')

    op.create_table('features_registry',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('key', sa.String(length=64), nullable=False),
        sa.Column('label', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('sort_order', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'))
    with op.batch_alter_table('features_registry', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_features_registry_key'), ['key'], unique=True)


def downgrade() -> None:
    op.drop_table('features_registry')
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('msp_tiers', sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")))
        batch_op.add_column(sa.Column('addons', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")))
        batch_op.add_column(sa.Column('limits', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")))
        batch_op.add_column(sa.Column('trial_days', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('annual_price', sa.Float(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('monthly_price', sa.Float(), nullable=False, server_default='0'))
        batch_op.drop_column('plan_type')
