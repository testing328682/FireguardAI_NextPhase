"""dynamic plans

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-06-23 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('plans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('monthly_price', sa.Float(), nullable=False, server_default='0'),
        sa.Column('annual_price', sa.Float(), nullable=False, server_default='0'),
        sa.Column('trial_days', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('is_visible', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('sort_order', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('features', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column('limits', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'))

    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_plans_name'), ['name'], unique=True)

    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('plan_id', sa.String(length=36), nullable=True))
        batch_op.create_foreign_key('fk_org_plan', 'plans', ['plan_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_constraint('fk_org_plan', type_='foreignkey')
        batch_op.drop_column('plan_id')
    op.drop_table('plans')
