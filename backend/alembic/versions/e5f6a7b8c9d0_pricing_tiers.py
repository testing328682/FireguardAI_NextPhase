"""pricing tiers, addons, and org plan config

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-06-23 14:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pricing_tiers', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")))
        batch_op.add_column(sa.Column('addons', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")))
        batch_op.add_column(sa.Column('msp_tiers', sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")))
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('analysis_frequency', sa.String(length=32), nullable=False, server_default='monthly'))


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('analysis_frequency')
        batch_op.drop_column('device_count')
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.drop_column('msp_tiers')
        batch_op.drop_column('addons')
        batch_op.drop_column('pricing_tiers')
