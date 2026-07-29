"""add missing device columns (last_analysis_at, severity counts)

Revision ID: b2c3d4e5f6a7
Revises: 9cf3ff84eee9
Create Date: 2026-06-22 01:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('last_analysis_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('critical_count', sa.Integer(), nullable=False, server_default=sa.text('0')))
        batch_op.add_column(sa.Column('high_count', sa.Integer(), nullable=False, server_default=sa.text('0')))
        batch_op.add_column(sa.Column('medium_count', sa.Integer(), nullable=False, server_default=sa.text('0')))
        batch_op.add_column(sa.Column('low_count', sa.Integer(), nullable=False, server_default=sa.text('0')))


def downgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_column('low_count')
        batch_op.drop_column('medium_count')
        batch_op.drop_column('high_count')
        batch_op.drop_column('critical_count')
        batch_op.drop_column('last_analysis_at')
