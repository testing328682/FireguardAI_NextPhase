"""analyze_mode column on devices

Revision ID: d6e7f8a9b0c1
Revises: c3d4e5f6a7b8
Create Date: 2026-07-01 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd6e7f8a9b0c1'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('analyze_mode', sa.String(16), nullable=False, server_default=sa.text("'manual'")))


def downgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_column('analyze_mode')
