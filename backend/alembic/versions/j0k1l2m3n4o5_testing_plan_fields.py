"""add is_testing and validity_minutes to plans

Revision ID: j0k1l2m3n4o5
Revises: i9j0k1l2m3n4
Create Date: 2026-06-30 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'j0k1l2m3n4o5'
down_revision: Union[str, None] = 'i9j0k1l2m3n4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_testing', sa.Boolean(), nullable=False, server_default=sa.text('false')))
        batch_op.add_column(sa.Column('validity_minutes', sa.Integer(), nullable=False, server_default=sa.text('0')))


def downgrade() -> None:
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.drop_column('validity_minutes')
        batch_op.drop_column('is_testing')
