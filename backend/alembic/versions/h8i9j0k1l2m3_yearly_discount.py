"""yearly discount percent

Revision ID: h8i9j0k1l2m3
Revises: g7h8i9j0k1l2
Create Date: 2026-06-25 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'h8i9j0k1l2m3'
down_revision: Union[str, None] = 'g7h8i9j0k1l2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('yearly_discount_pct', sa.Integer(), nullable=False, server_default='20'))


def downgrade() -> None:
    with op.batch_alter_table('plans', schema=None) as batch_op:
        batch_op.drop_column('yearly_discount_pct')
