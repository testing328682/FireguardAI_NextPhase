"""hidden_severities columns for org and device

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-23 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hidden_severities', sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")))
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hidden_severities', sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")))


def downgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_column('hidden_severities')
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('hidden_severities')
