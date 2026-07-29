"""license purchase history table

Revision ID: i9j0k1l2m3n4
Revises: h8i9j0k1l2m3
Create Date: 2026-06-26 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'i9j0k1l2m3n4'
down_revision: Union[str, None] = 'h8i9j0k1l2m3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('license_purchases',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('subscription_term', sa.String(length=32), nullable=False, server_default='monthly'),
        sa.Column('analysis_frequency', sa.String(length=32), nullable=False, server_default='monthly'),
        sa.Column('tier', sa.String(length=16), nullable=True),
        sa.Column('tier_device_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('total_devices', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('purchased_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'))
    with op.batch_alter_table('license_purchases', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_license_purchases_organization_id'), ['organization_id'], unique=False)
        batch_op.create_foreign_key('fk_lp_org', 'organizations', ['organization_id'], ['id'])


def downgrade() -> None:
    op.drop_table('license_purchases')
