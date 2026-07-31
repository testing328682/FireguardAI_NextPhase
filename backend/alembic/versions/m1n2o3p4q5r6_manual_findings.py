"""Add source column and make analysis_id nullable on findings

Revision ID: m1n2o3p4q5r6
Revises: l1m2n3o4p5q6
Create Date: 2026-07-30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "m1n2o3p4q5r6"
down_revision: Union[str, None] = "l1m2n3o4p5q6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Allow analysis_id to be NULL (manual findings have no analysis)
    op.alter_column("findings", "analysis_id", existing_type=sa.String(36), nullable=True)
    # Add source column to distinguish parser-generated vs manual findings
    op.add_column("findings", sa.Column("source", sa.String(16), nullable=False, server_default="parser"))


def downgrade() -> None:
    op.drop_column("findings", "source")
    op.alter_column("findings", "analysis_id", existing_type=sa.String(36), nullable=False)
