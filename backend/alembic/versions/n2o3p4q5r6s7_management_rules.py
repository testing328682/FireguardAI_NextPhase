"""Management rules: rules.kind + rules.definition

Revision ID: n2o3p4q5r6s7
Revises: m1n2o3p4q5r6
Create Date: 2026-08-30
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "n2o3p4q5r6s7"
down_revision: Union[str, None] = "m1n2o3p4q5r6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("rules", sa.Column(
        "kind", sa.String(16), nullable=False, server_default="cel"))
    op.add_column("rules", sa.Column("definition", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("rules", "definition")
    op.drop_column("rules", "kind")
