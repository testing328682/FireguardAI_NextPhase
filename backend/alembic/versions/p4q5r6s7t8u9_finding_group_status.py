"""Finding group status: persisted parent status for grouped findings

Revision ID: p4q5r6s7t8u9
Revises: o3p4q5r6s7t8
Create Date: 2026-09-03
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "p4q5r6s7t8u9"
down_revision: Union[str, None] = "o3p4q5r6s7t8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_group_status",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36),
                  sa.ForeignKey("organizations.id"), index=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), index=True),
        sa.Column("rule_id", sa.String(255), index=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("justification", sa.Text(), nullable=False, server_default=""),
        sa.Column("accepted_risk_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signed_off_by", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("device_id", "rule_id", name="uq_finding_group_status_device_rule"),
    )


def downgrade() -> None:
    op.drop_table("finding_group_status")
