"""Firmware intelligence: compliance-rule metadata + firmware versions/CVEs/issues

Revision ID: o3p4q5r6s7t8
Revises: n2o3p4q5r6s7
Create Date: 2026-08-31
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "o3p4q5r6s7t8"
down_revision: Union[str, None] = "n2o3p4q5r6s7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Defaults reproduce the historical hardcoded finding for existing rows.
    op.add_column("firmware_recommendations", sa.Column(
        "rule_enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("firmware_recommendations", sa.Column(
        "rule_key", sa.String(64), nullable=False,
        server_default="FW-FIRMWARE-COMPLIANCE"))
    op.add_column("firmware_recommendations", sa.Column(
        "rule_title", sa.String(512), nullable=False, server_default=""))
    op.add_column("firmware_recommendations", sa.Column(
        "rule_description", sa.Text(), nullable=False, server_default=""))
    op.add_column("firmware_recommendations", sa.Column(
        "rule_severity", sa.String(16), nullable=False, server_default="Critical"))
    op.add_column("firmware_recommendations", sa.Column(
        "rule_category", sa.String(128), nullable=False,
        server_default="Firmware Compliance"))
    op.add_column("firmware_recommendations", sa.Column(
        "rule_remediation", sa.Text(), nullable=False, server_default=""))

    op.create_table(
        "firmware_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("generation_id", sa.String(36),
                  sa.ForeignKey("device_generations.id"), index=True),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("version_norm", sa.String(64), nullable=False, index=True),
        sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )
    op.create_table(
        "firmware_cves",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("firmware_version_id", sa.String(36),
                  sa.ForeignKey("firmware_versions.id"), index=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
        sa.Column("extra", sa.JSON(), nullable=True),
    )
    op.create_table(
        "firmware_issues",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("firmware_version_id", sa.String(36),
                  sa.ForeignKey("firmware_versions.id"), index=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False, server_default=""),
        sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_table("firmware_issues")
    op.drop_table("firmware_cves")
    op.drop_table("firmware_versions")
    for col in ("rule_remediation", "rule_category", "rule_severity",
                "rule_description", "rule_title", "rule_key", "rule_enabled"):
        op.drop_column("firmware_recommendations", col)
