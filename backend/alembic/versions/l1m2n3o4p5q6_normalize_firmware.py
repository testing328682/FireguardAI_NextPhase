"""normalize firmware versions — strip SonicOS / SonicOS Enhanced prefixes

Revision ID: l1m2n3o4p5q6
Revises: k1l2m3n4o5p6
Create Date: 2026-07-11 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = 'l1m2n3o4p5q6'
down_revision: Union[str, None] = 'k1l2m3n4o5p6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Strip 'SonicOS ' and 'SonicOS Enhanced ' prefixes from firmware columns."""
    op.execute(
        "UPDATE devices SET firmware = trim(regexp_replace(firmware, '^SonicOS\\s*(Enhanced\\s*)?', '')) "
        "WHERE firmware ~ '^SonicOS'"
    )
    op.execute(
        "UPDATE firmware_recommendations SET version = "
        "trim(regexp_replace(version, '^SonicOS\\s*(Enhanced\\s*)?', '')) "
        "WHERE version ~ '^SonicOS'"
    )


def downgrade() -> None:
    """Restore prefix — best-effort: prepend 'SonicOS ' for Gen7+ patterns."""
    op.execute(
        "UPDATE devices SET firmware = 'SonicOS ' || firmware "
        "WHERE firmware ~ '^[0-9]+\\.' AND firmware NOT LIKE 'SonicOS%'"
    )
