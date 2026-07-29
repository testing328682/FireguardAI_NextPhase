"""merge heads

Revision ID: a17cd08bbcd9
Revises: 9cf3ff84eee9, d6e7f8a9b0c1, k1l2m3n4o5p6
Create Date: 2026-07-02 20:19:57.221318
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a17cd08bbcd9'
down_revision: Union[str, None] = ('9cf3ff84eee9', 'd6e7f8a9b0c1', 'k1l2m3n4o5p6')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
