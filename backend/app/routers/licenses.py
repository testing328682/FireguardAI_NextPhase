"""Pre-defined license templates — browse and purchase.

These are fixed license packs that customers can apply to their account.
Independent from the dynamic plan-builder in plans.py.
"""

from __future__ import annotations

import json as _json
from pathlib import Path

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["licenses"])

_LICENSES_PATH = Path(__file__).parent / "licenses.json"


@router.get("/licenses")
def list_licenses():
    """Return all pre-defined license templates (public-facing)."""
    with open(_LICENSES_PATH, encoding="utf-8") as fh:
        return _json.load(fh)
