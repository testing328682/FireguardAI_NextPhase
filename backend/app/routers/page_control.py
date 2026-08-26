"""Page Control endpoints — Server Admin controls customer-facing visibility.

Admin (superadmin-only) management lives under ``/api/v1/platform/page-control``;
a lightweight authenticated read endpoint under ``/api/v1/page-control`` lets the
customer frontend honour the flags (e.g. hiding the SSO section).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import page_control as pc
from ..database import get_db
from ..models import PageControlSetting, User
from ..schemas import PageControlOut, PageControlUpdate
from ..security import current_user, require_superadmin

router = APIRouter(prefix="/api/v1/platform/page-control", tags=["page-control"])
public_router = APIRouter(prefix="/api/v1/page-control", tags=["page-control"])


@router.get("", response_model=list[PageControlOut])
def list_page_controls(
    _: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
) -> list[PageControlOut]:
    """All catalogued pages/features with their current visibility state."""
    return [PageControlOut(**entry) for entry in pc.catalog_list(db)]


@router.put("/{key}", response_model=PageControlOut)
def update_page_control(
    key: str,
    body: PageControlUpdate,
    _: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
) -> PageControlOut:
    """Enable or disable a page/feature for all customer organizations."""
    meta = pc.PAGE_CONTROL_CATALOG.get(key)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"Unknown page control key: {key}")
    row = db.scalar(select(PageControlSetting).where(PageControlSetting.key == key))
    if row is None:
        row = PageControlSetting(
            key=key, label=meta["label"], description=meta.get("description", ""),
            enabled=body.enabled,
        )
        db.add(row)
    else:
        row.enabled = body.enabled
    db.commit()
    return PageControlOut(key=row.key, label=row.label, description=row.description, enabled=row.enabled)


@public_router.get("", response_model=dict[str, bool])
def page_control_state(
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    """Customer-facing visibility flags (authenticated)."""
    return pc.state_dict(db)
