"""PSIRT refresh changelog and manual refresh (admin)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, PsirtRefreshLog
from ..schemas import PsirtRefreshOut
from ..security import require_role
from .. import audit

router = APIRouter(prefix="/api/v1/settings/psirt", tags=["psirt"])


@router.get("/changelog", response_model=list[PsirtRefreshOut])
def changelog(limit: int = Query(default=30, le=200),
              user: User = Depends(require_role(Role.admin)),
              db: Session = Depends(get_db)) -> list[PsirtRefreshLog]:
    return list(db.scalars(
        select(PsirtRefreshLog).order_by(PsirtRefreshLog.ran_at.desc()).limit(limit)))


@router.post("/refresh", response_model=PsirtRefreshOut)
def manual_refresh(user: User = Depends(require_role(Role.admin)),
                   db: Session = Depends(get_db)) -> PsirtRefreshLog:
    """Trigger an immediate PSIRT refresh."""
    from ..psirt_refresh import refresh_psirt
    log = refresh_psirt(db, source="manual")
    audit.log_action(db, organization_id=user.organization_id, action="psirt.refresh",
                     resource_type="psirt", resource_id=log.id, user=user,
                     after={"changed": log.changed, "advisory_count": log.advisory_count})
    return log
