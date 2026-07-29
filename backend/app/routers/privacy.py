"""Privacy & compliance endpoints: GDPR export, right-to-erasure, retention.

A user may export their own data. Admins/owners may export or erase any user in
their organization. Erasure anonymises PII while preserving audit/finding history
(see ``app.privacy.RETENTION_EXCEPTIONS``).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, Organization
from ..security import current_user, require_role, _ROLE_RANK
from .. import privacy, audit
from ..retention import retention_days_for

router = APIRouter(prefix="/api/v1/privacy", tags=["privacy"])


@router.get("/me/export")
def export_me(user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    """Export the authenticated user's personal data as JSON (GDPR Art. 15/20)."""
    return privacy.export_user_data(db, user)


def _org_user(db: Session, user_id: str, actor: User) -> User:
    target = db.get(User, user_id)
    if target is None or target.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return target


@router.get("/users/{user_id}/export")
def export_user(user_id: str, actor: User = Depends(require_role(Role.admin)),
                db: Session = Depends(get_db)) -> dict:
    return privacy.export_user_data(db, _org_user(db, user_id, actor))


@router.post("/users/{user_id}/erase")
def erase_user(user_id: str, request: Request,
               actor: User = Depends(require_role(Role.admin)),
               db: Session = Depends(get_db)) -> dict:
    """Right-to-erasure (GDPR Art. 17). Anonymises PII with documented exceptions."""
    target = _org_user(db, user_id, actor)
    if target.id == actor.id and _ROLE_RANK[actor.role] >= _ROLE_RANK[Role.owner]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="An owner cannot erase their own account")
    result = privacy.erase_user(db, target)
    audit.log_action(db, organization_id=actor.organization_id, action="privacy.user_erased",
                     resource_type="user", resource_id=user_id, user=actor, request=request)
    return result


@router.get("/retention")
def retention_policy(user: User = Depends(current_user),
                     db: Session = Depends(get_db)) -> dict:
    org = db.get(Organization, user.organization_id)
    days = retention_days_for(org)
    return {"plan": org.plan.value, "retention_days": days,
            "unlimited": days == 0,
            "override": org.data_retention_days is not None}
