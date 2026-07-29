"""Audit-log query endpoint.

The log is append-only (writes happen via ``app.audit.log_action`` from across
the service). This router exposes a paginated, filterable read for admins.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, AuditLog
from ..schemas import AuditLogOut, AuditLogPage
from ..security import require_role

router = APIRouter(prefix="/api/v1", tags=["audit"])


@router.get("/audit-log", response_model=AuditLogPage)
def query_audit_log(
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        user_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = Query(default=50, le=500),
        offset: int = 0,
        actor: User = Depends(require_role(Role.admin)),
        db: Session = Depends(get_db)) -> AuditLogPage:
    """Paginated audit events for the actor's organization (admin only)."""
    base = select(AuditLog).where(AuditLog.organization_id == actor.organization_id)
    if action:
        base = base.where(AuditLog.action == action)
    if resource_type:
        base = base.where(AuditLog.resource_type == resource_type)
    if user_id:
        base = base.where(AuditLog.user_id == user_id)
    if since:
        base = base.where(AuditLog.created_at >= since)
    if until:
        base = base.where(AuditLog.created_at <= until)

    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    items = list(db.scalars(
        base.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)))
    return AuditLogPage(total=total, items=items)
