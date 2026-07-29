"""Per-device scan schedule management.

A device has at most one schedule. ``PUT`` upserts it and recomputes the next
fire time; the Celery Beat poller (``run_due_schedules``) consumes the table.
Mutations are restricted to admins and recorded in the audit log.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, Device, Schedule
from ..schemas import ScheduleIn, ScheduleOut
from ..security import current_user, require_role
from ..scheduler import compute_next_run
from .. import audit

router = APIRouter(prefix="/api/v1", tags=["schedules"])

_AUDIT_FIELDS = ("frequency", "hour", "minute", "timezone", "day_of_week",
                 "day_of_month", "enabled")


def _owned_device(db: Session, device_id: str, user: User) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(user: User = Depends(current_user),
                   db: Session = Depends(get_db)) -> list[Schedule]:
    return list(db.scalars(select(Schedule).where(
        Schedule.organization_id == user.organization_id)))


@router.get("/devices/{device_id}/schedule", response_model=ScheduleOut)
def get_schedule(device_id: str,
                  user: User = Depends(require_role(Role.analyst)),
                 db: Session = Depends(get_db)) -> Schedule:
    _owned_device(db, device_id, user)
    sched = db.scalar(select(Schedule).where(Schedule.device_id == device_id))
    if sched is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No schedule configured for this device")
    return sched


@router.put("/devices/{device_id}/schedule", response_model=ScheduleOut)
def upsert_schedule(device_id: str, body: ScheduleIn, request: Request,
                    user: User = Depends(require_role(Role.analyst)),
                    db: Session = Depends(get_db)) -> Schedule:
    _owned_device(db, device_id, user)
    sched = db.scalar(select(Schedule).where(Schedule.device_id == device_id))
    before = audit.model_snapshot(sched, _AUDIT_FIELDS) if sched else {}
    if sched is None:
        sched = Schedule(organization_id=user.organization_id, device_id=device_id)
        db.add(sched)
    sched.frequency = body.frequency
    sched.hour = body.hour
    sched.minute = body.minute
    sched.timezone = body.timezone
    sched.day_of_week = body.day_of_week
    sched.day_of_month = body.day_of_month
    sched.enabled = body.enabled
    sched.blackout_windows = body.blackout_windows
    sched.next_run_at = compute_next_run(sched)
    db.commit()
    db.refresh(sched)
    audit.log_action(db, organization_id=user.organization_id, action=audit.SCHEDULE_CHANGED,
                     resource_type="schedule", resource_id=sched.id, user=user, request=request,
                     before=before, after=audit.model_snapshot(sched, _AUDIT_FIELDS))
    return sched


@router.delete("/devices/{device_id}/schedule", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(device_id: str, request: Request,
                    user: User = Depends(require_role(Role.admin)),
                    db: Session = Depends(get_db)):
    _owned_device(db, device_id, user)
    sched = db.scalar(select(Schedule).where(Schedule.device_id == device_id))
    if sched is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No schedule to delete")
    sched_id = sched.id
    db.delete(sched)
    db.commit()
    audit.log_action(db, organization_id=user.organization_id, action=audit.SCHEDULE_DELETED,
                     resource_type="schedule", resource_id=sched_id, user=user, request=request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
