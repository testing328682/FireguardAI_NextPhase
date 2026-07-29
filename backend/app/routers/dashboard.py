"""Dashboard aggregation endpoint.

Assembles the post-login landing view from persisted data: fleet posture (with
a 90-day score trend), the open-findings funnel with a 24-hour delta, devices
needing attention, recent audit activity and a per-framework compliance
roll-up. Everything is scoped to the caller's organization.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    User, Device, Analysis, AnalysisStatus, Finding, FindingStatus, AuditLog,
    Schedule,
)
from ..schemas import DashboardResponse
from ..security import current_user

router = APIRouter(prefix="/api/v1", tags=["dashboard"])

ACTIVE_STATUSES = (FindingStatus.open, FindingStatus.acknowledged, FindingStatus.in_progress)
DEFAULT_FRAMEWORKS = ("CIS", "NIST", "PCI", "ISO 27001", "SonicWall BP")


def _fleet_posture(db: Session, org_id: str) -> dict:
    devices = list(db.scalars(select(Device).where(Device.organization_id == org_id)))
    grade_dist: dict[str, int] = defaultdict(int)
    score_sum = 0.0
    scored = 0
    for d in devices:
        if d.latest_grade:
            grade_dist[d.latest_grade] += 1
            score_sum += d.latest_score
            scored += 1

    # 90-day trend: average score per day across completed analyses.
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    rows = db.execute(
        select(Analysis.created_at, Analysis.score).where(
            Analysis.organization_id == org_id,
            Analysis.status == AnalysisStatus.complete,
            Analysis.created_at >= cutoff)).all()
    by_day: dict[str, list[float]] = defaultdict(list)
    for created_at, score in rows:
        by_day[created_at.date().isoformat()].append(score)
    trend = [{"date": day, "score": round(sum(v) / len(v), 1)}
             for day, v in sorted(by_day.items())]

    return {
        "device_count": len(devices),
        "scored_device_count": scored,
        "average_score": round(score_sum / scored, 1) if scored else 0.0,
        "grade_distribution": dict(grade_dist),
        "trend_90d": trend,
    }


def _findings_funnel(db: Session, org_id: str) -> dict:
    def open_count(sev: str) -> int:
        return db.scalar(select(func.count(Finding.id)).where(
            Finding.organization_id == org_id, Finding.severity == sev,
            Finding.status.in_(ACTIVE_STATUSES))) or 0

    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)

    def new_since(sev: str) -> int:
        return db.scalar(select(func.count(Finding.id)).where(
            Finding.organization_id == org_id, Finding.severity == sev,
            Finding.status.in_(ACTIVE_STATUSES),
            Finding.first_seen_at >= day_ago)) or 0

    crit, high = open_count("Critical"), open_count("High")
    return {
        "critical_open": crit,
        "high_open": high,
        "critical_delta_24h": new_since("Critical"),
        "high_delta_24h": new_since("High"),
        "total_open": db.scalar(select(func.count(Finding.id)).where(
            Finding.organization_id == org_id,
            Finding.status.in_(ACTIVE_STATUSES))) or 0,
    }


def _devices_needing_attention(db: Session, org_id: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    devices = list(db.scalars(select(Device).where(Device.organization_id == org_id)))
    out: list[dict] = []
    for d in devices:
        latest = db.scalar(select(Analysis).where(Analysis.device_id == d.id)
                           .order_by(Analysis.created_at.desc()).limit(1))
        reasons: list[str] = []
        if latest and latest.status == AnalysisStatus.failed:
            reasons.append("last scan failed")
        if d.latest_grade in ("D", "F"):
            reasons.append(f"grade {d.latest_grade}")
        if latest and latest.critical_count > 0:
            reasons.append(f"{latest.critical_count} critical")
        sched = db.scalar(select(Schedule).where(Schedule.device_id == d.id))
        if sched and sched.enabled and sched.next_run_at and sched.next_run_at < now:
            reasons.append("scan overdue")
        if reasons:
            out.append({
                "device_id": d.id, "serial": d.serial, "model": d.model,
                "friendly_name": d.friendly_name, "grade": d.latest_grade,
                "score": d.latest_score, "reasons": reasons,
            })
    out.sort(key=lambda r: r["score"])
    return out[:25]


def _recent_activity(db: Session, org_id: str) -> list[dict]:
    rows = db.scalars(select(AuditLog).where(AuditLog.organization_id == org_id)
                      .order_by(AuditLog.created_at.desc()).limit(15))
    return [{
        "action": r.action, "resource_type": r.resource_type,
        "resource_id": r.resource_id, "user_email": r.user_email,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]


def _compliance(db: Session, org_id: str) -> dict[str, float]:
    """Per-framework pass rate = share of scanned devices with no open finding
    mapped to that framework.
    """
    scanned = [d for d in db.scalars(select(Device).where(
        Device.organization_id == org_id)) if d.latest_grade]
    total = len(scanned)
    frameworks = {fw: set() for fw in DEFAULT_FRAMEWORKS}

    open_findings = db.scalars(select(Finding).where(
        Finding.organization_id == org_id, Finding.status.in_(ACTIVE_STATUSES)))
    for f in open_findings:
        for fw in (f.compliance or {}).keys():
            frameworks.setdefault(fw, set()).add(f.device_id)

    if total == 0:
        return {fw: 100.0 for fw in frameworks}
    return {fw: round(100.0 * (total - len(failing)) / total, 1)
            for fw, failing in frameworks.items()}


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(user: User = Depends(current_user),
              db: Session = Depends(get_db)) -> DashboardResponse:
    org_id = user.organization_id
    return DashboardResponse(
        fleet_posture=_fleet_posture(db, org_id),
        findings_funnel=_findings_funnel(db, org_id),
        devices_needing_attention=_devices_needing_attention(db, org_id),
        recent_activity=_recent_activity(db, org_id),
        compliance=_compliance(db, org_id),
    )
