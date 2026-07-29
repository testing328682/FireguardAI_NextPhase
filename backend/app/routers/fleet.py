"""Drift history and MSP fleet-overview endpoints."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Device, Customer, Analysis, AnalysisStatus, DriftEvent
from ..schemas import DriftEventOut, FleetSummary, FleetDeviceRow, DriftCompareResponse
from ..security import current_user

from firewallguard.analytics.drift import detect_drift

router = APIRouter(prefix="/api/v1", tags=["drift", "fleet"])


def _fp(f: dict) -> str:
    return f"{f.get('rule_id','')}::{f.get('object_type','')}::{f.get('object_name','')}"


@router.get("/devices/{device_id}/drift", response_model=list[DriftEventOut])
def device_drift(device_id: str,
                 user: User = Depends(current_user),
                 db: Session = Depends(get_db)) -> list[DriftEvent]:
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return list(db.scalars(
        select(DriftEvent).where(DriftEvent.device_id == device_id)
        .order_by(DriftEvent.created_at.desc())))


@router.get("/devices/{device_id}/compare", response_model=DriftCompareResponse)
def compare_analyses(device_id: str,
                     previous: str = Query(...), current: str = Query(...),
                     user: User = Depends(current_user),
                     db: Session = Depends(get_db)) -> DriftCompareResponse:
    """Diff two analyses on a device: new/resolved findings and config changes."""
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    def _load(aid: str) -> Analysis:
        a = db.get(Analysis, aid)
        if a is None or a.organization_id != user.organization_id or a.device_id != device_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Analysis not found for this device")
        return a

    prev, curr = _load(previous), _load(current)
    prev_findings = (prev.result_json or {}).get("findings", [])
    curr_findings = (curr.result_json or {}).get("findings", [])
    prev_keys = {_fp(f) for f in prev_findings}
    curr_keys = {_fp(f) for f in curr_findings}

    new = [f for f in curr_findings if _fp(f) not in prev_keys]
    resolved = [f for f in prev_findings if _fp(f) not in curr_keys]

    config_changes: list[dict] = []
    prev_snap = (prev.result_json or {}).get("snapshot")
    curr_snap = (curr.result_json or {}).get("snapshot")
    if prev_snap and curr_snap:
        config_changes = detect_drift(prev_snap, curr_snap).get("alerts", [])

    sev_counts: dict[str, int] = {}
    for f in new:
        sev_counts[f.get("severity", "Info")] = sev_counts.get(f.get("severity", "Info"), 0) + 1

    return DriftCompareResponse(
        previous_analysis_id=previous, current_analysis_id=current,
        new_findings=new, resolved_findings=resolved,
        config_changes=config_changes, severity_counts=sev_counts)


@router.get("/fleet", response_model=FleetSummary)
def fleet_overview(user: User = Depends(current_user),
                   db: Session = Depends(get_db)) -> FleetSummary:
    """Aggregate posture across every device in the organization.

    Designed for MSP dashboards: one row per managed device, plus roll-up
    statistics (average score, grade distribution, devices with critical
    findings, devices on vulnerable firmware).
    """
    devices = list(db.scalars(
        select(Device).where(Device.organization_id == user.organization_id)))
    customers = {c.id: c.name for c in db.scalars(
        select(Customer).where(Customer.organization_id == user.organization_id))}

    rows: list[FleetDeviceRow] = []
    grade_dist: dict[str, int] = defaultdict(int)
    score_sum = 0.0
    with_critical = 0
    vuln_fw = 0

    for d in devices:
        latest = db.scalar(
            select(Analysis).where(Analysis.device_id == d.id,
                                   Analysis.status == AnalysisStatus.complete)
            .order_by(Analysis.created_at.desc()).limit(1))
        if latest is None:
            continue
        score_sum += latest.score
        grade_dist[latest.grade] += 1
        if latest.critical_count > 0:
            with_critical += 1
        fw = (latest.result_json or {}).get("firmware_intelligence", {})
        if fw.get("advisory_count", 0) > 0:
            vuln_fw += 1
        rows.append(FleetDeviceRow(
            device_id=d.id, customer_id=d.customer_id,
            customer_name=customers.get(d.customer_id, "-"),
            serial=d.serial, model=d.model, firmware=d.firmware,
            score=latest.score, grade=latest.grade,
            critical_count=latest.critical_count, high_count=latest.high_count))

    n = len(rows)
    rows.sort(key=lambda r: r.score)
    return FleetSummary(
        device_count=n,
        average_score=round(score_sum / n, 1) if n else 0.0,
        grade_distribution=dict(grade_dist),
        devices_with_critical=with_critical,
        vulnerable_firmware_devices=vuln_fw,
        rows=rows)
