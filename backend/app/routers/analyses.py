"""TSR upload and analysis endpoints.

Upload flow:
    1. Enforce plan limits and file-size limits.
    2. Validate the TSR serial against the pre-registered device serial.
    3. Mark the device as configured and update its model/firmware.
    4. Persist the raw TSR to object storage and a ``Tsr`` row.
    5. Queue an ``Analysis`` and dispatch the Celery task. In environments
       without a broker the analysis may also be run inline via
       ``run_analysis_inline`` for synchronous responses.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import (
    User, Role, Customer, Device, Tsr, Analysis, AnalysisStatus,
)
from ..schemas import AnalysisSummary, AnalysisDetail
from ..security import current_user, require_role
from ..storage import save_tsr
from ..tasks import dispatch_analysis
from .. import audit

from firewallguard.tsr.parser import parse_tsr

router = APIRouter(prefix="/api/v1", tags=["analysis"])
settings = get_settings()


def _build_device_license_info(device):
    """Populate license dunder fields on a Device row from its cached license_info."""
    from datetime import datetime as _dt, timezone as _tz
    li = getattr(device, "license_info", None)
    if not li or not isinstance(li, dict):
        device.license_bundle = ""
        device.license_expiry = None
        device.license_days_remaining = None
        return
    now = _dt.now(_tz.utc)
    is_trial = li.get("is_trial", False)
    expired = False
    exp_str = li.get("expires_at")
    if exp_str:
        try:
            device.license_expiry = _dt.fromisoformat(exp_str)
            delta_seconds = (device.license_expiry - now).total_seconds()
            if delta_seconds >= 86400:
                device.license_days_remaining = int(delta_seconds // 86400)
            elif delta_seconds >= 3600:
                device.license_days_remaining = int(delta_seconds // 3600)
            elif delta_seconds >= 0:
                device.license_days_remaining = int(delta_seconds // 60)
            else:
                device.license_days_remaining = 0
                expired = True
        except Exception:
            device.license_expiry = None
            device.license_days_remaining = None
    else:
        device.license_expiry = None
        device.license_days_remaining = None

    # Build the bundle label: always one of "Active", "Active (Trial)",
    # "Expired", "Expired (Trial)", or "Tier-N".
    if expired:
        device.license_bundle = "Expired (Trial)" if is_trial else "Expired"
    elif li.get("tier"):
        device.license_bundle = f"Tier-{li.get('tier')}"
    elif is_trial:
        device.license_bundle = "Active (Trial)"
    else:
        device.license_bundle = "Active"


@router.post("/customers/{customer_id}/tsrs",
             response_model=AnalysisSummary, status_code=status.HTTP_202_ACCEPTED)
async def upload_tsr(customer_id: str,
                     request: Request,
                     file: UploadFile = File(...),
                     device_id: str | None = None,
                     user: User = Depends(require_role(Role.analyst)),
                     db: Session = Depends(get_db)) -> Analysis:
    """Upload a TSR for a pre-registered device.

    A ``device_id`` is required. The serial parsed from the TSR must match the
    registered device serial exactly. On success the device is marked configured
    and its model/firmware are updated from the TSR.
    """
    customer = db.get(Customer, customer_id)
    if customer is None or customer.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    if not device_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="device_id query parameter is required. Register the device first.")

    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.customer_id != customer_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Device does not belong to this customer.")

    raw = await file.read()
    if len(raw) > settings.max_tsr_size_mb * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"TSR exceeds {settings.max_tsr_size_mb} MB limit")
    text = raw.decode("utf-8", errors="replace")

    # Parse just enough to validate the serial.
    snapshot = parse_tsr(text, file.filename or "tsr")
    system = snapshot.get("system", {})
    tsr_serial = system.get("serial") or ""

    # Serial validation: TSR must belong to the registered device.
    if not tsr_serial or tsr_serial != device.serial:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Serial mismatch. The TSR reports serial '{tsr_serial or 'N/A'}', "
                                   f"but the registered device has serial '{device.serial}'.")
    # Update device model/firmware from the TSR and mark as configured.
    device.model = system.get("model", device.model)
    device.firmware = system.get("firmware", device.firmware)
    device.connection_method = "manual"
    device.configured = True
    device.was_ever_configured = True
    db.commit()

    storage_key = save_tsr(user.organization_id, device.id, file.filename or "tsr.txt", raw,
                           region=user.organization.region)
    tsr = Tsr(organization_id=user.organization_id, device_id=device.id,
              filename=file.filename or "tsr.txt", storage_key=storage_key,
              size_bytes=len(raw), uploaded_by=user.id)
    db.add(tsr)
    db.flush()

    analysis = Analysis(organization_id=user.organization_id, device_id=device.id,
                        tsr_id=tsr.id, status=AnalysisStatus.queued)
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    audit.log_action(db, organization_id=user.organization_id, action=audit.TSR_UPLOADED,
                     resource_type="tsr", resource_id=tsr.id, user=user, request=request,
                     after={"filename": tsr.filename, "device_id": device.id})

    # Enforce per-device TSR retention (keep latest 10).
    from ..tasks import enforce_tsr_retention
    enforce_tsr_retention(db, device.id)

    dispatch_analysis(analysis.id)
    return analysis


@router.get("/devices/{device_id}/analyses", response_model=list[AnalysisSummary])
def list_analyses(device_id: str,
                  user: User = Depends(current_user),
                  db: Session = Depends(get_db)) -> list[Analysis]:
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return list(db.scalars(
        select(Analysis).where(Analysis.device_id == device_id)
        .order_by(Analysis.created_at.desc())))


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: str,
                 user: User = Depends(current_user),
                 db: Session = Depends(get_db)) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None or analysis.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")
    return analysis
