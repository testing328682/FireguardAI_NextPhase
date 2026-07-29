"""Customer (managed-client) and device management endpoints.

All queries filter on the authenticated user's ``organization_id`` so a tenant
can never read or mutate another tenant's data. MSP organizations may hold many
customers; a direct customer organization typically holds one.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, Customer, Device, DeviceCredential, PlanTier
from ..schemas import (
    CustomerCreate, CustomerOut, CustomerUpdate, DeviceOut,
    DeviceRegisterRequest, DeviceLicenseChange, DeviceConnectRequest, DeviceConnectResponse,
    DeviceDetailOut, TsrHistoryItem, ConnectStep,
    DeviceCredentialOut, DeviceCredentialUpdate, CredentialTestResult,
    ApiConnectionLogOut,
)
from fastapi import Response
from ..security import current_user, require_role
from ..crypto import encrypt, decrypt
from ..sonicos import SonicOSClient, SonicOSError
from ..tasks import dispatch_pull, ingest_tsr_bytes, log_api_connection
from .. import audit, billing, api_flow

router = APIRouter(prefix="/api/v1", tags=["tenancy"])


@router.get("/customers", response_model=list[CustomerOut])
def list_customers(user: User = Depends(current_user),
                   db: Session = Depends(get_db)) -> list[Customer]:
    customers = list(db.scalars(
        select(Customer).where(Customer.organization_id == user.organization_id)))
    # Inject device_count into each customer for the response
    if customers:
        from collections import Counter
        cids = [c.id for c in customers]
        counts = Counter()
        for row in db.execute(select(Device.customer_id, func.count(Device.id))
                              .where(Device.customer_id.in_(cids))
                              .group_by(Device.customer_id)):
            counts[row[0]] = row[1]
        for c in customers:
            c.device_count = counts.get(c.id, 0)  # type: ignore[attr-defined]
    return customers


@router.post("/customers", response_model=CustomerOut, status_code=status.HTTP_201_CREATED)
def create_customer(body: CustomerCreate, request: Request,
                    user: User = Depends(require_role(Role.admin)),
                    db: Session = Depends(get_db)) -> Customer:
    customer = Customer(organization_id=user.organization_id, name=body.name,
                        location=body.location, business_unit=body.business_unit,
                        contact_email=body.contact_email,
                        primary_contact=body.primary_contact, phone=body.phone,
                        country=body.country, timezone=body.timezone, notes=body.notes)
    db.add(customer)
    db.commit()
    db.refresh(customer)
    audit.log_action(db, organization_id=user.organization_id, action=audit.CUSTOMER_CREATED,
                     resource_type="customer", resource_id=customer.id, user=user,
                     request=request, after={"name": customer.name})
    return customer


def _owned_customer(db: Session, customer_id: str, user: User) -> Customer:
    c = db.get(Customer, customer_id)
    if c is None or c.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
    return c


@router.get("/customers/{customer_id}", response_model=CustomerOut)
def get_customer(customer_id: str, user: User = Depends(current_user),
                 db: Session = Depends(get_db)) -> Customer:
    return _owned_customer(db, customer_id, user)


@router.patch("/customers/{customer_id}", response_model=CustomerOut)
def update_customer(customer_id: str, body: CustomerUpdate, request: Request,
                    user: User = Depends(require_role(Role.admin)),
                    db: Session = Depends(get_db)) -> Customer:
    customer = _owned_customer(db, customer_id, user)
    for field in ("name", "location", "business_unit", "contact_email", "notes"):
        val = getattr(body, field)
        if val is not None:
            setattr(customer, field, val)
    db.commit()
    db.refresh(customer)
    audit.log_action(db, organization_id=user.organization_id, action="customer.updated",
                     resource_type="customer", resource_id=customer.id, user=user, request=request)
    return customer


@router.delete("/customers/{customer_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_customer(customer_id: str, user: User = Depends(require_role(Role.admin)),
                    db: Session = Depends(get_db)):
    customer = _owned_customer(db, customer_id, user)
    if db.scalar(select(Device).where(Device.customer_id == customer_id)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Customer has devices; remove them first")
    db.delete(customer)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(customer_id: str | None = None,
                 decommissioned: bool = False,
                 user: User = Depends(current_user),
                 db: Session = Depends(get_db)) -> list[Device]:
    stmt = select(Device).where(Device.organization_id == user.organization_id)
    if customer_id:
        stmt = stmt.where(Device.customer_id == customer_id)
    # By default, exclude decommissioned devices.  Pass ?decommissioned=true
    # to list only decommissioned devices (for the Decommissioned view).
    stmt = stmt.where(Device.decommissioned.is_(decommissioned))
    devices = list(db.scalars(stmt))

    # Backfill live severity counts from findings so the counts always
    # reflect the current state (findings may be resolved between analyses).
    device_ids = [d.id for d in devices]
    if device_ids:
        from app.models import Finding
        rows = db.execute(
            select(
                Finding.device_id,
                func.sum(case((Finding.severity == "Critical", 1), else_=0)).label("crit"),
                func.sum(case((Finding.severity == "High", 1), else_=0)).label("high"),
                func.sum(case((Finding.severity == "Medium", 1), else_=0)).label("med"),
                func.sum(case((Finding.severity == "Low", 1), else_=0)).label("low"),
            )
            .where(
                Finding.device_id.in_(device_ids),
                Finding.status.in_(("open", "acknowledged", "in_progress")),
            )
            .group_by(Finding.device_id)
        ).all()
        live: dict[str, tuple] = {}
        for row in rows:
            did, crit, high, med, low = row
            live[did] = (crit or 0, high or 0, med or 0, low or 0)
        for d in devices:
            counts = live.get(d.id)
            if counts is not None:
                crit, high, med, low = counts
                d.critical_count = crit or 0
                d.high_count = high or 0
                d.medium_count = med or 0
                d.low_count = low or 0

    # Populate license bundle info via direct lookup (avoid relationship issues)
    from datetime import datetime as _dt, timezone as _tz
    from ..models import LicensePurchase as LPM
    now = _dt.now(_tz.utc)
    lp_ids = [d.license_purchase_id for d in devices if d.license_purchase_id]
    lp_map: dict[str, LPM] = {}
    if lp_ids:
        for lp in db.scalars(select(LPM).where(LPM.id.in_(lp_ids))):
            lp_map[lp.id] = lp
    for d in devices:
        lp = lp_map.get(d.license_purchase_id) if d.license_purchase_id else None
        li = d.license_info if isinstance(d.license_info, dict) else {}
        is_trial = li.get("is_trial", False)
        if lp is None and li:
            from .analyses import _build_device_license_info
            _build_device_license_info(d)
        elif lp is not None:
            d.license_expiry = lp.expires_at
            expired = False
            if lp.expires_at:
                exp = lp.expires_at
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=_tz.utc)
                delta_seconds = (exp - now).total_seconds()
                if delta_seconds >= 86400:
                    d.license_days_remaining = int(delta_seconds // 86400)
                elif delta_seconds >= 3600:
                    d.license_days_remaining = int(delta_seconds // 3600)  # hours
                elif delta_seconds >= 0:
                    d.license_days_remaining = int(delta_seconds // 60)   # minutes
                else:
                    d.license_days_remaining = 0
                    expired = True
            # Build the bundle label: "Active", "Active (Trial)",
            # "Expired", "Expired (Trial)", or "Tier-N".
            if expired:
                d.license_bundle = "Expired (Trial)" if is_trial else "Expired"
            elif is_trial:
                d.license_bundle = "Active (Trial)"
            elif lp.tier:
                d.license_bundle = f"Tier-{lp.tier}"
            else:
                d.license_bundle = "Active"

    # When listing decommissioned devices, hide any whose assigned license
    # has already expired — the license is no longer valid, so the device
    # should not appear in the decommissioned view.
    if decommissioned:
        devices = [d for d in devices
                   if not (d.license_expiry and d.license_days_remaining == 0
                           and d.license_bundle in ("Expired", "Expired (Trial)"))]

    return devices


@router.get("/devices/{device_id}", response_model=DeviceOut)
def get_device(device_id: str,
               user: User = Depends(current_user),
               db: Session = Depends(get_db)) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    from .analyses import _build_device_license_info
    _build_device_license_info(device)
    return device


@router.get("/devices/{device_id}/detail", response_model=DeviceDetailOut)
def get_device_detail(device_id: str,
                      user: User = Depends(current_user),
                      db: Session = Depends(get_db)):
    """Return device details with TSR upload history and analysis results."""
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    from .analyses import _build_device_license_info
    _build_device_license_info(device)

    # Fetch TSRs with their analysis (if available).  Favorites first,
    # then by upload date descending.
    from ..models import Tsr as TsrModel, Analysis as AnalysisModel
    tsr_rows = db.scalars(
        select(TsrModel).where(TsrModel.device_id == device_id)
        .order_by(TsrModel.favorite.desc(), TsrModel.uploaded_at.desc())).all()
    tsr_items: list = []
    for tsr in tsr_rows:
        analysis = db.scalar(
            select(AnalysisModel).where(AnalysisModel.tsr_id == tsr.id)
            .order_by(AnalysisModel.created_at.desc()).limit(1))
        tsr_items.append({
            "id": tsr.id, "filename": tsr.filename,
            "size_bytes": tsr.size_bytes, "uploaded_at": tsr.uploaded_at,
            "uploaded_by": tsr.uploaded_by or "",
            "favorite": bool(tsr.favorite),
            "analysis_id": analysis.id if analysis else None,
            "analysis_status": analysis.status.value if analysis else None,
            "analysis_score": analysis.score if analysis else None,
            "analysis_grade": analysis.grade if analysis else None,
        })

    result = {
        **{k: getattr(device, k) for k in DeviceOut.model_fields},
        "tsr_count": len(tsr_rows),
        "tsrs": tsr_items,
    }
    return result


@router.patch("/tsrs/{tsr_id}/favorite")
def toggle_tsr_favorite(tsr_id: str, body: dict,
                         user: User = Depends(require_role(Role.analyst)),
                         db: Session = Depends(get_db)):
    """Toggle the favorite flag on a TSR.  At most 5 TSRs per device may be
    favorited at once; the endpoint returns 400 if the limit would be exceeded
    when setting ``favorite`` to True."""
    from ..models import Tsr as TsrModel
    from sqlalchemy import func as sqlfunc

    tsr = db.get(TsrModel, tsr_id)
    if tsr is None or tsr.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TSR not found")

    want = bool(body.get("favorite", False))
    if want:
        current_favs = db.scalar(select(sqlfunc.count(TsrModel.id)).where(
            TsrModel.device_id == tsr.device_id,
            TsrModel.favorite.is_(True))) or 0
        if not tsr.favorite:
            current_favs += 1  # this TSR would become a new favorite
        if current_favs > 5:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Maximum 5 favorites per device.")
    tsr.favorite = want
    db.commit()
    return {"id": tsr.id, "favorite": tsr.favorite}


@router.delete("/tsrs/{tsr_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tsr(tsr_id: str,
               user: User = Depends(require_role(Role.analyst)),
               db: Session = Depends(get_db)):
    """Delete a TSR and its associated analysis and findings."""
    from ..models import Tsr as TsrModel, Analysis as AnalysisModel, Finding
    from sqlalchemy import delete as sqla_delete

    tsr = db.get(TsrModel, tsr_id)
    if tsr is None or tsr.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TSR not found")

    # Delete findings first, then analysis, then TSR.
    db.execute(sqla_delete(Finding).where(
        Finding.analysis_id.in_(
            select(AnalysisModel.id).where(AnalysisModel.tsr_id == tsr_id)
        )
    ))
    db.execute(sqla_delete(AnalysisModel).where(AnalysisModel.tsr_id == tsr_id))
    db.delete(tsr)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/tsrs/{tsr_id}/download")
def download_tsr(tsr_id: str,
                 user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    """Download the original TSR file for a device in the user's organization."""
    from ..models import Tsr as TsrModel
    from ..storage import load_tsr as storage_load
    from fastapi.responses import Response as FastResponse

    tsr = db.get(TsrModel, tsr_id)
    if tsr is None or tsr.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TSR not found")

    try:
        raw = storage_load(tsr.storage_key)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="TSR file no longer exists on the server")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to read TSR from storage")

    filename = tsr.filename or f"tsr-{tsr_id[:8]}.txt"
    return FastResponse(
        content=raw,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/devices", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def register_device(body: DeviceRegisterRequest, request: Request,
                    user: User = Depends(require_role(Role.analyst)),
                    db: Session = Depends(get_db)) -> Device:
    """Register a device by name and serial number. Each device consumes one license.

    A license represents the right to register and continuously analyze a
    device — it carries no analysis-frequency dimension. The device is created
    in an unconfigured state; connectivity (TSR upload or API connection) is a
    separate step that validates the serial matches.
    """
    from sqlalchemy import func as sqlfunc
    from datetime import datetime as dt, timezone as tz
    from ..models import LicensePurchase as LPModel, Plan as PlanModel

    customer = db.get(Customer, body.customer_id)
    if customer is None or customer.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    # Reject duplicate serial within the same organization.
    existing = db.scalar(select(Device).where(
        Device.organization_id == user.organization_id,
        Device.serial == body.serial))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"A device with serial '{body.serial}' already exists.")

    org = user.organization
    now_utc = dt.now(tz.utc)
    purchase_id = body.license_purchase_id

    if purchase_id:
        lp = db.get(LPModel, purchase_id)
        if lp is None or lp.organization_id != org.id:
            raise HTTPException(status_code=400, detail="Invalid license purchase")

        expires = lp.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=tz.utc)
        if expires is not None and expires <= now_utc:
            raise HTTPException(status_code=402, detail="This license has expired")

        plan = db.get(PlanModel, org.plan_id) if org.plan_id else None
        plan_type = plan.plan_type if plan else "professional"
        if plan_type == "msp" and lp.tier:
            total_licenses = lp.count * int(lp.tier)
        else:
            total_licenses = lp.count

        consumed_from_this = db.scalar(select(sqlfunc.count(Device.id)).where(
            Device.organization_id == org.id,
            Device.license_purchase_id == purchase_id)) or 0
        remaining = max(0, total_licenses - consumed_from_this)
        if remaining <= 0:
            raise HTTPException(status_code=402,
                detail="No licenses remaining in this purchase. Select another bundle.")

        # Determine if this is a trial (free-plan) license.
        plan = db.get(PlanModel, org.plan_id) if org.plan_id else None
        is_trial = (plan is None or plan.name == "Free") and org.plan == PlanTier.free
        lic_info = {
            "tier": lp.tier,
            "total_devices": lp.total_devices,
            "purchased_at": lp.purchased_at.isoformat() if lp.purchased_at else None,
            "expires_at": lp.expires_at.isoformat() if lp.expires_at else None,
            "is_trial": is_trial,
        }
        device = Device(organization_id=org.id, customer_id=body.customer_id,
                        serial=body.serial, friendly_name=body.friendly_name,
                        configured=False,
                        license_purchase_id=purchase_id,
                        license_info=lic_info)
    else:
        # No bundle selected — enforce the plan's flat device-count limit.
        billing.enforce_device_limit(db, org)
        device = Device(organization_id=org.id, customer_id=body.customer_id,
                        serial=body.serial, friendly_name=body.friendly_name,
                        configured=False)

    db.add(device)
    db.commit()
    db.refresh(device)

    audit.log_action(db, organization_id=org.id, action=audit.DEVICE_CREATED,
                     resource_type="device", resource_id=device.id, user=user,
                     request=request, after={"serial": device.serial,
                         "friendly_name": device.friendly_name})
    return device


def _run_api_flow(db: Session, hostname: str, port: int, username: str,
                  password: str, verify_tls: bool):
    """Fetch a TSR over the SonicOS API using the active configurable flow, or
    the legacy hardcoded client when no config is active.

    Returns ``(ok, raw_bytes, version, steps, error_kind, http_status, message)``.
    """
    active = api_flow.get_active_config(db)
    if active is not None:
        cfg = api_flow.config_to_dict(active)
        ctx = {"hostname": hostname, "ip": hostname, "port": port,
               "username": username, "password": password, "verify_tls": verify_tls}
        res = api_flow.run_flow(cfg, ctx)
        steps = [{
            "step": t["step"],
            "status": "ok" if t["success"] else "failed",
            "detail": (f"{t['method']} {t['url']} → "
                       f"{t['status_code'] if t['status_code'] is not None else '—'} "
                       f"({t['elapsed_ms']} ms)"
                       + (f" · {t['error']}" if t.get('error') else "")),
        } for t in res["traces"]]
        if not res["success"]:
            return (False, b"", {}, steps, "flow_failed", None,
                    res["error"] or "API flow failed")
        raw = (res.get("tsr_text") or "").encode("utf-8")
        if not raw.strip():
            return (False, b"", {}, steps, "bad_response", None,
                    "Flow succeeded but no TSR was captured — mark a step as the TSR step.")
        return (True, raw, dict(res.get("extracted", {})), steps, None, None, "")

    # Legacy fallback: hardcoded SonicOS client.
    client = SonicOSClient(hostname, port, username, password, verify_tls=verify_tls)
    steps = []
    try:
        version = client.test_connection()
        steps.append({"step": "Authenticate", "status": "ok",
                      "detail": "SonicOS API authentication succeeded"})
    except SonicOSError as exc:
        steps.append({"step": "Authenticate", "status": "failed", "detail": exc.detail or str(exc)})
        return (False, b"", {}, steps, exc.kind, exc.status_code, str(exc))
    try:
        raw = client.export_tech_support()
        steps.append({"step": "Export TSR", "status": "ok",
                      "detail": f"Downloaded {len(raw):,} bytes"})
    except SonicOSError as exc:
        steps.append({"step": "Export TSR", "status": "failed", "detail": exc.detail or str(exc)})
        return (False, b"", {}, steps, exc.kind, exc.status_code, str(exc))
    finally:
        try:
            client.logout()
        except Exception:  # noqa: BLE001
            pass
    return (True, raw, version, steps, None, None, "")


def _identify_from_tsr(raw: bytes) -> tuple[str, str, str]:
    """Best-effort (serial, model, firmware) from a TSR (GUI or API format)."""
    try:
        from firewallguard.tsr.normalize import normalize_tsr
        from firewallguard.tsr.reader import TSRDocument
        from firewallguard.tsr.parser import parse_system
        text, _fmt = normalize_tsr(raw.decode("utf-8", "replace"))
        info = parse_system(TSRDocument(text))
        return (str(info.get("serial") or ""), str(info.get("model") or ""),
                str(info.get("firmware") or ""))
    except Exception:  # noqa: BLE001 - identification is best effort
        return "", "", ""


@router.post("/devices/connect", response_model=DeviceConnectResponse)
def connect_device(body: DeviceConnectRequest, request: Request,
                   user: User = Depends(require_role(Role.analyst)),
                   db: Session = Depends(get_db)) -> DeviceConnectResponse:
    """Connect to a firewall over the SonicOS API: authenticate, download the
    Tech Support Report, and analyse it — no manual upload required.

    Modes (exactly one of):
      * ``device_id``  — connect a pre-registered device; the TSR serial must
        match the registered serial.
      * ``customer_id`` — register-and-connect a new firewall; the device is
        created from the TSR's serial / model / firmware.

    Returns per-step status (``steps``) plus ``error_kind`` / ``http_status`` on
    failure so the UI can explain exactly why a connection succeeded or failed.
    """
    steps: list[dict] = []

    def add(step: str, status_: str, detail: str = "") -> None:
        steps.append({"step": step, "status": status_, "detail": detail})

    def mark_failed(dev: Device | None, message: str) -> None:
        if dev is not None:
            dev.last_connection_status = "failed"
            dev.last_connection_error = message[:500]
            dev.last_connection_at = datetime.now(timezone.utc)
            db.commit()

    def fail(message: str, *, kind: str | None = None, http_status: int | None = None,
             dev: Device | None = None) -> DeviceConnectResponse:
        return DeviceConnectResponse(
            connection_status="failed", message=message, error_kind=kind,
            http_status=http_status, steps=steps, device_id=dev.id if dev else None)

    # Resolve target -----------------------------------------------------
    device: Device | None = None
    if body.device_id:
        device = db.get(Device, body.device_id)
        if device is None or device.organization_id != user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    elif body.customer_id:
        cust = db.get(Customer, body.customer_id)
        if cust is None or cust.organization_id != user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Provide device_id (existing device) or customer_id (new device)")

    now = datetime.now(timezone.utc)

    # Steps 1-2: run the active configurable flow (auth -> export ...), or the
    # legacy hardcoded client when no config is active.
    ok, raw, version, flow_steps, kind, http_status, message = _run_api_flow(
        db, body.hostname, body.port, body.username, body.password, body.verify_tls)
    steps.extend(flow_steps)
    if not ok:
        mark_failed(device, message)
        return fail(message, kind=kind, http_status=http_status, dev=device)

    # Step 3: identify the firewall (TSR first, /version as fallback) -----
    serial, model, firmware = _identify_from_tsr(raw)
    serial = serial or str(version.get("serial") or version.get("serial_number") or "")
    model = model or str(version.get("model") or "")
    firmware = firmware or str(version.get("firmware_version") or version.get("version") or "")
    add("Identify", "ok" if serial else "warn",
        f"Serial {serial or 'unknown'} · {model or 'model n/a'} · {firmware or 'firmware n/a'}")

    # Step 4: resolve / register the device ------------------------------
    if device is not None:
        if serial and device.serial and serial != device.serial:
            add("Verify serial", "failed",
                f"Expected '{device.serial}', firewall reports '{serial}'")
            mark_failed(device, "serial mismatch")
            return fail(f"Serial mismatch. Expected '{device.serial}', got '{serial}'.",
                        kind="serial_mismatch", dev=device)
    else:
        existing = None
        if serial:
            existing = db.scalar(select(Device).where(
                Device.organization_id == user.organization_id, Device.serial == serial))
        if existing is not None:
            device = existing
        else:
            billing.enforce_device_limit(db, user.organization)
            device = Device(organization_id=user.organization_id,
                            customer_id=body.customer_id,
                            serial=serial or f"api-{body.hostname}",
                            friendly_name=body.friendly_name or model or body.hostname,
                            configured=False)
            db.add(device)
            db.flush()
        add("Register device", "ok", f"Serial {device.serial}")

    # Persist device metadata + encrypted credentials --------------------
    device.model = model or device.model
    device.firmware = firmware or device.firmware
    device.connection_method = "api"
    device.configured = True
    device.was_ever_configured = True
    device.last_connection_status = "ok"
    device.last_connection_at = now
    device.last_connection_error = ""

    cred = db.scalar(select(DeviceCredential).where(DeviceCredential.device_id == device.id))
    if cred is None:
        cred = DeviceCredential(organization_id=user.organization_id, device_id=device.id)
        db.add(cred)
    cred.hostname = body.hostname
    cred.port = body.port
    cred.username = body.username
    cred.encrypted_password = encrypt(body.password) if body.save_password else ""
    cred.last_test_status = "ok"
    cred.last_test_at = now
    db.commit()

    log_api_connection(db, device_id=device.id,
                        organization_id=user.organization_id,
                        trigger="api_connect", host=body.hostname,
                        port=body.port, endpoint="TSR export",
                        http_status=200, response_time_ms=None,
                        success=True,
                        connected_serial=serial,
                        registered_serial=device.serial or "",
                        result_summary="Connected. TSR downloaded and analyzed.")

    audit.log_action(db, organization_id=user.organization_id, action=audit.DEVICE_CONNECTED,
                     resource_type="device", resource_id=device.id, user=user, request=request,
                     after={"hostname": body.hostname, "serial": device.serial})

    # Step 5: analyse the downloaded TSR (same path as an uploaded TSR) ---
    analysis_id = ingest_tsr_bytes(device.id, raw, uploaded_by="api-connect")
    add("Analyze", "ok" if analysis_id else "failed",
        "Findings ready" if analysis_id else "Analysis could not be created")

    return DeviceConnectResponse(
        device_id=device.id, connection_status="ok",
        message="Connected. TSR downloaded and analyzed.",
        version=version, analysis_id=analysis_id, steps=steps)


@router.post("/devices/{device_id}/pull", response_model=DeviceConnectResponse)
def pull_device(device_id: str,
                user: User = Depends(require_role(Role.analyst)),
                db: Session = Depends(get_db)) -> DeviceConnectResponse:
    """Trigger an on-demand API pull for a configured device.

    Runs synchronously so the TSR is retrieved and analysed before the
    response returns — the caller sees the result immediately.  Scheduled
    pulls still go through Celery for throughput.
    """
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    cred = db.scalar(select(DeviceCredential).where(DeviceCredential.device_id == device_id))
    if cred is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Device has no saved API credentials")

    # Run inline so Pull Now is immediate and reliable.
    try:
        from ..tasks import pull_and_analyze
        result = pull_and_analyze(device_id, uploaded_by="api-pull")
    except Exception as exc:
        import logging
        logging.getLogger("firewallguard").error(
            "Pull Now failed for device %s: %s", device_id[:8], exc, exc_info=True)
        return DeviceConnectResponse(
            device_id=device_id, connection_status="failed",
            message=f"Pull failed: {exc}")
    if result is None:
        # Re-fetch to get the latest connection error.
        db.refresh(device)
        return DeviceConnectResponse(
            device_id=device_id, connection_status="failed",
            message=device.last_connection_error or "Pull failed. Check API Connection Logs for details.")
    return DeviceConnectResponse(device_id=device_id, connection_status="ok",
                                  message="TSR retrieved and analysis started.",
                                  analysis_id=result)


@router.patch("/devices/{device_id}", response_model=DeviceOut)
def update_device(device_id: str, body: dict,
                  user: User = Depends(require_role(Role.analyst)),
                  db: Session = Depends(get_db)):
    """Update device metadata (friendly name, TSR retrieve mode, analyze mode)."""
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if "friendly_name" in body:
        device.friendly_name = body["friendly_name"]
    if "connection_method" in body:
        method = body["connection_method"]
        if method not in ("manual", "api"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="connection_method must be 'manual' or 'api'")
        device.connection_method = method
    if "analyze_mode" in body:
        mode = body["analyze_mode"]
        if mode not in ("manual", "auto"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="analyze_mode must be 'manual' or 'auto'")
        device.analyze_mode = mode
        from ..models import Schedule as SchedModel
        from ..scheduler import compute_next_run as _next_run
        sched = db.scalar(select(SchedModel).where(SchedModel.device_id == device_id))
        if mode == "manual" and sched is not None:
            # Switching to manual: disable the schedule so scans stop.
            sched.enabled = False
            sched.next_run_at = None
        elif mode == "auto" and sched is not None:
            # Switching to auto: re-enable the schedule and set the next run.
            sched.enabled = True
            sched.next_run_at = _next_run(sched)
    db.commit()
    db.refresh(device)
    return device


@router.patch("/devices/{device_id}/license", response_model=DeviceOut)
def change_device_license(device_id: str, body: DeviceLicenseChange,
                          user: User = Depends(require_role(Role.analyst)),
                          db: Session = Depends(get_db)):
    """Reassign a device to a different license purchase.

    Releases the current license assignment (if any) and consumes one slot from
    the target purchase. Validates that the target purchase belongs to the same
    organization, has not expired, and still has remaining capacity.
    """
    from sqlalchemy import func as sqlfunc
    from datetime import datetime as dt, timezone as tz
    from ..models import LicensePurchase as LPModel, Plan as PlanModel

    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    org = user.organization
    new_purchase_id = body.license_purchase_id

    # Validate the target purchase exists and belongs to this org.
    lp = db.get(LPModel, new_purchase_id)
    if lp is None or lp.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="License purchase not found or does not belong to your organization.")

    now_utc = dt.now(tz.utc)

    # Check expiry.
    expires = lp.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=tz.utc)
    if expires is not None and expires <= now_utc:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail="The selected license has expired.")

    # Determine capacity.
    plan = db.get(PlanModel, org.plan_id) if org.plan_id else None
    plan_type = plan.plan_type if plan else "professional"
    if plan_type == "msp" and lp.tier:
        total_capacity = lp.count * int(lp.tier)
    else:
        total_capacity = lp.count

    # Count devices already consuming from this purchase, excluding the current
    # device (it may already be assigned to this purchase — that's a no-op that
    # we still allow so the UI can safely re-select the same bundle).
    consumed = db.scalar(select(sqlfunc.count(Device.id)).where(
        Device.organization_id == org.id,
        Device.license_purchase_id == new_purchase_id,
        Device.id != device_id)) or 0

    if consumed >= total_capacity:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail="No licenses remaining in this purchase. Select another bundle.")

    # Reassign.
    previous_purchase_id = device.license_purchase_id
    device.license_purchase_id = new_purchase_id
    # Determine if the new purchase is a trial or paid license.
    plan = db.get(PlanModel, org.plan_id) if org.plan_id else None
    new_is_trial = (plan is None or plan.name == "Free") and org.plan == PlanTier.free
    device.license_info = {
        "tier": lp.tier,
        "total_devices": lp.total_devices,
        "purchased_at": lp.purchased_at.isoformat() if lp.purchased_at else None,
        "expires_at": lp.expires_at.isoformat() if lp.expires_at else None,
        "is_trial": new_is_trial,
    }
    db.commit()
    db.refresh(device)

    # Populate the license dunder fields for the response.
    from .analyses import _build_device_license_info
    _build_device_license_info(device)

    audit.log_action(db, organization_id=org.id, action="device.license_changed",
                     resource_type="device", resource_id=device.id, user=user,
                     before={"license_purchase_id": previous_purchase_id or ""},
                     after={"license_purchase_id": new_purchase_id})
    return device


@router.patch("/devices/{device_id}/visibility", response_model=DeviceOut)
def update_device_visibility(device_id: str, body: dict,
                             user: User = Depends(require_role(Role.analyst)),
                             db: Session = Depends(get_db)):
    """Update device-level findings visibility (hidden severities)."""
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if "hidden_severities" in body:
        device.hidden_severities = body["hidden_severities"]
    db.commit()
    db.refresh(device)
    return device


# ── API connection logs ─────────────────────────────────────────────
@router.get("/devices/{device_id}/connection-logs",
            response_model=list[ApiConnectionLogOut])
def list_connection_logs(device_id: str,
                         limit: int = 50,
                         user: User = Depends(current_user),
                         db: Session = Depends(get_db)):
    """Return recent API connection attempts for a device (newest first)."""
    from ..models import ApiConnectionLog as ACLog
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return list(db.scalars(
        select(ACLog).where(ACLog.device_id == device_id)
        .order_by(ACLog.timestamp.desc()).limit(max(1, min(limit, 100)))))


# ── Device API credentials ────────────────────────────────────────────
@router.get("/devices/{device_id}/credentials", response_model=DeviceCredentialOut)
def get_device_credentials(device_id: str,
                           user: User = Depends(require_role(Role.analyst)),
                           db: Session = Depends(get_db)) -> DeviceCredentialOut:
    """Return saved API connection details for a device. The password is never
    included in the response — only ``has_password`` indicates whether one is
    stored."""
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    cred = db.scalar(select(DeviceCredential).where(DeviceCredential.device_id == device_id))
    if cred is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No saved credentials for this device")
    return DeviceCredentialOut(
        id=cred.id, device_id=cred.device_id, hostname=cred.hostname,
        port=cred.port, username=cred.username,
        has_password=bool(cred.encrypted_password),
        last_test_status=cred.last_test_status,
        last_test_at=cred.last_test_at,
    )


@router.put("/devices/{device_id}/credentials", response_model=CredentialTestResult)
def update_device_credentials(device_id: str, body: DeviceCredentialUpdate,
                              user: User = Depends(require_role(Role.analyst)),
                              db: Session = Depends(get_db)) -> CredentialTestResult:
    """Create or update and test API credentials for a device.

    Accepts a partial update; when credentials already exist and ``password``
    is omitted / empty the existing encrypted password is kept.  For a
    first-time setup (no saved credentials yet) a new ``DeviceCredential``
    row is created.

    The endpoint always tests the connection against the firewall and only
    persists on success.
    """
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    cred = db.scalar(select(DeviceCredential).where(DeviceCredential.device_id == device_id))

    # Resolve the values we will test with.
    if cred is not None:
        hostname = body.hostname or cred.hostname
        port = body.port if body.port is not None else cred.port
        username = body.username or cred.username
        password = body.password or decrypt(cred.encrypted_password)
    else:
        # First-time setup — all fields are required.
        if not body.hostname or not body.username or not body.password:
            return CredentialTestResult(
                success=False,
                message="Hostname, username, and password are required for first-time API setup.",
                steps=[],
            )
        hostname = body.hostname
        port = body.port if body.port is not None else 443
        username = body.username
        password = body.password

    if not password:
        return CredentialTestResult(
            success=False,
            message="No password available. Enter a password or save one first.",
            steps=[],
        )

    now = datetime.now(timezone.utc)

    # Test the credentials before saving.
    ok, raw, _version, steps, kind, http_status, message = _run_api_flow(
        db, hostname, port, username, password,
        verify_tls=False,  # testing — user can adjust TLS setting separately if needed
    )

    # Derive endpoint info from the last step trace.
    last_step = steps[-1] if steps else {}
    endpoint_url = last_step.get("detail", "").split(" → ")[0] if last_step.get("detail") else ""
    elapsed_ms = sum(s.get("elapsed_ms", 0) for s in steps) if all(isinstance(s, dict) for s in steps) else None

    if not ok:
        log_api_connection(db, device_id=device.id,
                            organization_id=user.organization_id,
                            trigger="test_connect", host=hostname, port=port,
                            endpoint=endpoint_url or "API connection test",
                            http_status=http_status,
                            response_time_ms=elapsed_ms,
                            success=False, error_message=message or "Connection test failed",
                            registered_serial=device.serial or "")
        return CredentialTestResult(
            success=False,
            message=message or "Connection test failed",
            steps=[ConnectStep(step=s["step"], status=s["status"], detail=s.get("detail", ""))
                   for s in steps],
        )

    # Validate the firewall's serial number against the registered device.
    fw_serial = ""
    if raw and device.serial:
        fw_serial, _, _ = _identify_from_tsr(raw)
        if fw_serial and fw_serial != device.serial:
            log_api_connection(db, device_id=device.id,
                                organization_id=user.organization_id,
                                trigger="test_connect", host=hostname, port=port,
                                endpoint=endpoint_url or "API connection test",
                                http_status=200,
                                response_time_ms=elapsed_ms,
                                success=False,
                                error_message=f"Serial mismatch: registered '{device.serial}', connected '{fw_serial}'",
                                connected_serial=fw_serial,
                                registered_serial=device.serial or "")
            return CredentialTestResult(
                success=False,
                message=(
                    f"Serial number mismatch. This device is registered with "
                    f"serial '{device.serial}', but the connected firewall "
                    f"reports serial '{fw_serial}'. Please verify you are "
                    f"connecting to the correct firewall."
                ),
                steps=steps,
            )

    # Persist on success — create the row if this is a first-time setup.
    if cred is None:
        cred = DeviceCredential(organization_id=user.organization_id, device_id=device_id)
        db.add(cred)
    cred.hostname = hostname
    cred.port = port
    cred.username = username
    cred.encrypted_password = encrypt(password) if body.password else cred.encrypted_password
    cred.last_test_status = "ok"
    cred.last_test_at = now
    device.connection_method = "api"
    device.last_connection_status = "ok"
    device.last_connection_at = now
    device.last_connection_error = ""
    db.commit()

    log_api_connection(db, device_id=device.id,
                        organization_id=user.organization_id,
                        trigger="test_connect", host=hostname, port=port,
                        endpoint=endpoint_url or "API connection test",
                        http_status=200, response_time_ms=elapsed_ms,
                        success=True,
                        connected_serial=fw_serial,
                        registered_serial=device.serial or "",
                        result_summary="Connection successful. Credentials saved.")

    audit.log_action(db, organization_id=user.organization_id,
                     action="device.credentials_updated",
                     resource_type="device", resource_id=device.id, user=user,
                     after={"hostname": hostname})

    return CredentialTestResult(
        success=True,
        message="Connection successful. Credentials saved.",
        steps=[ConnectStep(step=s["step"], status=s["status"], detail=s.get("detail", ""))
               for s in steps],
    )


@router.delete("/devices/{device_id}")
def delete_device(device_id: str,
                  user: User = Depends(require_role(Role.admin)),
                  db: Session = Depends(get_db)):
    """Delete or decommission a device.

    - **Not configured** (never onboarded): full delete — the device row,
      its license assignment, and all related data are removed.  The license
      slot is released back to the pool.

    - **Configured** (TSR uploaded or API-connected): the device is
      *decommissioned*.  All TSRs, findings, analyses, stored files,
      schedules, and credentials are purged, but the device row is kept
      with ``decommissioned=True``.  The license remains consumed — it
      cannot be reused for a different serial number until it expires.
    """
    from datetime import datetime as _dt, timezone as _tz
    from ..models import (Tsr, Finding, DeviceCredential, Analysis,
                           Schedule, DriftEvent, RuleSuppression)
    from sqlalchemy import delete as sqla_delete
    from ..storage import delete_object as _del_obj

    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    # ── Scenario 1: never configured — full delete, release license ──
    if not device.was_ever_configured:
        # Collect storage keys before deleting TSR rows.
        storage_keys = [row[0] for row in db.execute(
            select(Tsr.storage_key).where(Tsr.device_id == device_id)).all()]

        db.execute(sqla_delete(Finding).where(
            Finding.analysis_id.in_(
                select(Analysis.id).where(Analysis.device_id == device_id))))
        db.execute(sqla_delete(Analysis).where(Analysis.device_id == device_id))
        db.execute(sqla_delete(Tsr).where(Tsr.device_id == device_id))
        db.execute(sqla_delete(Schedule).where(Schedule.device_id == device_id))
        db.execute(sqla_delete(DriftEvent).where(DriftEvent.device_id == device_id))
        db.execute(sqla_delete(RuleSuppression).where(RuleSuppression.device_id == device_id))
        db.execute(sqla_delete(DeviceCredential).where(DeviceCredential.device_id == device_id))
        db.flush()
        db.delete(device)
        db.commit()

        for key in storage_keys:
            if key:
                try:
                    _del_obj(key)
                except Exception:
                    pass
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ── Scenario 2: configured — decommission ──────────────────────
    # Purge child data but keep the device row.
    storage_keys = [row[0] for row in db.execute(
        select(Tsr.storage_key).where(Tsr.device_id == device_id)).all()]

    db.execute(sqla_delete(Finding).where(
        Finding.analysis_id.in_(
            select(Analysis.id).where(Analysis.device_id == device_id))))
    db.execute(sqla_delete(Analysis).where(Analysis.device_id == device_id))
    db.execute(sqla_delete(Tsr).where(Tsr.device_id == device_id))
    db.execute(sqla_delete(Schedule).where(Schedule.device_id == device_id))
    db.execute(sqla_delete(DriftEvent).where(DriftEvent.device_id == device_id))
    db.execute(sqla_delete(RuleSuppression).where(RuleSuppression.device_id == device_id))
    db.execute(sqla_delete(DeviceCredential).where(DeviceCredential.device_id == device_id))
    db.flush()

    device.decommissioned = True
    device.decommissioned_at = _dt.now(_tz.utc)
    # Reset posture fields since data is gone.
    device.latest_score = 0.0
    device.latest_grade = ""
    device.critical_count = 0
    device.high_count = 0
    device.medium_count = 0
    device.low_count = 0
    device.last_analysis_at = None
    db.commit()

    for key in storage_keys:
        if key:
            try:
                _del_obj(key)
            except Exception:
                pass

    audit.log_action(db, organization_id=device.organization_id,
                     action="device.decommissioned",
                     resource_type="device", resource_id=device.id, user=user,
                     after={"serial": device.serial,
                            "friendly_name": device.friendly_name})

    from .analyses import _build_device_license_info
    _build_device_license_info(device)
    return device


@router.post("/devices/{device_id}/recommission", response_model=DeviceOut)
def recommission_device(device_id: str,
                        user: User = Depends(require_role(Role.admin)),
                        db: Session = Depends(get_db)):
    """Restore a decommissioned device to the active devices list.

    The existing license assignment is kept.  Since all TSRs and findings
    were purged at decommission time the device starts fresh — it must be
    reconfigured (TSR upload or API connection) before analysis can resume.
    """
    device = db.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if not device.decommissioned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Device is not decommissioned.")

    device.decommissioned = False
    device.decommissioned_at = None
    device.configured = False
    db.commit()
    db.refresh(device)

    from .analyses import _build_device_license_info
    _build_device_license_info(device)

    audit.log_action(db, organization_id=device.organization_id,
                     action="device.recommissioned",
                     resource_type="device", resource_id=device.id, user=user,
                     after={"serial": device.serial})
    return device
