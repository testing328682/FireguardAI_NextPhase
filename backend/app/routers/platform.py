"""Platform-operator (superadmin) endpoints.

Cross-tenant overview for the operator running FirewallGuard AI. These routes
intentionally span all organizations and are gated by ``require_superadmin``;
no tenant-facing role grants access, and API tokens (transient principals)
cannot reach them.
"""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, File, Form, UploadFile, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import (
    User, Organization, Customer, Device, Finding, FindingStatus, Plan, ApiFlowConfig,
)
from ..schemas import (
    PlatformOverview, PlatformStats, PlatformOrgRow,
    ApiFlowConfigOut, ApiFlowConfigCreate, ApiFlowConfigUpdate,
    ApiFlowTestRequest, ApiFlowTestResult,
)
from ..security import require_superadmin
from .. import api_flow

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])
settings = get_settings()

ACTIVE = (FindingStatus.open, FindingStatus.acknowledged, FindingStatus.in_progress)


def _counts(db: Session, model) -> dict[str, int]:
    rows = db.execute(
        select(model.organization_id, func.count(model.id)).group_by(model.organization_id)).all()
    return {oid: n for oid, n in rows}


@router.get("/overview", response_model=PlatformOverview)
def overview(_: User = Depends(require_superadmin),
             db: Session = Depends(get_db)) -> PlatformOverview:
    orgs = list(db.scalars(select(Organization)))
    cust_counts = _counts(db, Customer)
    user_counts = _counts(db, User)

    # Per-org firewall count and average posture (scored devices only).
    dev_rows = db.execute(
        select(Device.organization_id, func.count(Device.id),
               func.avg(Device.latest_score)).where(Device.latest_grade != "")
        .group_by(Device.organization_id)).all()
    dev_count = {oid: n for oid, n, _avg in dev_rows}
    dev_avg = {oid: float(avg or 0) for oid, _n, avg in dev_rows}
    # All devices (including unscored) for the firewall total.
    all_dev = _counts(db, Device)

    # Open-critical findings per org.
    crit_rows = db.execute(
        select(Finding.organization_id, func.count(Finding.id)).where(
            Finding.severity == "Critical", Finding.status.in_(ACTIVE))
        .group_by(Finding.organization_id)).all()
    crit = {oid: n for oid, n in crit_rows}

    # Pre-load plan names for orgs with plan_id
    plan_names: dict[str, str] = {}
    orgs_with_plan = [(o, o.plan_id) for o in orgs if o.plan_id]
    if orgs_with_plan:
        plan_ids = set(p for _, p in orgs_with_plan)
        plans = db.scalars(select(Plan).where(Plan.id.in_(plan_ids))).all()
        plan_names = {p.id: p.name.lower() for p in plans}

    rows: list[PlatformOrgRow] = []
    plan_dist: dict[str, int] = defaultdict(int)
    region_dist: dict[str, int] = defaultdict(int)
    msp = direct = 0
    for o in orgs:
        pname = plan_names.get(o.plan_id, o.plan.value)
        plan_dist[pname] += 1
        region_dist[o.region] += 1
        if o.is_msp:
            msp += 1
        else:
            direct += 1
        rows.append(PlatformOrgRow(
            id=o.id, name=o.name, type="MSP" if o.is_msp else "Direct",
            plan=pname, region=o.region, subscription_status=o.subscription_status,
            customers=cust_counts.get(o.id, 0), firewalls=all_dev.get(o.id, 0),
            users=user_counts.get(o.id, 0), avg_score=round(dev_avg.get(o.id, 0.0), 1),
            open_critical=crit.get(o.id, 0), created_at=o.created_at))

    rows.sort(key=lambda r: (-r.open_critical, -r.firewalls))
    stats = PlatformStats(
        organizations=len(orgs), msp_count=msp, direct_count=direct,
        total_customers=sum(cust_counts.values()),
        total_firewalls=sum(all_dev.values()),
        total_users=sum(user_counts.values()),
        plan_distribution=dict(plan_dist), region_distribution=dict(region_dist))
    return PlatformOverview(stats=stats, organizations=rows)


# ---------------------------------------------------------------------------
# TSR Analysis Tester (superadmin)
# ---------------------------------------------------------------------------
@router.post("/analyze-tsr")
async def analyze_tsr(
        file: UploadFile = File(...),
        tsr_format: str = Form("auto"),   # auto | gui | api
        _: User = Depends(require_superadmin),
        db: Session = Depends(get_db)) -> dict:
    """Ad-hoc TSR analysis for operators. Detects/forces GUI vs API format,
    normalizes API TSRs, runs the full pipeline (with API rule-support
    suppression), and returns the result without persisting anything.
    """
    raw = await file.read()
    if len(raw) > settings.max_tsr_size_mb * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"TSR exceeds {settings.max_tsr_size_mb} MB limit")
    text = raw.decode("utf-8", errors="replace")

    from firewallguard.tsr.normalize import normalize_api_tsr, detect_tsr_format
    from firewallguard.pipeline import analyze_text
    from ..rule_engine import api_unsupported_system_keys

    fmt = tsr_format if tsr_format in ("gui", "api") else detect_tsr_format(text)
    if fmt == "api":
        text = normalize_api_tsr(text)
        suppressions = [{"rule_key": k, "action": "disable", "value": ""}
                        for k in api_unsupported_system_keys(db)]
    else:
        suppressions = []

    result = analyze_text(text, file.filename or "tester.tsr", suppressions=suppressions)
    score = result["score"]
    return {
        "filename": file.filename,
        "detected_format": fmt,
        "requested_format": tsr_format,
        "device": result.get("device", {}),
        "score": score["score"],
        "grade": score["grade"],
        "severity_counts": score["severity_counts"],
        "finding_count": result["finding_count"],
        "suppressed_rule_count": len(suppressions),
        "findings": [
            {"rule_id": f["rule_id"], "severity": f["severity"], "title": f["title"],
             "category": f["category"], "object_name": f.get("object_name", "")}
            for f in result["findings"]
        ],
    }


# ---------------------------------------------------------------------------
# Configurable API flow (superadmin) — versions, activate, tester
# ---------------------------------------------------------------------------
def _get_config_or_404(db: Session, config_id: str) -> ApiFlowConfig:
    cfg = db.get(ApiFlowConfig, config_id)
    if cfg is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Config not found")
    return cfg


@router.get("/api-configs", response_model=list[ApiFlowConfigOut])
def list_api_configs(_: User = Depends(require_superadmin),
                     db: Session = Depends(get_db)) -> list[ApiFlowConfig]:
    """List API flow configs, seeding the default SonicOS Gen7 config on first use."""
    api_flow.ensure_default_config(db)
    return list(db.scalars(select(ApiFlowConfig).order_by(ApiFlowConfig.name)))


@router.post("/api-configs", response_model=ApiFlowConfigOut, status_code=201)
def create_api_config(body: ApiFlowConfigCreate, _: User = Depends(require_superadmin),
                      db: Session = Depends(get_db)) -> ApiFlowConfig:
    if db.scalar(select(ApiFlowConfig).where(ApiFlowConfig.name == body.name)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"A config named '{body.name}' already exists.")
    first = db.scalar(select(ApiFlowConfig).limit(1)) is None
    cfg = ApiFlowConfig(name=body.name, description=body.description,
                        version_label=body.version_label, auth_type=body.auth_type,
                        verify_tls=body.verify_tls, timeout_seconds=body.timeout_seconds,
                        api_base=body.api_base, steps=body.steps, is_active=first)
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return cfg


@router.get("/api-configs/{config_id}", response_model=ApiFlowConfigOut)
def get_api_config(config_id: str, _: User = Depends(require_superadmin),
                   db: Session = Depends(get_db)) -> ApiFlowConfig:
    return _get_config_or_404(db, config_id)


@router.put("/api-configs/{config_id}", response_model=ApiFlowConfigOut)
def update_api_config(config_id: str, body: ApiFlowConfigUpdate,
                      _: User = Depends(require_superadmin),
                      db: Session = Depends(get_db)) -> ApiFlowConfig:
    cfg = _get_config_or_404(db, config_id)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(cfg, field, value)
    db.commit()
    db.refresh(cfg)
    return cfg


@router.post("/api-configs/{config_id}/activate", response_model=ApiFlowConfigOut)
def activate_api_config(config_id: str, _: User = Depends(require_superadmin),
                        db: Session = Depends(get_db)) -> ApiFlowConfig:
    cfg = _get_config_or_404(db, config_id)
    for other in db.scalars(select(ApiFlowConfig).where(ApiFlowConfig.is_active.is_(True))):
        other.is_active = False
    cfg.is_active = True
    db.commit()
    db.refresh(cfg)
    return cfg


@router.delete("/api-configs/{config_id}", status_code=204)
def delete_api_config(config_id: str, _: User = Depends(require_superadmin),
                      db: Session = Depends(get_db)):
    cfg = _get_config_or_404(db, config_id)
    was_active = cfg.is_active
    db.delete(cfg)
    db.flush()
    if was_active:  # promote another config so an active one remains
        nxt = db.scalar(select(ApiFlowConfig).order_by(ApiFlowConfig.name).limit(1))
        if nxt is not None:
            nxt.is_active = True
    db.commit()
    from fastapi import Response
    return Response(status_code=204)


@router.post("/api-configs/test", response_model=ApiFlowTestResult)
def test_api_config(body: ApiFlowTestRequest, _: User = Depends(require_superadmin),
                    db: Session = Depends(get_db)) -> ApiFlowTestResult:
    """Execute a flow (saved by id, or an inline draft) against a firewall and
    return a per-step trace. Nothing is persisted."""
    if body.config_id:
        cfg = api_flow.config_to_dict(_get_config_or_404(db, body.config_id))
    elif body.config is not None:
        cfg = body.config.model_dump()
    else:
        cfg = api_flow.default_config_dict()
    ctx = {"hostname": body.hostname, "ip": body.hostname, "port": body.port,
           "username": body.username, "password": body.password,
           "verify_tls": body.verify_tls}
    result = api_flow.run_flow(cfg, ctx)
    return ApiFlowTestResult(
        success=result["success"], error=result["error"],
        tsr_bytes=len(result.get("tsr_text") or ""),
        traces=result["traces"], extracted=result.get("extracted", {}))


def _bulk_delete(db: Session, model, *where_clauses):
    """Delete all rows matching the given where clause(s)."""
    stmt = select(model).where(*where_clauses)
    rows = db.scalars(stmt).all()
    for row in rows:
        db.delete(row)
    db.flush()
    return len(rows)


@router.delete("/organizations/{org_id}", status_code=200)
def delete_organization(org_id: str, _: User = Depends(require_superadmin),
                        db: Session = Depends(get_db)):
    """Permanently delete an organization and ALL associated data.

    Destroys every record linked to the tenant — users, customers, devices,
    TSRs, analyses, findings, licenses, API configs, connection logs,
    schedules, integrations, tokens, alerts, audit entries, and suppressions.

    The entire operation runs in a single transaction via the session;
    any failure rolls back completely.
    """
    from ..models import (
        AuditLog, FindingComment, DriftEvent, Schedule, DeviceCredential,
        RuleSuppression, ApiToken, Integration, AlertSubscription, SSOConfig,
        Customer, Tsr, Analysis, ApiConnectionLog, LicensePurchase,
    )
    org = db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    # Protect: platform operator cannot delete their own organization
    if _.organization_id == org_id:
        raise HTTPException(400, "Cannot delete your own organization.")

    # ── Count before deletion ──────────────────────────────────────
    user_count = db.scalar(select(func.count(User.id)).where(User.organization_id == org_id)) or 0
    device_ids = [r[0] for r in db.execute(select(Device.id).where(Device.organization_id == org_id)).all()]
    device_count = len(device_ids)
    analysis_count = db.scalar(select(func.count(Analysis.id)).where(Analysis.organization_id == org_id)) or 0
    finding_count = db.scalar(select(func.count(Finding.id)).where(Finding.organization_id == org_id)) or 0
    tsr_count = db.scalar(select(func.count(Tsr.id)).where(Tsr.organization_id == org_id)) or 0
    customer_count = db.scalar(select(func.count(Customer.id)).where(Customer.organization_id == org_id)) or 0

    org_name = org.name

    # ── Delete in dependency order (children first) ────────────────
    _bulk_delete(db, FindingComment, FindingComment.organization_id == org_id)
    _bulk_delete(db, DriftEvent, DriftEvent.organization_id == org_id)
    if device_ids:
        _bulk_delete(db, ApiConnectionLog, ApiConnectionLog.device_id.in_(device_ids))
        _bulk_delete(db, Schedule, Schedule.device_id.in_(device_ids))
        _bulk_delete(db, DeviceCredential, DeviceCredential.device_id.in_(device_ids))
    _bulk_delete(db, Finding, Finding.organization_id == org_id)
    _bulk_delete(db, Analysis, Analysis.organization_id == org_id)
    _bulk_delete(db, Tsr, Tsr.organization_id == org_id)
    _bulk_delete(db, RuleSuppression, RuleSuppression.organization_id == org_id)
    _bulk_delete(db, Device, Device.organization_id == org_id)
    _bulk_delete(db, ApiToken, ApiToken.organization_id == org_id)
    _bulk_delete(db, Integration, Integration.organization_id == org_id)
    _bulk_delete(db, AlertSubscription, AlertSubscription.organization_id == org_id)
    _bulk_delete(db, Schedule, Schedule.organization_id == org_id)
    _bulk_delete(db, ApiConnectionLog, ApiConnectionLog.organization_id == org_id)
    _bulk_delete(db, LicensePurchase, LicensePurchase.organization_id == org_id)
    _bulk_delete(db, SSOConfig, SSOConfig.organization_id == org_id)
    _bulk_delete(db, Customer, Customer.organization_id == org_id)
    _bulk_delete(db, User, User.organization_id == org_id)
    _bulk_delete(db, AuditLog, AuditLog.organization_id == org_id)
    db.delete(org)
    db.commit()

    return {
        "deleted": True,
        "organization_id": org_id,
        "organization_name": org_name,
        "users": user_count,
        "customers": customer_count,
        "devices": device_count,
        "analyses": analysis_count,
        "findings": finding_count,
        "tsrs": tsr_count,
    }
