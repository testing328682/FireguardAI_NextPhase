"""Dynamic plan management — admin CRUD + customer plan info + seeding.

Superadmin-only endpoints for creating, editing, cloning, and archiving plans.
Customer-facing endpoint returns plan details, features, limits, and usage.
"""

from __future__ import annotations

import json as _json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, func, text
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from ..database import get_db
from ..models import User, Organization, Plan, FeatureRegistry, LicensePurchase, Device, Finding, Customer
from ..schemas import PlanOut, PlanCreate, PlanUpdate, PlanAssignment, CustomerPlanInfo
from ..security import current_user, require_superadmin, require_role, Role
from .. import entitlements, audit

router = APIRouter(prefix="/api/v1", tags=["plans"])

DEFAULT_FEATURES = {
    "tsr_analysis": True, "ai_analysis": False, "pdf_reports": False,
    "compliance_reports": False, "firmware_advisor": False,
    "multi_tenant": False, "white_label": False, "api_access": False,
    "integrations": False,
}
DEFAULT_LIMITS = {
    "max_firewalls": 1, "max_users": 2, "max_tsr_uploads": 1,
    "max_reports": 5, "max_ai_requests": 0, "max_storage_gb": 1,
}

FEATURE_LABELS: dict[str, str] = {
    "tsr_analysis": "TSR Analysis", "ai_analysis": "AI Analysis",
    "pdf_reports": "PDF Reports", "compliance_reports": "Compliance Reports",
    "firmware_advisor": "Firmware Advisor", "multi_tenant": "Multi-Tenant Support",
    "white_label": "White Label Reports", "api_access": "API Access",
    "integrations": "Integrations",
}
LIMIT_LABELS: dict[str, str] = {
    "max_firewalls": "Max Firewalls", "max_users": "Max Users",
    "max_tsr_uploads": "Max TSR Uploads", "max_reports": "Max Reports",
    "max_ai_requests": "Max AI Requests", "max_storage_gb": "Max Storage (GB)",
}


# ── Admin CRUD ──────────────────────────────────────────────────────────

@router.get("/admin/plans", response_model=list[PlanOut])
def list_plans(_: User = Depends(require_superadmin),
               db: Session = Depends(get_db)):
    try:
        return list(db.scalars(select(Plan).order_by(Plan.sort_order.asc(), Plan.name.asc())))
    except Exception as e:
        from fastapi import HTTPException as HTTPE
        raise HTTPE(status_code=500, detail=f"Plan listing failed: {type(e).__name__}: {e}") from e


@router.post("/admin/plans", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
def create_plan(body: PlanCreate, request: Request,
                _: User = Depends(require_superadmin),
                db: Session = Depends(get_db)):
    plan = Plan(name=body.name, description=body.description,
                plan_type=body.plan_type,
                features=body.features or {}, price_per_device=body.price_per_device,
                pricing_tiers=body.pricing_tiers or {},
                is_testing=body.is_testing, validity_minutes=body.validity_minutes,
                yearly_discount_pct=body.yearly_discount_pct)
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


@router.get("/admin/plans/{plan_id}", response_model=PlanOut)
def get_plan(plan_id: str, _: User = Depends(require_superadmin),
             db: Session = Depends(get_db)):
    plan = db.get(Plan, plan_id)
    if plan is None: raise HTTPException(status_code=404, detail="Plan not found")
    return plan


@router.patch("/admin/plans/{plan_id}", response_model=PlanOut)
def update_plan(plan_id: str, body: PlanUpdate, request: Request,
                _: User = Depends(require_superadmin),
                db: Session = Depends(get_db)):
    plan = db.get(Plan, plan_id)
    if plan is None: raise HTTPException(status_code=404, detail="Plan not found")
    for field in ("name", "description", "plan_type", "is_active", "is_visible",
                  "sort_order", "features", "price_per_device", "pricing_tiers",
                  "yearly_discount_pct", "is_testing", "validity_minutes"):
        val = getattr(body, field)
        if val is not None:
            setattr(plan, field, val)
    plan.updated_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(plan)
    return plan


@router.post("/admin/plans/{plan_id}/clone", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
def clone_plan(plan_id: str, request: Request,
               _: User = Depends(require_superadmin),
               db: Session = Depends(get_db)):
    plan = db.get(Plan, plan_id)
    if plan is None: raise HTTPException(status_code=404, detail="Plan not found")
    clone = Plan(name=f"{plan.name} (Copy)", description=plan.description,
                 plan_type=plan.plan_type, features=dict(plan.features),
                 price_per_device=plan.price_per_device,
                 pricing_tiers=dict(plan.pricing_tiers), is_active=False, is_visible=False,
                 is_testing=plan.is_testing, validity_minutes=plan.validity_minutes)
    db.add(clone); db.commit(); db.refresh(clone)
    return clone


@router.delete("/admin/plans/{plan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_plan(plan_id: str, request: Request,
                _: User = Depends(require_superadmin),
                db: Session = Depends(get_db)):
    plan = db.get(Plan, plan_id)
    if plan is None: raise HTTPException(status_code=404, detail="Plan not found")
    # Unlink orgs before deleting
    db.execute(select(Organization).where(Organization.plan_id == plan_id))
    for org in db.scalars(select(Organization).where(Organization.plan_id == plan_id)):
        org.plan_id = None
    db.delete(plan); db.commit()
    return None


@router.post("/admin/plans/{plan_id}/assign")
def assign_plan(plan_id: str, body: PlanAssignment, request: Request,
                _: User = Depends(require_superadmin),
                db: Session = Depends(get_db)):
    plan = db.get(Plan, plan_id)
    if plan is None: raise HTTPException(status_code=404, detail="Plan not found")
    org = db.get(Organization, body.org_id)
    if org is None: raise HTTPException(status_code=404, detail="Organization not found")
    org.plan_id = plan_id
    db.commit()
    return {"status": "ok", "org_id": org.id, "plan_id": plan_id}


@router.post("/admin/organizations/{org_id}/reset-subscription")
def reset_subscription(org_id: str, _: User = Depends(require_superadmin),
                       db: Session = Depends(get_db)):
    """Reset an organization back to Free plan, clearing all licenses."""
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    org.plan_id = None
    org.device_count = 0
    org.license_allocations = {}
    org.subscription_term = "monthly"
    flag_modified(org, "license_allocations")
    # Delete all license purchases for this org (safe if table doesn't exist)
    try:
        for lp in db.scalars(select(LicensePurchase).where(LicensePurchase.organization_id == org_id)):
            db.delete(lp)
    except Exception:
        pass  # table may not exist yet
    db.commit()
    return {"status": "ok", "org_id": org.id, "message": "Subscription reset to Free"}


@router.post("/admin/organizations/{org_id}/factory-reset")
def factory_reset_org(org_id: str, _: User = Depends(require_superadmin),
                      db: Session = Depends(get_db)):
    """Full reset: wipe all customer data back to fresh sign-up state."""
    try:
        org = db.get(Organization, org_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Delete findings for this org
        for f in db.scalars(select(Finding).where(Finding.organization_id == org_id)):
            db.delete(f)
        db.flush()

        # Delete analyses first (they reference TSRs via nullable FK)
        from ..models import Tsr, Analysis
        for a in db.scalars(select(Analysis).where(Analysis.organization_id == org_id)):
            db.delete(a)
        db.flush()
        # Then delete TSRs
        for t in db.scalars(select(Tsr).where(Tsr.organization_id == org_id)):
            db.delete(t)
        db.flush()

        # Delete devices
        for d in db.scalars(select(Device).where(Device.organization_id == org_id)):
            db.delete(d)
        db.flush()

        # Delete non-default customers
        for c in db.scalars(select(Customer).where(Customer.organization_id == org_id)):
            if "(default)" not in (c.name or ""):
                db.delete(c)
        db.flush()

        # Delete license purchases
        try:
            for lp in db.scalars(select(LicensePurchase).where(LicensePurchase.organization_id == org_id)):
                db.delete(lp)
            db.flush()
        except Exception:
            pass

        # Reset plan to Free
        org.plan_id = None
        org.device_count = 0
        org.license_allocations = {}
        org.subscription_term = "monthly"
        flag_modified(org, "license_allocations")
        db.commit()
        return {"status": "ok", "org_id": org.id, "message": "Organization fully reset to fresh state"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Factory reset failed: {type(e).__name__}: {e}") from e


# ── Feature Registry ────────────────────────────────────────────────────

@router.get("/admin/features")
def list_features(_: User = Depends(require_superadmin),
                  db: Session = Depends(get_db)):
    try:
        return list(db.scalars(select(FeatureRegistry).order_by(FeatureRegistry.sort_order.asc())))
    except Exception as e:
        from fastapi import HTTPException as HTTPE
        raise HTTPE(status_code=500, detail=f"Feature listing failed: {type(e).__name__}: {e}") from e


@router.post("/admin/features", status_code=status.HTTP_201_CREATED)
def create_feature(body: dict, _: User = Depends(require_superadmin),
                   db: Session = Depends(get_db)):
    f = FeatureRegistry(key=body["key"], label=body["label"],
                        description=body.get("description", ""))
    db.add(f); db.commit(); db.refresh(f)
    return {"id": f.id, "key": f.key, "label": f.label, "description": f.description, "is_active": f.is_active}


@router.patch("/admin/features/{feature_id}")
def update_feature(feature_id: str, body: dict,
                   _: User = Depends(require_superadmin),
                   db: Session = Depends(get_db)):
    f = db.get(FeatureRegistry, feature_id)
    if f is None: raise HTTPException(status_code=404, detail="Feature not found")
    for field in ("key", "label", "description", "is_active", "sort_order"):
        if field in body: setattr(f, field, body[field])
    db.commit(); db.refresh(f)
    return {"id": f.id, "key": f.key, "label": f.label, "description": f.description, "is_active": f.is_active}


@router.delete("/admin/features/{feature_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_feature(feature_id: str, _: User = Depends(require_superadmin),
                   db: Session = Depends(get_db)):
    f = db.get(FeatureRegistry, feature_id)
    if f is None: raise HTTPException(status_code=404, detail="Feature not found")
    db.delete(f); db.commit()
    return None


# ── Customer-facing ─────────────────────────────────────────────────────

@router.get("/plans/available", response_model=list[PlanOut])
def available_plans(user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    """Plans visible for upgrade (active + visible)."""
    return list(db.scalars(select(Plan).where(
        Plan.is_active.is_(True), Plan.is_visible.is_(True))
        .order_by(Plan.sort_order.asc())))


@router.patch("/organization/plan", response_model=CustomerPlanInfo)
def update_org_plan(body: dict,
                    user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    """Customer selects a plan, device count, and subscription term."""
    try:
        org = db.get(Organization, user.organization_id)
        was_free = org.plan_id is None
        if "plan_id" in body:
            plan = db.get(Plan, body["plan_id"])
            if plan is None or not plan.is_active:
                raise HTTPException(status_code=400, detail="Plan not available")
            org.plan_id = body["plan_id"]
            if plan.plan_type == "msp":
                org.is_msp = True

            # If upgrading from Free to paid, remove the free license and
            # release any devices still assigned to it so they don't hold
            # a dangling FK. The device keeps its cached license_info (with
            # is_trial=True) so it still shows "Active (Trial)" status.
            # The user can then reassign via Change License.
            new_is_free = plan.name == "Free"
            if was_free and not new_is_free:
                try:
                    for lp in db.scalars(select(LicensePurchase).where(
                        LicensePurchase.organization_id == org.id,
                        LicensePurchase.count == 1,
                        LicensePurchase.total_devices == 1,
                        LicensePurchase.tier.is_(None),
                    )):
                        for d in db.scalars(select(Device).where(
                            Device.license_purchase_id == lp.id)):
                            d.license_purchase_id = None
                            # Keep license_info so "Active (Trial)" status persists.
                        db.flush()
                        db.delete(lp)
                    db.flush()
                except Exception:
                    pass
        if "device_count" in body:
            org.device_count = int(body["device_count"])
        if "subscription_term" in body:
            term = body["subscription_term"]
            if term not in ("monthly", "yearly"):
                raise HTTPException(status_code=400, detail="Invalid subscription term")
            org.subscription_term = term
        db.commit()
        return current_plan(user, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Plan update failed: {type(e).__name__}: {e}") from e


def _normalize_allocations(raw: dict, plan_type: str) -> dict:
    """Normalize legacy flat allocations into {sub_term: {freq: count}} structure.
    If already in new format (keys are 'monthly'/'yearly'), return as-is.
    """
    if not raw:
        return {"monthly": {}}
    # Detect: if top-level keys are sub-terms, we're in new format
    if all(k in ("monthly", "yearly") for k in raw.keys()):
        return raw
    # Legacy flat format → wrap under "monthly"
    return {"monthly": dict(raw)}


@router.post("/organization/purchase", response_model=CustomerPlanInfo)
def purchase_licenses(body: dict,
                      user: User = Depends(current_user),
                      db: Session = Depends(get_db)):
    """Purchase additional device licenses. Additive. Supports Monthly/Yearly terms.

    A license conveys only the right to register and continuously analyze a
    device — there is no analysis-frequency dimension to select.
    """
    org = db.get(Organization, user.organization_id)
    plan = entitlements._active_plan(db, org)
    if plan is None or plan.name == "Free":
        raise HTTPException(status_code=400, detail="Cannot purchase licenses on the Free plan.")

    count = int(body.get("count", 0))
    sub_term = body.get("subscription_term", "monthly")  # "monthly" or "yearly"
    if sub_term not in ("monthly", "yearly"):
        raise HTTPException(status_code=400, detail="Invalid subscription term")
    if count <= 0:
        raise HTTPException(status_code=400, detail="Count must be positive")

    alloc_raw = org.license_allocations or {}
    alloc = _json.loads(_json.dumps(alloc_raw))
    alloc = _normalize_allocations(alloc, plan.plan_type)

    plan_type = plan.plan_type
    sub = alloc.setdefault(sub_term, {})
    tier = str(body.get("tier", "10")) if plan_type == "msp" else None
    if plan_type == "msp":
        existing = sub.get(tier, 0)
        sub[tier] = (existing if isinstance(existing, (int, float)) else 0) + count
    else:
        existing = sub.get("licenses", 0)
        sub["licenses"] = (existing if isinstance(existing, (int, float)) else 0) + count

    org.license_allocations = alloc
    flag_modified(org, "license_allocations")

    # Record individual purchase for history/expiry tracking
    tier_devices = int(tier) if plan_type == "msp" else 0
    total_devs = count * tier_devices if plan_type == "msp" else count
    from datetime import timedelta
    if plan.is_testing and plan.validity_minutes > 0:
        expires = datetime.now(timezone.utc) + timedelta(minutes=plan.validity_minutes)
    else:
        expires = datetime.now(timezone.utc) + timedelta(days=365 if sub_term == "yearly" else 30)
    lp = LicensePurchase(
        organization_id=org.id, subscription_term=sub_term,
        tier=tier, tier_device_count=tier_devices, count=count, total_devices=total_devs,
        purchased_at=datetime.now(timezone.utc), expires_at=expires)
    db.add(lp)

    # Recalculate total device count
    total = 0
    for term, term_alloc in alloc.items():
        for k, v in (term_alloc or {}).items():
            if not isinstance(v, (int, float)):
                continue
            tier_mult = int(k) if plan_type == "msp" else 1
            total += v * tier_mult
    org.device_count = total
    db.flush()
    db.commit()
    db.refresh(org)

    return current_plan(user, db)


@router.get("/plans/current", response_model=CustomerPlanInfo)
def current_plan(user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    """Customer's current plan with calculated pricing."""
    org = db.get(Organization, user.organization_id)
    info = entitlements.plan_info(db, org)
    plan = entitlements._active_plan(db, org)
    tiers = (plan.pricing_tiers if plan else {}) or {}
    price_per_device = float(plan.price_per_device) if plan else 0.0
    plan_type = (plan.plan_type if plan else "professional")
    discount_pct = (plan.yearly_discount_pct if plan else 20) or 0
    dev_count = org.device_count or 0
    raw_alloc = dict(org.license_allocations or {}) if org else {}
    allocations = _normalize_allocations(raw_alloc, plan_type)

    # Calculate costs for both subscription terms. Professional plans use a
    # single flat price_per_device; MSP plans use a flat price per tier.
    monthly_cost = 0.0
    yearly_cost_monthly = 0.0
    yearly_total_raw = 0.0
    for term, term_alloc in allocations.items():
        items = term_alloc or {}
        term_total = 0.0
        if plan_type == "msp":
            for tier_str, count in items.items():
                if isinstance(count, (int, float)) and count > 0:
                    term_total += count * float(tiers.get(tier_str, 0))
        else:
            count = items.get("licenses", 0) if isinstance(items, dict) else 0
            if isinstance(count, (int, float)) and count > 0:
                term_total += count * price_per_device
        if term == "yearly":
            # Prices are annual when on yearly term
            yearly_total_raw = term_total * (1 - discount_pct / 100)
            yearly_cost_monthly = yearly_total_raw / 12
        else:
            monthly_cost = term_total

    # ── Auto-create free license for Free plan if none exists ──────
    from datetime import datetime as dt, timezone as tz, timedelta
    free_plan_check = info["name"] == "Free" or (not org.plan_id)
    if free_plan_check:
        try:
            free_lp = db.scalar(
                select(LicensePurchase).where(
                    LicensePurchase.organization_id == org.id,
                    LicensePurchase.subscription_term == "monthly",
                    LicensePurchase.count > 0,
                ))
        except Exception:
            free_lp = None
        if not free_lp:
            try:
                new_lp = LicensePurchase(
                    organization_id=org.id,
                    count=1,
                    subscription_term="monthly",
                    purchased_at=dt.now(tz.utc),
                    expires_at=dt.now(tz.utc) + timedelta(days=30),
                    tier=None,
                    tier_device_count=0,
                    total_devices=0,
                )
                db.add(new_lp)
                db.commit()
            except Exception:
                db.rollback()

    usage = {
        # Only count devices consuming from a paid license purchase.
        # Trial/unassigned devices (license_purchase_id IS NULL) are excluded
        # so "X/Y Used" reflects only purchased-license consumption.
        "firewalls": db.scalar(select(func.count(Device.id)).where(
            Device.organization_id == org.id,
            Device.license_purchase_id.isnot(None))) or 0,
        "users": db.scalar(select(func.count(User.id)).where(
            User.organization_id == org.id)) or 0,
    }

    # Fetch purchase history
    try:
        purchases = list(db.scalars(
            select(LicensePurchase).where(LicensePurchase.organization_id == org.id)
            .order_by(LicensePurchase.purchased_at.desc())))
    except Exception:
        purchases = []
    purchase_list = [{
        "id": p.id, "subscription_term": p.subscription_term,
        "tier": p.tier,
        "tier_device_count": p.tier_device_count, "count": p.count,
        "total_devices": p.total_devices,
        "purchased_at": p.purchased_at.isoformat() if p.purchased_at else None,
        "expires_at": p.expires_at.isoformat() if p.expires_at else None,
    } for p in purchases]

    return CustomerPlanInfo(
        plan_name=info["name"], plan_type=plan_type,
        features=info["features"], price_per_device=price_per_device, pricing_tiers=tiers,
        yearly_discount_pct=discount_pct,
        device_count=dev_count,
        monthly_cost=round(monthly_cost + yearly_cost_monthly, 2),
        yearly_total=round(yearly_total_raw, 2), usage=usage,
        license_allocations=allocations,
        purchase_history=purchase_list,
        subscription_term=org.subscription_term or "monthly")


# ── Seed default plans ──────────────────────────────────────────────────

def seed_plans(db: Session) -> int:
    """Create default plans if they don't exist. Idempotent."""
    defaults = [
        {"name": "Free", "description": "Basic TSR analysis for a single firewall.",
         "plan_type": "professional",
         "features": {"tsr_analysis": True, "pdf_reports": True},
         "price_per_device": 0,
         "sort_order": 0},
        {"name": "Professional", "description": "Flat per-device pricing, unlimited analyses.",
         "plan_type": "professional",
         "features": {"tsr_analysis": True, "pdf_reports": True, "firmware_advisor": True,
                      "api_access": True, "integrations": True, "compliance_reports": True},
         "price_per_device": 19,
         "sort_order": 1},
        {"name": "MSP", "description": "Tier-based pricing for managed service providers.",
         "plan_type": "msp",
         "features": {"tsr_analysis": True, "pdf_reports": True, "firmware_advisor": True,
                      "multi_tenant": True, "white_label": True, "api_access": True,
                      "integrations": True, "compliance_reports": True},
         "pricing_tiers": {"10": 49, "25": 99, "50": 179, "100": 299, "250": 599},
         "sort_order": 2},
    ]
    n = 0
    for d in defaults:
        existing = db.scalar(select(Plan).where(Plan.name == d["name"]))
        if existing is None:
            plan = Plan(name=d["name"], description=d["description"],
                        plan_type=d.get("plan_type", "professional"),
                        is_active=True, is_visible=True,
                        sort_order=d.get("sort_order", 0))
            plan.features = d.get("features", {})
            plan.price_per_device = d.get("price_per_device", 0)
            plan.pricing_tiers = d.get("pricing_tiers", {})
            db.add(plan); n += 1
        else:
            # Ensure correct plan_type for existing plans (migration backfill)
            expected = d.get("plan_type", "professional")
            if existing.plan_type != expected:
                existing.plan_type = expected
                existing.features = d.get("features", existing.features)
                existing.price_per_device = d.get("price_per_device", existing.price_per_device)
                existing.pricing_tiers = d.get("pricing_tiers", existing.pricing_tiers)
                n += 1
    if n: db.commit()

    # Seed default feature registry entries
    feature_defaults = [
        ("tsr_analysis", "TSR Analysis", "Upload and analyze Tech Support Reports"),
        ("pdf_reports", "PDF Reports", "Download technical PDF reports"),
        ("compliance_reports", "Compliance Reports", "Framework-based compliance matrix"),
        ("firmware_advisor", "Firmware Advisor", "PSIRT/CVE vulnerability intelligence"),
        ("multi_tenant", "Multi-Tenant", "Manage multiple customer organizations"),
        ("white_label", "White Label", "Branded reports with company logo"),
        ("api_access", "API Access", "Programmatic access via REST API tokens"),
        ("integrations", "Integrations", "Slack, Teams, Jira, ServiceNow connectors"),
        ("ai_analysis", "AI Analysis", "AI-powered attack path correlation"),
    ]
    for key, label, desc in feature_defaults:
        existing = db.scalar(select(FeatureRegistry).where(FeatureRegistry.key == key))
        if existing is None:
            db.add(FeatureRegistry(key=key, label=label, description=desc))
            n += 1
    if n: db.commit()
    return n


# ── License bundles (for device registration) ───────────────────────────

def ensure_free_license(db: Session, org: Organization) -> LicensePurchase:
    """Idempotently grant the org's free Monthly license (1 device, 30 days).

    Returns the active free ``LicensePurchase`` — the existing one if present,
    otherwise a new record dated from now. Anchors the start date to creation
    (registration / free-plan activation) and the expiry to +30 days.
    """
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    lp = db.scalar(select(LicensePurchase).where(
        LicensePurchase.organization_id == org.id,
        LicensePurchase.subscription_term == "monthly",
        LicensePurchase.tier.is_(None),
        LicensePurchase.count > 0).order_by(LicensePurchase.purchased_at.desc()))
    if lp is not None:
        return lp
    now = _dt.now(_tz.utc)
    lp = LicensePurchase(
        organization_id=org.id, subscription_term="monthly",
        count=1, total_devices=1,
        tier=None, tier_device_count=0,
        purchased_at=now, expires_at=now + _td(days=30))
    db.add(lp)
    db.commit()
    db.refresh(lp)
    return lp


@router.get("/organization/licenses")
def get_license_bundles(user: User = Depends(current_user),
                         db: Session = Depends(get_db)):
    """Return available license bundles with remaining counts for device registration."""
    from ..models import Device
    from sqlalchemy import func as sqlfunc

    org = db.get(Organization, user.organization_id)
    if org is None:
        return {"bundles": [], "free": True}

    from datetime import datetime as dt, timezone as tz, timedelta
    from ..models import LicensePurchase as LP

    def _ensure_lp_table():
        """Create license_purchases table if it doesn't exist (migration safety net)."""
        try:
            db.execute(text("SELECT 1 FROM license_purchases LIMIT 0"))
        except Exception:
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS license_purchases (
                    id VARCHAR(36) PRIMARY KEY,
                    organization_id VARCHAR(36) NOT NULL,
                    subscription_term VARCHAR(32) DEFAULT 'monthly',
                    tier VARCHAR(16),
                    tier_device_count INTEGER DEFAULT 0,
                    count INTEGER DEFAULT 1,
                    total_devices INTEGER DEFAULT 0,
                    purchased_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMPTZ
                )
            """))
            db.commit()
    _ensure_lp_table()

    alloc_raw = org.license_allocations or {}
    # Free plan check: NULL plan_id OR plan named "Free"
    is_free_plan = org.plan_id is None
    if not is_free_plan and org.plan_id:
        try:
            from ..models import Plan as PlanModel
            free_plan = db.get(PlanModel, org.plan_id)
            if free_plan and free_plan.name == "Free":
                is_free_plan = True
        except Exception:
            pass
    now_utc = dt.now(tz.utc)

    # If on Free plan with no purchases/empty allocs, surface the free license.
    if is_free_plan and (not alloc_raw or not any(alloc_raw.values())):
        free_purchase = ensure_free_license(db, org)
        used = db.scalar(select(sqlfunc.count(Device.id)).where(
            Device.organization_id == org.id)) or 0
        expires = free_purchase.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=tz.utc)  # SQLite stores naive datetimes
        expired = expires is not None and expires <= now_utc
        free_remaining = 0 if expired else max(0, free_purchase.count - used)
        start_iso = free_purchase.purchased_at.isoformat() if free_purchase.purchased_at else None
        expiry_iso = expires.isoformat() if expires else None
        return {
            "bundles": [{"purchase_id": free_purchase.id,
                         "tier": None,
                         "label": (f"Free License — {free_remaining} available"
                                   if free_remaining > 0
                                   else ("Free License — expired" if expired
                                         else "Free License — used")),
                         "remaining": free_remaining,
                         "start_date": start_iso, "expiry_date": expiry_iso}]
            if free_remaining > 0 else [],
            "free": True,
            "free_license": {
                "start_date": start_iso, "expiry_date": expiry_iso,
                "remaining": free_remaining, "total": free_purchase.count,
                "used": used, "expired": expired,
            },
        }

    plan = entitlements._active_plan(db, org)
    plan_type = plan.plan_type if plan else "professional"

    # ── Safety: remove any lingering free license on paid plans ──────
    # Release device references but keep license_info (is_trial=True) so
    # the device still shows "Active (Trial)" status until reassigned.
    if not is_free_plan:
        try:
            for lp in db.scalars(select(LicensePurchase).where(
                LicensePurchase.organization_id == org.id,
                LicensePurchase.count == 1,
                LicensePurchase.total_devices == 1,
                LicensePurchase.tier.is_(None),
            )):
                for d in db.scalars(select(Device).where(
                    Device.license_purchase_id == lp.id)):
                    d.license_purchase_id = None
                    # Keep license_info so "Active (Trial)" status persists.
                db.flush()
                db.delete(lp)
            db.commit()
        except Exception:
            db.rollback()

    # ── Return individual purchases (not aggregated) ──────────────────
    # Get all active (unexpired) purchases for this org, oldest first.
    all_purchases = list(db.scalars(
        select(LicensePurchase).where(
            LicensePurchase.organization_id == org.id,
            LicensePurchase.count > 0,
        ).order_by(LicensePurchase.purchased_at.asc())))

    # Count devices per purchase (direct FK, no FIFO needed)
    consumed_by_purchase: dict[str, int] = {}
    for d in db.scalars(select(Device).where(
        Device.organization_id == org.id,
        Device.license_purchase_id.isnot(None))):
        pid = getattr(d, "license_purchase_id", None)
        if pid:
            consumed_by_purchase[pid] = consumed_by_purchase.get(pid, 0) + 1

    bundles = []
    for lp in all_purchases:
        # Total licenses this purchase provides
        if plan_type == "msp" and lp.tier:
            total_licenses = lp.count * int(lp.tier)
            tier_label = f"Tier-{lp.tier} "
        else:
            total_licenses = lp.count
            tier_label = ""

        used_here = consumed_by_purchase.get(lp.id, 0)
        remaining = max(0, total_licenses - used_here)

        # Check expiry
        expires = lp.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=tz.utc)
        expired = expires is not None and expires <= now_utc
        if expired:
            remaining = 0

        if remaining <= 0 and not lp.purchased_at:
            continue  # skip fully consumed purchases with no date

        purchased_str = lp.purchased_at.strftime("%d %b %Y") if lp.purchased_at else "—"

        bundles.append({
            "purchase_id": lp.id,
            "tier": lp.tier,
            "label": f"{tier_label}License — {remaining} left (purchased {purchased_str})",
            "remaining": remaining,
            "start_date": lp.purchased_at.isoformat() if lp.purchased_at else None,
            "expiry_date": expires.isoformat() if expires else None,
        })

    return {"bundles": bundles, "free": False}
