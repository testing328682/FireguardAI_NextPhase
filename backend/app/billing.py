"""Billing and plan-limit enforcement.

Plan limits (device count, scheduled scans, integrations) are enforced at the
API layer from ``settings.plan_limits``. Stripe is optional: when
``settings.stripe_api_key`` is unset the module runs in *local mode* — checkout
immediately applies the requested plan so the product is fully usable in
development without Stripe. A 14-day trial grants Professional features and
downgrades to Free on expiry.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Organization, Device, Schedule, Integration, PlanTier

logger = logging.getLogger("firewallguard.billing")
settings = get_settings()


def _limit(plan: PlanTier, key: str) -> int:
    return settings.plan_limits.get(plan.value, {}).get(key, 0)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def effective_plan(org: Organization) -> PlanTier:
    """Plan after accounting for an expired trial (without mutating the row)."""
    if org.subscription_status == "trialing":
        ends = _aware(org.trial_ends_at)
        if ends and ends < datetime.now(timezone.utc):
            return PlanTier.free
    return org.plan


def enforce_device_limit(db: Session, org: Organization) -> None:
    """Enforce the org's device limit.

    ``org.device_count`` (set from purchased dynamic-plan licenses) takes
    precedence when configured. When it is 0 — no licenses purchased yet, or
    no dynamic plan selected — fall back to the static per-plan-tier limit
    from ``settings.plan_limits`` (e.g. 1 device on Free) rather than treating
    the org as unlimited.
    """
    count = db.scalar(select(func.count(Device.id)).where(
        Device.organization_id == org.id)) or 0
    max_devices = org.device_count or _limit(effective_plan(org), "devices")
    if max_devices > 0 and count >= max_devices:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail=f"Device limit reached ({max_devices}). Upgrade to add more.")


def enforce_schedule_limit(db: Session, org: Organization) -> None:
    count = db.scalar(select(func.count(Schedule.id)).where(
        Schedule.organization_id == org.id)) or 0
    if count >= _limit(effective_plan(org), "schedules"):
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail="Scheduled-scan limit reached for your plan.")


def enforce_integration_limit(db: Session, org: Organization) -> None:
    count = db.scalar(select(func.count(Integration.id)).where(
        Integration.organization_id == org.id)) or 0
    if count >= _limit(effective_plan(org), "integrations"):
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail="Integration limit reached for your plan.")


def start_trial(db: Session, org: Organization) -> None:
    """Begin a 14-day Professional trial."""
    org.subscription_status = "trialing"
    org.trial_ends_at = datetime.now(timezone.utc) + timedelta(days=settings.trial_days)
    org.plan = PlanTier.professional
    db.commit()


def downgrade_expired_trials(db: Session) -> int:
    """Downgrade trialing orgs whose trial has lapsed to Free."""
    now = datetime.now(timezone.utc)
    orgs = db.scalars(select(Organization).where(
        Organization.subscription_status == "trialing")).all()
    n = 0
    for org in orgs:
        ends = _aware(org.trial_ends_at)
        if ends and ends < now:
            org.plan = PlanTier.free
            org.subscription_status = "none"
            org.trial_ends_at = None
            n += 1
    if n:
        db.commit()
    return n


def _price_for(plan: PlanTier) -> str:
    return {PlanTier.professional: settings.stripe_price_professional,
            PlanTier.msp: settings.stripe_price_msp}.get(plan, "")


def create_checkout(db: Session, org: Organization, plan: PlanTier) -> dict:
    """Create a Stripe Checkout session, or apply the plan directly in local mode."""
    if plan == PlanTier.free:
        org.plan = PlanTier.free
        org.subscription_status = "none"
        db.commit()
        return {"mode": "local", "url": None, "message": "Downgraded to Free."}

    if not settings.stripe_api_key:
        # Local/dev mode: no Stripe configured — apply the plan immediately.
        org.plan = plan
        org.subscription_status = "active"
        db.commit()
        return {"mode": "local", "url": None,
                "message": f"Stripe not configured; applied {plan.value} plan locally."}

    import stripe
    stripe.api_key = settings.stripe_api_key
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": _price_for(plan), "quantity": 1}],
            success_url=f"{settings.public_app_url}/#/settings/organization?billing=success",
            cancel_url=f"{settings.public_app_url}/#/settings/organization?billing=cancel",
            client_reference_id=org.id,
            customer=org.stripe_customer_id or None,
            metadata={"organization_id": org.id, "plan": plan.value})
    except Exception as exc:  # noqa: BLE001
        logger.error("Stripe checkout failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Stripe error: {exc}")
    return {"mode": "stripe", "url": session.url, "message": ""}


def handle_stripe_event(db: Session, event: dict) -> None:
    """Apply a Stripe webhook event to the organization's subscription state."""
    etype = event.get("type", "")
    obj = event.get("data", {}).get("object", {})
    org_id = (obj.get("metadata", {}) or {}).get("organization_id") or obj.get("client_reference_id")
    if not org_id:
        return
    org = db.get(Organization, org_id)
    if org is None:
        return
    if etype in ("checkout.session.completed", "customer.subscription.updated"):
        plan = (obj.get("metadata", {}) or {}).get("plan")
        if plan in (PlanTier.professional.value, PlanTier.msp.value):
            org.plan = PlanTier(plan)
        org.subscription_status = "active"
        if obj.get("customer"):
            org.stripe_customer_id = obj["customer"]
        if obj.get("subscription"):
            org.stripe_subscription_id = obj["subscription"]
    elif etype in ("customer.subscription.deleted", "invoice.payment_failed"):
        org.subscription_status = "canceled"
        org.plan = PlanTier.free
    db.commit()
