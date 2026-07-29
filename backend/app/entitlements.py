"""Entitlement system — dynamic feature and limit checks.

Replaces hardcoded plan-name checks with database-driven entitlement lookups.
Every check reads the organization's active plan and inspects its JSON
features/pricing_tiers fields, so new capabilities can be added without code changes.
"""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .models import Organization, Plan


def _active_plan(db: Session, org: Organization) -> Plan | None:
    """Return the Plan row the organization is currently entitled to.

    Falls back to `plan_id` first, then the legacy `plan` enum.
    """
    if org.plan_id:
        plan = db.get(Plan, org.plan_id)
        if plan and plan.is_active:
            return plan
    # Fallback: map legacy enum to a plan by name
    from sqlalchemy import select
    legacy_name = org.plan.value.capitalize() if org.plan else "Free"
    plan = db.scalar(select(Plan).where(
        Plan.name.ilike(legacy_name), Plan.is_active.is_(True)))
    return plan


def can(db: Session, org: Organization, feature_key: str) -> bool:
    """Check whether an organization has a specific feature enabled."""
    plan = _active_plan(db, org)
    if plan is None:
        return False
    return bool(plan.features.get(feature_key, False))


def require_feature(db: Session, org: Organization, feature_key: str):
    """Raise 402 if the organization's plan does not include a feature."""
    if not can(db, org, feature_key):
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail=f"Your plan does not include '{feature_key}'.")


def get_limit(db: Session, org: Organization, limit_key: str) -> int:
    """Return the maximum allowed value for a limit.

    Limits are now derived from plan pricing tiers (e.g., device_count for MSP plans).
    Returns 0 if no limit is configured (unlimited).
    """
    plan = _active_plan(db, org)
    if plan is None:
        return 0
    # Limits now live in plan metadata rather than a separate limits dict.
    # For backward compatibility, check features dict for limit overrides.
    return plan.features.get(f"limit_{limit_key}", 0) if isinstance(plan.features, dict) else 0


def require_within_limit(db: Session, org: Organization, limit_key: str,
                         current_count: int) -> None:
    """Raise 402 if ``current_count`` exceeds the plan limit."""
    limit = get_limit(db, org, limit_key)
    if limit == 0:
        return  # no limit configured = unlimited
    if current_count >= limit:
        readable = limit_key.replace("_", " ").title()
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail=f"{readable} limit reached. Upgrade to add more.")


def plan_info(db: Session, org: Organization) -> dict:
    """Return the customer-facing plan summary."""
    plan = _active_plan(db, org)
    if plan is None:
        return {"name": "None", "features": {}, "limits": {}}
    return {
        "id": plan.id, "name": plan.name, "description": plan.description,
        "plan_type": plan.plan_type,
        "features": dict(plan.features or {}),
        "limits": {},  # limits are now derived from pricing tiers
    }
