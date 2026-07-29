"""Organization and billing endpoints (plan management, trial, Stripe)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import User, Role, Organization
from ..schemas import (
    OrganizationDetail, OrganizationUpdate, CheckoutRequest, CheckoutResponse,
)
from ..security import current_user, require_role
from .. import billing, audit

router = APIRouter(prefix="/api/v1", tags=["billing"])
settings = get_settings()


def _org(db: Session, user: User) -> Organization:
    return db.get(Organization, user.organization_id)


@router.get("/organization", response_model=OrganizationDetail)
def get_organization(user: User = Depends(current_user),
                     db: Session = Depends(get_db)) -> OrganizationDetail:
    # Opportunistically downgrade an expired trial on read.
    billing.downgrade_expired_trials(db)
    org = _org(db, user)
    return _detail(org)


@router.patch("/organization/visibility", response_model=OrganizationDetail)
def update_org_visibility(body: dict,
                          user: User = Depends(require_role(Role.admin)),
                          db: Session = Depends(get_db)):
    """Update organization-level findings visibility (hidden severities)."""
    org = _org(db, user)
    if "hidden_severities" in body:
        org.hidden_severities = body["hidden_severities"]
    db.commit()
    return _detail(org)


def _detail(org: Organization) -> OrganizationDetail:
    return OrganizationDetail(
        id=org.id, name=org.name, is_msp=org.is_msp, plan=org.plan,
        subscription_status=org.subscription_status, trial_ends_at=org.trial_ends_at,
        has_stripe_customer=bool(org.stripe_customer_id), region=org.region,
        data_retention_days=org.data_retention_days,
        brand_company_name=org.brand_company_name, brand_logo_url=org.brand_logo_url,
        brand_primary_color=org.brand_primary_color, brand_contact=org.brand_contact,
        hidden_severities=org.hidden_severities or [])


@router.get("/regions")
def regions() -> dict:
    """Available data-residency regions (for sign-up and settings)."""
    return {"regions": settings.regions, "default": settings.default_region}


@router.patch("/organization", response_model=OrganizationDetail)
def update_organization(body: OrganizationUpdate, request: Request,
                        user: User = Depends(require_role(Role.admin)),
                        db: Session = Depends(get_db)) -> OrganizationDetail:
    """Update org settings: name, data residency region, branding, retention."""
    from fastapi import HTTPException
    org = _org(db, user)
    if body.region is not None and body.region not in settings.regions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown region")
    for field in ("name", "region", "data_retention_days", "brand_company_name",
                  "brand_logo_url", "brand_primary_color", "brand_contact"):
        val = getattr(body, field)
        if val is not None:
            setattr(org, field, val)
    db.commit()
    audit.log_action(db, organization_id=org.id, action="organization.updated",
                     resource_type="organization", resource_id=org.id, user=user, request=request)
    return _detail(org)


@router.post("/billing/start-trial", response_model=OrganizationDetail)
def start_trial(request: Request, user: User = Depends(require_role(Role.admin)),
                db: Session = Depends(get_db)) -> OrganizationDetail:
    org = _org(db, user)
    if org.subscription_status in ("trialing", "active"):
        from fastapi import HTTPException
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Organization already has an active plan or trial")
    billing.start_trial(db, org)
    audit.log_action(db, organization_id=org.id, action="billing.trial_started",
                     resource_type="organization", resource_id=org.id, user=user, request=request)
    return get_organization(user, db)


@router.post("/billing/checkout", response_model=CheckoutResponse)
def checkout(body: CheckoutRequest, request: Request,
             user: User = Depends(require_role(Role.admin)),
             db: Session = Depends(get_db)) -> CheckoutResponse:
    org = _org(db, user)
    result = billing.create_checkout(db, org, body.plan)
    audit.log_action(db, organization_id=org.id, action="billing.checkout",
                     resource_type="organization", resource_id=org.id, user=user, request=request,
                     after={"plan": body.plan.value, "mode": result["mode"]})
    return CheckoutResponse(**result)


@router.post("/billing/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)) -> dict:
    """Stripe webhook receiver. Verifies the signature when a secret is set."""
    payload = await request.body()
    event: dict
    if settings.stripe_api_key and settings.stripe_webhook_secret:
        import stripe
        try:
            event = stripe.Webhook.construct_event(
                payload, request.headers.get("stripe-signature", ""),
                settings.stripe_webhook_secret)
        except Exception:  # noqa: BLE001
            from fastapi import HTTPException
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Invalid Stripe signature")
    else:
        import json
        event = json.loads(payload or b"{}")
    billing.handle_stripe_event(db, event)
    return {"received": True}
