"""Integration management (Slack and other external systems).

Secrets such as the Slack webhook URL are stored Fernet-encrypted and never
returned by the API (responses expose ``has_secret`` only). The test action
posts a sample message through the configured webhook.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, Integration, IntegrationType
from ..schemas import IntegrationIn, IntegrationOut
from ..security import current_user, require_role
from ..crypto import encrypt, decrypt
from .. import audit, billing

router = APIRouter(prefix="/api/v1", tags=["integrations"])


def _to_out(integ: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=integ.id, type=integ.type, name=integ.name, enabled=integ.enabled,
        config=integ.config or {}, has_secret=bool(integ.encrypted_secret),
        last_status=integ.last_status, last_delivery_at=integ.last_delivery_at,
        created_at=integ.created_at)


@router.get("/integrations", response_model=list[IntegrationOut])
def list_integrations(user: User = Depends(current_user),
                      db: Session = Depends(get_db)) -> list[IntegrationOut]:
    rows = db.scalars(select(Integration).where(
        Integration.organization_id == user.organization_id))
    return [_to_out(i) for i in rows]


@router.post("/integrations", response_model=IntegrationOut, status_code=status.HTTP_201_CREATED)
def upsert_integration(body: IntegrationIn, request: Request,
                       user: User = Depends(require_role(Role.admin)),
                       db: Session = Depends(get_db)) -> IntegrationOut:
    """Create or update an integration of a given type (one per type per tenant)."""
    integ = db.scalar(select(Integration).where(
        Integration.organization_id == user.organization_id,
        Integration.type == body.type))
    if integ is None:
        billing.enforce_integration_limit(db, user.organization)
        integ = Integration(organization_id=user.organization_id, type=body.type)
        db.add(integ)
    integ.name = body.name or body.type.value
    integ.enabled = body.enabled
    config = dict(body.config or {})
    # Trackers get a stable per-integration webhook token for inbound sync.
    if body.type in (IntegrationType.jira, IntegrationType.servicenow) and not config.get("webhook_token"):
        import secrets
        config["webhook_token"] = secrets.token_urlsafe(24)
    integ.config = config
    if body.webhook_url:
        integ.encrypted_secret = encrypt(body.webhook_url)
    db.commit()
    db.refresh(integ)
    audit.log_action(db, organization_id=user.organization_id, action=audit.INTEGRATION_SAVED,
                     resource_type="integration", resource_id=integ.id, user=user,
                     request=request, after={"type": body.type.value, "enabled": body.enabled})
    return _to_out(integ)


@router.post("/integrations/{integration_id}/test")
def test_integration(integration_id: str, user: User = Depends(require_role(Role.admin)),
                     db: Session = Depends(get_db)) -> dict:
    """Send a sample message through the integration's webhook."""
    integ = db.get(Integration, integration_id)
    if integ is None or integ.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    url = decrypt(integ.encrypted_secret)
    if not url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No webhook URL configured")
    text = "FirewallGuard AI test message — your integration is configured correctly."
    try:
        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)  # noqa: S310
        integ.last_status = "ok"
    except Exception as exc:  # noqa: BLE001
        integ.last_status = "failed"
        db.commit()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Delivery failed: {exc}")
    integ.last_delivery_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok"}


@router.post("/integrations/webhooks/{system}/{token}")
async def tracker_webhook(system: str, token: str, request: Request,
                          db: Session = Depends(get_db)) -> dict:
    """Receive a Jira/ServiceNow status update and sync the linked finding.

    The webhook URL embeds a per-integration ``webhook_token`` (set in config) so
    the receiver can authenticate the caller without a session.
    """
    if system not in ("jira", "servicenow"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown tracker")
    itype = IntegrationType.jira if system == "jira" else IntegrationType.servicenow
    # Match the token against any integration of this type (multi-tenant safe:
    # the linked finding is resolved by ticket ref within its own org).
    integs = db.scalars(select(Integration).where(Integration.type == itype)).all()
    integ = next((i for i in integs if (i.config or {}).get("webhook_token") == token), None)
    if integ is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook token")

    body = await request.json()
    from .. import ticketing
    if system == "jira":
        ref = body.get("issue", {}).get("key") or body.get("key", "")
        ext_status = (body.get("issue", {}).get("fields", {}).get("status", {}).get("name")
                      or body.get("status", ""))
    else:
        ref = body.get("number", "")
        ext_status = str(body.get("state", ""))
    updated = ticketing.apply_external_status(db, system, ref, ext_status)
    return {"synced": updated, "ticket": ref}


@router.delete("/integrations/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(integration_id: str, user: User = Depends(require_role(Role.admin)),
                       db: Session = Depends(get_db)):
    integ = db.get(Integration, integration_id)
    if integ is None or integ.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    db.delete(integ)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
