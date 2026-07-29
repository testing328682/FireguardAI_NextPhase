"""Alert subscription management.

Subscriptions describe where and when FirewallGuard AI should push alerts
(new critical findings, a security service being disabled, firmware
vulnerabilities, or critical configuration drift). Delivery is performed by the
worker after each analysis; see ``app.alerting``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, AlertSubscription
from ..schemas import AlertSubscriptionCreate, AlertSubscriptionOut
from ..security import current_user, require_role

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("/subscriptions", response_model=list[AlertSubscriptionOut])
def list_subscriptions(user: User = Depends(current_user),
                       db: Session = Depends(get_db)) -> list[AlertSubscription]:
    return list(db.scalars(select(AlertSubscription).where(
        AlertSubscription.organization_id == user.organization_id)))


@router.post("/subscriptions", response_model=AlertSubscriptionOut,
             status_code=status.HTTP_201_CREATED)
def create_subscription(body: AlertSubscriptionCreate,
                        user: User = Depends(require_role(Role.admin)),
                        db: Session = Depends(get_db)) -> AlertSubscription:
    sub = AlertSubscription(organization_id=user.organization_id, **body.model_dump())
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return sub


@router.delete("/subscriptions/{subscription_id}")
def delete_subscription(subscription_id: str,
                        user: User = Depends(require_role(Role.admin)),
                        db: Session = Depends(get_db)):
    sub = db.get(AlertSubscription, subscription_id)
    if sub is None or sub.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")
    db.delete(sub)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
