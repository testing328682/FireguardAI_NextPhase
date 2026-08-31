"""Append-only audit logging.

``log_action`` writes one immutable ``AuditLog`` row per privileged action. It
is deliberately defensive: an audit-write failure must never break the action
being audited, so all errors are swallowed (and rolled back) rather than raised.

Callers pass ``before``/``after`` snapshots of the affected resource; helper
``model_snapshot`` extracts a JSON-safe subset of a model's columns.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User

logger = logging.getLogger("firewallguard.audit")

# Common action verbs, kept as constants so spellings stay consistent.
LOGIN = "auth.login"
LOGIN_FAILED = "auth.login_failed"
LOGOUT = "auth.logout"
MFA_ENABLED = "auth.mfa_enabled"
MFA_DISABLED = "auth.mfa_disabled"
USER_CREATED = "user.created"
CUSTOMER_CREATED = "customer.created"
DEVICE_CREATED = "device.created"
DEVICE_CONNECTED = "device.connected"
TSR_UPLOADED = "tsr.uploaded"
RULE_CREATED = "rule.created"
RULE_UPDATED = "rule.updated"
RULE_DELETED = "rule.deleted"
RULE_STATE_CHANGED = "rule.state_changed"
SUPPRESSION_CREATED = "rule.suppression_created"
INTEGRATION_SAVED = "integration.saved"
API_TOKEN_CREATED = "api_token.created"
API_TOKEN_REVOKED = "api_token.revoked"
FINDING_STATUS_CHANGED = "finding.status_changed"
FINDING_ASSIGNED = "finding.assigned"
DEVICE_CHANGED = "device.changed"
SCHEDULE_CHANGED = "schedule.changed"
SCHEDULE_DELETED = "schedule.deleted"


def model_snapshot(obj: Any, fields: tuple[str, ...]) -> dict:
    """Return a JSON-safe dict of selected attributes from a model instance."""
    out: dict[str, Any] = {}
    for f in fields:
        val = getattr(obj, f, None)
        out[f] = val.value if hasattr(val, "value") else (
            val if isinstance(val, (str, int, float, bool, type(None))) else str(val))
    return out


def client_meta(request: Optional[Request]) -> tuple[str, str]:
    """Extract (ip_address, user_agent) from a request, tolerating None."""
    if request is None:
        return "", ""
    ip = request.client.host if request.client else ""
    return ip, request.headers.get("user-agent", "")[:512]


def log_action(db: Session, *, organization_id: str,
               action: str, resource_type: str, resource_id: str = "",
               user: Optional[User] = None,
               before: Optional[dict] = None, after: Optional[dict] = None,
               request: Optional[Request] = None,
               user_email: str = "", user_id: str = "") -> None:
    """Write an audit row. Never raises."""
    ip, ua = client_meta(request)
    try:
        entry = AuditLog(
            organization_id=organization_id,
            user_id=(user.id if user else user_id) or None,
            user_email=(user.email if user else user_email),
            action=action, resource_type=resource_type, resource_id=resource_id or "",
            before=before or {}, after=after or {},
            ip_address=ip, user_agent=ua)
        db.add(entry)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - auditing must never break the action
        logger.warning("Audit write failed for %s: %s", action, exc)
        db.rollback()
