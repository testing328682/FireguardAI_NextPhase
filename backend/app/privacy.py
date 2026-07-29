"""GDPR data export and right-to-erasure.

``export_user_data`` returns a JSON-serialisable bundle of a user's personal
data and activity. ``erase_user`` anonymises a user's PII while preserving
records that must be retained for security and compliance (audit log entries,
finding history) — those are anonymised rather than deleted. The set of
retention exceptions is returned so the action is self-documenting.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import User, Organization, Finding, FindingComment, AuditLog, ApiToken
from .security import hash_password

# Records intentionally NOT deleted on erasure (anonymised instead), with the
# legal/operational basis. Returned to the caller for transparency.
RETENTION_EXCEPTIONS = [
    {"record": "audit_logs",
     "basis": "Security & SOC 2 audit trail; anonymised (email removed), not deleted."},
    {"record": "finding_comments",
     "basis": "Investigation history integrity; author email anonymised."},
]


def export_user_data(db: Session, user: User) -> dict:
    """Return all personal data held for ``user`` as a JSON-safe dict."""
    org = db.get(Organization, user.organization_id)
    comments = db.scalars(select(FindingComment).where(
        FindingComment.author_id == user.id)).all()
    assigned = db.scalars(select(Finding).where(Finding.assignee_id == user.id)).all()
    audit = db.scalars(select(AuditLog).where(AuditLog.user_id == user.id)
                       .order_by(AuditLog.created_at.desc()).limit(1000)).all()
    tokens = db.scalars(select(ApiToken).where(ApiToken.created_by == user.id)).all()

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "user": {
            "id": user.id, "email": user.email, "full_name": user.full_name,
            "role": user.role.value, "mfa_enabled": user.mfa_enabled,
            "notify_new_critical": user.notify_new_critical,
            "notify_scan_failed": user.notify_scan_failed,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "organization": {"id": org.id, "name": org.name, "region": org.region} if org else {},
        "authored_comments": [
            {"id": c.id, "finding_id": c.finding_id, "body": c.body,
             "created_at": c.created_at.isoformat() if c.created_at else None}
            for c in comments],
        "assigned_findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "status": f.status.value}
            for f in assigned],
        "api_tokens": [
            {"id": t.id, "name": t.name, "prefix": t.prefix, "revoked": t.revoked}
            for t in tokens],
        "audit_events": [
            {"action": a.action, "resource_type": a.resource_type,
             "resource_id": a.resource_id, "ip_address": a.ip_address,
             "created_at": a.created_at.isoformat() if a.created_at else None}
            for a in audit],
    }


def erase_user(db: Session, user: User) -> dict:
    """Anonymise a user's PII, preserving compliance records (anonymised).

    Returns a summary including the retention exceptions applied.
    """
    placeholder = f"erased-{user.id[:8]}@deleted.invalid"

    # Anonymise authored comments and audit entries rather than delete them.
    for c in db.scalars(select(FindingComment).where(FindingComment.author_id == user.id)):
        c.author_email = "erased-user"
        c.author_id = None
    for a in db.scalars(select(AuditLog).where(AuditLog.user_id == user.id)):
        a.user_email = "erased-user"
    # Unassign open findings.
    for f in db.scalars(select(Finding).where(Finding.assignee_id == user.id)):
        f.assignee_id = None
    # Revoke API tokens created by the user.
    for t in db.scalars(select(ApiToken).where(ApiToken.created_by == user.id)):
        t.revoked = True

    # Scrub the user record itself.
    user.email = placeholder
    user.full_name = ""
    user.hashed_password = hash_password(secrets.token_urlsafe(32))
    user.is_active = False
    user.mfa_enabled = False
    user.totp_secret = ""
    user.backup_codes = []
    db.commit()

    return {"erased_user_id": user.id, "anonymized_email": placeholder,
            "retention_exceptions": RETENTION_EXCEPTIONS}
