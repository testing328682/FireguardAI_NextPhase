"""Jira and ServiceNow ticketing.

When a finding is acknowledged, ``maybe_create_ticket`` opens an issue in the
tenant's configured tracker (if ``auto_create`` is on) and records the
reference, URL and status on the finding. ``apply_external_status`` maps a
tracker's status back onto the finding for bidirectional sync via the webhook
receivers.

Tracker config lives in the ``Integration`` row: non-secret options in
``config`` (base URL, project/table, username, field map, ``auto_create``,
``webhook_token``) and the API token/password Fernet-encrypted in
``encrypted_secret``.
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.request
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Integration, IntegrationType, Finding, FindingStatus, FindingComment, CommentType
from .crypto import decrypt

logger = logging.getLogger("firewallguard.ticketing")


class TicketingError(Exception):
    pass


def _post(url: str, payload: dict, auth_user: str, auth_secret: str) -> dict:
    raw = json.dumps(payload).encode()
    token = base64.b64encode(f"{auth_user}:{auth_secret}".encode()).decode()
    req = urllib.request.Request(url, data=raw, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "Authorization": f"Basic {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - operator-configured
            return json.loads(resp.read() or b"{}")
    except Exception as exc:  # noqa: BLE001
        raise TicketingError(str(exc)) from exc


def create_jira_issue(cfg: dict, secret: str, finding: Finding) -> dict:
    base = cfg.get("base_url", "").rstrip("/")
    project = cfg.get("project", "")
    issue_type = cfg.get("issue_type", "Task")
    payload = {"fields": {
        "project": {"key": project},
        "summary": f"[{finding.severity}] {finding.title}",
        "description": (f"{finding.description}\n\nRemediation: {finding.remediation}\n\n"
                        f"FirewallGuard finding {finding.id} (rule {finding.rule_id})."),
        "issuetype": {"name": issue_type}}}
    data = _post(f"{base}/rest/api/2/issue", payload, cfg.get("username", ""), secret)
    key = data.get("key", "")
    return {"ref": key, "url": f"{base}/browse/{key}" if key else "", "status": "Open"}


def create_servicenow_incident(cfg: dict, secret: str, finding: Finding) -> dict:
    instance = cfg.get("instance_url", "").rstrip("/")
    table = cfg.get("table", "incident")
    payload = {"short_description": f"[{finding.severity}] {finding.title}",
               "description": f"{finding.description}\n\nRemediation: {finding.remediation}",
               "category": "security"}
    data = _post(f"{instance}/api/now/table/{table}", payload, cfg.get("username", ""), secret)
    result = data.get("result", {})
    number = result.get("number", "")
    sys_id = result.get("sys_id", "")
    return {"ref": number,
            "url": f"{instance}/nav_to.do?uri={table}.do?sys_id={sys_id}" if sys_id else "",
            "status": result.get("state", "New")}


def _tracker_integration(db: Session, organization_id: str) -> Integration | None:
    return db.scalar(select(Integration).where(
        Integration.organization_id == organization_id,
        Integration.type.in_([IntegrationType.jira, IntegrationType.servicenow]),
        Integration.enabled.is_(True)))


def maybe_create_ticket(db: Session, finding: Finding) -> bool:
    """Create a tracker ticket for a finding if a tracker is set to auto-create."""
    if finding.ticket_ref:
        return False
    integ = _tracker_integration(db, finding.organization_id)
    if integ is None or not (integ.config or {}).get("auto_create"):
        return False
    secret = decrypt(integ.encrypted_secret)
    try:
        if integ.type == IntegrationType.jira:
            res = create_jira_issue(integ.config, secret, finding)
            system = "jira"
        else:
            res = create_servicenow_incident(integ.config, secret, finding)
            system = "servicenow"
    except TicketingError as exc:
        logger.warning("Ticket creation failed for finding %s: %s", finding.id, exc)
        return False
    finding.ticket_system = system
    finding.ticket_ref = res["ref"]
    finding.ticket_url = res["url"]
    finding.ticket_status = res["status"]
    db.commit()
    return True


# External tracker status -> finding status (best-effort mapping).
_JIRA_MAP = {"done": FindingStatus.fixed, "resolved": FindingStatus.fixed,
             "closed": FindingStatus.fixed, "in progress": FindingStatus.in_progress,
             "in review": FindingStatus.in_progress}
_SNOW_MAP = {"6": FindingStatus.fixed, "7": FindingStatus.fixed, "2": FindingStatus.in_progress}


def apply_external_status(db: Session, system: str, ticket_ref: str, external_status: str) -> bool:
    """Update the finding linked to a ticket when its tracker status changes."""
    finding = db.scalar(select(Finding).where(
        Finding.ticket_system == system, Finding.ticket_ref == ticket_ref))
    if finding is None:
        return False
    finding.ticket_status = external_status
    mapping = _JIRA_MAP if system == "jira" else _SNOW_MAP
    new_status = mapping.get(str(external_status).lower())
    if new_status is not None and finding.status != new_status:
        prev = finding.status.value
        finding.status = new_status
        if new_status == FindingStatus.fixed:
            finding.resolved_at = datetime.now(timezone.utc)
        db.add(FindingComment(
            organization_id=finding.organization_id, finding_id=finding.id, author_id=None,
            author_email=f"{system}-sync", comment_type=CommentType.status_change,
            body=f"Synced from {system} ticket {ticket_ref} ({external_status}).",
            from_status=prev, to_status=new_status.value))
    db.commit()
    return True
