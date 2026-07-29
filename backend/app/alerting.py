"""Alert evaluation and delivery.

After an analysis completes the worker calls ``evaluate_and_send_alerts``. For
each active subscription in the organization it checks the configured triggers
against the new analysis (and its drift event, if any) and delivers a message
over the subscription's channel - email via SMTP, or an HTTP webhook POST.

Delivery failures are logged and swallowed so that a broken alert target never
fails an otherwise successful analysis.
"""

from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage

from sqlalchemy import select

from .config import get_settings
from .models import (
    Analysis, AlertSubscription, AlertChannel, DriftEvent, Device, User,
    Integration, IntegrationType,
)
from .crypto import decrypt

logger = logging.getLogger("firewallguard.alerting")
settings = get_settings()


def send_slack(db, organization_id: str, event_key: str, text: str) -> None:
    """Post ``text`` to every enabled Slack integration opted into ``event_key``.

    ``event_key`` is one of ``new_critical`` / ``scan_failed`` / ``weekly_digest``;
    the integration's ``config`` holds per-event toggles (default on).
    """
    import urllib.request
    integrations = db.scalars(select(Integration).where(
        Integration.organization_id == organization_id,
        Integration.type == IntegrationType.slack,
        Integration.enabled.is_(True)))
    for integ in integrations:
        if not (integ.config or {}).get(event_key, True):
            continue
        url = decrypt(integ.encrypted_secret)
        if not url:
            continue
        try:
            payload = json.dumps({"text": text}).encode("utf-8")
            req = urllib.request.Request(url, data=payload,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)  # noqa: S310 - operator-configured webhook
        except Exception as exc:  # noqa: BLE001
            logger.warning("Slack delivery failed for org %s: %s", organization_id, exc)


def _build_message(analysis: Analysis, drift: DriftEvent | None,
                   sub: AlertSubscription) -> tuple[str, str] | None:
    reasons: list[str] = []
    result = analysis.result_json or {}
    device = result.get("device", {})

    if sub.on_new_critical and analysis.critical_count > 0:
        reasons.append(f"{analysis.critical_count} critical finding(s)")
    if sub.on_firmware_vuln and result.get("firmware_intelligence", {}).get("advisory_count", 0) > 0:
        reasons.append("firmware matched a published advisory")
    if sub.on_service_disabled and drift is not None:
        for a in drift.alerts:
            if a.get("category") == "Security Services" and a.get("change_type") == "changed" \
                    and a.get("current_state") == "Disabled":
                reasons.append(f"{a.get('title')}")
    if sub.on_critical_drift and drift is not None:
        if drift.severity_counts.get("Critical", 0) > 0:
            reasons.append("critical configuration drift detected")

    if not reasons:
        return None

    subject = (f"[FirewallGuard AI] {device.get('model','Device')} "
               f"{device.get('serial','')} - grade {analysis.grade} ({analysis.score:.0f}/100)")
    body = (
        f"FirewallGuard AI analysis for {device.get('model')} (serial {device.get('serial')}).\n\n"
        f"Security score: {analysis.score:.0f}/100  Grade: {analysis.grade}\n"
        f"Findings: {analysis.finding_count} "
        f"({analysis.critical_count} critical, {analysis.high_count} high)\n\n"
        f"Alert triggered by: {', '.join(reasons)}.\n\n"
        "Sign in to FirewallGuard AI to review findings, attack paths and remediation."
    )
    return subject, body


def _send_email(target: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = settings.alert_from_address
    msg["To"] = target
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.send_message(msg)


def _send_webhook(target: str, subject: str, body: str, analysis: Analysis) -> None:
    import urllib.request
    payload = json.dumps({
        "subject": subject, "body": body,
        "score": analysis.score, "grade": analysis.grade,
        "critical": analysis.critical_count, "high": analysis.high_count,
        "device": (analysis.result_json or {}).get("device", {}),
    }).encode("utf-8")
    req = urllib.request.Request(target, data=payload,
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)  # noqa: S310 - target is operator-configured


def _notify_users(db, org_id: str, pref_attr: str, subject: str, body: str) -> None:
    """Email every active org user who has opted into ``pref_attr``."""
    users = db.scalars(select(User).where(
        User.organization_id == org_id, User.is_active.is_(True)))
    for user in users:
        if not getattr(user, pref_attr, False):
            continue
        try:
            _send_email(user.email, subject, body)
        except Exception as exc:  # noqa: BLE001
            logger.warning("User notification failed for %s: %s", user.email, exc)


def evaluate_and_send_alerts(db, analysis: Analysis, new_critical: list | None = None) -> None:
    drift = db.scalar(
        select(DriftEvent).where(DriftEvent.current_analysis_id == analysis.id))
    subs = db.scalars(select(AlertSubscription).where(
        AlertSubscription.organization_id == analysis.organization_id))
    for sub in subs:
        built = _build_message(analysis, drift, sub)
        if built is None:
            continue
        subject, body = built
        try:
            if sub.channel == AlertChannel.email:
                _send_email(sub.target, subject, body)
            else:
                _send_webhook(sub.target, subject, body, analysis)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Alert delivery failed for %s: %s", sub.target, exc)

    # Per-user notifications for newly-open critical findings.
    if new_critical:
        device = (analysis.result_json or {}).get("device", {})
        titles = "\n".join(f"  - {f.title}" for f in new_critical[:10])
        subject = (f"[FirewallGuard AI] {len(new_critical)} new critical finding(s) "
                   f"on {device.get('model','device')} {device.get('serial','')}")
        body = (
            f"A new analysis surfaced {len(new_critical)} new critical finding(s):\n\n"
            f"{titles}\n\n"
            f"Security score: {analysis.score:.0f}/100  Grade: {analysis.grade}\n\n"
            "Sign in to FirewallGuard AI to triage these findings."
        )
        _notify_users(db, analysis.organization_id, "notify_new_critical", subject, body)
        send_slack(db, analysis.organization_id, "new_critical", f"*{subject}*\n{body}")


def send_scan_failure_alert(db, analysis: Analysis) -> None:
    """Notify opted-in users that an analysis failed."""
    device = db.get(Device, analysis.device_id)
    serial = device.serial if device else analysis.device_id
    subject = f"[FirewallGuard AI] Scan failed for device {serial}"
    body = (
        f"An analysis for device {serial} failed to complete.\n\n"
        f"Error: {analysis.error or 'unknown error'}\n\n"
        "Sign in to FirewallGuard AI to review and retry."
    )
    _notify_users(db, analysis.organization_id, "notify_scan_failed", subject, body)
    send_slack(db, analysis.organization_id, "scan_failed", f"*{subject}*\n{body}")
