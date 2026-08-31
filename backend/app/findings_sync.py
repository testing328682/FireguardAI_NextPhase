"""Persist pipeline findings into the workflow table and reconcile lifecycle.

The analysis pipeline emits findings as plain dicts inside ``result_json``. This
module turns them into tracked ``Finding`` rows that carry triage state across
scans of the same device. The reconciliation rules are:

* A finding is identified across scans by a ``fingerprint`` = rule + affected
  object. This is what makes state sticky.
* A previously **fixed** finding that is detected again is auto-reopened.
* A previously open / acknowledged / in-progress finding that is *no longer*
  detected is auto-resolved (marked fixed) — the condition went away.
* False-positive, accepted-risk and suppressed states are preserved on re-detect.
* Accepted-risk findings whose expiry has passed are reopened.

The returned summary lists findings that became Critical and newly open, which
the alerting layer uses to notify subscribers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from .models import Analysis, Finding, FindingComment, FindingStatus, CommentType

# States that a re-detected finding should keep rather than reopen.
_STICKY = {FindingStatus.false_positive, FindingStatus.accepted_risk, FindingStatus.suppressed}
# States considered "active" for auto-resolution when a finding disappears.
_ACTIVE = {FindingStatus.open, FindingStatus.acknowledged, FindingStatus.in_progress}


def fingerprint(rule_id: str, object_type: str, object_name: str) -> str:
    return f"{rule_id}::{object_type}::{object_name}"


def _system_comment(finding: Finding, org_id: str, body: str,
                    from_status: str = "", to_status: str = "") -> FindingComment:
    return FindingComment(
        organization_id=org_id, finding_id=finding.id, author_id=None,
        author_email="system", comment_type=CommentType.status_change,
        body=body, from_status=from_status, to_status=to_status)


def _content_from_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Map a pipeline finding dict to Finding column values (content only)."""
    return {
        "rule_id": d.get("rule_id", ""),
        "severity": d.get("severity", "Info"),
        "title": d.get("title", ""),
        "category": d.get("category", ""),
        "description": d.get("description", ""),
        "evidence": d.get("evidence", []),
        "business_impact": d.get("business_impact", ""),
        "technical_impact": d.get("technical_impact", ""),
        "remediation": d.get("remediation", ""),
        "verification": d.get("verification", []),
        "compliance": d.get("compliance", {}),
        "exploitability": d.get("exploitability", ""),
        "object_name": d.get("object_name", ""),
        "object_type": d.get("object_type", ""),
        "object_detail": d.get("object_detail", ""),
    }


def reopen_expired_accepted_risk(db, device_id: str) -> int:
    """Reopen accepted-risk findings on a device whose expiry has passed."""
    now = datetime.now(timezone.utc)
    expired = db.scalars(select(Finding).where(
        Finding.device_id == device_id,
        Finding.status == FindingStatus.accepted_risk,
        Finding.accepted_risk_expiry.is_not(None),
        Finding.accepted_risk_expiry < now)).all()
    for f in expired:
        prev = f.status.value
        f.status = FindingStatus.open
        f.accepted_risk_expiry = None
        f.signed_off_by = None
        db.add(_system_comment(f, f.organization_id,
                               "Accepted-risk window expired; finding reopened.",
                               from_status=prev, to_status="open"))
    if expired:
        db.commit()
    return len(expired)


def sync_findings(db, analysis: Analysis) -> dict[str, Any]:
    """Reconcile the analysis result into ``Finding`` rows.

    Returns a summary dict including ``new_critical`` (list of finding rows that
    are newly open and Critical) for downstream alerting.
    """
    result = analysis.result_json or {}
    incoming = result.get("findings", [])
    now = datetime.now(timezone.utc)

    reopen_expired_accepted_risk(db, analysis.device_id)

    # Existing findings on this device, indexed by fingerprint (latest wins).
    # Manual findings are excluded from reconciliation — they persist independently.
    existing = db.scalars(select(Finding).where(
        Finding.device_id == analysis.device_id)).all()
    by_fp: dict[str, Finding] = {}
    resolved = 0
    for f in sorted(existing,
                    key=lambda r: ((r.last_seen_at or r.first_seen_at or now), r.id)):
        if f.source == "manual":
            continue
        shadowed = by_fp.get(f.fingerprint)
        by_fp[f.fingerprint] = f
        if shadowed is not None and shadowed.status in _ACTIVE:
            # Two rows sharing one identity are an artifact (historically
            # possible when several objects collapsed to the same
            # fingerprint). Keep the newest row; resolve the shadowed one so
            # it cannot linger open forever outside reconciliation.
            prev_status = shadowed.status.value
            shadowed.status = FindingStatus.fixed
            shadowed.resolved_at = now
            db.add(_system_comment(shadowed, analysis.organization_id,
                                   "Duplicate finding identity superseded by a newer record; auto-resolved.",
                                   from_status=prev_status, to_status="fixed"))
            resolved += 1

    seen: set[str] = set()
    new_critical: list[Finding] = []
    created = reopened = updated = 0

    for d in incoming:
        fp = fingerprint(d.get("rule_id", ""), d.get("object_type", ""), d.get("object_name", ""))
        if fp in seen:
            # Two findings in one analysis collapsing to the same identity
            # must not insert duplicate rows — the first occurrence wins.
            continue
        seen.add(fp)
        content = _content_from_dict(d)
        prior = by_fp.get(fp)

        if prior is None:
            row = Finding(
                organization_id=analysis.organization_id, device_id=analysis.device_id,
                analysis_id=analysis.id, fingerprint=fp,
                status=FindingStatus.open, first_seen_at=now, last_seen_at=now,
                **content)
            db.add(row)
            db.flush()
            created += 1
            if row.severity == "Critical":
                new_critical.append(row)
            continue

        # Refresh content + provenance on every re-detect.
        for k, v in content.items():
            setattr(prior, k, v)
        prior.analysis_id = analysis.id
        prior.last_seen_at = now

        if prior.status == FindingStatus.fixed:
            prior.status = FindingStatus.open
            prior.resolved_at = None
            db.add(_system_comment(prior, analysis.organization_id,
                                   "Condition still present on rescan; finding auto-reopened.",
                                   from_status="fixed", to_status="open"))
            reopened += 1
            if prior.severity == "Critical":
                new_critical.append(prior)
        elif prior.status in _STICKY:
            pass  # keep suppressed/false-positive/accepted-risk state
        else:
            updated += 1

    # Findings that disappeared from the scan: auto-resolve active ones.
    # Manual findings are never auto-resolved.
    for fp, f in by_fp.items():
        if fp in seen:
            continue
        if f.source == "manual":
            continue
        if f.status in _ACTIVE:
            f.status = FindingStatus.fixed
            f.resolved_at = now
            db.add(_system_comment(f, analysis.organization_id,
                                   "Condition no longer detected; finding auto-resolved.",
                                   from_status=f.status.value, to_status="fixed"))
            resolved += 1

    db.commit()
    return {"created": created, "reopened": reopened, "updated": updated,
            "resolved": resolved, "new_critical": new_critical}
