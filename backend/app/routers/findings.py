"""Finding workflow endpoints.

Findings are persisted per analysis (see ``findings_sync``) and tracked through
a triage lifecycle. This router exposes a cross-device explorer, per-finding
detail, state transitions (each requiring a comment), assignment, comments and
bulk actions. All queries are scoped to the caller's organization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    User, Role, Finding, FindingComment, FindingStatus, CommentType,
    Analysis, AnalysisStatus,
)
from ..schemas import (
    FindingSummary, FindingDetail, FindingTransition, FindingAssign,
    FindingCommentOut, FindingCommentCreate, BulkTransition,
    ManualFindingUpdate, FindingGroupSummary, FindingGroupDetail,
    FindingGroupTransition,
)
from ..security import current_user, require_role, _ROLE_RANK
from .. import audit
from .. import finding_groups

router = APIRouter(prefix="/api/v1", tags=["findings"])

# Permitted state transitions. A finding instance may move directly between
# any two of the six triage statuses at any time (an affected object that is
# e.g. already Fixed can be moved straight to Accepted Risk without detouring
# through Open first) — the only remaining restrictions are the admin-only
# gate and the justification/expiry requirements below, not the state graph.
_ALL_STATUSES = set(FindingStatus)
_ALLOWED: dict[FindingStatus, set[FindingStatus]] = {
    s: _ALL_STATUSES - {s} for s in _ALL_STATUSES
}
# States that only an admin (or higher) may set.
_ADMIN_ONLY = {FindingStatus.suppressed, FindingStatus.accepted_risk}
_TERMINAL_RESOLVED = {FindingStatus.fixed, FindingStatus.false_positive}


def _get_finding(db: Session, finding_id: str, user: User) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None or f.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return f


def _apply_transition(db: Session, f: Finding, body: FindingTransition,
                      user: User, request: Optional[Request]) -> None:
    target = body.to_status
    current = f.status
    if target == current:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Finding is already {current.value}")
    if target not in _ALLOWED.get(current, set()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Cannot move a finding from {current.value} to {target.value}")
    if target in _ADMIN_ONLY and _ROLE_RANK[user.role] < _ROLE_RANK[Role.admin]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Only an admin may set status '{target.value}'")
    if target in (FindingStatus.false_positive, FindingStatus.accepted_risk) and not body.justification:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"A justification is required to set '{target.value}'")
    if target == FindingStatus.accepted_risk and body.accepted_risk_expiry is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="An accepted-risk expiry date is required")

    now = datetime.now(timezone.utc)
    f.status = target
    if body.justification is not None:
        f.justification = body.justification
    if body.ticket_ref is not None:
        f.ticket_ref = body.ticket_ref
    if target == FindingStatus.accepted_risk:
        f.accepted_risk_expiry = body.accepted_risk_expiry
        f.signed_off_by = user.id
    f.resolved_at = now if target in _TERMINAL_RESOLVED else None

    db.add(FindingComment(
        organization_id=f.organization_id, finding_id=f.id, author_id=user.id,
        author_email=user.email, comment_type=CommentType.status_change,
        body=body.comment, from_status=current.value, to_status=target.value))
    # The status change may have moved a finding across the resolved/active
    # boundary; the device's live score must reflect that immediately.
    from ..device_scoring import recompute_device_score
    recompute_device_score(db, f.device_id)
    db.commit()
    audit.log_action(db, organization_id=f.organization_id,
                     action=audit.FINDING_STATUS_CHANGED, resource_type="finding",
                     resource_id=f.id, user=user, request=request,
                     before={"status": current.value}, after={"status": target.value})

    # On acknowledgement, optionally open a tracker ticket (Jira/ServiceNow).
    if target == FindingStatus.acknowledged:
        try:
            from .. import ticketing
            ticketing.maybe_create_ticket(db, f)
        except Exception:  # noqa: BLE001 - ticketing must never break triage
            db.rollback()


@router.get("/findings", response_model=list[FindingSummary])
def list_findings(
        severity: Optional[str] = None,
        status_: Optional[FindingStatus] = Query(default=None, alias="status"),
        category: Optional[str] = None,
        device_id: Optional[str] = None,
        analysis_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        assignee_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        q: Optional[str] = None,
        max_age_days: Optional[int] = None,
        limit: int = Query(default=100, le=500),
        offset: int = 0,
        user: User = Depends(current_user),
        db: Session = Depends(get_db)) -> list[Finding]:
    """Cross-device findings explorer with filters (org-scoped)."""
    stmt = select(Finding).where(Finding.organization_id == user.organization_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status_:
        stmt = stmt.where(Finding.status == status_)
    if category:
        stmt = stmt.where(Finding.category == category)
    if device_id:
        stmt = stmt.where(Finding.device_id == device_id)
    if analysis_id:
        stmt = stmt.where(Finding.analysis_id == analysis_id)
    if customer_id:
        # MSP per-customer segregation: limit to devices of that customer.
        from ..models import Device
        device_ids = [d.id for d in db.scalars(select(Device.id).where(
            Device.organization_id == user.organization_id,
            Device.customer_id == customer_id))]
        stmt = stmt.where(Finding.device_id.in_(device_ids or ["__none__"]))
    if assignee_id:
        stmt = stmt.where(Finding.assignee_id == assignee_id)
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Finding.title.ilike(like) | Finding.object_name.ilike(like))
    if max_age_days is not None:
        cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400
        stmt = stmt.where(Finding.first_seen_at >= datetime.fromtimestamp(cutoff, tz=timezone.utc))

    _sev = ("Critical", "High", "Medium", "Low", "Info")
    rows = list(db.scalars(stmt.order_by(Finding.last_seen_at.desc()).limit(limit).offset(offset)))
    rows.sort(key=lambda f: _sev.index(f.severity) if f.severity in _sev else 9)
    return rows


def _scoped_finding_query(user: User, db: Session, *, device_id: str | None,
                          customer_id: str | None, category: str | None,
                          q: str | None):
    stmt = select(Finding).where(Finding.organization_id == user.organization_id)
    if device_id:
        stmt = stmt.where(Finding.device_id == device_id)
    if customer_id:
        from ..models import Device
        dids = [d.id for d in db.scalars(select(Device.id).where(
            Device.organization_id == user.organization_id,
            Device.customer_id == customer_id))]
        stmt = stmt.where(Finding.device_id.in_(dids or ["__none__"]))
    if category:
        stmt = stmt.where(Finding.category == category)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Finding.title.ilike(like) | Finding.object_name.ilike(like))
    return stmt


@router.get("/finding-groups", response_model=list[FindingGroupSummary])
def list_finding_groups(
        severity: Optional[str] = None,
        status_: Optional[FindingStatus] = Query(default=None, alias="status"),
        category: Optional[str] = None,
        device_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        q: Optional[str] = None,
        user: User = Depends(current_user),
        db: Session = Depends(get_db)) -> list[dict]:
    """Grouped findings: one entry per (device, rule) with the PARENT's own
    persisted status and affected-instance counts. This is the authoritative
    "1 finding, N affected" view — its length is the grouped finding count
    the KPIs use."""
    stmt = _scoped_finding_query(user, db, device_id=device_id, customer_id=customer_id,
                                 category=category, q=q)
    instances = list(db.scalars(stmt))
    device_ids = list({f.device_id for f in instances})
    status_by_key = finding_groups.load_group_statuses(db, user.organization_id, device_ids)
    groups = finding_groups.build_groups(instances, status_by_key)
    if severity:
        groups = [g for g in groups if g["severity"] == severity]
    if status_:
        groups = [g for g in groups if g["status"] == status_.value]
    return groups


@router.get("/finding-groups/detail", response_model=FindingGroupDetail)
def get_finding_group(device_id: str, rule_id: str,
                      user: User = Depends(current_user),
                      db: Session = Depends(get_db)) -> dict:
    """Shared finding metadata plus the list of affected instances (the
    checklist the UI manages individually) and the parent's own status."""
    instances = list(db.scalars(
        _scoped_finding_query(user, db, device_id=device_id, customer_id=None,
                              category=None, q=None)
        .where(Finding.rule_id == rule_id)))
    if not instances:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding group not found")
    # Single-group detail page: safe to get-or-create so a freshly-viewed
    # group has a real row to transition later (never done for list views).
    group_row = finding_groups.get_or_create_group_status(
        db, user.organization_id, device_id, rule_id)
    db.commit()
    summary = finding_groups.build_groups(
        instances, {(device_id, rule_id): group_row.status})[0]
    rep = db.get(Finding, summary["representative_id"])
    instances.sort(key=lambda f: (finding_groups.is_resolved(f.status),
                                  (f.object_name or "").lower()))
    return {
        **summary,
        "description": rep.description, "evidence": rep.evidence or [],
        "business_impact": rep.business_impact, "technical_impact": rep.technical_impact,
        "remediation": rep.remediation, "verification": rep.verification or [],
        "compliance": rep.compliance or {},
        "instances": instances,
    }


@router.post("/finding-groups/transition", response_model=FindingGroupDetail)
def transition_finding_group(body: FindingGroupTransition, request: Request,
                             user: User = Depends(require_role(Role.analyst)),
                             db: Session = Depends(get_db)) -> dict:
    """Change the PARENT status of a grouped finding.

    An OPEN-classified status (open/acknowledged/in_progress/suppressed) may
    be set at any time. A FIXED-classified status (fixed/false_positive/
    accepted_risk) is rejected with 400 while any affected instance is still
    OPEN-classified — the parent is never auto-resolved; the user must
    explicitly choose it once every instance is itself resolved.
    """
    instances = list(db.scalars(
        _scoped_finding_query(user, db, device_id=body.device_id, customer_id=None,
                              category=None, q=None)
        .where(Finding.rule_id == body.rule_id)))
    if not instances:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding group not found")
    if len(instances) == 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This finding has a single affected object — transition it directly "
                   f"via POST /findings/{instances[0].id}/transition.")

    group_row = finding_groups.get_or_create_group_status(
        db, user.organization_id, body.device_id, body.rule_id)
    current = FindingStatus(group_row.status)
    target = body.to_status
    if target == current:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Finding is already {current.value}")
    if target.value in finding_groups.RESOLVED_STATES and not finding_groups.can_resolve(instances):
        open_count = sum(1 for i in instances if not finding_groups.is_resolved(i.status))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot set the finding to '{target.value}' while {open_count} affected "
                   f"object(s) remain open. Resolve every affected object first.")
    if target in _ADMIN_ONLY and _ROLE_RANK[user.role] < _ROLE_RANK[Role.admin]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Only an admin may set status '{target.value}'")
    if target in (FindingStatus.false_positive, FindingStatus.accepted_risk) and not body.justification:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"A justification is required to set '{target.value}'")
    if target == FindingStatus.accepted_risk and body.accepted_risk_expiry is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="An accepted-risk expiry date is required")

    group_row.status = target.value
    if body.justification is not None:
        group_row.justification = body.justification
    if target == FindingStatus.accepted_risk:
        group_row.accepted_risk_expiry = body.accepted_risk_expiry
        group_row.signed_off_by = user.id
    db.commit()
    audit.log_action(db, organization_id=user.organization_id,
                     action=audit.FINDING_STATUS_CHANGED, resource_type="finding_group",
                     resource_id=f"{body.device_id}::{body.rule_id}", user=user, request=request,
                     before={"status": current.value}, after={"status": target.value,
                                                                "comment": body.comment})

    summary = finding_groups.build_groups(
        instances, {(body.device_id, body.rule_id): group_row.status})[0]
    rep = db.get(Finding, summary["representative_id"])
    instances.sort(key=lambda f: (finding_groups.is_resolved(f.status),
                                  (f.object_name or "").lower()))
    return {
        **summary,
        "description": rep.description, "evidence": rep.evidence or [],
        "business_impact": rep.business_impact, "technical_impact": rep.technical_impact,
        "remediation": rep.remediation, "verification": rep.verification or [],
        "compliance": rep.compliance or {},
        "instances": instances,
    }


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, user: User = Depends(current_user),
                db: Session = Depends(get_db)) -> Finding:
    f = _get_finding(db, finding_id, user)
    f.comments.sort(key=lambda c: c.created_at)
    return f


@router.post("/findings/{finding_id}/transition", response_model=FindingDetail)
def transition_finding(finding_id: str, body: FindingTransition, request: Request,
                       user: User = Depends(require_role(Role.analyst)),
                       db: Session = Depends(get_db)) -> Finding:
    f = _get_finding(db, finding_id, user)
    _apply_transition(db, f, body, user, request)
    db.refresh(f)
    return f


@router.post("/findings/{finding_id}/assign", response_model=FindingDetail)
def assign_finding(finding_id: str, body: FindingAssign, request: Request,
                   user: User = Depends(require_role(Role.analyst)),
                   db: Session = Depends(get_db)) -> Finding:
    f = _get_finding(db, finding_id, user)
    if body.assignee_id:
        assignee = db.get(User, body.assignee_id)
        if assignee is None or assignee.organization_id != user.organization_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Assignee must be a user in this organization")
    before = f.assignee_id
    f.assignee_id = body.assignee_id
    if body.due_date is not None:
        f.due_date = body.due_date
    note = body.comment or (f"Assigned to {body.assignee_id}" if body.assignee_id else "Unassigned")
    db.add(FindingComment(
        organization_id=f.organization_id, finding_id=f.id, author_id=user.id,
        author_email=user.email, comment_type=CommentType.assignment, body=note))
    db.commit()
    audit.log_action(db, organization_id=f.organization_id, action=audit.FINDING_ASSIGNED,
                     resource_type="finding", resource_id=f.id, user=user, request=request,
                     before={"assignee_id": before}, after={"assignee_id": body.assignee_id})
    db.refresh(f)
    return f


@router.post("/findings/{finding_id}/comments", response_model=FindingCommentOut,
             status_code=status.HTTP_201_CREATED)
def add_comment(finding_id: str, body: FindingCommentCreate,
                user: User = Depends(require_role(Role.analyst)),
                db: Session = Depends(get_db)) -> FindingComment:
    f = _get_finding(db, finding_id, user)
    comment = FindingComment(
        organization_id=f.organization_id, finding_id=f.id, author_id=user.id,
        author_email=user.email, comment_type=CommentType.comment, body=body.body)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


@router.delete("/findings/{finding_id}/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_comment(finding_id: str, comment_id: str,
                   user: User = Depends(require_role(Role.analyst)),
                   db: Session = Depends(get_db)):
    f = _get_finding(db, finding_id, user)
    comment = db.get(FindingComment, comment_id)
    if comment is None or comment.finding_id != f.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")
    # Only the author or an admin may delete; system/status entries are immutable.
    is_admin = _ROLE_RANK[user.role] >= _ROLE_RANK[Role.admin]
    if comment.comment_type != CommentType.comment:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="History entries cannot be deleted")
    if comment.author_id != user.id and not is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You may only delete your own comments")
    db.delete(comment)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/analyses/{analysis_id}/findings", response_model=list[FindingSummary])
def list_analysis_findings(analysis_id: str,
                           severity: Optional[str] = None,
                           status_: Optional[FindingStatus] = Query(default=None, alias="status"),
                           category: Optional[str] = None,
                           q: Optional[str] = None,
                           user: User = Depends(current_user),
                           db: Session = Depends(get_db)):
    """Return findings for a specific analysis, loaded from result_json.

    Unlike ``GET /findings?analysis_id=`` which filters the live findings table
    (where rows are mutated across scans), this endpoint loads the snapshot of
    findings from the analysis result and cross-references the findings table
    for current triage status. This gives the user the complete set of findings
    that existed at the time of that analysis, with live workflow state.
    """
    analysis = db.get(Analysis, analysis_id)
    if analysis is None or analysis.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    result_json = analysis.result_json or {}
    snapshot_findings = result_json.get("findings", [])

    # Build lookup of current triage state keyed by fingerprint.
    # A fingerprint can legitimately have multiple live rows (legacy duplicate
    # rows from older analyses that sync_findings only collapses while active).
    # Resolution is DETERMINISTIC so the snapshot summary can never flip
    # between requests: an ACTIVE row (open / acknowledged / in_progress)
    # always wins over a resolved row, and among equally-classed rows the most
    # recently created wins. (The previous unordered last-wins made the mapped
    # status depend on the scan order — the same TSR could summarize as
    # "252 open" or "133 open" depending on row ordering.)
    from ..models import Device as DeviceModel
    device = db.get(DeviceModel, analysis.device_id)
    db_findings = db.scalars(select(Finding).where(
        Finding.device_id == analysis.device_id)).all() if device else []
    _ACTIVE_STATES = {FindingStatus.open, FindingStatus.acknowledged, FindingStatus.in_progress}
    status_by_fp: dict[str, Finding] = {}
    for f in db_findings:
        cur = status_by_fp.get(f.fingerprint)
        if cur is None:
            status_by_fp[f.fingerprint] = f
            continue
        cur_active = cur.status in _ACTIVE_STATES
        f_active = f.status in _ACTIVE_STATES
        if f_active and not cur_active:
            status_by_fp[f.fingerprint] = f
        elif f_active == cur_active and (f.created_at or f.id) > (cur.created_at or cur.id):
            status_by_fp[f.fingerprint] = f

    # Collapse duplicate-fingerprint snapshot entries into one row, matching the
    # live findings table: sync_findings persists exactly one row per fingerprint
    # (rule + object_type + object_name). A raw analysis snapshot can contain
    # many entries sharing one fingerprint — e.g. dozens of address objects with
    # a blank name "-" all yield ``AOB-003::Address Object::-`` — so emitting one
    # row per array entry inflated this view's counts far above the authoritative
    # live-table counts shown on the Dashboard and Security Analytics. Deduping
    # here keeps all three surfaces on the same finding set and status semantics.
    seen_fps: set[str] = set()
    out: list = []
    for sf in snapshot_findings:
        fp = f"{sf.get('rule_id','')}::{sf.get('object_type','')}::{sf.get('object_name','')}"
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        live = status_by_fp.get(fp)
        current_status = live.status.value if live else "open"

        # Optional filters
        if severity and sf.get("severity") != severity:
            continue
        if status_ and current_status != status_.value:
            continue
        if category and sf.get("category") != category:
            continue
        if q:
            ql = q.lower()
            title = (sf.get("title") or "").lower()
            obj = (sf.get("object_name") or "").lower()
            if ql not in title and ql not in obj:
                continue

        out.append({
            "id": live.id if live else f"snapshot-{analysis_id[:8]}-{fp}",
            "device_id": analysis.device_id,
            "analysis_id": analysis.id,
            "rule_id": sf.get("rule_id", ""),
            "source": live.source if live else "parser",
            "severity": sf.get("severity", "Info"),
            "title": sf.get("title", ""),
            "category": sf.get("category", ""),
            "status": current_status,
            "exploitability": sf.get("exploitability", ""),
            "object_name": sf.get("object_name", ""),
            "object_type": sf.get("object_type", ""),
            "assignee_id": live.assignee_id if live else None,
            "due_date": live.due_date if live else None,
            "ticket_ref": live.ticket_ref if live else "",
            "first_seen_at": live.first_seen_at if live else analysis.created_at,
            "last_seen_at": live.last_seen_at if live else analysis.created_at,
        })

    # Append manual findings (not in any analysis snapshot).
    manual_findings = db.scalars(select(Finding).where(
        Finding.device_id == analysis.device_id,
        Finding.source == "manual")).all()
    for mf in manual_findings:
        if severity and mf.severity != severity:
            continue
        if status_ and mf.status.value != status_.value:
            continue
        if category and mf.category != category:
            continue
        if q:
            ql = q.lower()
            title = (mf.title or "").lower()
            obj = (mf.object_name or "").lower()
            if ql not in title and ql not in obj:
                continue
        out.append({
            "id": mf.id,
            "device_id": mf.device_id,
            "analysis_id": mf.analysis_id or "",
            "rule_id": mf.rule_id,
            "severity": mf.severity,
            "title": mf.title,
            "category": mf.category,
            "status": mf.status.value,
            "exploitability": mf.exploitability,
            "object_name": mf.object_name,
            "object_type": mf.object_type,
            "assignee_id": mf.assignee_id,
            "due_date": mf.due_date,
            "ticket_ref": mf.ticket_ref,
            "first_seen_at": mf.first_seen_at,
            "last_seen_at": mf.last_seen_at,
            "source": "manual",
        })

    return out


@router.post("/findings/bulk-transition")
def bulk_transition(body: BulkTransition, request: Request,
                    user: User = Depends(require_role(Role.analyst)),
                    db: Session = Depends(get_db)) -> dict:
    """Apply one transition to many findings; reports per-finding results."""
    results: dict[str, list[str]] = {"updated": [], "skipped": []}
    for fid in body.finding_ids:
        f = db.get(Finding, fid)
        if f is None or f.organization_id != user.organization_id:
            results["skipped"].append(fid)
            continue
        try:
            _apply_transition(db, f, FindingTransition(
                to_status=body.to_status, comment=body.comment,
                justification=body.justification,
                accepted_risk_expiry=body.accepted_risk_expiry), user, request)
            results["updated"].append(fid)
        except HTTPException:
            db.rollback()
            results["skipped"].append(fid)
    return results


# ── Manual Finding Edit / Delete ──────────────────────────────────────────

@router.put("/findings/{finding_id}", response_model=FindingDetail)
def update_manual_finding(
    finding_id: str,
    body: ManualFindingUpdate,
    user: User = Depends(require_role(Role.analyst)),
    db: Session = Depends(get_db),
) -> Finding:
    """Update a manual finding's fields (parser findings are read-only)."""
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if f.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if f.source != "manual":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only manually created findings can be edited")
    updates = body.model_dump(exclude_none=True)
    for k, v in updates.items():
        if k == "status":
            setattr(f, k, FindingStatus(v))
        elif k == "evidence":
            setattr(f, k, [v] if v else [])
        else:
            setattr(f, k, v)
    if "status" in updates or "severity" in updates:
        from ..device_scoring import recompute_device_score
        recompute_device_score(db, f.device_id)
    db.commit()
    db.refresh(f)
    return f


@router.delete("/findings/{finding_id}")
def delete_manual_finding(
    finding_id: str,
    user: User = Depends(require_role(Role.analyst)),
    db: Session = Depends(get_db),
):
    """Delete a manual finding (parser findings cannot be deleted)."""
    f = db.scalars(select(Finding).where(Finding.id == finding_id)).first()
    if f is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if f.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if f.source != "manual":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only manually created findings can be deleted")
    device_id = f.device_id
    db.delete(f)
    db.flush()
    from ..device_scoring import recompute_device_score
    recompute_device_score(db, device_id)
    db.commit()
    return {"ok": True}