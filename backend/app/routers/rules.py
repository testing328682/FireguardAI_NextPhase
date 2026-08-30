"""Rule admin endpoints: library, editor, approval workflow, test, overrides.

System rules (organization_id null) are read-only mirrors of the Python catalog.
Custom rules are tenant-authored CEL rules that move through a Draft → Submitted
→ Approved workflow before they evaluate in the pipeline. Tenant suppressions /
severity overrides apply to both system and custom rules by rule key.
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status, UploadFile, File
from sqlalchemy import select, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    User, Role, Rule, RuleVersion, RuleSource, RuleState, RuleSuppression, Analysis,
    BuilderSnapshot,
)
from ..schemas import (
    RuleOut, RuleDetail, RuleCreate, RuleUpdate, RuleStateChange,
    RuleTestRequest, RuleTestResponse, SuppressionCreate, SuppressionOut,
    BuilderSnapshotRef, BuilderTestRequest,
)
from ..security import current_user, require_role, require_superadmin
from ..rule_engine import (
    evaluate_condition, compile_condition, CELError, detection_logic, rule_api_support,
)
from .. import audit

router = APIRouter(prefix="/api/v1", tags=["rules"])


def _annotate(rule: Rule) -> Rule:
    """Attach the computed API-TSR support level for serialization."""
    rule.api_support = rule_api_support(rule.key, rule.condition or "")
    return rule


def _visible(db: Session, rule_id: str, user: User) -> Rule:
    rule = db.get(Rule, rule_id)
    if rule is None or (rule.organization_id not in (None, user.organization_id)):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


def _require_editable(rule: Rule, user: User) -> None:
    """Raise 403 unless the user can edit this rule.

    - Custom rules: editable by the owning tenant (analyst+).
    - System rules: editable only by platform superadmins.
    """
    if rule.source == RuleSource.system or rule.organization_id != user.organization_id:
        if rule.source == RuleSource.system and getattr(user, "is_superadmin", False):
            return  # superadmins may edit system rules
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="System rules can only be edited by a platform operator")


@router.get("/rules", response_model=list[RuleOut])
def list_rules(source: Optional[RuleSource] = None,
               state: Optional[RuleState] = None,
               severity: Optional[str] = None,
               category: Optional[str] = None,
               q: Optional[str] = None,
               user: User = Depends(current_user),
               db: Session = Depends(get_db)) -> list[Rule]:
    """List system (global) and this tenant's custom rules, with filters."""
    stmt = select(Rule).where(or_(
        Rule.organization_id.is_(None), Rule.organization_id == user.organization_id))
    if source:
        stmt = stmt.where(Rule.source == source)
    if state:
        stmt = stmt.where(Rule.state == state)
    if severity:
        stmt = stmt.where(Rule.severity == severity)
    if category:
        stmt = stmt.where(Rule.category == category)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Rule.title.ilike(like) | Rule.key.ilike(like))
    return [_annotate(r) for r in db.scalars(stmt.order_by(Rule.key))]


@router.get("/rules/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: str, user: User = Depends(current_user),
             db: Session = Depends(get_db)) -> Rule:
    rule = _visible(db, rule_id, user)
    rule.versions.sort(key=lambda v: v.version)
    return _annotate(rule)


def _record_version(db: Session, rule: Rule, user: User, note: str) -> None:
    db.add(RuleVersion(
        rule_id=rule.id, version=rule.current_version, title=rule.title,
        severity=rule.severity, condition=rule.condition, remediation=rule.remediation,
        change_note=note, edited_by=user.id))


@router.post("/rules", response_model=RuleDetail, status_code=status.HTTP_201_CREATED)
def create_rule(body: RuleCreate, request: Request,
                user: User = Depends(require_role(Role.analyst)),
                db: Session = Depends(get_db)) -> Rule:
    """Create a rule. Superadmins may create system rules (source=system, org_id null)."""
    # Superadmins creating system rules
    if body.source == RuleSource.system:
        if not getattr(user, "is_superadmin", False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Only a platform operator can create system rules")
        if not body.key or not body.key.strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="A rule key (e.g. FW-MGT-099) is required for system rules")
        # Ensure the key is unique among system rules
        existing = db.scalar(select(Rule).where(
            Rule.key == body.key.strip(), Rule.organization_id.is_(None)))
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"System rule key '{body.key}' already exists")
        try:
            compile_condition(body.condition)
        except CELError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Invalid CEL condition: {exc}")
        rule = Rule(
            organization_id=None, key=body.key.strip(),
            title=body.title, category=body.category, severity=body.severity,
            description=body.description or detection_logic(body.title, body.category, body.severity),
            condition=body.condition, remediation=body.remediation,
            compliance=body.compliance, references=body.references,
            source=RuleSource.system, state=RuleState.approved, enabled=True, current_version=1,
            created_by=user.id)
        db.add(rule)
        db.flush()
        _record_version(db, rule, user, "Created (system)")
        db.commit()
        db.refresh(rule)
        audit.log_action(db, organization_id=user.organization_id, action=audit.RULE_CREATED,
                         resource_type="rule", resource_id=rule.id, user=user, request=request,
                         after={"key": rule.key, "title": rule.title, "source": "system"})
        return rule

    # Standard custom rule
    try:
        compile_condition(body.condition)
    except CELError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid CEL condition: {exc}")
    rule = Rule(
        organization_id=user.organization_id, key=f"CUSTOM-{uuid.uuid4().hex[:8].upper()}",
        title=body.title, category=body.category, severity=body.severity,
        description=body.description, condition=body.condition, remediation=body.remediation,
        compliance=body.compliance, references=body.references,
        source=RuleSource.custom, state=RuleState.draft, enabled=True, current_version=1,
        created_by=user.id)
    db.add(rule)
    db.flush()
    _record_version(db, rule, user, "Created")
    db.commit()
    db.refresh(rule)
    audit.log_action(db, organization_id=user.organization_id, action=audit.RULE_CREATED,
                     resource_type="rule", resource_id=rule.id, user=user, request=request,
                     after={"key": rule.key, "title": rule.title})
    return rule


@router.patch("/rules/{rule_id}", response_model=RuleDetail)
def update_rule(rule_id: str, body: RuleUpdate, request: Request,
                user: User = Depends(require_role(Role.analyst)),
                db: Session = Depends(get_db)) -> Rule:
    """Edit a rule. System rules (superadmin only) stay approved; custom rules return to Draft."""
    rule = _visible(db, rule_id, user)
    _require_editable(rule, user)
    if body.condition is not None:
        try:
            compile_condition(body.condition)
        except CELError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Invalid CEL condition: {exc}")
        rule.condition = body.condition
    for field in ("title", "category", "severity", "description", "remediation",
                  "compliance", "references"):
        val = getattr(body, field)
        if val is not None:
            setattr(rule, field, val)
    rule.current_version += 1

    # System rules stay approved (no workflow); custom rules return to Draft.
    if rule.source == RuleSource.system:
        # Also refresh the plain-English description if the condition changed.
        if body.condition is not None:
            rule.description = detection_logic(rule.title, rule.category, rule.severity)
        rule.state = RuleState.approved
        # Ensure system rules retain their global scope.
        rule.organization_id = None
        # Clear approval fields (system rules are implicitly approved).
        rule.approved_by = None
    else:
        rule.state = RuleState.draft   # edits require re-approval

    _record_version(db, rule, user, body.change_note or "Edited")
    db.commit()
    db.refresh(rule)
    audit.log_action(db, organization_id=user.organization_id, action=audit.RULE_UPDATED,
                     resource_type="rule", resource_id=rule.id, user=user, request=request,
                     after={"version": rule.current_version})
    return rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: str, user: User = Depends(require_role(Role.admin)),
                db: Session = Depends(get_db)):
    rule = _visible(db, rule_id, user)
    _require_editable(rule, user)
    db.delete(rule)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/rules/{rule_id}/submit", response_model=RuleDetail)
def submit_rule(rule_id: str, body: RuleStateChange, request: Request,
                user: User = Depends(require_role(Role.analyst)),
                db: Session = Depends(get_db)) -> Rule:
    rule = _visible(db, rule_id, user)
    _require_editable(rule, user)
    if rule.state != RuleState.draft:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Only draft rules can be submitted")
    rule.state = RuleState.submitted
    db.commit()
    db.refresh(rule)
    audit.log_action(db, organization_id=user.organization_id, action=audit.RULE_STATE_CHANGED,
                     resource_type="rule", resource_id=rule.id, user=user, request=request,
                     after={"state": "submitted"})
    return rule


@router.post("/rules/{rule_id}/approve", response_model=RuleDetail)
def approve_rule(rule_id: str, body: RuleStateChange, request: Request,
                 user: User = Depends(require_role(Role.admin)),
                 db: Session = Depends(get_db)) -> Rule:
    """Approve a submitted rule (admin). Approved rules evaluate in the pipeline."""
    rule = _visible(db, rule_id, user)
    _require_editable(rule, user)
    if rule.state != RuleState.submitted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Only submitted rules can be approved")
    rule.state = RuleState.approved
    rule.approved_by = user.id
    db.commit()
    db.refresh(rule)
    audit.log_action(db, organization_id=user.organization_id, action=audit.RULE_STATE_CHANGED,
                     resource_type="rule", resource_id=rule.id, user=user, request=request,
                     after={"state": "approved"})
    return rule


# Declared before "/rules/{rule_id}/test": route matching is declaration-
# ordered, so the dynamic route would otherwise capture rule_id="builder".
@router.post("/rules/builder/test", response_model=RuleTestResponse)
def test_builder_condition(
    body: BuilderTestRequest,
    user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
) -> RuleTestResponse:
    """Test a hand-written CEL condition against a reference snapshot.

    Resolution order: an inline snapshot, then the referenced analysis, then
    the caller's saved builder snapshot (so the UI does not need to re-send
    a multi-megabyte snapshot on every test run).
    """
    snapshot = body.snapshot
    if snapshot is None and body.analysis_id:
        analysis = db.get(Analysis, body.analysis_id)
        if analysis is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        snapshot = (analysis.result_json or {}).get("snapshot")
    if snapshot is None:
        row = db.scalar(select(BuilderSnapshot).where(
            BuilderSnapshot.user_id == user.id))
        if row is not None:
            snapshot = row.snapshot
    if not snapshot:
        raise HTTPException(status_code=404, detail="No parsed snapshot available")
    fired, error = evaluate_condition(body.condition, snapshot)
    return RuleTestResponse(fired=fired, error=error)


@router.post("/rules/{rule_id}/test", response_model=RuleTestResponse)
def test_rule(rule_id: str, body: RuleTestRequest, user: User = Depends(current_user),
              db: Session = Depends(get_db)) -> RuleTestResponse:
    """Evaluate a rule (or an unsaved condition) against a snapshot."""
    rule = _visible(db, rule_id, user)
    condition = body.condition if body.condition is not None else rule.condition
    if not condition:
        return RuleTestResponse(fired=None, error="System rules have no CEL condition to test")

    snapshot = body.snapshot
    if snapshot is None and body.analysis_id:
        analysis = db.get(Analysis, body.analysis_id)
        if analysis is None or analysis.organization_id != user.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")
        snapshot = (analysis.result_json or {}).get("snapshot")
    if snapshot is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Provide a snapshot or an analysis_id to test against")

    fired, error = evaluate_condition(condition, snapshot)
    return RuleTestResponse(fired=fired, error=error)


# ---- CEL rule builder (superadmin) ---------------------------------------
@router.get("/rules/builder/snapshots", response_model=list[BuilderSnapshotRef])
def list_builder_snapshots(
    user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List completed analyses (across all tenants) for use as reference TSRs
    in the CEL Rule Builder.  Returns device model / serial / firmware so the
    operator can pick the right snapshot."""
    rows = db.execute(
        select(Analysis.id, Analysis.result_json, Analysis.generated_at)
        .where(Analysis.status == "complete")
        .order_by(Analysis.generated_at.desc())
        .limit(50)
    ).all()
    out: list[dict] = []
    for row in rows:
        rj = row.result_json or {}
        dev = rj.get("device", {})
        out.append({
            "analysis_id": row.id,
            "device_model": dev.get("model", ""),
            "device_serial": dev.get("serial", ""),
            "device_firmware": dev.get("firmware", ""),
            "generated_at": row.generated_at,
        })
    return out


@router.post("/rules/builder/upload")
async def upload_builder_tsr(
    file: UploadFile = File(...),
    user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    """Upload a TSR file and return its parsed snapshot for the rule builder.
    No analysis or device is created — this is for reference only."""
    import logging
    _log = logging.getLogger("firewallguard.builder")

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    if not file.filename.lower().endswith((".wri", ".txt", ".tsr")):
        raise HTTPException(status_code=400, detail="Please upload a .wri or .txt TSR file")

    # Read the file (stream to a bytes buffer to avoid memory issues with huge files).
    try:
        raw = await file.read()
        if len(raw) > 50 * 1024 * 1024:  # 50 MB limit
            raise HTTPException(status_code=400, detail="TSR file too large (max 50 MB)")
        text = raw.decode("utf-8", errors="replace")
    except HTTPException:
        raise
    except Exception:
        _log.exception("Failed to read uploaded TSR")
        raise HTTPException(status_code=400, detail="Failed to read uploaded file")

    if len(text.strip()) < 100:
        raise HTTPException(status_code=400, detail="File appears empty or too small")

    _log.info("Parsing uploaded TSR: %s (%d bytes)", file.filename, len(raw))

    from firewallguard.tsr.normalize import normalize_tsr
    from firewallguard.tsr.parser import parse_tsr
    try:
        # Same pre-step as every ingest path: API-format TSRs are rebuilt
        # into GUI-equivalent text so the parser sees one shape.
        text, tsr_format = normalize_tsr(text)
        snapshot = parse_tsr(text, source_name=file.filename)
    except Exception as exc:
        _log.exception("TSR parse failed for %s", file.filename)
        raise HTTPException(status_code=400, detail=f"Failed to parse TSR: {exc}")

    # Persist the snapshot in the DB so it survives across sessions / devices.
    existing = db.scalar(select(BuilderSnapshot).where(
        BuilderSnapshot.user_id == user.id))
    if existing:
        existing.filename = file.filename
        existing.snapshot = snapshot
    else:
        db.add(BuilderSnapshot(user_id=user.id, filename=file.filename, snapshot=snapshot))
    db.commit()

    return {
        "filename": file.filename,
        "snapshot": snapshot,
        "meta": snapshot.get("meta", {}),
        "tsr_format": tsr_format,
    }


@router.get("/rules/builder/snapshot/saved")
def get_saved_builder_snapshot(
    user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    """Return the superadmin's persisted reference TSR snapshot, if any."""
    row = db.scalar(select(BuilderSnapshot).where(
        BuilderSnapshot.user_id == user.id))
    if row is None:
        raise HTTPException(status_code=404, detail="No saved TSR snapshot")
    return {
        "filename": row.filename,
        "snapshot": row.snapshot,
    }


@router.get("/rules/builder/snapshot/{analysis_id}")
def get_builder_snapshot(
    analysis_id: str,
    user: User = Depends(require_superadmin),
    db: Session = Depends(get_db),
) -> dict:
    """Return the parsed TSR snapshot from a completed analysis for browsing
    in the CEL Rule Builder."""
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    snapshot = (analysis.result_json or {}).get("snapshot")
    if not snapshot:
        raise HTTPException(status_code=404, detail="No parsed snapshot in this analysis")
    return snapshot


# ---- suppressions / overrides --------------------------------------------
@router.get("/rule-suppressions", response_model=list[SuppressionOut])
def list_suppressions(rule_key: Optional[str] = None,
                      user: User = Depends(current_user),
                      db: Session = Depends(get_db)) -> list[RuleSuppression]:
    stmt = select(RuleSuppression).where(
        RuleSuppression.organization_id == user.organization_id)
    if rule_key:
        stmt = stmt.where(RuleSuppression.rule_key == rule_key)
    return list(db.scalars(stmt.order_by(RuleSuppression.created_at.desc())))


@router.post("/rule-suppressions", response_model=SuppressionOut,
             status_code=status.HTTP_201_CREATED)
def create_suppression(body: SuppressionCreate, request: Request,
                       user: User = Depends(require_role(Role.admin)),
                       db: Session = Depends(get_db)) -> RuleSuppression:
    from ..models import SuppressionAction
    if body.action == SuppressionAction.override_severity and not body.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="A target severity is required to override")
    supp = RuleSuppression(
        organization_id=user.organization_id, rule_key=body.rule_key,
        device_id=body.device_id, action=body.action, value=body.value,
        reason=body.reason, expires_at=body.expires_at, created_by=user.id)
    db.add(supp)
    db.commit()
    db.refresh(supp)
    audit.log_action(db, organization_id=user.organization_id, action=audit.SUPPRESSION_CREATED,
                     resource_type="rule_suppression", resource_id=supp.id, user=user,
                     request=request, after={"rule_key": body.rule_key, "action": body.action.value})
    return supp


@router.delete("/rule-suppressions/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_suppression(suppression_id: str, user: User = Depends(require_role(Role.admin)),
                       db: Session = Depends(get_db)):
    supp = db.get(RuleSuppression, suppression_id)
    if supp is None or supp.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression not found")
    db.delete(supp)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
