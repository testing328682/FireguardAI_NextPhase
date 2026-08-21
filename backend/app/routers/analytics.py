"""Advanced fleet analytics (trends).

Aggregates posture and remediation metrics for the trends dashboard:
12-month score progression per device, mean-time-to-remediate by severity,
finding recurrence rate, the top-10 firing rules, and category evolution. All
queries are organization-scoped.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    User, Device, Analysis, AnalysisStatus, Finding, FindingComment, CommentType,
    FindingStatus, Organization, LicensePurchase, Tsr, ApiConnectionLog,
    DeviceGeneration, GenerationDevice, FirmwareRecommendation,
)
from ..security import current_user

router = APIRouter(prefix="/api/v1", tags=["analytics"])

_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def _month(dt: datetime) -> str:
    return dt.strftime("%Y-%m")


def _score_progression(db: Session, org_id: str) -> list[dict]:
    rows = db.execute(
        select(Analysis.device_id, Analysis.created_at, Analysis.score).where(
            Analysis.organization_id == org_id,
            Analysis.status == AnalysisStatus.complete)).all()
    by_device: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for device_id, created_at, score in rows:
        by_device[device_id][_month(created_at)].append(score)
    serials = {d.id: d.serial for d in db.scalars(select(Device).where(
        Device.organization_id == org_id))}
    out = []
    for device_id, months in by_device.items():
        points = [{"month": m, "score": round(sum(v) / len(v), 1)}
                  for m, v in sorted(months.items())][-12:]
        out.append({"device_id": device_id, "serial": serials.get(device_id, "?"),
                    "points": points})
    return out


def _mttr_by_severity(db: Session, org_id: str) -> dict[str, float]:
    rows = db.scalars(select(Finding).where(
        Finding.organization_id == org_id, Finding.resolved_at.is_not(None))).all()
    buckets: dict[str, list[float]] = defaultdict(list)
    for f in rows:
        if not f.first_seen_at or not f.resolved_at:
            continue
        first = f.first_seen_at if f.first_seen_at.tzinfo else f.first_seen_at.replace(tzinfo=timezone.utc)
        done = f.resolved_at if f.resolved_at.tzinfo else f.resolved_at.replace(tzinfo=timezone.utc)
        days = (done - first).total_seconds() / 86400.0
        if days >= 0:
            buckets[f.severity].append(days)
    return {sev: round(sum(buckets[sev]) / len(buckets[sev]), 2)
            for sev in _SEVERITIES if buckets.get(sev)}


def _recurrence_rate(db: Session, org_id: str) -> dict:
    total = db.scalar(select(func.count(Finding.id)).where(
        Finding.organization_id == org_id)) or 0
    # A recurrence is an auto-reopen: a status_change comment fixed -> open.
    recurring_findings = db.scalar(select(func.count(func.distinct(FindingComment.finding_id)))
        .where(FindingComment.organization_id == org_id,
               FindingComment.comment_type == CommentType.status_change,
               FindingComment.from_status == "fixed",
               FindingComment.to_status == "open")) or 0
    rate = round(recurring_findings / total, 3) if total else 0.0
    return {"total_findings": total, "recurring_findings": recurring_findings, "rate": rate}


def _top_rules(db: Session, org_id: str) -> list[dict]:
    rows = db.execute(
        select(Finding.rule_id, Finding.title, func.count(Finding.id).label("n"))
        .where(Finding.organization_id == org_id)
        .group_by(Finding.rule_id, Finding.title)
        .order_by(func.count(Finding.id).desc()).limit(10)).all()
    return [{"rule_id": r[0], "title": r[1], "count": r[2]} for r in rows]


def _category_evolution(db: Session, org_id: str) -> list[dict]:
    rows = db.execute(
        select(Finding.first_seen_at, Finding.category).where(
            Finding.organization_id == org_id)).all()
    by_month: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for first_seen, category in rows:
        if first_seen is None:
            continue
        by_month[_month(first_seen)][category or "Uncategorized"] += 1
    months = sorted(by_month.keys())[-12:]
    return [{"month": m, "categories": dict(by_month[m])} for m in months]


@router.get("/analytics/trends")
def trends(user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    org_id = user.organization_id
    return {
        "score_progression": _score_progression(db, org_id),
        "mttr_by_severity": _mttr_by_severity(db, org_id),
        "recurrence": _recurrence_rate(db, org_id),
        "top_rules": _top_rules(db, org_id),
        "category_evolution": _category_evolution(db, org_id),
    }


# ── Executive Summary (Security Analytics dashboard) ──────────────────────

ACTIVE_FINDING_STATUSES = (FindingStatus.open, FindingStatus.acknowledged, FindingStatus.in_progress)
# String forms of the above, for comparing against status-change event ``to_status``.
_ACTIVE_STATUS_VALUES = {"open", "acknowledged", "in_progress"}


def _device_filter(db, org_id: str, customer_id: str | None = None, device_ids: list[str] | None = None):
    """Return device IDs scoped to org + optional filters, excluding decommissioned."""
    if device_ids:
        # Explicit device ID list (cross-filtering) — validate they belong to the org
        q = select(Device.id).where(Device.organization_id == org_id,
                                     Device.decommissioned.is_(False),
                                     Device.id.in_(device_ids))
        return [r[0] for r in db.execute(q).all()]
    q = select(Device.id).where(Device.organization_id == org_id,
                                 Device.decommissioned.is_(False))
    if customer_id:
        q = q.where(Device.customer_id == customer_id)
    return [r[0] for r in db.execute(q).all()]


def _coerce_utc(ts: datetime | None) -> datetime | None:
    """Normalize a possibly-naive datetime to timezone-aware UTC."""
    if ts is None:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _parse_local_today(local_today: str | None) -> date:
    """The user's local calendar 'today'; falls back to the server's UTC date."""
    if local_today:
        try:
            return datetime.strptime(local_today, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).date()


def _end_of_local_day_utc(d: date, tz_offset_min: int) -> datetime:
    """UTC instant at the END of local calendar day *d*.

    ``tz_offset_min`` is JavaScript ``Date.getTimezoneOffset()`` in minutes, for
    which ``UTC = local + offset`` (e.g. IST is -330). The end of local day *d*
    is the start of local day *d+1*; converting that local midnight to UTC gives
    the cutoff instant used to evaluate "state as of end of that day".
    """
    local_midnight_next = datetime(d.year, d.month, d.day, tzinfo=timezone.utc) + timedelta(days=1)
    return local_midnight_next + timedelta(minutes=tz_offset_min)


def _day_series(start: date, end: date) -> list[date]:
    """Inclusive list of calendar dates from *start* to *end*."""
    if end < start:
        return []
    return [start + timedelta(days=i) for i in range((end - start).days + 1)]


def _active_at(timeline: list[tuple[datetime, bool]], cutoff: datetime) -> bool:
    """Whether a finding is active at *cutoff*, given its sorted transition list."""
    active = False
    for ts, is_active in timeline:
        if ts <= cutoff:
            active = is_active
        else:
            break
    return active


def _finding_timelines(db, org_id: str, device_ids: list[str] | None):
    """Reconstruct each finding's active/inactive history from its status events.

    A finding is born ``open`` (active) at ``first_seen_at``. Every status change
    — manual or automatic — is recorded as an append-only ``status_change``
    comment, so the ordered event log is the authoritative, immutable history:
    resolving a finding today appends a dated transition and never rewrites the
    past. ``resolved_at`` is added as a backstop (covers rows whose resolution
    predates event logging), and a final transition pinned at ``now`` ties the
    present state to the live status, so today's trend point always equals the
    live card count.

    Returns ``(severity_by_id, timelines)`` where each timeline is a chronological
    list of ``(utc_instant, is_active)`` transitions.
    """
    fq = select(Finding.id, Finding.severity, Finding.first_seen_at,
                Finding.created_at, Finding.resolved_at, Finding.status).where(
        Finding.organization_id == org_id)
    if device_ids:
        fq = fq.where(Finding.device_id.in_(device_ids))
    severity_by_id: dict[str, str] = {}
    timelines: dict[str, list[tuple[datetime, bool]]] = {}
    current_active: dict[str, bool] = {}
    for fid, severity, first_seen, created, resolved, fstatus in db.execute(fq):
        born = _coerce_utc(first_seen) or _coerce_utc(created) or datetime.now(timezone.utc)
        tl: list[tuple[datetime, bool]] = [(born, True)]
        rz = _coerce_utc(resolved)
        if rz is not None:
            tl.append((rz, False))
        severity_by_id[fid] = severity
        status_val = fstatus.value if hasattr(fstatus, "value") else str(fstatus)
        current_active[fid] = status_val in _ACTIVE_STATUS_VALUES
        timelines[fid] = tl
    if timelines:
        eq = (select(FindingComment.finding_id, FindingComment.to_status,
                     FindingComment.created_at)
              .where(FindingComment.finding_id.in_(list(timelines.keys())),
                     FindingComment.comment_type == CommentType.status_change)
              .order_by(FindingComment.created_at))
        for fid, to_status, ts in db.execute(eq):
            tl = timelines.get(fid)
            if tl is not None:
                tl.append((_coerce_utc(ts), (to_status or "").lower() in _ACTIVE_STATUS_VALUES))
    now = datetime.now(timezone.utc)
    for fid, tl in timelines.items():
        tl.append((now, current_active[fid]))
        tl.sort(key=lambda x: x[0])
    return severity_by_id, timelines


def _active_findings_by_day(db, org_id: str, device_ids: list[str] | None,
                            days: list[date], tz_offset_min: int) -> dict[str, dict[str, int]]:
    """Dense per-day active-finding counts by severity.

    Each day's value is the number of findings active as of the END of that local
    day — a point-in-time reconstruction, so historical days are immutable.
    """
    severity_by_id, timelines = _finding_timelines(db, org_id, device_ids)
    out: dict[str, dict[str, int]] = {}
    for d in days:
        cutoff = _end_of_local_day_utc(d, tz_offset_min)
        counts = {s: 0 for s in _SEVERITIES}
        for fid, tl in timelines.items():
            if _active_at(tl, cutoff):
                sev = severity_by_id.get(fid)
                if sev in counts:
                    counts[sev] += 1
        out[d.strftime("%Y-%m-%d")] = counts
    return out


def _score_by_day(db, org_id: str, device_ids: list[str] | None,
                  days: list[date], tz_offset_min: int) -> list[dict]:
    """Dense per-day average score = mean over devices of each device's latest
    score as of end of that local day. Days before any analysis are omitted."""
    q = select(Analysis.device_id, Analysis.created_at, Analysis.score).where(
        Analysis.organization_id == org_id, Analysis.status == AnalysisStatus.complete)
    if device_ids:
        q = q.where(Analysis.device_id.in_(device_ids))
    by_dev: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
    for did, ts, score in db.execute(q):
        by_dev[did].append((_coerce_utc(ts), score))
    for lst in by_dev.values():
        lst.sort(key=lambda x: x[0])
    result: list[dict] = []
    for d in days:
        cutoff = _end_of_local_day_utc(d, tz_offset_min)
        scores: list[float] = []
        for lst in by_dev.values():
            latest = None
            for ts, score in lst:
                if ts <= cutoff:
                    latest = score
                else:
                    break
            if latest is not None and latest > 0:
                scores.append(latest)
        val = round(sum(scores) / len(scores), 1) if scores else 0.0
        result.append({"date": d.strftime("%Y-%m-%d"), "value": val})
    return result


def _devices_by_day(db, org_id: str, device_ids: list[str] | None,
                    days: list[date], tz_offset_min: int) -> list[dict]:
    """Dense per-day cumulative count of (non-decommissioned) devices that existed
    as of the end of each local day."""
    q = select(Device.created_at).where(
        Device.organization_id == org_id, Device.decommissioned.is_(False))
    if device_ids:
        q = q.where(Device.id.in_(device_ids))
    created = sorted(c for c in (_coerce_utc(r[0]) for r in db.execute(q)) if c is not None)
    result: list[dict] = []
    for d in days:
        cutoff = _end_of_local_day_utc(d, tz_offset_min)
        result.append({"date": d.strftime("%Y-%m-%d"),
                       "value": sum(1 for c in created if c <= cutoff)})
    return result


def _protected_by_day(db, org_id: str, org: Organization | None, device_ids: list[str] | None,
                      days: list[date], tz_offset_min: int) -> list[dict]:
    """Dense per-day protected-device percentage, reconstructed point-in-time from
    license windows and trial/subscription state.

    License windows (``purchased_at``/``expires_at``) are evaluated per day. Org
    subscription state has no historical record, so an active/trial subscription
    is treated as covering the window (an approximation for the rare case of a
    mid-window subscription change).
    """
    devices = list(db.scalars(select(Device).where(
        Device.organization_id == org_id, Device.decommissioned.is_(False),
        *([Device.id.in_(device_ids)] if device_ids else []))))
    lp_ids = {d.license_purchase_id for d in devices if d.license_purchase_id}
    lps: dict[str, LicensePurchase] = {}
    if lp_ids:
        lps = {lp.id: lp for lp in db.scalars(
            select(LicensePurchase).where(LicensePurchase.id.in_(lp_ids)))}
    trial_end = _coerce_utc(org.trial_ends_at) if org else None
    sub_active = bool(org and org.subscription_status == "active")
    sub_trialing = bool(org and org.subscription_status == "trialing")
    result: list[dict] = []
    for d in days:
        cutoff = _end_of_local_day_utc(d, tz_offset_min)
        existing = [dev for dev in devices
                    if (c := _coerce_utc(dev.created_at)) is not None and c <= cutoff]
        if not existing:
            result.append({"date": d.strftime("%Y-%m-%d"), "value": 0.0})
            continue
        prot = 0
        for dev in existing:
            if sub_active or (sub_trialing and trial_end and cutoff < trial_end):
                prot += 1
                continue
            lp = lps.get(dev.license_purchase_id)
            if lp:
                pa = _coerce_utc(lp.purchased_at)
                ex = _coerce_utc(lp.expires_at)
                if pa and pa <= cutoff and (ex is None or ex > cutoff):
                    prot += 1
        result.append({"date": d.strftime("%Y-%m-%d"),
                       "value": round(prot / len(existing) * 100, 1)})
    return result


def _score_to_grade(score: float) -> str:
    if score >= 100:
        return "Secure"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _is_device_protected(device: Device, org: Organization, db: Session) -> bool:
    """A device is 'protected' if it has an active license or the org has an active trial."""
    # Active trial?
    now = datetime.now(timezone.utc)
    if org.subscription_status == "trialing" and org.trial_ends_at:
        trial_end = org.trial_ends_at if org.trial_ends_at.tzinfo else org.trial_ends_at.replace(tzinfo=timezone.utc)
        if trial_end > now:
            return True
    # Active subscription?
    if org.subscription_status == "active":
        return True
    # Active license?
    if device.license_purchase_id:
        lp = db.get(LicensePurchase, device.license_purchase_id)
        if lp and lp.expires_at:
            expires = lp.expires_at if lp.expires_at.tzinfo else lp.expires_at.replace(tzinfo=timezone.utc)
            if expires > now:
                return True
    return False


@router.get("/analytics/executive-summary")
def executive_summary(
    range_days: int = 30,
    customer_id: str | None = None,
    device_ids: str | None = None,
    local_today: str | None = None,
    tz_offset: int = 0,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return executive dashboard summary for the Security Analytics page.

    Trend series are point-in-time reconstructions: each calendar day's value is
    the state as of the END of that day in the user's local timezone. Historical
    days are therefore immutable — completing (or resolving) an analysis today
    only moves today's point. ``local_today`` (ISO date, e.g. "2026-07-09") and
    ``tz_offset`` (JavaScript ``Date.getTimezoneOffset()`` minutes) define the
    user's day boundaries; without them the server's UTC day is used.
    ``range_days`` controls the lookback window (default 30).
    """
    org_id = user.organization_id
    end_date = _parse_local_today(local_today)
    start_date = end_date - timedelta(days=range_days)
    days = _day_series(start_date, end_date)
    dids = [d.strip() for d in device_ids.split(",") if d.strip()] if device_ids else None
    device_ids = _device_filter(db, org_id, customer_id, dids)

    all_devices = list(db.scalars(select(Device).where(Device.id.in_(device_ids))))
    configured = [d for d in all_devices if d.configured]
    org = db.get(Organization, org_id)

    # ── Trend series (immutable history; only today reflects live state) ─
    findings_by_day = _active_findings_by_day(db, org_id, device_ids, days, tz_offset)
    ordered = sorted(findings_by_day.keys())
    critical_trend = [{"date": ds, "value": findings_by_day[ds]["Critical"]} for ds in ordered]
    high_trend = [{"date": ds, "value": findings_by_day[ds]["High"]} for ds in ordered]
    score_trend = _score_by_day(db, org_id, device_ids, days, tz_offset)
    device_trend = _devices_by_day(db, org_id, device_ids, days, tz_offset)
    protection_trend = _protected_by_day(db, org_id, org, device_ids, days, tz_offset)

    # ── Cards (current/live state) ──────────────────────────────────────
    current_scores = [d.latest_score for d in configured if d.latest_score > 0]
    overall_score = round(sum(current_scores) / len(current_scores), 1) if current_scores else 0.0
    overall_grade = _score_to_grade(overall_score)

    def _count_active(severity: str) -> int:
        q = select(func.count(Finding.id)).where(
            Finding.organization_id == org_id,
            Finding.severity == severity,
            Finding.status.in_(ACTIVE_FINDING_STATUSES))
        if device_ids:
            q = q.where(Finding.device_id.in_(device_ids))
        return db.scalar(q) or 0

    critical_count = _count_active("Critical")
    high_count = _count_active("High")
    total_devices = len(all_devices)
    configured_count = len(configured)

    protected = [d for d in all_devices if _is_device_protected(d, org, db)]
    protected_count = len(protected)
    protected_pct = round(protected_count / total_devices * 100, 1) if total_devices else 0.0

    # Active / expired device counts.
    # A device is Active when its license (from LicensePurchase or cached
    # license_info) is currently valid — regardless of whether it's a trial,
    # testing, or paid license.  Only truly expired licenses count as Expired.
    now_utc = datetime.now(timezone.utc)
    active_count = 0
    expired_count = 0
    for d in all_devices:
        expires_at = None
        # Prefer the FK-linked LicensePurchase row.
        if d.license_purchase_id:
            lp = db.get(LicensePurchase, d.license_purchase_id)
            if lp and lp.expires_at:
                expires_at = lp.expires_at
        # Fall back to cached license_info (survives LicensePurchase deletion;
        # used for trial / testing-plan devices).
        if expires_at is None:
            li = d.license_info if isinstance(d.license_info, dict) else {}
            exp_str = li.get("expires_at")
            if exp_str:
                try:
                    expires_at = datetime.fromisoformat(exp_str)
                except (ValueError, TypeError):
                    pass
        if expires_at is not None:
            exp = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
            if exp > now_utc:
                active_count += 1
            else:
                expired_count += 1

    # ── Day-over-day deltas, derived from the same immutable series ──────
    def _delta(trend: list[dict]) -> float:
        return round(trend[-1]["value"] - trend[-2]["value"], 1) if len(trend) >= 2 else 0.0

    score_delta = _delta(score_trend)
    critical_delta = int(_delta(critical_trend))
    high_delta = int(_delta(high_trend))

    return {
        "overall_score": overall_score,
        "overall_grade": overall_grade,
        "score_delta": score_delta,
        "score_trend": score_trend,
        "critical_count": critical_count,
        "critical_delta": critical_delta,
        "critical_trend": critical_trend,
        "high_count": high_count,
        "high_delta": high_delta,
        "high_trend": high_trend,
        "total_devices": total_devices,
        "configured_devices": configured_count,
        "device_trend": device_trend,
        "protected_count": protected_count,
        "protected_percentage": protected_pct,
        "protection_trend": protection_trend,
        "active_devices": active_count,
        "expired_devices": expired_count,
    }


# ── Dashboard Charts (Phase 2) ─────────────────────────────────────────

@router.get("/analytics/dashboard-charts")
def dashboard_charts(
    range_days: int = 30,
    customer_id: str | None = None,
    device_ids: str | None = None,
    all_firmware: bool = False,
    all_findings: bool = False,
    local_today: str | None = None,
    tz_offset: int = 0,
    hidden_severities: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return all chart data for the Security Analytics dashboard.

    Single endpoint returning score trend, severity distribution,
    grade distribution, firmware distribution, and top findings.

    ``local_today`` / ``tz_offset`` define the user's day boundaries
    for the score trend window; without them the server's UTC day is used.

    ``hidden_severities`` is a comma-separated list of severity names that
    must be excluded from all finding-based calculations (global filter).
    """
    org_id = user.organization_id
    end_date = _parse_local_today(local_today)
    since_dt = datetime(end_date.year, end_date.month, end_date.day, tzinfo=timezone.utc)
    since = since_dt - timedelta(days=range_days)
    dids = [d.strip() for d in device_ids.split(",") if d.strip()] if device_ids else None
    device_ids = _device_filter(db, org_id, customer_id, dids)
    hidden_set = {h.strip() for h in hidden_severities.split(",") if h.strip()} if hidden_severities else set()

    # ── Device list ──────────────────────────────────────────────────
    all_devices = list(db.scalars(
        select(Device).where(Device.id.in_(device_ids))))
    configured = [d for d in all_devices if d.configured]

    # ── 1. Score trend ──────────────────────────────────────────────
    score_rows = db.execute(
        select(func.date(Analysis.created_at),
               func.avg(Analysis.score),
               func.count(func.distinct(Analysis.device_id)))
        .where(Analysis.organization_id == org_id,
               Analysis.device_id.in_(device_ids),
               Analysis.status == AnalysisStatus.complete,
               Analysis.created_at >= since)
        .group_by(func.date(Analysis.created_at))
        .order_by(func.date(Analysis.created_at))
    ).all()
    score_trend = [
        {"date": str(r[0]), "avg_score": round(float(r[1]), 1), "device_count": r[2]}
        for r in score_rows
    ]

    # ── 2. Findings by severity ─────────────────────────────────────
    sev_hidden = Finding.severity.notin_(hidden_set) if hidden_set else True
    sev_rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.organization_id == org_id,
               Finding.device_id.in_(device_ids),
               Finding.status.in_(ACTIVE_FINDING_STATUSES),
               sev_hidden)
        .group_by(Finding.severity)
    ).all()
    sev_counts: dict[str, int] = {s: 0 for s in _SEVERITIES}
    for sev, cnt in sev_rows:
        sev_counts[sev] = cnt
    total_findings = sum(sev_counts.values())
    severity_distribution = {
        sev: {
            "count": sev_counts.get(sev, 0),
            "pct": round(sev_counts.get(sev, 0) / total_findings * 100, 1) if total_findings else 0,
        }
        for sev in _SEVERITIES
    }

    # ── 2b. Findings by status (Open vs In Progress vs Fixed) ─────────
    status_rows = db.execute(
        select(Finding.status, func.count(Finding.id))
        .where(Finding.organization_id == org_id,
               Finding.device_id.in_(device_ids),
               sev_hidden)
        .group_by(Finding.status)
    ).all()
    status_counts: dict[str, int] = {(s.value if hasattr(s, "value") else str(s)): c for s, c in status_rows}
    status_open = status_counts.get("open", 0)
    status_progress = status_counts.get("acknowledged", 0) + status_counts.get("in_progress", 0)
    status_fixed = status_counts.get("fixed", 0) + status_counts.get("false_positive", 0) + status_counts.get("accepted_risk", 0)
    status_total = status_open + status_progress + status_fixed
    status_distribution = {
        "open": {
            "count": status_open,
            "pct": round(status_open / status_total * 100, 1) if status_total else 0,
        },
        "in_progress": {
            "count": status_progress,
            "pct": round(status_progress / status_total * 100, 1) if status_total else 0,
        },
        "fixed": {
            "count": status_fixed,
            "pct": round(status_fixed / status_total * 100, 1) if status_total else 0,
        },
    }

    # ── 3. Grade distribution ───────────────────────────────────────
    grade_dist: dict[str, int] = {}
    for d in configured:
        g = d.latest_grade or "F"
        grade_dist[g] = grade_dist.get(g, 0) + 1
    total_graded = sum(grade_dist.values())
    grades = ["A", "B", "C", "D", "F"]
    grade_distribution = {
        g: {
            "count": grade_dist.get(g, 0),
            "pct": round(grade_dist.get(g, 0) / total_graded * 100, 1) if total_graded else 0,
        }
        for g in grades
    }

    # ── 4. Firmware distribution ────────────────────────────────────
    fw_map: dict[str, int] = {}
    for d in configured:
        fw = (d.firmware or "Unknown").strip()
        fw_map[fw] = fw_map.get(fw, 0) + 1
    total_fw_devices = sum(fw_map.values())
    fw_sorted = sorted(
        [{"firmware": fw, "count": cnt,
          "pct": round(cnt / total_fw_devices * 100, 1) if total_fw_devices else 0}
         for fw, cnt in fw_map.items()],
        key=lambda x: (-x["count"], x["firmware"]),
    )
    firmware_distribution = fw_sorted[:10]  # top 10 for widget
    all_firmware_list = fw_sorted if all_firmware else []

    # ── 5. Most common findings ─────────────────────────────────────
    findings_base = (
        select(Finding.rule_id, Finding.title, Finding.severity,
               func.count(Finding.id).label("n"),
               func.count(func.distinct(Finding.device_id)).label("d"))
        .where(Finding.organization_id == org_id,
               Finding.device_id.in_(device_ids),
               Finding.status.in_(ACTIVE_FINDING_STATUSES),
               sev_hidden)
        .group_by(Finding.rule_id, Finding.title, Finding.severity)
        .order_by(func.count(Finding.id).desc())
    )
    top_rows = db.execute(findings_base.limit(5)).all()
    top_findings = [
        {"rule_id": r[0], "title": r[1], "severity": r[2], "count": r[3], "devices": r[4]}
        for r in top_rows
    ]
    all_findings_list: list[dict] = []
    if all_findings:
        all_rows = db.execute(findings_base).all()
        all_findings_list = [{"rule_id": r[0], "title": r[1], "severity": r[2], "count": r[3], "devices": r[4]} for r in all_rows]
    total_unique = db.scalar(
        select(func.count(func.distinct(Finding.rule_id)))
        .where(Finding.organization_id == org_id,
               Finding.device_id.in_(device_ids),
               Finding.status.in_(ACTIVE_FINDING_STATUSES),
               sev_hidden)
    ) or 0

    return {
        "score_trend": score_trend,
        "severity_distribution": severity_distribution,
        "total_findings": total_findings,
        "grade_distribution": grade_distribution,
        "total_graded_devices": total_graded,
        "firmware_distribution": firmware_distribution,
        "total_firmware_devices": total_fw_devices,
        "top_findings": top_findings,
        "status_distribution": status_distribution,
        "total_unique_findings": total_unique,
        "all_firmware_list": all_firmware_list,
        "all_findings_list": all_findings_list,
    }


# ── Operational Summary (Phase 3) ──────────────────────────────────────

@router.get("/analytics/operational-summary")
def operational_summary(
    range_days: int = 30,
    customer_id: str | None = None,
    device_ids: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return operational intelligence data for the Security Analytics dashboard."""
    org_id = user.organization_id
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=range_days)
    dids = [d.strip() for d in device_ids.split(",") if d.strip()] if device_ids else None
    device_ids = _device_filter(db, org_id, customer_id, dids)

    # ── Devices ──────────────────────────────────────────────────────
    all_devices = list(db.scalars(
        select(Device).where(Device.id.in_(device_ids))))
    configured = [d for d in all_devices if d.configured]
    not_configured = [d for d in all_devices if not d.configured]

    # Expired license: configured devices with an expired license purchase
    expired_count = 0
    for d in configured:
        if d.license_purchase_id:
            lp = db.get(LicensePurchase, d.license_purchase_id)
            if lp and lp.expires_at:
                expires = lp.expires_at if lp.expires_at.tzinfo else lp.expires_at.replace(tzinfo=timezone.utc)
                if expires <= now:
                    expired_count += 1

    # ── Analysis activity ────────────────────────────────────────────
    # Count analyses in the time window by source, via Tsr.uploaded_by
    tsr_ids = [a.tsr_id for a in db.scalars(
        select(Analysis).where(Analysis.organization_id == org_id,
                               Analysis.device_id.in_(device_ids),
                               Analysis.status == AnalysisStatus.complete,
                               Analysis.created_at >= since))]
    auto_scans = 0
    manual_pulls = 0
    manual_uploads = 0
    if tsr_ids:
        tsrs = db.scalars(select(Tsr).where(Tsr.id.in_(tsr_ids))).all()
        for t in tsrs:
            ub = (t.uploaded_by or "").lower()
            if ub == "api-scheduled":
                auto_scans += 1
            elif ub == "api-pull":
                manual_pulls += 1
            else:
                manual_uploads += 1

    # Failed API pulls from connection logs
    failed_pulls = db.scalar(select(func.count(ApiConnectionLog.id)).where(
        ApiConnectionLog.organization_id == org_id,
        ApiConnectionLog.device_id.in_(device_ids),
        ApiConnectionLog.success.is_(False),
        ApiConnectionLog.timestamp >= since)) or 0

    # ── API connection status ────────────────────────────────────────
    api_connected = 0
    api_failed = 0
    manual_devices = 0
    for d in configured:
        if d.connection_method == "api":
            if d.last_connection_status == "ok":
                api_connected += 1
            else:
                api_failed += 1
        else:
            manual_devices += 1

    # ── Recently changed devices ─────────────────────────────────────
    changed: list[dict] = []
    for d in configured:
        analyses = db.scalars(
            select(Analysis).where(
                Analysis.device_id == d.id,
                Analysis.status == AnalysisStatus.complete)
            .order_by(Analysis.created_at.desc()).limit(2)
        ).all()
        if len(analyses) < 2:
            continue
        curr, prev = analyses[0], analyses[1]
        delta = curr.score - prev.score
        if delta > 0:
            trend = "Improved"
        elif delta < 0:
            trend = "Dropped"
        else:
            trend = "No Change"
        changed.append({
            "device_id": d.id,
            "device_name": d.friendly_name or d.model or d.serial,
            "trend": trend,
            "old_score": prev.score,
            "new_score": curr.score,
            "changed_at": curr.created_at.isoformat() if curr.created_at else "",
        })
    # Sort by most recent first, limit to 5
    changed.sort(key=lambda x: x["changed_at"], reverse=True)
    recently_changed = changed[:5]

    # ── Customer overview (MSP only) ─────────────────────────────────
    org = db.get(Organization, org_id)
    customer_overview: list[dict] = []
    if org and org.is_msp:
        from ..models import Customer
        customers = db.scalars(
            select(Customer).where(Customer.organization_id == org_id)).all()
        for c in customers:
            cdevs = [d for d in all_devices if d.customer_id == c.id and d.configured]
            if not cdevs:
                continue
            avg_score = round(sum(d.latest_score for d in cdevs) / len(cdevs), 1)
            crit = sum(d.critical_count or 0 for d in cdevs)
            customer_overview.append({
                "customer_id": c.id,
                "customer_name": c.name,
                "device_count": len(cdevs),
                "avg_score": avg_score,
                "critical_count": crit,
            })
        # Sort by critical findings desc
        customer_overview.sort(key=lambda x: x["critical_count"], reverse=True)

    return {
        "device_health": {
            "configured": len(configured),
            "not_configured": len(not_configured),
            "expired_license": expired_count,
        },
        "analysis_activity": {
            "automatic_scans": auto_scans,
            "manual_pulls": manual_pulls,
            "manual_uploads": manual_uploads,
            "failed_pulls": failed_pulls,
        },
        "api_status": {
            "api_connected": api_connected,
            "api_failed": api_failed,
            "manual_devices": manual_devices,
        },
        "recently_changed": recently_changed,
        "customer_overview": customer_overview,
        "is_msp": org.is_msp if org else False,
    }


# ── Risk Trend ─────────────────────────────────────────────────────────

@router.get("/analytics/risk-trend")
def risk_trend(
    range_days: int = 30,
    customer_id: str | None = None,
    device_ids: str | None = None,
    local_today: str | None = None,
    tz_offset: int = 0,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return daily active severity counts for the Risk Trend widget.

    Each day is the number of findings *active* as of the end of that local day —
    a point-in-time reconstruction, so history is immutable and reflects both new
    findings and resolutions. ``local_today``/``tz_offset`` define the user's day
    boundaries (see ``executive_summary``).
    """
    org_id = user.organization_id
    end_date = _parse_local_today(local_today)
    start_date = end_date - timedelta(days=range_days)
    days = _day_series(start_date, end_date)
    dids = [d.strip() for d in device_ids.split(",") if d.strip()] if device_ids else None
    dev_ids = _device_filter(db, org_id, customer_id, dids)

    severities = ["Critical", "High", "Medium", "Low"]
    findings_by_day = _active_findings_by_day(db, org_id, dev_ids, days, tz_offset)
    trend: list[dict] = []
    for ds in sorted(findings_by_day.keys()):
        counts = findings_by_day[ds]
        trend.append({"date": ds, **{s: counts.get(s, 0) for s in severities}})

    # Deltas: net change across the window (first vs last day).
    deltas: dict[str, int] = {}
    if len(trend) >= 2:
        first, last = trend[0], trend[-1]
        for s in severities:
            deltas[s] = last[s] - first[s]
    else:
        for s in severities:
            deltas[s] = 0

    return {"trend": trend, "deltas": deltas}


# ── Firmware Compliance ──────────────────────────────────────────────────

@router.get("/analytics/firmware-compliance")
def firmware_compliance(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return per-generation firmware compliance for the tenant's devices.

    Each generation that has at least one device is included.  Devices whose
    firmware exactly matches the generation's recommended version are counted
    as ``latest``; all others are ``older``.
    """
    org_id = user.organization_id

    # All non-decommissioned devices for this tenant.
    devices = list(db.scalars(
        select(Device).where(
            Device.organization_id == org_id,
            Device.decommissioned.is_(False),
        )))

    # Build a model → device list index.
    by_model: dict[str, list[Device]] = {}
    for d in devices:
        m = (d.model or "").strip()
        if m:
            by_model.setdefault(m, []).append(d)

    # All generations with their models and recommended firmware.
    gens = db.scalars(
        select(DeviceGeneration).order_by(DeviceGeneration.sort_order)
    ).all()

    result: list[dict] = []
    for g in gens:
        rec_fw = g.firmware[0].version.strip() if g.firmware else ""
        gen_devices: list[Device] = []
        for gd in g.devices:
            gen_devices.extend(by_model.get(gd.model, []))
        if not gen_devices:
            continue  # no tenant devices for this generation

        latest = sum(1 for d in gen_devices
                     if (d.firmware or "").strip() == rec_fw)
        older = len(gen_devices) - latest
        result.append({
            "generation": g.name,
            "recommended_firmware": rec_fw,
            "latest_count": latest,
            "older_count": older,
            "total": len(gen_devices),
        })

    return {"generations": result}