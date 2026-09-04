"""Finding grouping: one logical finding per (device, rule), many instances.

A detection rule that flags several configuration objects produces one
``Finding`` row per object (see ``findings_sync`` — each row already carries
``rule_id`` plus ``object_name``/``object_type``/``object_detail`` and its own
``status``). The instances that share ``(device_id, rule_id)`` are the
"affected policies/rules" of a single logical finding.

The PARENT finding has its own persisted status (``FindingGroupStatus``, keyed
by ``(device_id, rule_id)`` so it survives re-analysis). It is never derived
from the instances — a user must explicitly set it. Only one rule is
server-enforced:

    A FIXED-classified status (fixed / false_positive / accepted_risk) may be
    set on the parent only when every instance is ALSO FIXED-classified.
    An OPEN-classified status (open / acknowledged / in_progress / suppressed)
    may be set on the parent at any time, regardless of instance statuses.

This mirrors the instance-level classification used throughout the app for
"is this finding done":

    FIXED-classified = fixed, false_positive, accepted_risk
    OPEN-classified   = open, acknowledged, in_progress, suppressed  (everything else)

Note this differs from the older ``ACTIVE_FINDING_STATUSES`` tuple used
elsewhere (open/acknowledged/in_progress, excluding suppressed) — that tuple
answers a different, narrower question ("does this instance need triage
attention right now"); the classification here answers "is the underlying
condition resolved", which is what parent-eligibility and grouped finding
counts must use. A suppressed instance is silenced, not fixed, so it still
blocks the parent from resolving.
"""

from __future__ import annotations

from typing import Any, Iterable

from .models import Finding, FindingGroupStatus

# Statuses that mean "the underlying condition is resolved". Every other
# FindingStatus value (open, acknowledged, in_progress, suppressed) is
# OPEN-classified for the purposes of grouping/eligibility.
RESOLVED_STATES = {"fixed", "false_positive", "accepted_risk"}


def group_key(f: Finding) -> tuple[str, str]:
    return (f.device_id, f.rule_id)


def _status_value(s: Any) -> str:
    return s.value if hasattr(s, "value") else str(s)


def is_resolved(status: Any) -> bool:
    return _status_value(status) in RESOLVED_STATES


def load_group_statuses(db, organization_id: str,
                        device_ids: list[str] | None = None) -> dict[tuple[str, str], str]:
    """Batch-read persisted parent statuses. Read-only — never inserts, so it
    is safe to call from list endpoints over many groups at once. A group with
    no row yet is simply absent from the returned dict (caller defaults to
    "open", the implicit starting state)."""
    from sqlalchemy import select
    stmt = select(FindingGroupStatus.device_id, FindingGroupStatus.rule_id,
                 FindingGroupStatus.status).where(
        FindingGroupStatus.organization_id == organization_id)
    if device_ids:
        stmt = stmt.where(FindingGroupStatus.device_id.in_(device_ids))
    return {(did, rid): status for did, rid, status in db.execute(stmt).all()}


def get_or_create_group_status(db, organization_id: str, device_id: str,
                               rule_id: str) -> FindingGroupStatus:
    """Fetch the parent's persisted status row, creating a default ``open``
    row on first access. Used by the single-group detail/transition endpoints
    (low volume — safe to write on read), never by list endpoints."""
    from sqlalchemy import select
    row = db.scalar(select(FindingGroupStatus).where(
        FindingGroupStatus.device_id == device_id,
        FindingGroupStatus.rule_id == rule_id))
    if row is None:
        row = FindingGroupStatus(organization_id=organization_id, device_id=device_id,
                                 rule_id=rule_id, status="open")
        db.add(row)
        db.flush()
    return row


def _counts(instances: list[Finding]) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    for i in instances:
        s = _status_value(i.status)
        status_counts[s] = status_counts.get(s, 0) + 1
    total = len(instances)
    fixed = sum(n for s, n in status_counts.items() if s in RESOLVED_STATES)
    return {
        "affected_total": total,
        "affected_fixed": fixed,
        "affected_open": total - fixed,
        "affected_suppressed": status_counts.get("suppressed", 0),
        "status_counts": status_counts,
    }


def _representative(instances: list[Finding]) -> Finding:
    """The instance whose metadata (title/severity/category/evidence/...)
    represents the group. Prefer an unresolved instance so the detail page
    surfaces something actionable; fall back to the most recently seen row."""
    unresolved = [i for i in instances if not is_resolved(i.status)]
    pool = unresolved or instances
    return max(pool, key=lambda i: (i.last_seen_at or i.first_seen_at, i.id))


def can_resolve(instances: Iterable[Finding]) -> bool:
    """True when every instance is FIXED-classified — the only time the
    parent may be moved to a FIXED-classified status."""
    return all(is_resolved(i.status) for i in instances)


def effective_status(instances: list[Finding],
                     status_by_key: dict[tuple[str, str], str], key: tuple[str, str]) -> str:
    """The status a group is classified by.

    A group of exactly ONE instance has no separate "parent" concept — a
    single-object finding (e.g. firmware) IS that instance, so its own status
    is authoritative directly; there is no extra confirmation step. A group
    of TWO OR MORE instances uses the persisted parent status (default
    "open" if never explicitly transitioned) — see the module docstring for
    why that is never auto-derived from the instances.
    """
    if len(instances) == 1:
        return _status_value(instances[0].status)
    return status_by_key.get(key, "open")


def build_groups(findings: list[Finding],
                 status_by_key: dict[tuple[str, str], str] | None = None
                 ) -> list[dict[str, Any]]:
    """Collapse instance rows into grouped-finding summaries, one per rule.

    ``status_by_key`` supplies the persisted parent status per
    ``(device_id, rule_id)``, used only for groups with 2+ instances (see
    ``effective_status``). Manual findings (``source == "manual"``) are
    single-object by nature and still form a group of one, so they surface
    unchanged.
    """
    status_by_key = status_by_key or {}
    buckets: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        buckets.setdefault(group_key(f), []).append(f)

    _sev = ("Critical", "High", "Medium", "Low", "Info")
    groups: list[dict[str, Any]] = []
    for key, instances in buckets.items():
        device_id, rule_id = key
        rep = _representative(instances)
        counts = _counts(instances)
        parent_status = effective_status(instances, status_by_key, key)
        groups.append({
            "group_id": f"{device_id}::{rule_id}",
            "device_id": device_id,
            "rule_id": rule_id,
            "representative_id": rep.id,
            "severity": rep.severity,
            "title": rep.title,
            "category": rep.category,
            "status": parent_status,
            "can_resolve": can_resolve(instances),
            "source": rep.source,
            "first_seen_at": min((i.first_seen_at for i in instances if i.first_seen_at),
                                 default=rep.first_seen_at),
            "last_seen_at": max((i.last_seen_at for i in instances if i.last_seen_at),
                                default=rep.last_seen_at),
            **counts,
        })
    groups.sort(key=lambda g: (_sev.index(g["severity"]) if g["severity"] in _sev else 9,
                               -g["affected_open"], g["title"]))
    return groups


def grouped_counts(rows: Iterable[tuple[str, str, str, Any]],
                   status_by_key: dict[tuple[str, str], str] | None = None
                   ) -> dict[str, Any]:
    """Count logical findings (groups), not instance rows.

    ``rows`` are ``(device_id, rule_id, severity, status)`` tuples, one per
    instance. A group's effective status is its own instance's status when it
    has exactly one (see ``effective_status``), else the persisted parent
    status from ``status_by_key`` (default "open"). Returns the group-level
    severity distribution (ACTIVE groups only), a status bucket breakdown
    (open / in_progress / fixed), and the total active group count.
    """
    status_by_key = status_by_key or {}
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for device_id, rule_id, severity, inst_status in rows:
        b = buckets.setdefault((device_id, rule_id), {"sev": severity, "statuses": []})
        b["statuses"].append(_status_value(inst_status))

    sev_active: dict[str, int] = {}
    status_buckets = {"open": 0, "in_progress": 0, "fixed": 0}
    active_groups = 0
    for key, b in buckets.items():
        statuses = b["statuses"]
        status = statuses[0] if len(statuses) == 1 else status_by_key.get(key, "open")
        if status in RESOLVED_STATES:
            status_buckets["fixed"] += 1
        else:
            active_groups += 1
            sev_active[b["sev"]] = sev_active.get(b["sev"], 0) + 1
            status_buckets["open" if status == "open" else "in_progress"] += 1
    return {"severity_active": sev_active, "status_buckets": status_buckets,
            "active_groups": active_groups}
