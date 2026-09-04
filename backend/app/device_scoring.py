"""Live device security score.

``Device.latest_score`` / ``latest_grade`` represent the device's CURRENT
security posture and must be kept in sync with the live triage state of its
findings — not frozen at whatever the pipeline detected the moment a TSR was
parsed. ``recompute_device_score`` is the single entry point for that: it
reuses ``score_findings`` (firewallguard/analytics/scoring.py) UNCHANGED,
feeding it only the device's currently-ACTIVE (non-resolved-status) findings,
one row per affected object — the same granularity the pipeline itself scores
at, so grouping (a display/triage concept) never changes the formula's
semantics.

This is deliberately separate from ``Analysis.score``, which stays an
immutable historical record of what a specific scan detected at parse time
(used by TSR history/comparison and by past days of the score trend).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from . import finding_groups
from .models import Device, Finding
from firewallguard.analytics.scoring import score_findings


def recompute_device_score(db, device_id: str) -> dict[str, Any]:
    """Recompute ``Device.latest_score``/``latest_grade`` from the device's
    currently-active findings and persist it onto the (already-loaded-or-not)
    Device row. Does not commit — the caller controls the transaction."""
    device = db.get(Device, device_id)
    if device is None:
        return {}
    instances = list(db.scalars(select(Finding).where(Finding.device_id == device_id)))
    active = [f for f in instances if not finding_groups.is_resolved(f.status)]
    result = score_findings(active)
    device.latest_score = result["score"]
    device.latest_grade = result["grade"]
    return result
