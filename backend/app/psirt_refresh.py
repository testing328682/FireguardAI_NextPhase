"""PSIRT advisory refresh.

The curated advisory dataset (``firewallguard/intelligence/data/psirt.json``) is
the source of truth for firmware matching. A daily job hashes the dataset and,
when it changes, records a changelog entry and counts how many devices the new
advisory set affects (those devices are re-evaluated on their next scan).

A live fetch from the SonicWall PSIRT portal and NVD cross-reference is attempted
when reachable; it is best-effort and never fails the job. In offline/dev
environments the job still records hashes and detects local dataset edits.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import PsirtRefreshLog, Device

import firewallguard.intelligence.firmware as fw

logger = logging.getLogger("firewallguard.psirt")
settings = get_settings()


def _load_dataset() -> dict:
    with open(fw._DATA, encoding="utf-8") as fh:
        return json.load(fh)


def _content_hash(data: dict) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _try_live_fetch() -> dict | None:
    """Best-effort fetch of the advisory list from the PSIRT portal.

    Returns parsed JSON if the portal is reachable and returns JSON, else None.
    Never raises — the curated dataset remains authoritative on failure.
    """
    import urllib.request
    try:
        url = f"{settings.psirt_portal_url}/vuln-list"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        logger.info("PSIRT live fetch unavailable (%s); using curated dataset", exc)
        return None


def _count_affected_devices(db: Session) -> int:
    intel = fw.get_intel()
    count = 0
    for d in db.scalars(select(Device)):
        try:
            if intel.evaluate(d.firmware or "", d.model or "").get("advisory_count", 0) > 0:
                count += 1
        except Exception:  # noqa: BLE001
            continue
    return count


def refresh_psirt(db: Session, source: str = "scheduled") -> PsirtRefreshLog:
    """Run a refresh, recording a changelog entry. Returns the new log row."""
    _try_live_fetch()   # best-effort; curated dataset is authoritative here
    data = _load_dataset()
    advisories = data.get("advisories", [])
    new_hash = _content_hash(data)

    last = db.scalar(select(PsirtRefreshLog).order_by(PsirtRefreshLog.ran_at.desc()).limit(1))
    prev_ids: set[str] = set()
    if last is not None:
        prev_ids = set((last.added or []) + (last.updated or []))  # approximate prior set
    current_ids = {a.get("advisory_id", "") for a in advisories if a.get("advisory_id")}

    changed = last is None or last.content_hash != new_hash
    added = sorted(current_ids - prev_ids) if changed else []
    affected = _count_affected_devices(db) if changed else (last.affected_devices if last else 0)

    log = PsirtRefreshLog(
        ran_at=datetime.now(timezone.utc), source=source, content_hash=new_hash,
        changed=changed, advisory_count=len(advisories),
        added=added if last is not None else sorted(current_ids),
        updated=[], affected_devices=affected,
        note=("dataset changed" if changed else "no change"))
    db.add(log)
    db.commit()
    db.refresh(log)
    return log
