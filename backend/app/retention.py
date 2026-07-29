"""Data-retention enforcement.

Each organization retains analyses and TSRs for a window derived from its plan
tier (``settings.retention_days``) unless it sets ``data_retention_days``. The
daily purge deletes analyses, their findings/comments and TSR rows older than
the window (0 = unlimited). Object-storage blobs are removed best-effort.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Organization, Analysis, Tsr, Finding, FindingComment, DriftEvent

logger = logging.getLogger("firewallguard.retention")
settings = get_settings()


def retention_days_for(org: Organization) -> int:
    if org.data_retention_days is not None:
        return org.data_retention_days
    return settings.retention_days.get(org.plan.value, 0)


def purge_expired(db: Session) -> dict:
    """Delete data older than each org's retention window. Returns counts."""
    now = datetime.now(timezone.utc)
    deleted_analyses = deleted_tsrs = 0
    for org in db.scalars(select(Organization)):
        days = retention_days_for(org)
        if not days:
            continue
        cutoff = now - timedelta(days=days)
        old = db.scalars(select(Analysis).where(
            Analysis.organization_id == org.id, Analysis.created_at < cutoff)).all()
        for a in old:
            for f in db.scalars(select(Finding).where(Finding.analysis_id == a.id)):
                db.execute(FindingComment.__table__.delete().where(
                    FindingComment.finding_id == f.id))
                db.delete(f)
            db.execute(DriftEvent.__table__.delete().where(
                (DriftEvent.current_analysis_id == a.id) |
                (DriftEvent.previous_analysis_id == a.id)))
            tsr = db.get(Tsr, a.tsr_id)
            db.delete(a)
            if tsr is not None:
                _delete_blob(tsr.storage_key)
                db.delete(tsr)
                deleted_tsrs += 1
            deleted_analyses += 1
    db.commit()
    return {"analyses": deleted_analyses, "tsrs": deleted_tsrs}


def _delete_blob(storage_key: str) -> None:
    try:
        from .storage import delete_object
        delete_object(storage_key)
    except Exception as exc:  # noqa: BLE001 - blob cleanup is best-effort
        logger.debug("Blob delete skipped for %s: %s", storage_key, exc)
