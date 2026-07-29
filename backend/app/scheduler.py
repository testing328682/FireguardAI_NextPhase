"""Schedule arithmetic and per-tenant scan concurrency control.

``compute_next_run`` turns a ``Schedule`` row into the next UTC datetime it
should fire, honouring frequency, time-of-day, day-of-week/month and blackout
windows. ``acquire_scan_slot`` / ``release_scan_slot`` enforce a per-tenant
ceiling on concurrent scans using Redis counters; if Redis is unavailable the
limit fails open so scans still run.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from .config import get_settings
from .models import Schedule, ScheduleFrequency

logger = logging.getLogger("firewallguard.scheduler")
settings = get_settings()


def _in_blackout(when: datetime, windows: list) -> bool:
    """Return True if ``when`` (UTC) falls inside any blackout window.

    Each window is ``{"start": ISO8601, "end": ISO8601}``.
    """
    for w in windows or []:
        try:
            start = datetime.fromisoformat(w["start"])
            end = datetime.fromisoformat(w["end"])
        except (KeyError, ValueError):
            continue
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        if start <= when <= end:
            return True
    return False


def compute_next_run(schedule: Schedule, after: Optional[datetime] = None) -> Optional[datetime]:
    """Compute the next fire time strictly after ``after`` (default: now, UTC).

    Times are computed in UTC. ``timezone`` on the schedule is informational for
    Phase 1 (the field is persisted for the UI); production would localise here.
    Manual schedules never fire automatically and return None.
    """
    if not schedule.enabled or schedule.frequency == ScheduleFrequency.manual:
        return None

    now = after or datetime.now(timezone.utc)
    hour = now.hour if schedule.frequency == ScheduleFrequency.hourly else schedule.hour
    candidate = now.replace(hour=hour, minute=schedule.minute,
                            second=0, microsecond=0)

    def advance(c: datetime) -> datetime:
        if schedule.frequency == ScheduleFrequency.hourly:
            return c + timedelta(hours=1)
        if schedule.frequency == ScheduleFrequency.daily:
            return c + timedelta(days=1)
        if schedule.frequency == ScheduleFrequency.weekly:
            return c + timedelta(days=1)
        return c + timedelta(days=1)  # monthly: step a day at a time until match

    # Walk forward (bounded) until we find the first valid, non-blackout slot.
    for _ in range(0, 800):
        valid = candidate > now
        if valid and schedule.frequency == ScheduleFrequency.weekly \
                and schedule.day_of_week is not None:
            valid = candidate.weekday() == schedule.day_of_week
        if valid and schedule.frequency == ScheduleFrequency.monthly \
                and schedule.day_of_month is not None:
            valid = candidate.day == schedule.day_of_month
        if valid and not _in_blackout(candidate, schedule.blackout_windows):
            return candidate
        candidate = advance(candidate)
    return None


# ---- per-tenant concurrency (Redis) --------------------------------------
def _redis():
    import redis  # imported lazily; optional at runtime
    return redis.Redis.from_url(settings.redis_url)


def acquire_scan_slot(organization_id: str) -> bool:
    """Try to reserve a scan slot for a tenant. Fails open if Redis is down."""
    key = f"fgai:scan_slots:{organization_id}"
    try:
        client = _redis()
        current = client.incr(key)
        client.expire(key, 3600)  # safety net against leaked slots
        if current > settings.max_concurrent_scans_per_tenant:
            client.decr(key)
            return False
        return True
    except Exception as exc:  # noqa: BLE001 - no Redis -> do not block scans
        logger.debug("Scan-slot acquire fell open (no Redis?): %s", exc)
        return True


def release_scan_slot(organization_id: str) -> None:
    key = f"fgai:scan_slots:{organization_id}"
    try:
        client = _redis()
        if client.decr(key) < 0:
            client.set(key, 0)
    except Exception:  # noqa: BLE001
        pass
