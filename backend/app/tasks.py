"""Background processing.

The heavy work - running the full analysis pipeline on a multi-megabyte TSR -
is performed by a Celery worker so the API stays responsive. ``dispatch_analysis``
sends the task to the broker; if Celery is not configured (for example in a
single-process development setup) it falls back to running the analysis inline.

After an analysis completes the worker computes drift against the previous
analysis for the same device and fires any matching alert subscriptions.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from celery import Celery
from sqlalchemy import select

from .config import get_settings
from .database import SessionLocal
from .models import (
    Analysis, AnalysisStatus, Device, Tsr, DriftEvent, Schedule, DeviceCredential,
    Organization,
)
from .storage import load_tsr, save_tsr, delete_object
from .alerting import evaluate_and_send_alerts, send_scan_failure_alert
from .findings_sync import sync_findings
from .scheduler import compute_next_run, acquire_scan_slot, release_scan_slot
from .crypto import decrypt
from .sonicos import SonicOSClient, SonicOSError

from firewallguard.pipeline import analyze_text
from firewallguard.analytics.drift import detect_drift

logger = logging.getLogger("firewallguard.tasks")

settings = get_settings()

# Number of recent TSRs to retain per device.
_TSR_RETENTION_COUNT = 10

# ── API connection log helper (shared with devices.py) ────────────────
_MAX_CONNECTION_LOGS = 100


def log_api_connection(db, *, device_id: str, organization_id: str,
                       trigger: str, host: str, port: int, endpoint: str,
                       http_status: int | None, response_time_ms: int | None,
                       success: bool, error_message: str = "",
                       connected_serial: str = "", registered_serial: str = "",
                       result_summary: str = "") -> None:
    """Record an API connection attempt and enforce the per-device log cap."""
    from .models import ApiConnectionLog
    from sqlalchemy import func as sqlfunc, delete as sqla_delete
    from datetime import datetime as _dt, timezone as _tz

    try:
        log = ApiConnectionLog(
            organization_id=organization_id, device_id=device_id,
            timestamp=_dt.now(_tz.utc), trigger=trigger, host=host, port=port,
            endpoint=endpoint, http_status=http_status,
            response_time_ms=response_time_ms, success=success,
            error_message=error_message, connected_serial=connected_serial,
            registered_serial=registered_serial, result_summary=result_summary,
        )
        db.add(log)
        db.flush()

        # Prune old entries beyond the cap.
        count = db.scalar(select(sqlfunc.count(ApiConnectionLog.id)).where(
            ApiConnectionLog.device_id == device_id)) or 0
        if count > _MAX_CONNECTION_LOGS:
            excess = count - _MAX_CONNECTION_LOGS
            old_ids = [
                row[0] for row in db.execute(
                    select(ApiConnectionLog.id)
                    .where(ApiConnectionLog.device_id == device_id)
                    .order_by(ApiConnectionLog.timestamp.asc()).limit(excess)
                ).all()
            ]
            if old_ids:
                db.execute(sqla_delete(ApiConnectionLog).where(
                    ApiConnectionLog.id.in_(old_ids)))
    except Exception:
        logger.warning("Failed to record API connection log for device %s",
                       device_id[:8], exc_info=True)


def enforce_tsr_retention(db, device_id: str, keep: int = _TSR_RETENTION_COUNT) -> int:
    """Delete the oldest *non-favorited* TSRs for a device beyond the *keep* limit.

    Favorited TSRs are never deleted.  The total number of TSRs retained is at
    most *keep*: favorites count toward the limit, and the remaining slots are
    filled with the most recent non-favorite TSRs.

    Cascades through findings → drift events → analyses → TSR rows, and
    removes the stored file from object storage (best-effort).
    """
    from .models import Finding
    from sqlalchemy import delete as sqla_delete, func as sqlfunc

    # Count favorites and total.
    fav_count = db.scalar(select(sqlfunc.count(Tsr.id)).where(
        Tsr.device_id == device_id, Tsr.favorite.is_(True))) or 0
    total = db.scalar(select(sqlfunc.count(Tsr.id)).where(
        Tsr.device_id == device_id)) or 0

    # Non-favorite slots available.
    non_fav_slots = max(0, keep - fav_count)
    non_fav_total = total - fav_count

    if non_fav_total <= non_fav_slots:
        return 0  # nothing to delete

    # Identify the excess non-favorite TSRs: oldest first, skipping the
    # *non_fav_slots* most recent non-favorites.
    excess_ids = [
        row[0] for row in db.execute(
            select(Tsr.id).where(
                Tsr.device_id == device_id,
                Tsr.favorite.is_(False))
            .order_by(Tsr.uploaded_at.desc()).offset(non_fav_slots)
        ).all()
    ]
    if not excess_ids:
        return 0

    deleted = 0
    for tsr_id in excess_ids:
        tsr = db.get(Tsr, tsr_id)
        if tsr is None:
            continue
        storage_key = tsr.storage_key

        # 1. Findings linked through the analysis.
        db.execute(sqla_delete(Finding).where(
            Finding.analysis_id.in_(
                select(Analysis.id).where(Analysis.tsr_id == tsr_id)
            )
        ))
        # 2. Drift events that reference this analysis.
        db.execute(sqla_delete(DriftEvent).where(
            DriftEvent.previous_analysis_id.in_(
                select(Analysis.id).where(Analysis.tsr_id == tsr_id)
            )
        ))
        db.execute(sqla_delete(DriftEvent).where(
            DriftEvent.current_analysis_id.in_(
                select(Analysis.id).where(Analysis.tsr_id == tsr_id)
            )
        ))
        # 3. Analysis row.
        db.execute(sqla_delete(Analysis).where(Analysis.tsr_id == tsr_id))
        # 4. TSR row.
        db.delete(tsr)
        db.flush()

        # 5. Storage file (best-effort — the DB row is already gone).
        if storage_key:
            try:
                delete_object(storage_key)
            except Exception:
                logger.debug("Could not delete storage object %s", storage_key)

        deleted += 1

    if deleted:
        db.commit()
        logger.info("TSR retention: deleted %d old TSR(s) for device %s "
                     "(%d favorites + %d non-favorites, kept %d total)",
                     deleted, device_id[:8], fav_count, non_fav_total - deleted, keep)
    return deleted

celery_app = Celery("firewallguard",
                    broker=settings.celery_broker_url,
                    backend=settings.celery_result_backend)
celery_app.conf.task_default_queue = "analysis"


def run_analysis_inline(analysis_id: str) -> None:
    """Execute the full pipeline for one analysis and persist the result."""
    db = SessionLocal()
    try:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            return
        analysis.status = AnalysisStatus.running
        db.commit()

        tsr = db.get(Tsr, analysis.tsr_id)
        raw = load_tsr(tsr.storage_key)
        text = raw.decode("utf-8", errors="replace")

        # Detect GUI vs API TSR format and, for API, normalize to GUI-equivalent
        # text so the same parser/rules apply (see firewallguard/tsr/normalize.py).
        from firewallguard.tsr.normalize import normalize_tsr
        text, tsr_format = normalize_tsr(text)

        # Hybrid rule layer: tenant CEL rules add findings; suppressions/overrides
        # are applied to the combined set before scoring.  System rule CEL
        # conditions (superadmin overrides) filter Python-generated findings.
        from .rule_engine import make_pipeline_hooks, api_unsupported_system_keys
        extra_fn, suppressions, system_filter_fn = make_pipeline_hooks(
            db, analysis.organization_id, analysis.device_id)
        # API TSRs lose space-separated table/phrase data; rules sourced from
        # those sections are not evaluated (suppressed) to avoid false results.
        if tsr_format == "api":
            suppressions = list(suppressions) + [
                {"rule_key": k, "action": "disable", "value": ""}
                for k in api_unsupported_system_keys(db)]
        result = analyze_text(text, tsr.filename,
                              extra_findings_fn=extra_fn, suppressions=suppressions,
                              system_filter_fn=system_filter_fn)
        result["tsr_format"] = tsr_format

        score = result["score"]
        sev = score["severity_counts"]
        # ── Firmware compliance check (admin-configured generations) ────
        # Run this BEFORE storing counts so the Critical firmware finding
        # is included in the device / analysis severity tallies.
        try:
            from .rule_engine import check_firmware_compliance
            fw_finding = check_firmware_compliance(
                db,
                result["device"].get("model", ""),
                result["device"].get("firmware", ""),
            )
            if fw_finding:
                result["findings"].append(fw_finding.to_dict())
                result["finding_count"] = len(result["findings"])
                sev = result["score"]["severity_counts"]
                # The rule's severity is configurable in Product Config.
                sev[fw_finding.severity] = sev.get(fw_finding.severity, 0) + 1
        except Exception:
            logger.warning("Firmware compliance check failed; continuing", exc_info=True)

        analysis.result_json = result
        analysis.score = score["score"]
        analysis.grade = score["grade"]
        analysis.finding_count = result["finding_count"]
        analysis.critical_count = sev.get("Critical", 0)
        analysis.high_count = sev.get("High", 0)
        analysis.status = AnalysisStatus.complete

        device = db.get(Device, analysis.device_id)
        # Provisional value from this scan's raw detections; recomputed below
        # from live triage state once sync_findings reconciles the rows.
        device.latest_score = score["score"]
        device.latest_grade = score["grade"]
        device.firmware = result["device"].get("firmware") or device.firmware
        device.last_analysis_at = datetime.now(timezone.utc)
        # Sync open severity counts from the analysis.
        device.critical_count = sev.get("Critical", 0)
        device.high_count = sev.get("High", 0)
        device.medium_count = sev.get("Medium", 0)
        device.low_count = sev.get("Low", 0)
        db.commit()

        # Persist findings into the workflow table (auto-reopen/resolve) and
        # surface newly-open critical findings to the alerting layer.
        sync = sync_findings(db, analysis)

        # The device's live score reflects current triage state (sticky
        # fixed/false-positive/accepted-risk findings no longer count), which
        # sync_findings only just finished reconciling — recompute now.
        from .device_scoring import recompute_device_score
        recompute_device_score(db, analysis.device_id)
        db.commit()

        _compute_drift(db, analysis)
        evaluate_and_send_alerts(db, analysis, new_critical=sync["new_critical"])
    except Exception as exc:  # noqa: BLE001 - record failure, never crash worker
        db.rollback()
        analysis = db.get(Analysis, analysis_id)
        if analysis is not None:
            analysis.status = AnalysisStatus.failed
            analysis.error = str(exc)[:2000]
            db.commit()
            try:
                send_scan_failure_alert(db, analysis)
            except Exception:  # noqa: BLE001 - alert failure must not mask the original
                pass
    finally:
        db.close()


def _compute_drift(db, current: Analysis) -> None:
    previous = db.scalar(
        select(Analysis).where(
            Analysis.device_id == current.device_id,
            Analysis.status == AnalysisStatus.complete,
            Analysis.id != current.id)
        .order_by(Analysis.created_at.desc()).limit(1))
    if previous is None:
        return
    prev_snap = (previous.result_json or {}).get("snapshot")
    curr_snap = (current.result_json or {}).get("snapshot")
    if not prev_snap or not curr_snap:
        return
    drift = detect_drift(prev_snap, curr_snap)
    event = DriftEvent(
        organization_id=current.organization_id, device_id=current.device_id,
        previous_analysis_id=previous.id, current_analysis_id=current.id,
        alert_count=drift["alert_count"], severity_counts=drift["severity_counts"],
        alerts=drift["alerts"])
    db.add(event)
    db.commit()


@celery_app.task(name="firewallguard.run_analysis")
def run_analysis_task(analysis_id: str) -> None:
    run_analysis_inline(analysis_id)


def dispatch_analysis(analysis_id: str) -> None:
    """Queue the analysis, or run inline when no broker is available."""
    if os.environ.get("FGAI_INLINE_TASKS") == "1":
        run_analysis_inline(analysis_id)
        return
    try:
        run_analysis_task.delay(analysis_id)
    except Exception:  # noqa: BLE001 - broker unreachable -> inline fallback
        run_analysis_inline(analysis_id)


# ---------------------------------------------------------------------------
# Scheduled scans
# ---------------------------------------------------------------------------
def _create_scheduled_analysis(db, device: Device) -> str | None:
    """Create a fresh Analysis from the device's most recent TSR.

    Phase 1 re-evaluates the latest uploaded TSR against current rules and PSIRT
    data (API-pull is Phase 2). Returns the new analysis id, or None when the
    device has no TSR to scan.
    """
    tsr = db.scalar(select(Tsr).where(Tsr.device_id == device.id)
                    .order_by(Tsr.uploaded_at.desc()).limit(1))
    if tsr is None:
        return None
    analysis = Analysis(organization_id=device.organization_id, device_id=device.id,
                        tsr_id=tsr.id, status=AnalysisStatus.queued)
    db.add(analysis)
    db.commit()
    return analysis.id


@celery_app.task(name="firewallguard.scheduled_scan", bind=True,
                 max_retries=settings.scan_max_retries, acks_late=True)
def scheduled_scan_task(self, device_id: str) -> None:
    """Run a scheduled scan with per-tenant concurrency and backoff retry."""
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
        if device is None:
            return
        org_id = device.organization_id
        if not acquire_scan_slot(org_id):
            # Tenant at its concurrency ceiling; retry shortly without counting
            # against the failure budget.
            raise self.retry(countdown=settings.scan_retry_backoff_seconds, max_retries=10)
        try:
            analysis_id = _create_scheduled_analysis(db, device)
            if analysis_id is None:
                return
            run_analysis_inline(analysis_id)
            failed = db.get(Analysis, analysis_id)
            if failed and failed.status == AnalysisStatus.failed:
                raise RuntimeError(failed.error or "analysis failed")
        finally:
            release_scan_slot(org_id)
    except Exception as exc:  # noqa: BLE001
        countdown = settings.scan_retry_backoff_seconds * (2 ** self.request.retries)
        try:
            raise self.retry(exc=exc, countdown=countdown)
        except self.MaxRetriesExceededError:
            logger.error("Scheduled scan for %s exhausted retries: %s", device_id, exc)
    finally:
        db.close()


def enqueue_scheduled_scan(device_id: str) -> None:
    """Dispatch a scheduled scan, falling back to inline execution."""
    if os.environ.get("FGAI_INLINE_TASKS") == "1":
        db = SessionLocal()
        try:
            device = db.get(Device, device_id)
            if device is None:
                return
            analysis_id = _create_scheduled_analysis(db, device)
        finally:
            db.close()
        if analysis_id:
            run_analysis_inline(analysis_id)
        return
    try:
        scheduled_scan_task.delay(device_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not enqueue scheduled scan for %s: %s", device_id, exc)


# ---------------------------------------------------------------------------
# API pull (SonicOS REST)
# ---------------------------------------------------------------------------
def ingest_tsr_bytes(device_id: str, raw: bytes, uploaded_by: str = "api-pull") -> str | None:
    """Persist raw TSR bytes for a device and run analysis inline.

    Shared by the API pull worker and the API-connect endpoint so a TSR obtained
    over the SonicOS API is stored and analysed exactly like an uploaded one.
    Returns the new analysis id, or None if the device no longer exists.
    """
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
        if device is None:
            return None
        now = datetime.now(timezone.utc)
        filename = f"{uploaded_by}-{now.strftime('%Y%m%dT%H%M%S')}.txt"
        org = db.get(Organization, device.organization_id)
        storage_key = save_tsr(device.organization_id, device.id, filename, raw,
                               region=org.region if org else None)
        tsr = Tsr(organization_id=device.organization_id, device_id=device.id,
                  filename=filename, storage_key=storage_key, size_bytes=len(raw),
                  uploaded_by=uploaded_by)
        db.add(tsr)
        db.flush()
        analysis = Analysis(organization_id=device.organization_id, device_id=device.id,
                            tsr_id=tsr.id, status=AnalysisStatus.queued)
        db.add(analysis)
        db.commit()

        # Enforce per-device TSR retention (keep latest 10).
        # (enforce_tsr_retention commits its own work.)
        enforce_tsr_retention(db, device_id)

        analysis_id = analysis.id
    finally:
        db.close()
    run_analysis_inline(analysis_id)
    return analysis_id


def pull_and_analyze(device_id: str, uploaded_by: str = "api-pull") -> str | None:
    """Pull a TSR from a device over the SonicOS API and queue its analysis.

    Updates the device's connectivity status, stores the downloaded TSR and
    returns the new analysis id (or None on connectivity failure).

    *uploaded_by* is stamped on the Tsr row: ``"api-pull"`` for on-demand pulls,
    ``"api-scheduled"`` for automatic scheduled collection.
    """
    print(f"[PULL] pull_and_analyze START for device={device_id[:8]}")
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
        if device is None:
            print(f"[PULL]   device not found")
            return None
        cred = db.scalar(select(DeviceCredential).where(
            DeviceCredential.device_id == device_id))
        if cred is None:
            print(f"[PULL]   no credentials found for device")
            return None

        now = datetime.now(timezone.utc)
        password = decrypt(cred.encrypted_password)
        from . import api_flow
        active = api_flow.get_active_config(db)

        trigger = "scheduled_pull" if uploaded_by == "api-scheduled" else "pull_now"

        def _mark_failed(detail: str, endpoint: str = "", http_status: int | None = None,
                         elapsed_ms: int | None = None) -> None:
            device.last_connection_status = "failed"
            device.last_connection_error = detail[:500]
            device.last_connection_at = now
            cred.last_test_status = "failed"
            cred.last_test_at = now
            db.commit()
            log_api_connection(db, device_id=device_id,
                               organization_id=device.organization_id,
                               trigger=trigger, host=cred.hostname, port=cred.port,
                               endpoint=endpoint or "", http_status=http_status,
                               response_time_ms=elapsed_ms, success=False,
                               error_message=detail[:500],
                               registered_serial=device.serial or "")
            logger.warning("API pull failed for device %s: %s", device_id, detail)

        if active is not None:
            res = api_flow.run_flow(api_flow.config_to_dict(active), {
                "hostname": cred.hostname, "ip": cred.hostname, "port": cred.port,
                "username": cred.username, "password": password,
                "verify_tls": active.verify_tls})
            raw = (res.get("tsr_text") or "").encode("utf-8")
            if not res["success"] or not raw.strip():
                _mark_failed(res.get("error") or "active API flow returned no TSR")
                return None
        else:
            client = SonicOSClient(cred.hostname, cred.port, cred.username, password)
            try:
                client.login()
                raw = client.export_tech_support()
            except SonicOSError as exc:
                _mark_failed(str(exc))
                return None
            finally:
                try:
                    client.logout()
                except Exception:  # noqa: BLE001
                    pass

        # Validate the firewall serial against the registered device.
        fw_serial = ""
        if raw and device.serial:
            from firewallguard.tsr.normalize import normalize_tsr
            from firewallguard.tsr.reader import TSRDocument
            from firewallguard.tsr.parser import parse_system
            try:
                text, _fmt = normalize_tsr(raw.decode("utf-8", "replace"))
                info = parse_system(TSRDocument(text))
                fw_serial = str(info.get("serial") or "")
                if fw_serial and fw_serial != device.serial:
                    _mark_failed(
                        f"Serial number mismatch. This device is registered "
                        f"with serial '{device.serial}', but the connected "
                        f"firewall reports serial '{fw_serial}'."
                    )
                    return None
            except Exception:
                pass  # best-effort — don't block the pull on parse errors

        device.last_connection_status = "ok"
        device.last_connection_error = ""
        device.last_connection_at = now
        cred.last_test_status = "ok"
        cred.last_test_at = now

        log_api_connection(db, device_id=device_id,
                           organization_id=device.organization_id,
                           trigger=trigger, host=cred.hostname, port=cred.port,
                           endpoint="TSR export", http_status=200,
                           response_time_ms=None, success=True,
                           connected_serial=fw_serial,
                           registered_serial=device.serial or "",
                           result_summary="TSR downloaded successfully.")
        db.commit()
    finally:
        db.close()

    print(f"[PULL]   TSR retrieved ({len(raw)} bytes), ingesting...")
    result = ingest_tsr_bytes(device_id, raw, uploaded_by=uploaded_by)
    print(f"[PULL]   DONE — analysis_id={result[:8] if result else 'None'}")
    return result


@celery_app.task(name="firewallguard.pull_and_analyze")
def pull_and_analyze_task(device_id: str, uploaded_by: str = "api-pull") -> None:
    pull_and_analyze(device_id, uploaded_by=uploaded_by)


def dispatch_pull(device_id: str, uploaded_by: str = "api-pull") -> None:
    """Queue an API pull, or run inline when no broker is available."""
    print(f"[PULL] dispatch_pull called for device={device_id[:8]}")
    if os.environ.get("FGAI_INLINE_TASKS") == "1":
        print(f"[PULL]   running inline")
        pull_and_analyze(device_id, uploaded_by=uploaded_by)
        return
    try:
        pull_and_analyze_task.delay(device_id, uploaded_by=uploaded_by)
        print(f"[PULL]   queued via Celery")
    except Exception as exc:  # noqa: BLE001 - broker unreachable -> inline fallback
        print(f"[PULL]   Celery queue failed ({exc}), running inline")
        pull_and_analyze(device_id, uploaded_by=uploaded_by)


@celery_app.task(name="firewallguard.run_due_schedules")
def run_due_schedules() -> int:
    """Celery Beat tick: enqueue scans for every schedule that is due.

    Reads the schedule table, fires due schedules, then advances each one's
    ``next_run_at``. Returns the number of scans enqueued.
    """
    db = SessionLocal()
    fired = 0
    try:
        now = datetime.now(timezone.utc)
        # Opportunistically downgrade any expired trials on each tick.
        try:
            from .billing import downgrade_expired_trials
            downgrade_expired_trials(db)
        except Exception:  # noqa: BLE001
            pass
        due = db.scalars(select(Schedule).where(
            Schedule.enabled.is_(True),
            Schedule.next_run_at.is_not(None),
            Schedule.next_run_at <= now)).all()
        print(f"[SCHED] {len(due)} schedule(s) due at {now.isoformat()}")
        for sched in due:
            device = db.get(Device, sched.device_id)
            if device is None:
                print(f"[SCHED]   dev={sched.device_id[:8]} — device not found, skipping")
                sched.next_run_at = compute_next_run(sched, after=now)
                continue
            # API-pull devices fetch a fresh TSR; manual devices re-analyse the
            # most recent upload against current rules and PSIRT data.
            if device.connection_method == "api":
                print(f"[SCHED]   dev={device.id[:8]} — dispatching scheduled pull")
                dispatch_pull(sched.device_id, uploaded_by="api-scheduled")
            else:
                print(f"[SCHED]   dev={device.id[:8]} — dispatching manual re-scan")
                enqueue_scheduled_scan(sched.device_id)
            sched.last_run_at = now
            sched.next_run_at = compute_next_run(sched, after=now)
            fired += 1
        db.commit()
        return fired
    finally:
        db.close()


@celery_app.task(name="firewallguard.purge_expired_data")
def purge_expired_data_task() -> dict:
    """Daily data-retention purge across all organizations."""
    from .retention import purge_expired
    db = SessionLocal()
    try:
        return purge_expired(db)
    finally:
        db.close()


@celery_app.task(name="firewallguard.psirt_refresh")
def psirt_refresh_task() -> bool:
    """Daily PSIRT advisory refresh with content-hash change detection."""
    from .psirt_refresh import refresh_psirt
    db = SessionLocal()
    try:
        log = refresh_psirt(db, source="scheduled")
        return bool(log.changed)
    finally:
        db.close()


@celery_app.on_after_configure.connect
def _register_periodic(sender, **_kwargs):
    """Register periodic tasks with Celery Beat."""
    from celery.schedules import crontab
    sender.add_periodic_task(float(settings.schedule_tick_seconds),
                             run_due_schedules.s(),
                             name="poll-device-schedules")
    sender.add_periodic_task(crontab(hour=settings.psirt_refresh_hour, minute=0),
                             psirt_refresh_task.s(),
                             name="daily-psirt-refresh")
    sender.add_periodic_task(crontab(hour=settings.retention_purge_hour, minute=0),
                             purge_expired_data_task.s(),
                             name="daily-retention-purge")
