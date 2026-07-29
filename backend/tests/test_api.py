"""API tests for Phase 1 features.

Covers authentication, MFA enrollment/verification, account lockout, the
finding workflow (transitions, comments, bulk, tenant isolation), scheduled
scans, the dashboard aggregation and the audit log. Findings are seeded by
running the pipeline result-sync directly against a fabricated analysis so the
tests do not depend on a reference TSR.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models import (
    Device, Analysis, AnalysisStatus, Finding, FindingStatus, Schedule, ScheduleFrequency,
)
from app import mfa as mfa_mod
from app.findings_sync import sync_findings, reopen_expired_accepted_risk


def auth_headers(client, email: str, password: str) -> dict:
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _finding_dict(rule_id, title, severity="Critical", obj="WAN>LAN allow-any"):
    return {
        "rule_id": rule_id, "title": title, "severity": severity,
        "category": "Access Control", "description": "d", "evidence": ["e"],
        "business_impact": "b", "technical_impact": "t", "remediation": "r",
        "verification": ["v"], "compliance": {"CIS": ["1.1"]}, "exploitability": "High",
        "object_name": obj, "object_type": "Access Rule", "object_detail": "detail",
    }


def _seed_analysis(org_id, customer_id, findings, serial="SN-TEST-1"):
    """Create a device + complete analysis and persist its findings."""
    db = SessionLocal()
    try:
        device = Device(organization_id=org_id, customer_id=customer_id,
                        serial=serial, model="TZ670", firmware="SonicOS 7.3.0",
                        friendly_name="Edge", latest_score=40.0, latest_grade="F")
        db.add(device)
        db.flush()
        analysis = Analysis(organization_id=org_id, device_id=device.id, tsr_id="t-1",
                            status=AnalysisStatus.complete, score=40.0, grade="F",
                            finding_count=len(findings),
                            critical_count=sum(1 for f in findings if f["severity"] == "Critical"),
                            high_count=sum(1 for f in findings if f["severity"] == "High"),
                            result_json={"findings": findings, "device": {"serial": serial}})
        db.add(analysis)
        db.commit()
        summary = sync_findings(db, analysis)
        return {"device_id": device.id, "analysis_id": analysis.id,
                "new_critical": len(summary["new_critical"])}
    finally:
        db.close()


# ---- registration --------------------------------------------------------
def test_self_registration(client, db_schema):
    res = client.post("/api/v1/auth/register", json={
        "full_name": "Dana Owner", "company_name": "Dana Co", "email": "dana@example.com",
        "password": "Sup3rStrongPass!", "phone": "+1-555-0100", "address": "1 Main St",
        "is_msp": True})
    assert res.status_code == 201, res.text
    token = res.json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    me = client.get("/api/v1/auth/me", headers=h).json()
    assert me["email"] == "dana@example.com" and me["role"] == "owner"
    assert me["phone"] == "+1-555-0100" and me["address"] == "1 Main St"
    # Org is an MSP with a default customer ready for uploads.
    org = client.get("/api/v1/organization", headers=h).json()
    assert org["is_msp"] is True and org["name"] == "Dana Co"
    assert len(client.get("/api/v1/customers", headers=h).json()) == 1


def test_registration_rejects_duplicate_email(client, org_a):
    res = client.post("/api/v1/auth/register", json={
        "full_name": "Dup", "company_name": "Dup Co", "email": org_a["email"],
        "password": "Sup3rStrongPass!"})
    assert res.status_code == 409


# ---- auth ----------------------------------------------------------------
def test_login_and_me(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    me = client.get("/api/v1/auth/me", headers=h)
    assert me.status_code == 200
    assert me.json()["email"] == org_a["email"]
    assert me.json()["mfa_enabled"] is False


def test_login_rejects_bad_password(client, org_a):
    res = client.post("/api/v1/auth/login",
                      json={"email": org_a["email"], "password": "wrong"})
    assert res.status_code == 401


def test_account_lockout(client, org_a):
    for _ in range(5):
        client.post("/api/v1/auth/login",
                    json={"email": org_a["email"], "password": "wrong"})
    # Correct password is now refused: the account is locked.
    res = client.post("/api/v1/auth/login",
                      json={"email": org_a["email"], "password": org_a["password"]})
    assert res.status_code == 423


# ---- MFA -----------------------------------------------------------------
def test_mfa_enrollment_and_login(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=h)
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    assert enroll.json()["otpauth_uri"].startswith("otpauth://totp/")

    # Activate with a valid TOTP derived from the secret.
    code = mfa_mod._hotp(secret, int(datetime.now(timezone.utc).timestamp()) // 30)
    act = client.post("/api/v1/auth/mfa/activate", headers=h, json={"code": code})
    assert act.status_code == 200
    backup_codes = act.json()["backup_codes"]
    assert len(backup_codes) == 10

    # Login now returns an MFA challenge rather than tokens.
    login = client.post("/api/v1/auth/login",
                        json={"email": org_a["email"], "password": org_a["password"]})
    assert login.status_code == 200 and login.json()["mfa_required"] is True
    mfa_token = login.json()["mfa_token"]

    # A backup code completes the second factor.
    verify = client.post("/api/v1/auth/mfa/verify",
                         json={"mfa_token": mfa_token, "code": backup_codes[0]})
    assert verify.status_code == 200
    assert verify.json()["access_token"]


# ---- findings workflow ---------------------------------------------------
def test_findings_listed_and_filtered(client, org_a):
    info = _seed_analysis(org_a["org_id"], org_a["customer_id"],
                          [_finding_dict("ACR-007", "Allow-any rule"),
                           _finding_dict("ACR-008", "Broad service", severity="High",
                                         obj="SVC-any")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    allf = client.get("/api/v1/findings", headers=h)
    assert allf.status_code == 200 and len(allf.json()) == 2
    crit = client.get("/api/v1/findings?severity=Critical", headers=h)
    assert len(crit.json()) == 1
    assert info["new_critical"] == 1


def test_finding_transition_requires_comment(client, org_a):
    _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding_dict("ACR-007", "x")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    fid = client.get("/api/v1/findings", headers=h).json()[0]["id"]
    # Missing comment -> validation error.
    bad = client.post(f"/api/v1/findings/{fid}/transition", headers=h,
                      json={"to_status": "acknowledged"})
    assert bad.status_code == 422
    ok = client.post(f"/api/v1/findings/{fid}/transition", headers=h,
                     json={"to_status": "acknowledged", "comment": "triaging"})
    assert ok.status_code == 200 and ok.json()["status"] == "acknowledged"


def test_accepted_risk_requires_justification_and_expiry(client, org_a):
    _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding_dict("ACR-007", "x")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    fid = client.get("/api/v1/findings", headers=h).json()[0]["id"]
    # Without justification/expiry -> 400.
    res = client.post(f"/api/v1/findings/{fid}/transition", headers=h,
                      json={"to_status": "accepted_risk", "comment": "c"})
    assert res.status_code == 400
    expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    ok = client.post(f"/api/v1/findings/{fid}/transition", headers=h,
                     json={"to_status": "accepted_risk", "comment": "c",
                           "justification": "compensating control in place",
                           "accepted_risk_expiry": expiry})
    assert ok.status_code == 200 and ok.json()["status"] == "accepted_risk"


def test_fixed_finding_reopens_on_redetect(client, org_a):
    seed = _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding_dict("ACR-007", "x")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    fid = client.get("/api/v1/findings", headers=h).json()[0]["id"]
    client.post(f"/api/v1/findings/{fid}/transition", headers=h,
                json={"to_status": "fixed", "comment": "remediated"})
    # Re-run analysis on the same device with the same finding present.
    db = SessionLocal()
    try:
        device_id = seed["device_id"]
        analysis = Analysis(organization_id=org_a["org_id"], device_id=device_id, tsr_id="t-2",
                            status=AnalysisStatus.complete, score=40, grade="F",
                            result_json={"findings": [_finding_dict("ACR-007", "x")],
                                         "device": {"serial": "SN-TEST-1"}})
        db.add(analysis)
        db.commit()
        sync_findings(db, analysis)
    finally:
        db.close()
    again = client.get(f"/api/v1/findings/{fid}", headers=h).json()
    assert again["status"] == "open"  # auto-reopened


def test_expired_accepted_risk_reopens(db_schema):
    """Direct test of the expiry reopen helper."""
    db = SessionLocal()
    try:
        f = Finding(organization_id="o", device_id="d", analysis_id="a", rule_id="R",
                    fingerprint="R::x::y", severity="High", title="t",
                    status=FindingStatus.accepted_risk,
                    accepted_risk_expiry=datetime.now(timezone.utc) - timedelta(days=1))
        db.add(f)
        db.commit()
        count = reopen_expired_accepted_risk(db, "d")
        db.refresh(f)
        assert count == 1 and f.status == FindingStatus.open
    finally:
        db.close()


def test_bulk_transition(client, org_a):
    _seed_analysis(org_a["org_id"], org_a["customer_id"],
                   [_finding_dict("ACR-007", "a"), _finding_dict("ACR-008", "b", obj="z")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    ids = [f["id"] for f in client.get("/api/v1/findings", headers=h).json()]
    res = client.post("/api/v1/findings/bulk-transition", headers=h,
                      json={"finding_ids": ids, "to_status": "acknowledged", "comment": "bulk"})
    assert res.status_code == 200 and len(res.json()["updated"]) == 2


# ---- tenant isolation ----------------------------------------------------
def test_finding_tenant_isolation(client, org_a, org_b):
    _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding_dict("ACR-007", "x")])
    a_headers = auth_headers(client, org_a["email"], org_a["password"])
    fid = client.get("/api/v1/findings", headers=a_headers).json()[0]["id"]

    b_headers = auth_headers(client, org_b["email"], org_b["password"])
    # Org B sees none of Org A's findings and cannot fetch one by id.
    assert client.get("/api/v1/findings", headers=b_headers).json() == []
    assert client.get(f"/api/v1/findings/{fid}", headers=b_headers).status_code == 404


# ---- dashboard -----------------------------------------------------------
def test_dashboard_aggregates(client, org_a):
    _seed_analysis(org_a["org_id"], org_a["customer_id"],
                   [_finding_dict("ACR-007", "a"),
                    _finding_dict("ACR-008", "b", severity="High", obj="z")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/dashboard", headers=h)
    assert res.status_code == 200
    body = res.json()
    assert body["findings_funnel"]["critical_open"] == 1
    assert body["findings_funnel"]["high_open"] == 1
    assert "CIS" in body["compliance"]
    assert body["fleet_posture"]["device_count"] >= 1


# ---- schedules -----------------------------------------------------------
def test_schedule_crud(client, org_a):
    seed = _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding_dict("ACR-007", "x")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    did = seed["device_id"]
    put = client.put(f"/api/v1/devices/{did}/schedule", headers=h,
                     json={"frequency": "daily", "hour": 2, "minute": 30})
    assert put.status_code == 200
    assert put.json()["next_run_at"] is not None
    got = client.get(f"/api/v1/devices/{did}/schedule", headers=h)
    assert got.status_code == 200 and got.json()["frequency"] == "daily"
    assert client.delete(f"/api/v1/devices/{did}/schedule", headers=h).status_code == 204


# ---- audit log -----------------------------------------------------------
def test_audit_log_records_login_and_status_change(client, org_a):
    _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding_dict("ACR-007", "x")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    fid = client.get("/api/v1/findings", headers=h).json()[0]["id"]
    client.post(f"/api/v1/findings/{fid}/transition", headers=h,
                json={"to_status": "acknowledged", "comment": "c"})
    res = client.get("/api/v1/audit-log", headers=h)
    assert res.status_code == 200
    actions = {e["action"] for e in res.json()["items"]}
    assert "auth.login" in actions
    assert "finding.status_changed" in actions
