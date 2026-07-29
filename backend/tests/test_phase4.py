"""Phase 4 tests: security headers, GDPR export/erasure, retention purge,
multi-region storage routing, white-label branding, advanced analytics.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models import (
    Organization, Device, Analysis, AnalysisStatus, Finding, FindingStatus, PlanTier,
)
from app.findings_sync import sync_findings
from app.retention import purge_expired, retention_days_for
from app import storage


def auth_headers(client, email, password):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _finding(rule_id, title, severity="High", obj="x"):
    return {"rule_id": rule_id, "title": title, "severity": severity, "category": "Access Control",
            "description": "d", "evidence": ["e"], "business_impact": "b", "technical_impact": "t",
            "remediation": "r", "verification": ["v"], "compliance": {}, "exploitability": "High",
            "object_name": obj, "object_type": "Access Rule", "object_detail": "x"}


def _seed_analysis(org_id, customer_id, findings, serial="SN-P4"):
    db = SessionLocal()
    try:
        device = Device(organization_id=org_id, customer_id=customer_id, serial=serial,
                        model="TZ670", firmware="SonicOS 7.3.0", friendly_name="Edge",
                        latest_score=55, latest_grade="C")
        db.add(device)
        db.flush()
        analysis = Analysis(organization_id=org_id, device_id=device.id, tsr_id="t",
                            status=AnalysisStatus.complete, score=55, grade="C",
                            result_json={"findings": findings, "snapshot": {}, "device": {"serial": serial}})
        db.add(analysis)
        db.commit()
        sync_findings(db, analysis)
        return {"device_id": device.id, "analysis_id": analysis.id}
    finally:
        db.close()


# ---- security headers ----------------------------------------------------
def test_security_headers(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert "max-age" in res.headers.get("Strict-Transport-Security", "")
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src" in res.headers.get("Content-Security-Policy", "")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"


# ---- GDPR ----------------------------------------------------------------
def test_gdpr_self_export(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/privacy/me/export", headers=h)
    assert res.status_code == 200
    body = res.json()
    assert body["user"]["email"] == org_a["email"]
    assert "audit_events" in body and "assigned_findings" in body


def test_right_to_erasure(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    # Create a second user to erase.
    created = client.post("/api/v1/auth/users", headers=h, json={
        "email": "erase-me@example.com", "password": "Sup3rStrongPass!", "role": "analyst"})
    assert created.status_code == 201
    uid = created.json()["id"]
    res = client.post(f"/api/v1/privacy/users/{uid}/erase", headers=h)
    assert res.status_code == 200
    body = res.json()
    assert body["anonymized_email"].endswith("@deleted.invalid")
    assert any(e["record"] == "audit_logs" for e in body["retention_exceptions"])


# ---- retention -----------------------------------------------------------
def test_retention_policy_endpoint(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/privacy/retention", headers=h)
    assert res.status_code == 200
    assert res.json()["retention_days"] == 90      # professional default


def test_retention_purge_deletes_old(db_schema, org_a):
    seed = _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding("ACR-007", "x")])
    db = SessionLocal()
    try:
        org = db.get(Organization, org_a["org_id"])
        org.plan = PlanTier.free           # 30-day retention
        a = db.get(Analysis, seed["analysis_id"])
        a.created_at = datetime.now(timezone.utc) - timedelta(days=60)
        db.commit()
        assert retention_days_for(org) == 30
        result = purge_expired(db)
        assert result["analyses"] >= 1
        assert db.get(Analysis, seed["analysis_id"]) is None
    finally:
        db.close()


# ---- multi-region storage -----------------------------------------------
def test_region_storage_routing():
    key = storage.save_tsr("org1", "dev1", "tsr.txt", b"hello", region="eu")
    assert key.startswith("eu/")
    assert storage.load_tsr(key) == b"hello"
    storage.delete_object(key)


def test_org_region_update(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.patch("/api/v1/organization", headers=h, json={"region": "eu"})
    assert res.status_code == 200 and res.json()["region"] == "eu"
    bad = client.patch("/api/v1/organization", headers=h, json={"region": "moon"})
    assert bad.status_code == 400


# ---- white-label branding ------------------------------------------------
def test_branding_update_and_pdf(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.patch("/api/v1/organization", headers=h, json={
        "brand_company_name": "Acme MSP", "brand_primary_color": "#aa0000",
        "brand_contact": "soc@acme.example"})
    assert res.status_code == 200 and res.json()["brand_company_name"] == "Acme MSP"

    # The PDF generator accepts branding and produces a non-trivial document.
    from firewallguard.report.generator import build_executive_pdf
    analysis = {"device": {"model": "TZ670", "serial": "X", "firmware": "7.3.0"},
                "generated_at": "2026-01-01T00:00:00", "finding_count": 3,
                "exploitability": {}, "source_name": "test",
                "score": {"score": 80, "grade": "B", "grade_label": "Good",
                          "severity_counts": {"Critical": 0, "High": 1, "Medium": 2, "Low": 0, "Info": 0},
                          "category_counts": {}, "total_findings": 3},
                "findings": [], "attack_paths": [],
                "firmware_intelligence": {"matched_advisories": [], "advisory_count": 0}}
    path = os.path.join(tempfile.mkdtemp(), "exec.pdf")
    build_executive_pdf(analysis, path, {"company_name": "Acme MSP", "primary_color": "#aa0000"})
    assert os.path.getsize(path) > 1000


# ---- findings export -----------------------------------------------------
def test_xlsx_export(client, org_a):
    seed = _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding("ACR-007", "x")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get(f"/api/v1/analyses/{seed['analysis_id']}/export/xlsx", headers=h)
    assert res.status_code == 200
    assert "spreadsheetml" in res.headers["content-type"]
    assert res.content[:2] == b"PK"          # xlsx is a zip archive


# ---- system rule detection logic ----------------------------------------
def test_system_rules_have_logic(db_schema):
    from app.rule_engine import seed_system_rules
    from app.models import Rule, RuleSource
    db = SessionLocal()
    try:
        seed_system_rules(db)
        from sqlalchemy import select
        rule = db.scalar(select(Rule).where(Rule.source == RuleSource.system))
        assert rule is not None
        assert rule.description and "evaluated in Python" not in rule.description
        assert "fires when" in rule.description.lower()
    finally:
        db.close()


# ---- advanced analytics --------------------------------------------------
def test_analytics_trends(client, org_a):
    _seed_analysis(org_a["org_id"], org_a["customer_id"],
                   [_finding("ACR-007", "a"), _finding("ACR-008", "b", obj="z")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/analytics/trends", headers=h)
    assert res.status_code == 200
    body = res.json()
    for key in ("score_progression", "mttr_by_severity", "recurrence", "top_rules", "category_evolution"):
        assert key in body
    assert body["recurrence"]["total_findings"] >= 2
    assert any(r["rule_id"] == "ACR-007" for r in body["top_rules"])
