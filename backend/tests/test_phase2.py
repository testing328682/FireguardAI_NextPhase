"""Phase 2 API tests: SonicOS connect (mocked), CEL rules, suppressions,
compliance matrix, integrations, API tokens and drift comparison.
"""

from __future__ import annotations

from app.database import SessionLocal
from app.models import (
    Device, Analysis, AnalysisStatus, Rule, RuleSource, RuleState,
)
from app.findings_sync import sync_findings
from app.rule_engine import evaluate_custom_rules, resolve_suppressions, seed_system_rules


def auth_headers(client, email: str, password: str) -> dict:
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _finding(rule_id, title, severity="Critical", obj="WAN>LAN any", framework="CIS v8"):
    return {"rule_id": rule_id, "title": title, "severity": severity,
            "category": "Access Control", "description": "d", "evidence": ["e"],
            "business_impact": "b", "technical_impact": "t", "remediation": "r",
            "verification": ["v"], "compliance": {framework: ["1.1"]}, "exploitability": "High",
            "object_name": obj, "object_type": "Access Rule", "object_detail": "x"}


def _seed_analysis(org_id, customer_id, findings, snapshot=None, serial="SN-P2"):
    db = SessionLocal()
    try:
        device = Device(organization_id=org_id, customer_id=customer_id, serial=serial,
                        model="TZ670", firmware="SonicOS 7.3.0", friendly_name="Edge",
                        latest_score=40.0, latest_grade="F")
        db.add(device)
        db.flush()
        analysis = Analysis(organization_id=org_id, device_id=device.id, tsr_id="t",
                            status=AnalysisStatus.complete, score=40, grade="F",
                            result_json={"findings": findings, "snapshot": snapshot or {},
                                         "device": {"serial": serial}})
        db.add(analysis)
        db.commit()
        sync_findings(db, analysis)
        return {"device_id": device.id, "analysis_id": analysis.id}
    finally:
        db.close()


# ---- SonicOS connect (mocked) -------------------------------------------
class _FakeClient:
    def __init__(self, *a, **k):
        pass

    def test_connection(self):
        return {"serial": "API-SERIAL-1", "model": "NSa 2700", "firmware_version": "SonicOS 7.3.0"}

    def login(self):
        return None

    def export_tech_support(self):
        return b"SonicWall Tech Support Report\nSerial Number: API-SERIAL-1\n"


def test_device_connect(client, org_a, monkeypatch):
    import app.routers.devices as devices_mod
    import app.tasks as tasks_mod
    monkeypatch.setattr(devices_mod, "SonicOSClient", _FakeClient)
    monkeypatch.setattr(tasks_mod, "SonicOSClient", _FakeClient)

    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.post("/api/v1/devices/connect", headers=h, json={
        "customer_id": org_a["customer_id"], "hostname": "10.0.0.1", "port": 443,
        "username": "admin", "password": "pw"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["connection_status"] == "ok"
    assert body["device_id"]

    # The device is now an API device with credentials saved.
    dev = client.get(f"/api/v1/devices/{body['device_id']}", headers=h).json()
    assert dev["connection_method"] == "api"
    assert dev["last_connection_status"] == "ok"


# ---- CEL rules + workflow ------------------------------------------------
def test_rule_create_submit_approve(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    created = client.post("/api/v1/rules", headers=h, json={
        "title": "IPS disabled", "severity": "High",
        "condition": "snapshot.security_services.ips_enabled == false"})
    assert created.status_code == 201, created.text
    rid = created.json()["id"]
    assert created.json()["state"] == "draft"

    assert client.post(f"/api/v1/rules/{rid}/submit", headers=h, json={}).json()["state"] == "submitted"
    assert client.post(f"/api/v1/rules/{rid}/approve", headers=h, json={}).json()["state"] == "approved"


def test_rule_invalid_cel_rejected(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.post("/api/v1/rules", headers=h, json={
        "title": "bad", "condition": "snapshot.((("})
    assert res.status_code == 400


def test_rule_test_endpoint(client, org_a):
    seed = _seed_analysis(org_a["org_id"], org_a["customer_id"], [_finding("ACR-007", "x")],
                          snapshot={"security_services": {"ips_enabled": False}})
    h = auth_headers(client, org_a["email"], org_a["password"])
    rid = client.post("/api/v1/rules", headers=h, json={
        "title": "IPS off", "condition": "snapshot.security_services.ips_enabled == false"}).json()["id"]
    res = client.post(f"/api/v1/rules/{rid}/test", headers=h,
                      json={"analysis_id": seed["analysis_id"]})
    assert res.status_code == 200
    assert res.json()["fired"] is True


def test_custom_rule_evaluates_in_engine(db_schema, org_a):
    """Approved custom rule yields a finding from evaluate_custom_rules."""
    db = SessionLocal()
    try:
        db.add(Rule(organization_id=org_a["org_id"], key="CUSTOM-1", title="No IPS",
                    severity="High", category="Custom",
                    condition="snapshot.security_services.ips_enabled == false",
                    source=RuleSource.custom, state=RuleState.approved, enabled=True,
                    current_version=1))
        db.commit()
        findings = evaluate_custom_rules(db, org_a["org_id"],
                                         {"security_services": {"ips_enabled": False}})
        assert len(findings) == 1 and findings[0].rule_id == "CUSTOM-1"
    finally:
        db.close()


# ---- suppressions --------------------------------------------------------
def test_suppression_create_and_resolve(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.post("/api/v1/rule-suppressions", headers=h, json={
        "rule_key": "ACR-007", "action": "disable", "reason": "accepted"})
    assert res.status_code == 201
    db = SessionLocal()
    try:
        supp = resolve_suppressions(db, org_a["org_id"], None)
        assert any(s["rule_key"] == "ACR-007" and s["action"] == "disable" for s in supp)
    finally:
        db.close()


# ---- compliance ----------------------------------------------------------
def test_compliance_matrix(client, org_a):
    _seed_analysis(org_a["org_id"], org_a["customer_id"],
                   [_finding("ACR-007", "x", framework="CIS v8")])
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/compliance/matrix?framework=CIS v8", headers=h)
    assert res.status_code == 200
    body = res.json()
    assert len(body["devices"]) == 1
    assert "1.1" in body["controls"]
    cell = body["cells"][f"{body['devices'][0]['device_id']}|1.1"]
    assert cell["status"] == "fail"


# ---- integrations --------------------------------------------------------
def test_slack_integration_save(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.post("/api/v1/integrations", headers=h, json={
        "type": "slack", "enabled": True,
        "webhook_url": "https://hooks.slack.com/services/T/B/X",
        "config": {"new_critical": True}})
    assert res.status_code == 201
    listed = client.get("/api/v1/integrations", headers=h).json()
    assert listed[0]["has_secret"] is True   # secret stored, not returned


# ---- API tokens ----------------------------------------------------------
def test_api_token_auth_and_revoke(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    created = client.post("/api/v1/settings/api-tokens", headers=h,
                          json={"name": "ci", "scopes": ["admin"]})
    assert created.status_code == 201
    token = created.json()["token"]
    token_id = created.json()["id"]
    assert token.startswith("fgat_")

    # The token authenticates API calls in place of a JWT.
    th = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/customers", headers=th).status_code == 200

    # After revocation it is rejected.
    assert client.delete(f"/api/v1/settings/api-tokens/{token_id}", headers=h).status_code == 204
    assert client.get("/api/v1/customers", headers=th).status_code == 401


# ---- drift comparison ----------------------------------------------------
def test_drift_comparison(client, org_a):
    seed = _seed_analysis(org_a["org_id"], org_a["customer_id"],
                          [_finding("ACR-007", "a"), _finding("ACR-008", "b", obj="z")])
    device_id = seed["device_id"]
    # Second analysis: ACR-008 resolved, ACR-009 new.
    db = SessionLocal()
    try:
        a2 = Analysis(organization_id=org_a["org_id"], device_id=device_id, tsr_id="t2",
                      status=AnalysisStatus.complete, score=50, grade="F",
                      result_json={"findings": [_finding("ACR-007", "a"),
                                                _finding("ACR-009", "c", obj="q")],
                                   "snapshot": {}})
        db.add(a2)
        db.commit()
        current_id = a2.id
    finally:
        db.close()
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get(f"/api/v1/devices/{device_id}/compare"
                     f"?previous={seed['analysis_id']}&current={current_id}", headers=h)
    assert res.status_code == 200
    body = res.json()
    new_titles = {f["title"] for f in body["new_findings"]}
    resolved_titles = {f["title"] for f in body["resolved_findings"]}
    assert "c" in new_titles
    assert "b" in resolved_titles
