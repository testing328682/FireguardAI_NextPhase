"""Authored global (system) CEL rules must generate findings in analyses.

Regression tests for the CEL Rule Builder execution gap: a rule saved as a
*system* rule (organization_id NULL) with a key outside the Python catalog was
visible in every tenant's rule library but was never evaluated during device
analyses — ``evaluate_custom_rules`` selects only tenant custom rules, and the
system-rule CEL layer only *filters* catalog findings. The fix routes authored
system rules through ``evaluate_authored_system_rules`` in the pipeline hooks.
"""

from __future__ import annotations

import glob
import os

import pytest

from app.database import SessionLocal
from app.models import Customer, Device, Rule, RuleSource, RuleState, User
from app.rule_engine import evaluate_authored_system_rules

SSLVPN_CONDITION = ('snapshot.sslvpn.certificate == "Use Selfsigned Certificate" '
                    '&& snapshot.sslvpn.port == 8443')

SYNTHETIC_TSR = """\
#System : Status_START
#Blade_1_STATUS_START
Model : TZ 470
Firmware Version : SonicOS 7.1.1-7047
Serial number : SN-SSL-1
#Blade_1_STATUS_END
#System : Status_END
#SSL VPN : Server Settings_START
SSL VPN Port : 8443
Certificate Selection : Use Selfsigned Certificate
SSL VPN User Domain : LocalDomain
#SSL VPN : Server Settings_END
"""


def auth_headers(client, email: str, password: str) -> dict:
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _superadmin_headers(client, org: dict) -> dict:
    db = SessionLocal()
    try:
        db.get(User, org["owner_id"]).is_superadmin = True
        db.commit()
    finally:
        db.close()
    return auth_headers(client, org["email"], org["password"])


def _add_system_rule(key: str, condition: str, *, enabled: bool = True,
                     title: str = "BAD SSLVPN CONFIG", severity: str = "Medium",
                     category: str = "SSL VPN") -> None:
    db = SessionLocal()
    try:
        db.add(Rule(organization_id=None, key=key, title=title, category=category,
                    severity=severity, description="d", condition=condition,
                    remediation="Use a CA-signed certificate.", compliance={},
                    references=[], source=RuleSource.system,
                    state=RuleState.approved, enabled=enabled, current_version=1))
        db.commit()
    finally:
        db.close()


def _register_device(org: dict, serial: str) -> str:
    """Create a registered (not yet configured) device directly in the DB."""
    db = SessionLocal()
    try:
        device = Device(organization_id=org["org_id"], customer_id=org["customer_id"],
                        serial=serial, friendly_name="SSLVPN test", configured=False)
        db.add(device)
        db.commit()
        return device.id
    finally:
        db.close()


# ---- unit: which system rules are generative -------------------------------
def test_authored_system_rules_generate_findings(client, org_a):
    snapshot = {"sslvpn": {"certificate": "Use Selfsigned Certificate", "port": 8443}}
    _add_system_rule("GBL-FIRES-1", SSLVPN_CONDITION)
    _add_system_rule("GBL-FALSE-1", "snapshot.sslvpn.port == 9999")
    _add_system_rule("GBL-OFF-1", SSLVPN_CONDITION, enabled=False)
    # Catalog-mirror row: its findings come from Python code; the CEL must
    # never generate a duplicate finding even when it evaluates to true.
    _add_system_rule("FW-MGT-002", "true")

    db = SessionLocal()
    try:
        findings = evaluate_authored_system_rules(db, snapshot)
    finally:
        db.close()

    assert [f.rule_id for f in findings] == ["GBL-FIRES-1"]
    f = findings[0]
    assert f.title == "BAD SSLVPN CONFIG"
    assert f.severity == "Medium"
    assert f.category == "SSL VPN"
    assert f.evidence == ["Matched global rule condition."]


# ---- end to end: the exact reported flow ------------------------------------
def _run_flow(client, org: dict, tsr_bytes: bytes, filename: str,
              serial: str, rule_key: str) -> dict:
    """Superadmin authors a global rule → tenant uploads a TSR → findings."""
    sa_headers = _superadmin_headers(client, org)
    res = client.post("/api/v1/rules", headers=sa_headers, json={
        "title": "BAD SSLVPN CONFIG", "severity": "Medium", "category": "SSL VPN",
        "condition": SSLVPN_CONDITION, "source": "system", "key": rule_key,
        "remediation": "Use a CA-signed certificate."})
    assert res.status_code == 201, res.text

    device_id = _register_device(org, serial)
    res = client.post(f"/api/v1/customers/{org['customer_id']}/tsrs",
                      headers=sa_headers, params={"device_id": device_id},
                      files={"file": (filename, tsr_bytes, "text/plain")})
    assert res.status_code in (200, 201, 202), res.text

    res = client.get("/api/v1/findings", headers=sa_headers,
                     params={"device_id": device_id})
    assert res.status_code == 200, res.text
    return {"device_id": device_id,
            "findings": {f["title"]: f for f in res.json()}}


def test_global_rule_fires_on_uploaded_tsr(client, org_a):
    out = _run_flow(client, org_a, SYNTHETIC_TSR.encode(), "synthetic.wri",
                    serial="SN-SSL-1", rule_key="GBL-SSLVPN-E2E")
    finding = out["findings"].get("BAD SSLVPN CONFIG")
    assert finding is not None, f"finding missing; got {list(out['findings'])}"
    assert finding["severity"] == "Medium"
    assert finding["category"] == "SSL VPN"
    assert finding["rule_id"] == "GBL-SSLVPN-E2E"
    assert finding["status"] == "open"


def test_global_rule_does_not_fire_when_condition_false(client, org_a):
    tsr = SYNTHETIC_TSR.replace("SSL VPN Port : 8443", "SSL VPN Port : 4433")
    out = _run_flow(client, org_a, tsr.encode(), "synthetic.wri",
                    serial="SN-SSL-1", rule_key="GBL-SSLVPN-NEG")
    assert "BAD SSLVPN CONFIG" not in out["findings"]


# ---- acceptance: the exact reference TSR ------------------------------------
_TSR_DIR = os.environ.get(
    "FGAI_TSR_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "TSRs"))
_REFERENCE = os.path.join(_TSR_DIR, "techSupport_2CB8EDA47A18_9-12.wri")


@pytest.mark.skipif(not os.path.exists(_REFERENCE), reason="Reference TSR not available")
def test_reference_tsr_produces_bad_sslvpn_config_finding(client, org_a):
    with open(_REFERENCE, "rb") as fh:
        tsr_bytes = fh.read()
    # Serial exactly as the parser reports it for this report.
    out = _run_flow(client, org_a, tsr_bytes, os.path.basename(_REFERENCE),
                    serial="2CB8-EDA4-7A18", rule_key="GBL-SSLVPN-REF")
    finding = out["findings"].get("BAD SSLVPN CONFIG")
    assert finding is not None, f"finding missing; got {sorted(out['findings'])[:20]}"
    assert finding["severity"] == "Medium"
    assert finding["category"] == "SSL VPN"
    assert finding["rule_id"] == "GBL-SSLVPN-REF"
    assert finding["status"] == "open"
