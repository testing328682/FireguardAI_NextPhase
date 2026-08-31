"""Product Config firmware intelligence: compliance rule + CVE/issue metadata.

Covers the configurable compliance finding (metadata, enable/disable), the
firmware-version intelligence lookup (CVEs, known issues, remediation), the
release-tolerant version matching, Product Config API validation, and the
snapshot property of historical findings.
"""

from __future__ import annotations

from app.database import SessionLocal
from app.models import (
    DeviceGeneration, FirmwareCve, FirmwareIssue, FirmwareRecommendation,
    FirmwareVersion, GenerationDevice, User,
)
from app.rule_engine import (
    check_firmware_compliance, firmware_matches, normalize_firmware_version,
)

LATEST = "7.3.3-7013-R8777"


def _seed_generation(name="Gen 7", model="TZ 670", latest=LATEST,
                     rule: dict | None = None,
                     versions: list[dict] | None = None) -> str:
    """Create a generation + model mapping + firmware config directly."""
    db = SessionLocal()
    try:
        gen = DeviceGeneration(name=name)
        db.add(gen)
        db.flush()
        db.add(GenerationDevice(generation_id=gen.id, model=model))
        rec = FirmwareRecommendation(generation_id=gen.id, version=latest,
                                     **(rule or {}))
        db.add(rec)
        for v in versions or []:
            fv = FirmwareVersion(
                generation_id=gen.id, version=v["version"],
                version_norm=normalize_firmware_version(v["version"]),
                remediation=v.get("remediation", ""))
            db.add(fv)
            db.flush()
            for c in v.get("cves", []):
                db.add(FirmwareCve(firmware_version_id=fv.id, extra={}, **c))
            for i in v.get("issues", []):
                db.add(FirmwareIssue(firmware_version_id=fv.id, **i))
        db.commit()
        return gen.id
    finally:
        db.close()


def _check(model="TZ 670", firmware="7.3.0-7012"):
    db = SessionLocal()
    try:
        return check_firmware_compliance(db, model, firmware)
    finally:
        db.close()


# ---- version matching --------------------------------------------------------
def test_firmware_matching_semantics():
    assert firmware_matches("7.3.0-7012", "7.3.0-7012")
    # Build metadata does not break a release match (either direction).
    assert firmware_matches("7.3.0-7012", "7.3.0-7012-R8150")
    assert firmware_matches("7.3.0-7012-R8150", "7.3.0-7012")
    assert firmware_matches("SonicOS 7.3.0-7012", "7.3.0-7012-R8150")
    # Token boundaries: never partial-number matches.
    assert not firmware_matches("7.3.0-701", "7.3.0-7012")
    assert not firmware_matches("7.3.0-7012", "7.3.0-70121")
    assert not firmware_matches("7.3.1-7012", "7.3.0-7012")
    assert not firmware_matches("", "7.3.0-7012")


# ---- existing behavior --------------------------------------------------------
def test_outdated_firmware_generates_default_finding(client, org_a):
    _seed_generation()
    f = _check(firmware="7.3.0-7012")
    assert f is not None
    assert f.rule_id == "FW-FIRMWARE-COMPLIANCE"
    assert f.severity == "Critical"
    assert f.category == "Firmware Compliance"
    assert f.object_type == "Device" and f.object_name == "TZ 670"
    assert any("Recommended Firmware: " + LATEST in e for e in f.evidence)


def test_compliant_and_unknown_model(client, org_a):
    _seed_generation()
    assert _check(firmware=LATEST) is None                     # exact match
    assert _check(firmware="7.3.3-7013") is None               # same release, no build tag
    assert _check(model="NSsp 15700", firmware="1.0") is None  # unmapped model


def test_rule_disabled_generates_nothing(client, org_a):
    _seed_generation(rule={"rule_enabled": False})
    assert _check(firmware="7.3.0-7012") is None


def test_rule_metadata_drives_the_finding(client, org_a):
    _seed_generation(rule={
        "rule_key": "FIRMWARE_OUTDATED", "rule_title": "Outdated SonicOS Firmware",
        "rule_description": "Custom description.", "rule_severity": "High",
        "rule_category": "Firmware Management",
        "rule_remediation": "Upgrade to the latest recommended firmware."})
    f = _check(firmware="7.3.0-7012")
    assert f.rule_id == "FIRMWARE_OUTDATED"
    assert f.title == "Outdated SonicOS Firmware"
    assert f.description.startswith("Custom description.")
    assert f.severity == "High"
    assert f.category == "Firmware Management"
    assert f.remediation == "Upgrade to the latest recommended firmware."


# ---- firmware intelligence -----------------------------------------------------
INTEL = [{
    "version": "7.3.0-7012",
    "remediation": f"Upgrade to {LATEST}",
    "cves": [
        {"cve_id": "CVE-2026-12345", "description": "Example vulnerability.",
         "cvss": 8.8, "remediation": f"Upgrade to {LATEST}."},
        {"cve_id": "CVE-2026-55555", "description": "Second vulnerability."},
    ],
    "issues": [
        {"title": "DHCP Not Working",
         "description": "DHCP clients may fail to obtain an IP address.",
         "remediation": "Upgrade to 7.3.2 or later."},
        {"title": "VPN intermittently fails", "severity": "High"},
    ],
}, {
    "version": "7.3.2-7010",   # record with no cves/issues
}]


def test_intelligence_attached_for_detected_version(client, org_a):
    _seed_generation(versions=INTEL)
    f = _check(firmware="7.3.0-7012-R8150")   # build tag still matches the record
    text = "\n".join(f.evidence)
    assert "CVE-2026-12345" in text and "CVSS 8.8" in text
    assert "CVE-2026-55555" in text
    assert "DHCP Not Working" in text and "VPN intermittently fails" in text
    assert "Upgrade to 7.3.2 or later." in text
    assert f"Recommended Action: Upgrade to {LATEST}" in text
    assert "2 known CVE(s) and 2 known issue(s)" in f.description
    # One finding only — intelligence rides on the compliance finding.
    assert f.rule_id == "FW-FIRMWARE-COMPLIANCE"


def test_version_with_no_configured_issues(client, org_a):
    _seed_generation(versions=INTEL)
    f = _check(firmware="7.3.2-7010")
    text = "\n".join(f.evidence)
    assert "No known CVEs or issues are configured" in text
    assert "does not indicate the absence" not in text


def test_unknown_version_is_not_claimed_safe(client, org_a):
    _seed_generation(versions=INTEL)
    f = _check(firmware="7.2.5-1234")
    text = "\n".join(f.evidence)
    assert "No firmware intelligence is configured for version 7.2.5-1234" in text
    assert "does not indicate the absence of known vulnerabilities" in text
    assert "No known CVEs" not in text


def test_cves_without_bugs_and_bugs_without_cves(client, org_a):
    _seed_generation(versions=[
        {"version": "7.1.0-1111", "cves": [{"cve_id": "CVE-2025-11111"}]},
        {"version": "7.1.1-2222", "issues": [{"title": "Panic on boot"}]},
    ])
    f1 = _check(firmware="7.1.0-1111")
    t1 = "\n".join(f1.evidence)
    assert "CVE-2025-11111" in t1 and "Known Issues" not in t1
    f2 = _check(firmware="7.1.1-2222")
    t2 = "\n".join(f2.evidence)
    assert "Panic on boot" in t2 and "Known Vulnerabilities" not in t2


def test_model_mapping_selects_correct_generation(client, org_a):
    _seed_generation(name="Gen 7", model="TZ 670", latest="7.9.9",
                     rule={"rule_key": "GEN7-FW"})
    _seed_generation(name="Gen 8", model="TZ 80", latest="8.9.9",
                     rule={"rule_key": "GEN8-FW"})
    assert _check(model="TZ 670", firmware="7.0.0").rule_id == "GEN7-FW"
    assert _check(model="TZ 80", firmware="8.0.0").rule_id == "GEN8-FW"


def test_two_devices_get_independent_intelligence(client, org_a):
    _seed_generation(versions=INTEL)
    f_old = _check(firmware="7.3.0-7012")
    f_mid = _check(firmware="7.3.2-7010")
    assert "CVE-2026-12345" in "\n".join(f_old.evidence)
    assert "CVE-2026-12345" not in "\n".join(f_mid.evidence)


def test_reanalysis_produces_stable_identity(client, org_a):
    _seed_generation(versions=INTEL)
    from app.findings_sync import fingerprint
    a = _check(firmware="7.3.0-7012")
    b = _check(firmware="7.3.0-7012")
    assert fingerprint(a.rule_id, a.object_type, a.object_name) == \
        fingerprint(b.rule_id, b.object_type, b.object_name)


def test_config_change_applies_to_next_analysis(client, org_a):
    gen_id = _seed_generation()
    assert _check(firmware="7.3.0-7012").severity == "Critical"
    db = SessionLocal()
    try:
        rec = db.scalar(
            __import__("sqlalchemy").select(FirmwareRecommendation).where(
                FirmwareRecommendation.generation_id == gen_id))
        rec.rule_severity = "Medium"
        db.commit()
    finally:
        db.close()
    assert _check(firmware="7.3.0-7012").severity == "Medium"


# ---- API validation ------------------------------------------------------------
def _superadmin_headers(client, org):
    db = SessionLocal()
    try:
        db.get(User, org["owner_id"]).is_superadmin = True
        db.commit()
    finally:
        db.close()
    res = client.post("/api/v1/auth/login",
                      json={"email": org["email"], "password": org["password"]})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_product_config_api_validation(client, org_a):
    h = _superadmin_headers(client, org_a)
    gen = client.post("/api/v1/platform/generations", headers=h,
                      json={"name": "Gen V"}).json()
    gid = gen["id"]
    assert client.put(f"/api/v1/platform/generations/{gid}/firmware", headers=h,
                      json={"version": "SonicOS 7.3.3-7013-R8777",
                            "rule_severity": "High"}).status_code == 200

    # Previous version cannot equal (release-match) the latest.
    res = client.post(f"/api/v1/platform/generations/{gid}/firmware-versions",
                      headers=h, json={"version": "7.3.3-7013"})
    assert res.status_code == 409

    fv = client.post(f"/api/v1/platform/generations/{gid}/firmware-versions",
                     headers=h, json={"version": "7.3.0-7012"}).json()
    # Duplicate (even with build tag) is rejected.
    assert client.post(f"/api/v1/platform/generations/{gid}/firmware-versions",
                       headers=h,
                       json={"version": "7.3.0-7012-R8150"}).status_code == 409
    # Latest cannot be moved onto a configured previous version.
    assert client.put(f"/api/v1/platform/generations/{gid}/firmware", headers=h,
                      json={"version": "7.3.0-7012"}).status_code == 409

    # CVE validation: format, duplicates, CVSS bounds, optional CVSS.
    fv_id = fv["id"]
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/cves",
                       headers=h, json={"cve_id": "notacve"}).status_code == 400
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/cves",
                       headers=h, json={"cve_id": "cve-2026-12345",
                                        "cvss": 8.8}).status_code == 201
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/cves",
                       headers=h, json={"cve_id": "CVE-2026-12345"}).status_code == 409
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/cves",
                       headers=h, json={"cve_id": "CVE-2026-2", "cvss": 11}).status_code == 400
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/cves",
                       headers=h, json={"cve_id": "CVE-2026-99999"}).status_code == 201

    # Issue validation.
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/issues",
                       headers=h, json={"title": ""}).status_code == 400
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/issues",
                       headers=h, json={"title": "DHCP broken",
                                        "severity": "Sideways"}).status_code == 400
    assert client.post(f"/api/v1/platform/firmware-versions/{fv_id}/issues",
                       headers=h, json={"title": "DHCP broken"}).status_code == 201

    # Rule metadata validation.
    assert client.put(f"/api/v1/platform/generations/{gid}/firmware", headers=h,
                      json={"rule_severity": "Sideways"}).status_code == 400
    assert client.put(f"/api/v1/platform/generations/{gid}/firmware", headers=h,
                      json={"rule_key": "###"}).status_code == 400
    # Collision with a global rule-library key is rejected (FW-MGT-002 is a
    # seeded catalog key in production; create one here to simulate).
    from app.models import Rule, RuleSource, RuleState
    db = SessionLocal()
    try:
        db.add(Rule(organization_id=None, key="FW-MGT-002", title="t",
                    source=RuleSource.system, state=RuleState.approved,
                    condition="", enabled=True))
        db.commit()
    finally:
        db.close()
    assert client.put(f"/api/v1/platform/generations/{gid}/firmware", headers=h,
                      json={"rule_key": "FW-MGT-002"}).status_code == 409

    # Listing exposes rule + versions with counts.
    gens = client.get("/api/v1/platform/generations", headers=h).json()
    gv = next(g for g in gens if g["id"] == gid)
    assert gv["firmware_rule"]["severity"] == "High"
    assert gv["firmware_versions"][0]["cve_count"] == 2
    assert gv["firmware_versions"][0]["issue_count"] == 1


# ---- end to end: TSR upload + snapshot immutability ------------------------------
FW_TSR = """\
#System : Status_START
#Blade_1_STATUS_START
Model : TZ 470
Firmware Version : SonicOS 7.1.1-7047
Serial number : SN-FW-1
#Blade_1_STATUS_END
#System : Status_END
"""


def test_e2e_upload_attaches_intelligence_and_snapshots_it(client, org_a):
    h = _superadmin_headers(client, org_a)
    gen = client.post("/api/v1/platform/generations", headers=h,
                      json={"name": "Gen E2E"}).json()
    client.put(f"/api/v1/platform/generations/{gen['id']}/firmware", headers=h,
               json={"version": "9.9.9-9999", "rule_key": "FW-E2E",
                     "rule_title": "Outdated SonicOS Firmware"})
    client.post(f"/api/v1/platform/generations/{gen['id']}/devices", headers=h,
                json={"model": "TZ 470"})
    fv = client.post(f"/api/v1/platform/generations/{gen['id']}/firmware-versions",
                     headers=h, json={"version": "7.1.1-7047",
                                      "remediation": "Upgrade to 9.9.9-9999"}).json()
    cve = client.post(f"/api/v1/platform/firmware-versions/{fv['id']}/cves",
                      headers=h, json={"cve_id": "CVE-2026-77777",
                                       "cvss": 9.1}).json()

    from app.models import Device
    db = SessionLocal()
    try:
        device = Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                        serial="SN-FW-1", friendly_name="fw", configured=False)
        db.add(device)
        db.commit()
        device_id = device.id
    finally:
        db.close()

    def upload():
        res = client.post(f"/api/v1/customers/{org_a['customer_id']}/tsrs",
                          headers=h, params={"device_id": device_id},
                          files={"file": ("fw.wri", FW_TSR.encode(), "text/plain")})
        assert res.status_code in (200, 201, 202), res.text

    upload()
    rows = [f for f in client.get("/api/v1/findings", headers=h,
                                  params={"device_id": device_id}).json()
            if f["rule_id"] == "FW-E2E"]
    assert len(rows) == 1
    assert rows[0]["title"] == "Outdated SonicOS Firmware"

    # Re-analysis must not duplicate the finding.
    upload()
    rows2 = [f for f in client.get("/api/v1/findings", headers=h,
                                   params={"device_id": device_id}).json()
             if f["rule_id"] == "FW-E2E"]
    assert len(rows2) == 1 and rows2[0]["id"] == rows[0]["id"]

    # Snapshot property: removing the CVE from Product Config must not
    # rewrite the evidence of the already-generated finding.
    detail = client.get(f"/api/v1/findings/{rows[0]['id']}", headers=h).json()
    assert any("CVE-2026-77777" in e for e in detail["evidence"])
    assert client.delete(f"/api/v1/platform/firmware-cves/{cve['id']}",
                         headers=h).status_code == 204
    detail_after = client.get(f"/api/v1/findings/{rows[0]['id']}", headers=h).json()
    assert any("CVE-2026-77777" in e for e in detail_after["evidence"])
