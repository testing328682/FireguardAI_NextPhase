"""Finding-metrics semantics shared by Dashboard and Security Analytics.

Locks down the status definitions used by the analytics widgets so the two
pages cannot drift apart again:

  * ACTIVE ("Open Findings") = open / acknowledged / in_progress
  * RESOLVED ("Fixed" bucket) = fixed / false_positive / accepted_risk
  * suppressed is excluded from the Open vs Fixed widget total
  * severity distribution counts ACTIVE findings only, with percentages
    computed against the same (possibly severity-filtered) total
  * zero counts are real values and always present in the distribution
"""

from __future__ import annotations

from app.database import SessionLocal
from app.models import Device, Finding, FindingStatus


def auth_headers(client, email, password):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _add_device(org: dict, serial: str = "SN-1") -> str:
    db = SessionLocal()
    try:
        d = Device(organization_id=org["org_id"], customer_id=org["customer_id"],
                   serial=serial, friendly_name=serial, configured=True,
                   latest_score=50.0, latest_grade="C")
        db.add(d)
        db.commit()
        return d.id
    finally:
        db.close()


def _add_finding(org: dict, device_id: str, severity: str, status: FindingStatus,
                 rule: str = "R", i: int = 0) -> None:
    db = SessionLocal()
    try:
        db.add(Finding(
            organization_id=org["org_id"], device_id=device_id, analysis_id="a1",
            rule_id=rule, fingerprint=f"{rule}:{severity}:{device_id}:{status.value}:{i}",
            severity=severity, title=f"{rule} {severity} {i}", status=status))
        db.commit()
    finally:
        db.close()


def _charts(client, org: dict, hidden: str | None = None) -> dict:
    qs = f"?hidden_severities={hidden}" if hidden else ""
    res = client.get(f"/api/v1/analytics/dashboard-charts{qs}",
                     headers=auth_headers(client, org["email"], org["password"]))
    assert res.status_code == 200, res.text
    return res.json()


# ---- status buckets (Open vs Fixed widget) ---------------------------------

def test_status_buckets_and_total(client, org_a):
    """Open + In Progress bucket (ack/in_progress) + Fixed bucket (fixed/fp/ar);
    suppressed excluded from the widget total entirely."""
    d = _add_device(org_a)
    _add_finding(org_a, d, "High", FindingStatus.open, i=0)
    _add_finding(org_a, d, "High", FindingStatus.open, i=1)
    _add_finding(org_a, d, "High", FindingStatus.open, i=2)
    _add_finding(org_a, d, "Medium", FindingStatus.acknowledged, i=3)
    _add_finding(org_a, d, "Medium", FindingStatus.in_progress, i=4)
    _add_finding(org_a, d, "Low", FindingStatus.fixed, i=5)
    _add_finding(org_a, d, "Low", FindingStatus.fixed, i=6)
    _add_finding(org_a, d, "Low", FindingStatus.false_positive, i=7)
    _add_finding(org_a, d, "Low", FindingStatus.accepted_risk, i=8)
    _add_finding(org_a, d, "Info", FindingStatus.suppressed, i=9)

    out = _charts(client, org_a)
    sd = out["status_distribution"]
    # open=3, in_progress bucket=ack(1)+in_progress(1)=2, fixed bucket=fixed(2)+fp(1)+ar(1)=4
    assert sd["open"]["count"] == 3
    assert sd["in_progress"]["count"] == 2
    assert sd["fixed"]["count"] == 4
    # widget total = 3 + 2 + 4 = 9 — the suppressed finding is not counted
    assert sd["open"]["count"] + sd["in_progress"]["count"] + sd["fixed"]["count"] == 9
    assert sd["open"]["pct"] == 33.3
    assert sd["in_progress"]["pct"] == 22.2
    assert sd["fixed"]["pct"] == 44.4


def test_severity_distribution_counts_active_only(client, org_a):
    """Fixed findings must never leak into the severity (open) distribution."""
    d = _add_device(org_a)
    _add_finding(org_a, d, "Critical", FindingStatus.open, i=0)
    _add_finding(org_a, d, "Critical", FindingStatus.open, i=1)
    _add_finding(org_a, d, "High", FindingStatus.open, i=2)
    _add_finding(org_a, d, "Critical", FindingStatus.fixed, i=3)
    _add_finding(org_a, d, "Low", FindingStatus.fixed, i=4)

    out = _charts(client, org_a)
    dist = out["severity_distribution"]
    assert dist["Critical"]["count"] == 2
    assert dist["High"]["count"] == 1
    assert dist["Low"]["count"] == 0          # the fixed Low must not appear
    assert out["total_findings"] == 3
    assert out["total_findings"] == sum(b["count"] for b in dist.values())


def test_zero_severities_are_present_not_missing(client, org_a):
    """A severity with zero findings is reported as count 0 / pct 0."""
    d = _add_device(org_a)
    _add_finding(org_a, d, "High", FindingStatus.open, i=0)

    out = _charts(client, org_a)
    dist = out["severity_distribution"]
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        assert sev in dist, f"{sev} missing from distribution"
        assert "count" in dist[sev] and "pct" in dist[sev]
    assert dist["Medium"]["count"] == 0 and dist["Medium"]["pct"] == 0


def test_hidden_severity_denominator_consistent(client, org_a):
    """Disabling a severity removes it from BOTH the displayed counts and the
    percentage denominator (no hidden-vs-included mismatch)."""
    d = _add_device(org_a)
    _add_finding(org_a, d, "Critical", FindingStatus.open, i=0)
    _add_finding(org_a, d, "Critical", FindingStatus.open, i=1)
    _add_finding(org_a, d, "High", FindingStatus.open, i=2)
    _add_finding(org_a, d, "Low", FindingStatus.open, i=3)
    _add_finding(org_a, d, "Low", FindingStatus.open, i=4)
    _add_finding(org_a, d, "Low", FindingStatus.open, i=5)

    out = _charts(client, org_a, hidden="Low")
    dist = out["severity_distribution"]
    # Hidden severities are reported with count 0 (never dropped from the
    # shape), and are excluded from the total and percentage denominators.
    assert dist["Low"]["count"] == 0
    assert out["total_findings"] == 3           # 2 Critical + 1 High
    assert dist["Critical"]["count"] == 2
    assert dist["Critical"]["pct"] == 66.7      # 2 / 3 — denominator excludes Low
    assert dist["High"]["pct"] == 33.3


def test_status_distribution_respects_hidden_severities(client, org_a):
    d = _add_device(org_a)
    _add_finding(org_a, d, "Critical", FindingStatus.open, i=0)
    _add_finding(org_a, d, "Low", FindingStatus.open, i=1)
    _add_finding(org_a, d, "Low", FindingStatus.fixed, i=2)

    out = _charts(client, org_a, hidden="Low")
    sd = out["status_distribution"]
    assert sd["open"]["count"] == 1             # only the Critical open remains
    assert sd["fixed"]["count"] == 0            # Low fixed excluded too


def test_dashboard_charts_and_executive_summary_agree(client, org_a):
    """The Dashboard (charts) and Security Analytics (executive summary) must
    see the same active-finding population for the same scope."""
    d = _add_device(org_a)
    _add_finding(org_a, d, "Critical", FindingStatus.open, i=0)
    _add_finding(org_a, d, "High", FindingStatus.open, i=1)
    _add_finding(org_a, d, "High", FindingStatus.open, i=2)
    _add_finding(org_a, d, "Low", FindingStatus.fixed, i=3)

    charts = _charts(client, org_a)
    res = client.get("/api/v1/analytics/executive-summary",
                     headers=auth_headers(client, org_a["email"], org_a["password"]))
    assert res.status_code == 200, res.text
    summary = res.json()

    assert charts["severity_distribution"]["Critical"]["count"] == summary["critical_count"]
    assert charts["severity_distribution"]["High"]["count"] == summary["high_count"]
    assert charts["total_findings"] == 3


def test_analysis_findings_status_is_deterministic(client, org_a):
    """Snapshot cross-reference (GET /analyses/{id}/findings): an ACTIVE live
    row always wins over a resolved row for the same fingerprint, regardless of
    row order — so the Device Findings summary can never flip between requests
    (previously unordered last-wins depended on scan order)."""
    from app.models import Analysis, AnalysisStatus

    db = SessionLocal()
    try:
        d = Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                   serial="SN-DET", friendly_name="SN-DET", configured=True,
                   latest_score=0.0, latest_grade="F")
        db.add(d)
        db.flush()

        snap_findings = [
            {"rule_id": "R1", "object_type": "Address Object", "object_name": "OBJ1",
             "severity": "High", "title": "t1", "category": "c"},
            {"rule_id": "R2", "object_type": "Address Object", "object_name": "OBJ2",
             "severity": "Low", "title": "t2", "category": "c"},
        ]
        a = Analysis(organization_id=org_a["org_id"], device_id=d.id,
                     tsr_id=f"t-{d.id}", status=AnalysisStatus.complete, score=0.0, grade="F",
                     finding_count=2, critical_count=0, high_count=1,
                     result_json={"findings": snap_findings})
        db.add(a)
        db.flush()

        # R1: RESOLVED row inserted FIRST, ACTIVE row second — active must win.
        db.add(Finding(organization_id=org_a["org_id"], device_id=d.id, analysis_id=a.id,
                       rule_id="R1", fingerprint="R1::Address Object::OBJ1",
                       severity="High", title="t1", status=FindingStatus.fixed))
        db.flush()
        db.add(Finding(organization_id=org_a["org_id"], device_id=d.id, analysis_id=a.id,
                       rule_id="R1", fingerprint="R1::Address Object::OBJ1",
                       severity="High", title="t1", status=FindingStatus.open))
        # R2: only a resolved row.
        db.add(Finding(organization_id=org_a["org_id"], device_id=d.id, analysis_id=a.id,
                       rule_id="R2", fingerprint="R2::Address Object::OBJ2",
                       severity="Low", title="t2", status=FindingStatus.fixed))
        db.commit()
        aid = a.id
    finally:
        db.close()

    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get(f"/api/v1/analyses/{aid}/findings", headers=h)
    assert res.status_code == 200, res.text
    statuses = {r["rule_id"]: r["status"] for r in res.json()}
    assert statuses == {"R1": "open", "R2": "fixed"}


def test_analysis_findings_dedupe_matches_live_table(client, org_a):
    """The Device Findings snapshot view (GET /analyses/{id}/findings) must
    collapse duplicate-fingerprint snapshot entries into one row, exactly as
    sync_findings dedupes the live table. Otherwise objects that share an
    identity — e.g. many address objects with a blank name "-" — inflate the
    device view far above the account-level Dashboard/Analytics counts.

    Reproduces the reported case: a snapshot with 60 AOB entries all named "-"
    plus one distinct finding — 61 array entries, 2 unique fingerprints — must
    surface as exactly 2 device-view rows and 1 open (matching the single live
    active row), not 60 open.
    """
    from app.models import Analysis, AnalysisStatus

    db = SessionLocal()
    try:
        d = Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                   serial="SN-DUP", friendly_name="SN-DUP", configured=True,
                   latest_score=0.0, latest_grade="F")
        db.add(d)
        db.flush()

        # 60 snapshot entries sharing one fingerprint (blank object name "-"),
        # plus one genuinely-distinct finding.
        snap_findings = [
            {"rule_id": "AOB-003", "object_type": "Address Object", "object_name": "-",
             "severity": "Low", "title": f"blank object {i}", "category": "Address Objects"}
            for i in range(60)
        ] + [
            {"rule_id": "AOB-001", "object_type": "Address Object", "object_name": "X0 IP",
             "severity": "High", "title": "named object", "category": "Address Objects"},
        ]
        a = Analysis(organization_id=org_a["org_id"], device_id=d.id,
                     tsr_id=f"t-{d.id}", status=AnalysisStatus.complete, score=0.0,
                     grade="F", finding_count=len(snap_findings), critical_count=0,
                     high_count=1, result_json={"findings": snap_findings})
        db.add(a)
        db.flush()

        # The live table has exactly one row per unique fingerprint (what
        # sync_findings would persist): both currently open.
        db.add(Finding(organization_id=org_a["org_id"], device_id=d.id, analysis_id=a.id,
                       rule_id="AOB-003", fingerprint="AOB-003::Address Object::-",
                       severity="Low", title="blank object", status=FindingStatus.open))
        db.add(Finding(organization_id=org_a["org_id"], device_id=d.id, analysis_id=a.id,
                       rule_id="AOB-001", fingerprint="AOB-001::Address Object::X0 IP",
                       severity="High", title="named object", status=FindingStatus.open))
        db.commit()
        aid = a.id
    finally:
        db.close()

    h = auth_headers(client, org_a["email"], org_a["password"])
    rows = client.get(f"/api/v1/analyses/{aid}/findings", headers=h).json()
    # 61 snapshot entries collapse to 2 unique-fingerprint rows.
    assert len(rows) == 2
    open_rows = [r for r in rows if r["status"] == "open"]
    assert len(open_rows) == 2
    # Device view now agrees with the live findings table for this device.
    live = client.get(f"/api/v1/findings?device_id={d.id}", headers=h).json()
    live_open = [r for r in live if r["status"] == "open"]
    assert len(open_rows) == len(live_open) == 2