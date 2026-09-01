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
