"""Overall security score aggregation (executive summary endpoint).

Regression tests for the 0%-exclusion bug: a device that has been analyzed
and legitimately scored 0 must participate in the fleet average. Only
never-analyzed devices (no grade yet) are excluded. Both the Dashboard and
Security Analytics read `overall_score` from this endpoint, so one test
covers both pages.
"""

from __future__ import annotations

from app.database import SessionLocal
from app.models import Analysis, AnalysisStatus, Device


def auth_headers(client, email: str, password: str) -> dict:
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _add_device(org: dict, serial: str, score: float | None, grade: str,
                configured: bool = True, with_analysis: bool = False) -> str:
    db = SessionLocal()
    try:
        device = Device(organization_id=org["org_id"], customer_id=org["customer_id"],
                        serial=serial, friendly_name=serial, configured=configured,
                        latest_score=score if score is not None else 0.0,
                        latest_grade=grade)
        db.add(device)
        db.flush()
        if with_analysis:
            db.add(Analysis(organization_id=org["org_id"], device_id=device.id,
                            tsr_id=f"t-{serial}", status=AnalysisStatus.complete,
                            score=score or 0.0, grade=grade))
        db.commit()
        return device.id
    finally:
        db.close()


def _summary(client, org: dict) -> dict:
    h = auth_headers(client, org["email"], org["password"])
    res = client.get("/api/v1/analytics/executive-summary", headers=h)
    assert res.status_code == 200, res.text
    return res.json()


def test_zero_score_participates_in_overall(client, org_a):
    # The reported case: 0% and 24% must average to 12%, not 24%.
    _add_device(org_a, "SN-A", 0.0, "F")
    _add_device(org_a, "SN-B", 24.0, "F")
    out = _summary(client, org_a)
    assert out["overall_score"] == 12.0
    assert out["scored_devices"] == 2
    assert out["overall_grade"] == "F"


def test_zero_score_with_three_devices(client, org_a):
    _add_device(org_a, "SN-A", 0.0, "F")
    _add_device(org_a, "SN-B", 24.0, "F")
    _add_device(org_a, "SN-C", 50.0, "E")
    out = _summary(client, org_a)
    assert out["overall_score"] == 24.7          # (0 + 24 + 50) / 3
    assert out["scored_devices"] == 3


def test_never_analyzed_devices_are_excluded_not_zero_scores(client, org_a):
    _add_device(org_a, "SN-A", 0.0, "F")          # analyzed, scored 0 — include
    _add_device(org_a, "SN-B", 24.0, "F")         # analyzed — include
    _add_device(org_a, "SN-C", None, "")          # configured, never analyzed — exclude
    _add_device(org_a, "SN-D", None, "", configured=False)  # not configured — exclude
    out = _summary(client, org_a)
    assert out["overall_score"] == 12.0
    assert out["scored_devices"] == 2


def test_all_devices_scored_zero_is_a_real_zero(client, org_a):
    _add_device(org_a, "SN-A", 0.0, "F")
    out = _summary(client, org_a)
    assert out["overall_score"] == 0.0
    assert out["scored_devices"] == 1
    assert out["overall_grade"] == "F"           # a real score, not "no data"


def test_no_scored_devices_reports_no_grade(client, org_a):
    _add_device(org_a, "SN-C", None, "")          # configured but never analyzed
    out = _summary(client, org_a)
    assert out["overall_score"] == 0.0
    assert out["scored_devices"] == 0
    assert out["overall_grade"] == ""            # lets the UI show "No Data"


# ---- score trend (Dashboard "Security Score Trend" + Security Analytics
# ---- sparkline both read score_trend from this same endpoint) ---------------
def test_trend_latest_point_includes_zero_scores(client, org_a):
    # The reported case: latest analyses are 0 and 24 → today's trend point
    # must be 12, matching the live overall score — never 24.
    _add_device(org_a, "SN-A", 0.0, "F", with_analysis=True)
    _add_device(org_a, "SN-B", 24.0, "F", with_analysis=True)
    out = _summary(client, org_a)
    assert out["score_trend"], "expected a dense trend series"
    latest = out["score_trend"][-1]["value"]
    assert latest == 12.0
    assert latest == out["overall_score"]        # trend and widget must agree


def test_trend_excludes_never_analyzed_devices_only(client, org_a):
    _add_device(org_a, "SN-A", 0.0, "F", with_analysis=True)
    _add_device(org_a, "SN-B", 24.0, "F", with_analysis=True)
    _add_device(org_a, "SN-C", None, "")          # no analyses — not in trend
    out = _summary(client, org_a)
    assert out["score_trend"][-1]["value"] == 12.0


def test_trend_all_zero_is_zero_not_missing(client, org_a):
    _add_device(org_a, "SN-A", 0.0, "F", with_analysis=True)
    out = _summary(client, org_a)
    assert out["score_trend"][-1]["value"] == 0.0
    assert out["overall_score"] == 0.0
