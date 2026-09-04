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
    # Each call is a DISTINCT logical finding: counts are grouped by
    # (device, rule_id), so a unique rule per row keeps these as separate
    # findings. Use _add_instance to add several affected objects to ONE rule.
    db = SessionLocal()
    try:
        db.add(Finding(
            organization_id=org["org_id"], device_id=device_id, analysis_id="a1",
            rule_id=f"{rule}-{i}", fingerprint=f"{rule}:{severity}:{device_id}:{status.value}:{i}",
            severity=severity, title=f"{rule} {severity} {i}",
            object_name=f"obj-{i}", status=status))
        db.commit()
    finally:
        db.close()


def _add_instance(org: dict, device_id: str, rule: str, severity: str,
                  status: FindingStatus, obj: str) -> None:
    """Add one affected-object instance to a shared (device, rule) group."""
    db = SessionLocal()
    try:
        db.add(Finding(
            organization_id=org["org_id"], device_id=device_id, analysis_id="a1",
            rule_id=rule, fingerprint=f"{rule}::Object::{obj}",
            severity=severity, title=f"{rule} finding", object_type="Object",
            object_name=obj, status=status))
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
    """Open + In Progress bucket (ack/in_progress/suppressed) + Fixed bucket
    (fixed/fp/ar). Each finding here is a single-instance group, so its own
    status is authoritative directly (see finding_groups.effective_status) —
    Suppressed is OPEN-classified (never excluded), per the classification
    used everywhere for grouped findings."""
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
    # open=3, in_progress bucket=ack(1)+in_progress(1)+suppressed(1)=3, fixed=fixed(2)+fp(1)+ar(1)=4
    assert sd["open"]["count"] == 3
    assert sd["in_progress"]["count"] == 3
    assert sd["fixed"]["count"] == 4
    # widget total = 3 + 3 + 4 = 10 — every finding is counted, none excluded
    assert sd["open"]["count"] + sd["in_progress"]["count"] + sd["fixed"]["count"] == 10


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


def test_finding_trend_last_point_matches_grouped_kpi(client, org_a):
    """High/Critical KPI cards and their sparkline trend must agree: a rule
    with N open instances is ONE logical finding, and today's trend point is
    the live grouped count (previously the trend counted instance ROWS — a
    rule with several objects inflated it, e.g. 53 rows vs 22 groups)."""
    d = _add_device(org_a)
    # R1: 3 open High instances + 1 fixed High instance -> 1 logical finding
    for n in range(3):
        _add_instance(org_a, d, "R1", "High", FindingStatus.open, obj=f"o{n}")
    _add_instance(org_a, d, "R1", "High", FindingStatus.fixed, obj="o9")
    # R2: 2 open High instances -> 1 logical finding
    _add_instance(org_a, d, "R2", "High", FindingStatus.open, obj="o0")
    _add_instance(org_a, d, "R2", "High", FindingStatus.open, obj="o1")
    # R3: single fixed High finding -> resolved, not counted
    _add_finding(org_a, d, "High", FindingStatus.fixed, rule="R3", i=0)
    # R4: single open Critical finding -> 1 logical Critical finding
    _add_finding(org_a, d, "Critical", FindingStatus.open, rule="R4", i=0)

    res = client.get("/api/v1/analytics/executive-summary",
                     headers=auth_headers(client, org_a["email"], org_a["password"]))
    assert res.status_code == 200, res.text
    s = res.json()
    assert s["high_count"] == 2                # R1 + R2 (R3 fixed excluded)
    assert s["critical_count"] == 1
    assert s["high_trend"], "expected a populated trend"
    assert s["high_trend"][-1]["value"] == 2   # trend agrees with the KPI card
    assert s["critical_trend"][-1]["value"] == 1


def test_grouped_finding_counts_as_one(client, org_a):
    """A rule affecting 5 objects is ONE finding in the counts, not five —
    with the affected total still available. (Requirement 6.)"""
    d = _add_device(org_a)
    for n in range(5):
        _add_instance(org_a, d, "IKE-DH", "High", FindingStatus.open, f"policy-{n}")
    out = _charts(client, org_a)
    assert out["severity_distribution"]["High"]["count"] == 1     # one logical finding
    assert out["total_findings"] == 1
    assert out["status_distribution"]["open"]["count"] == 1

    groups = client.get("/api/v1/finding-groups",
                        headers=auth_headers(client, org_a["email"], org_a["password"])).json()
    g = next(x for x in groups if x["rule_id"] == "IKE-DH")
    assert g["affected_total"] == 5 and g["affected_open"] == 5
    assert g["status"] == "open"


def test_grouped_finding_parent_never_auto_resolved(client, org_a):
    """The parent's status is NEVER auto-derived from its children — not even
    when every affected object becomes fixed. It only becomes ELIGIBLE
    (can_resolve=True); a user must explicitly transition it. (Requirement 5.)"""
    d = _add_device(org_a)
    for n in range(5):
        _add_instance(org_a, d, "IKE-DH", "High", FindingStatus.open, f"policy-{n}")
    h = auth_headers(client, org_a["email"], org_a["password"])

    def group():
        return next(x for x in client.get("/api/v1/finding-groups", headers=h).json()
                    if x["rule_id"] == "IKE-DH")

    detail = client.get(f"/api/v1/finding-groups/detail?device_id={d}&rule_id=IKE-DH",
                        headers=h).json()
    ids = [i["id"] for i in detail["instances"]]

    # Fix 3 of 5 → parent stays "open" (untouched), not eligible to resolve.
    client.post("/api/v1/findings/bulk-transition", headers=h,
                json={"finding_ids": ids[:3], "to_status": "fixed", "comment": "patched 3"})
    g = group()
    assert g["status"] == "open" and g["affected_fixed"] == 3 and g["affected_open"] == 2
    assert g["can_resolve"] is False
    charts = _charts(client, org_a)
    assert charts["status_distribution"]["open"]["count"] == 1
    assert charts["status_distribution"]["fixed"]["count"] == 0

    # Fix the last 2 → parent is now ELIGIBLE, but still "open" until a human
    # explicitly closes it. The dashboard must NOT show it as fixed yet.
    client.post("/api/v1/findings/bulk-transition", headers=h,
                json={"finding_ids": ids[3:], "to_status": "fixed", "comment": "patched rest"})
    g = group()
    assert g["status"] == "open" and g["affected_open"] == 0
    assert g["can_resolve"] is True
    charts = _charts(client, org_a)
    assert charts["status_distribution"]["open"]["count"] == 1
    assert charts["status_distribution"]["fixed"]["count"] == 0


def test_grouped_finding_parent_transition_rules(client, org_a):
    """Server-enforced parent transition rules (requirements 2-4, 9):
    OPEN-classified statuses are always allowed; FIXED-classified statuses
    are rejected while any child remains OPEN-classified, and accepted once
    every child is FIXED-classified. A single-instance group has no separate
    parent endpoint."""
    d = _add_device(org_a)
    for n in range(3):
        _add_instance(org_a, d, "IKE-DH", "High", FindingStatus.open, f"policy-{n}")
    h = auth_headers(client, org_a["email"], org_a["password"])

    # The parent can move to an OPEN-classified status at any time, even
    # while every child is still plain "open" (untouched).
    res = client.post("/api/v1/finding-groups/transition", headers=h,
                      json={"device_id": d, "rule_id": "IKE-DH",
                            "to_status": "acknowledged", "comment": "triaging"})
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "acknowledged"
    charts = _charts(client, org_a)
    assert charts["status_distribution"]["in_progress"]["count"] == 1

    # Blocked: cannot resolve while children remain open.
    res = client.post("/api/v1/finding-groups/transition", headers=h,
                      json={"device_id": d, "rule_id": "IKE-DH",
                            "to_status": "fixed", "comment": "try close"})
    assert res.status_code == 400
    assert "affected object(s) remain open" in res.json()["detail"]

    # Resolve every child, then the parent can move to a FIXED-classified
    # status via an explicit transition (never automatically).
    detail = client.get(f"/api/v1/finding-groups/detail?device_id={d}&rule_id=IKE-DH",
                        headers=h).json()
    ids = [i["id"] for i in detail["instances"]]
    client.post("/api/v1/findings/bulk-transition", headers=h,
                json={"finding_ids": ids, "to_status": "fixed", "comment": "all patched"})
    res = client.post("/api/v1/finding-groups/transition", headers=h,
                      json={"device_id": d, "rule_id": "IKE-DH",
                            "to_status": "fixed", "comment": "close it"})
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "fixed"
    charts = _charts(client, org_a)
    assert charts["status_distribution"]["fixed"]["count"] == 1

    # Suppressed also blocks resolution (it is OPEN-classified) — reopen one
    # child as suppressed and confirm the parent can no longer be re-fixed.
    client.post(f"/api/v1/findings/{ids[0]}/transition", headers=h,
               json={"to_status": "suppressed", "comment": "silenced", "justification": "noise"})
    res = client.post("/api/v1/finding-groups/transition", headers=h,
                      json={"device_id": d, "rule_id": "IKE-DH",
                            "to_status": "open", "comment": "reopen"})
    assert res.status_code == 200, res.text
    res = client.post("/api/v1/finding-groups/transition", headers=h,
                      json={"device_id": d, "rule_id": "IKE-DH",
                            "to_status": "fixed", "comment": "retry close"})
    assert res.status_code == 400

    # A single-instance group has no separate parent endpoint.
    _add_instance(org_a, d, "SOLO-RULE", "Low", FindingStatus.open, "only-object")
    res = client.post("/api/v1/finding-groups/transition", headers=h,
                      json={"device_id": d, "rule_id": "SOLO-RULE",
                            "to_status": "acknowledged", "comment": "x"})
    assert res.status_code == 400
    assert "single affected object" in res.json()["detail"]


def test_child_findings_move_freely_between_any_status(client, org_a):
    """No restriction on direct status-to-status movement for an affected
    instance — any of the six statuses may follow any other. (Requirement 1.)"""
    d = _add_device(org_a)
    _add_instance(org_a, d, "IKE-DH", "High", FindingStatus.open, "policy-0")
    h = auth_headers(client, org_a["email"], org_a["password"])
    fid = client.get("/api/v1/finding-groups/detail?device_id=" + d + "&rule_id=IKE-DH",
                     headers=h).json()["instances"][0]["id"]

    def move(to_status, **extra):
        body = {"to_status": to_status, "comment": "x", **extra}
        res = client.post(f"/api/v1/findings/{fid}/transition", headers=h, json=body)
        assert res.status_code == 200, res.text
        return res.json()["status"]

    # Direct hops that were PREVIOUSLY blocked by the old state graph.
    assert move("fixed") == "fixed"
    assert move("accepted_risk", justification="risk accepted",
               accepted_risk_expiry="2099-01-01T00:00:00Z") == "accepted_risk"
    assert move("false_positive", justification="not real") == "false_positive"
    assert move("suppressed") == "suppressed"
    assert move("acknowledged") == "acknowledged"
    assert move("in_progress") == "in_progress"
    assert move("fixed") == "fixed"
    charts = _charts(client, org_a)
    assert charts["severity_distribution"]["High"]["count"] == 0
    assert charts["status_distribution"]["fixed"]["count"] == 1


def test_finding_group_detail_lists_instances(client, org_a):
    d = _add_device(org_a)
    for n in range(3):
        _add_instance(org_a, d, "IKE-DH", "High", FindingStatus.open, f"policy-{n}")
    h = auth_headers(client, org_a["email"], org_a["password"])
    detail = client.get(f"/api/v1/finding-groups/detail?device_id={d}&rule_id=IKE-DH",
                        headers=h).json()
    assert detail["affected_total"] == 3
    assert sorted(i["object_name"] for i in detail["instances"]) == ["policy-0", "policy-1", "policy-2"]
    assert detail["title"] == "IKE-DH finding"


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


# ---- live device score (Overall Security Score) ----------------------------

def test_device_score_recomputes_on_status_change(client, org_a):
    """Device.latest_score must reflect the CURRENT triage state, not just
    whatever the pipeline detected at analysis time. Resolving every Critical
    and High finding must raise the score immediately (no re-scan needed),
    and reopening one must drop it again — the score is never frozen after
    the initial write."""
    d = _add_device(org_a)
    for n in range(4):
        _add_instance(org_a, d, "CRIT-RULE", "Critical", FindingStatus.open, f"c-{n}")
    for n in range(9):
        _add_instance(org_a, d, "HIGH-RULE", "High", FindingStatus.open, f"h-{n}")
    h = auth_headers(client, org_a["email"], org_a["password"])

    def _score() -> float:
        res = client.get("/api/v1/devices", headers=h)
        assert res.status_code == 200, res.text
        return next(x for x in res.json() if x["id"] == d)["latest_score"]

    # Any Critical finding caps the score at 59 (grade F) — score_findings().
    before = _score()
    assert before <= 59.0

    crit_ids = [i["id"] for i in client.get(
        f"/api/v1/finding-groups/detail?device_id={d}&rule_id=CRIT-RULE", headers=h
    ).json()["instances"]]
    res = client.post("/api/v1/findings/bulk-transition", headers=h,
                      json={"finding_ids": crit_ids, "to_status": "fixed",
                            "comment": "patched"})
    assert res.status_code == 200, res.text

    high_ids = [i["id"] for i in client.get(
        f"/api/v1/finding-groups/detail?device_id={d}&rule_id=HIGH-RULE", headers=h
    ).json()["instances"]]
    res = client.post("/api/v1/findings/bulk-transition", headers=h,
                      json={"finding_ids": high_ids, "to_status": "fixed",
                            "comment": "patched"})
    assert res.status_code == 200, res.text

    # No active findings remain -> a perfect score, immediately, no re-scan.
    after = _score()
    assert after == 100.0
    assert after > before

    # Reopening one High finding must push the score back down (capped at 79).
    res = client.post(f"/api/v1/findings/{high_ids[0]}/transition", headers=h,
                      json={"to_status": "open", "comment": "regressed"})
    assert res.status_code == 200, res.text
    reopened = _score()
    assert reopened < after
    assert reopened <= 79.0


def test_device_score_ignores_suppressed_and_accepted_risk_consistently(client, org_a):
    """False Positive / Accepted Risk stop contributing (RESOLVED-classified,
    same as Fixed); Suppressed keeps contributing (OPEN-classified) — matching
    the existing finding_groups classification, not a newly invented one."""
    d = _add_device(org_a)
    _add_instance(org_a, d, "FP-RULE", "High", FindingStatus.open, "o1")
    _add_instance(org_a, d, "SUPPRESSED-RULE", "High", FindingStatus.open, "o2")
    h = auth_headers(client, org_a["email"], org_a["password"])

    def _score() -> float:
        res = client.get("/api/v1/devices", headers=h)
        return next(x for x in res.json() if x["id"] == d)["latest_score"]

    fp_id = client.get(f"/api/v1/finding-groups/detail?device_id={d}&rule_id=FP-RULE",
                       headers=h).json()["instances"][0]["id"]
    res = client.post(f"/api/v1/findings/{fp_id}/transition", headers=h,
                      json={"to_status": "false_positive", "comment": "not real",
                            "justification": "verified benign"})
    assert res.status_code == 200, res.text
    # One High finding (Suppressed-rule) remains active -> capped at 79, not 100.
    assert _score() <= 79.0

    supp_id = client.get(
        f"/api/v1/finding-groups/detail?device_id={d}&rule_id=SUPPRESSED-RULE", headers=h
    ).json()["instances"][0]["id"]
    res = client.post(f"/api/v1/findings/{supp_id}/transition", headers=h,
                      json={"to_status": "suppressed", "comment": "silenced",
                            "justification": "known noise"})
    assert res.status_code == 200, res.text
    # Suppressed still counts as active risk, so the score stays capped, not 100.
    assert _score() <= 79.0
