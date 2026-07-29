"""Tests for the analysis engine.

These tests exercise the parser, rule engine, scoring, drift detection and the
end-to-end pipeline. They run without the database or web stack. The reference
TSR path can be overridden with the FGAI_TEST_TSR environment variable; when no
TSR is available the TSR-dependent tests are skipped.
"""

from __future__ import annotations

import copy
import os

import pytest

from firewallguard.tsr.parser import parse_tsr
from firewallguard.rules.engine import registry, SEVERITIES
import firewallguard.rules.catalog  # noqa: F401 - registers rules
from firewallguard.analytics.scoring import score_findings
from firewallguard.analytics.drift import detect_drift
from firewallguard.pipeline import analyze_text

TSR_PATH = os.environ.get(
    "FGAI_TEST_TSR",
    "/mnt/user-data/uploads/techSupport_18C2411FFAA5_8-27.wri")


def _has_tsr() -> bool:
    return os.path.exists(TSR_PATH)


@pytest.fixture(scope="module")
def tsr_text() -> str:
    if not _has_tsr():
        pytest.skip("No reference TSR available")
    with open(TSR_PATH, encoding="utf-8", errors="replace") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def snapshot(tsr_text: str) -> dict:
    return parse_tsr(tsr_text, "test")


# ---- parser --------------------------------------------------------------
def test_parser_extracts_system(snapshot):
    sysd = snapshot["system"]
    assert sysd["model"]
    assert sysd["serial"]
    assert "SonicOS" in sysd["firmware"]


def test_parser_extracts_collections(snapshot):
    assert len(snapshot["access_rules"]) > 100
    assert len(snapshot["nat_policies"]) > 10
    assert len(snapshot["address_objects"]["objects"]) > 100
    assert len(snapshot["services"]["objects"]) > 0


def test_address_objects_have_reference_metadata(snapshot):
    objs = snapshot["address_objects"]["objects"]
    assert any("reference_count" in o for o in objs)


# ---- rules ---------------------------------------------------------------
def test_rules_produce_findings(snapshot):
    findings = registry.run_all(snapshot)
    assert findings, "expected at least one finding for a real-world TSR"
    for f in findings:
        assert f.severity in SEVERITIES
        assert f.rule_id and f.title
        assert f.remediation


def test_findings_are_sorted_by_severity(snapshot):
    findings = registry.run_all(snapshot)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    ranks = [order[f.severity] for f in findings]
    assert ranks == sorted(ranks)


# ---- scoring -------------------------------------------------------------
def test_clean_config_scores_high():
    result = score_findings([])
    assert result["score"] == 100
    assert result["grade"] == "Secure"


def test_critical_finding_forces_failing_grade(snapshot):
    findings = registry.run_all(snapshot)
    result = score_findings(findings)
    if result["severity_counts"]["Critical"] > 0:
        assert result["score"] <= 59
        assert result["grade"] == "F"


def test_score_is_bounded(snapshot):
    findings = registry.run_all(snapshot)
    result = score_findings(findings)
    assert 0 <= result["score"] <= 100


# ---- drift ---------------------------------------------------------------
def test_drift_detects_disabled_service(snapshot):
    prev = copy.deepcopy(snapshot)
    curr = copy.deepcopy(snapshot)
    prev["security_services"]["ips_enabled"] = True
    curr["security_services"]["ips_enabled"] = False
    drift = detect_drift(prev, curr)
    assert drift["alert_count"] >= 1
    assert any(a["category"] == "Security Services" and a["severity"] == "Critical"
               for a in drift["alerts"])


def test_drift_detects_no_change(snapshot):
    drift = detect_drift(snapshot, copy.deepcopy(snapshot))
    assert drift["alert_count"] == 0


# ---- pipeline ------------------------------------------------------------
def test_pipeline_end_to_end(tsr_text):
    analysis = analyze_text(tsr_text, "test")
    assert analysis["device"]["serial"]
    assert 0 <= analysis["score"]["score"] <= 100
    assert analysis["finding_count"] == len(analysis["findings"])
    assert isinstance(analysis["attack_paths"], list)
    # result must be JSON-serialisable
    import json
    json.dumps(analysis, default=str)


# ---- per-object findings & PSIRT ----------------------------------------
def test_per_object_findings_carry_names(snapshot):
    findings = registry.run_all(snapshot)
    named = [f for f in findings if f.object_name]
    assert named, "expected per-object findings to carry an object_name"
    # Per-object rules should each name a specific object and type.
    acr = [f for f in findings if f.rule_id == "ACR-007"]
    for f in acr:
        assert f.object_name
        assert f.object_type == "Access Rule"


def test_psirt_matches_real_advisories(tsr_text):
    analysis = analyze_text(tsr_text, "test")
    fw = analysis["firmware_intelligence"]
    # SonicOS 7.3.0-7012 (Gen7) must match the three known advisories.
    assert fw["advisory_count"] >= 3
    ids = {a["advisory_id"] for a in fw["matched_advisories"]}
    assert "SNWLID-2025-0016" in ids
    assert "SNWLID-2026-0004" in ids
    assert fw["max_cvss"] >= 8.0


def test_firmware_findings_present(tsr_text):
    analysis = analyze_text(tsr_text, "test")
    psirt = [f for f in analysis["findings"] if f["rule_id"].startswith("FW-PSIRT-")]
    assert psirt, "expected firmware advisory findings in the result"
