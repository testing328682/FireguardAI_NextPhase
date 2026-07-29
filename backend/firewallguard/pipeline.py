"""Analysis pipeline orchestrator.

Ties the individual stages together into a single, repeatable analysis:

    parse  ->  rules  ->  firmware intelligence  ->  correlation  ->  scoring

The output is a single JSON-serialisable ``analysis`` dictionary that the API
layer, the report generator and the drift engine all consume. Keeping the
result as a plain dictionary (rather than ORM objects) means an analysis can be
stored, transmitted and re-loaded without any database dependency.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .tsr.parser import parse_tsr
from .rules.engine import registry, Finding
from .intelligence.firmware import get_intel
from .intelligence.correlation import correlate
from .analytics.scoring import score_findings, exploitability_distribution

# Importing the catalog registers every rule on the shared registry.
from .rules import catalog as _catalog  # noqa: F401
from .rules import catalog_parity as _catalog_parity  # noqa: F401
from .rules import catalog_info as _catalog_info  # noqa: F401


def analyze_text(text: str, source_name: str = "tsr", *,
                 extra_findings_fn=None, suppressions=None,
                 system_filter_fn=None) -> Dict[str, Any]:
    """Run the full pipeline on raw TSR text and return an analysis dict.

    ``extra_findings_fn(snapshot) -> List[Finding]`` lets a caller (the service
    layer) inject findings from DB-stored CEL rules. ``suppressions`` is an
    optional list of ``{"rule_key", "action", "value"}`` dicts applied before
    scoring (see ``_apply_suppressions``). ``system_filter_fn(snapshot) ->
    set[str] | None`` is an optional callback that returns rule keys whose
    system-rule CEL conditions evaluated to False (superadmin customizations);
    matching Python-generated findings are filtered out. All three keep this
    package DB-agnostic.
    """
    snapshot = parse_tsr(text, source_name)
    return analyze_snapshot(snapshot, extra_findings_fn=extra_findings_fn,
                            suppressions=suppressions,
                            system_filter_fn=system_filter_fn)


def analyze_snapshot(snapshot: Dict[str, Any], *,
                     extra_findings_fn=None, suppressions=None,
                     system_filter_fn=None) -> Dict[str, Any]:
    """Run rules, intelligence, correlation and scoring on a parsed snapshot."""
    findings: List[Finding] = registry.run_all(snapshot)

    # Filter findings by system rule CEL conditions (superadmin customizations).
    if system_filter_fn is not None:
        try:
            suppress_keys = system_filter_fn(snapshot) or set()
        except Exception:  # noqa: BLE001 - filter failure must not break scan
            suppress_keys = set()
        if suppress_keys:
            findings = [f for f in findings if f.rule_id not in suppress_keys]

    if extra_findings_fn is not None:
        try:
            findings = findings + list(extra_findings_fn(snapshot) or [])
        except Exception:  # noqa: BLE001 - custom-rule layer must never break a scan
            pass

    system = snapshot.get("system", {})
    firmware_intel = get_intel().evaluate(
        system.get("firmware", ""), system.get("model", ""))

    # Promote firmware advisories into findings so they participate in scoring
    # and correlation alongside configuration findings.
    findings = findings + _firmware_findings(firmware_intel)
    findings = _apply_suppressions(findings, suppressions)
    findings.sort(key=_finding_sort_key)

    attack_paths = correlate(findings, firmware_intel)
    scoring = score_findings(findings)
    exploitability = exploitability_distribution(findings)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_name": snapshot.get("meta", {}).get("source_name"),
        "device": {
            "model": system.get("model"),
            "firmware": system.get("firmware"),
            "serial": system.get("serial"),
            "ha_mode": system.get("ha_mode"),
            "uptime": system.get("uptime"),
        },
        "score": scoring,
        "exploitability": exploitability,
        "findings": [f.to_dict() for f in findings],
        "finding_count": len(findings),
        "firmware_intelligence": firmware_intel,
        "attack_paths": [p.to_dict() for p in attack_paths],
        "snapshot": snapshot,
    }


def _apply_suppressions(findings: List[Finding], suppressions) -> List[Finding]:
    """Apply tenant suppressions: drop disabled rules, override severities.

    ``suppressions`` is a list of ``{"rule_key", "action", "value"}``. ``action``
    is ``"disable"`` (remove the finding) or ``"override_severity"`` (set
    ``value`` as the new severity). Matching is by rule id.
    """
    if not suppressions:
        return findings
    disabled = {s["rule_key"] for s in suppressions if s.get("action") == "disable"}
    overrides = {s["rule_key"]: s.get("value") for s in suppressions
                 if s.get("action") == "override_severity" and s.get("value")}
    out: List[Finding] = []
    for f in findings:
        if f.rule_id in disabled:
            continue
        if f.rule_id in overrides:
            f.severity = overrides[f.rule_id]
        out.append(f)
    return out


_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _finding_sort_key(f: Finding):
    return (_SEV_ORDER.get(f.severity, 9), -f.affected_count, f.rule_id)


def _firmware_findings(firmware_intel: Dict[str, Any]) -> List[Finding]:
    """Convert matched PSIRT advisories and EoL status into findings."""
    out: List[Finding] = []
    advisories = firmware_intel.get("matched_advisories", [])
    for adv in advisories:
        cvss = adv.get("cvss", 0.0)
        if cvss >= 9.0:
            sev = "Critical"
        elif cvss >= 7.0:
            sev = "High"
        elif cvss >= 4.0:
            sev = "Medium"
        else:
            sev = "Low"
        cves = ", ".join(adv.get("cve", [])) or adv.get("advisory_id", "advisory")
        out.append(Finding(
            rule_id=f"FW-PSIRT-{adv.get('advisory_id', 'NA')}",
            title=f"Firmware affected by {cves}",
            severity=sev, category="Firmware Security",
            description=adv.get("summary", "The running firmware matches a published advisory."),
            evidence=[
                f"Running firmware: {firmware_intel.get('firmware')}",
                f"Advisory: {adv.get('advisory_id')} (CVSS {cvss})",
            ],
            business_impact="A known firmware vulnerability materially raises breach likelihood and may carry regulatory weight once a CVE is public.",
            technical_impact=adv.get("summary", ""),
            remediation=adv.get("upgrade_recommendation", "Upgrade to a fixed firmware release."),
            verification=["Confirm the firmware version after upgrade", "Re-run analysis and confirm the advisory no longer matches"],
            risk_reduction="High" if sev in ("Critical", "High") else "Medium",
            references=[adv.get("url", "")] if adv.get("url") else [],
            compliance={},
            likelihood=4 if sev in ("Critical", "High") else 3,
            impact=5 if sev == "Critical" else 4,
            exposure=4,
            affected_count=1,
        ))

    eol = firmware_intel.get("eol", {})
    if str(eol.get("status", "")).lower() in ("eol", "end-of-life", "ended"):
        out.append(Finding(
            rule_id="FW-PSIRT-EOL",
            title="Device platform is past end-of-life",
            severity="High", category="Firmware Security",
            description="The hardware platform is reported past its end-of-life date and will not receive security fixes.",
            evidence=[f"Series: {eol.get('series')}", f"Status: {eol.get('status')}", str(eol.get('note', ''))],
            business_impact="Unsupported hardware cannot be patched against future vulnerabilities, creating unbounded long-term risk.",
            technical_impact="No further firmware security updates will be issued for this platform.",
            remediation="Plan migration to a currently supported SonicWall platform.",
            verification=["Confirm replacement hardware is under active support"],
            risk_reduction="High", references=[], compliance={},
            likelihood=3, impact=4, exposure=3, affected_count=1))
    return out
