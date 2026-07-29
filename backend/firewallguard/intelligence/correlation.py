"""Correlation engine.

Turns an unordered list of findings into prioritised *attack paths*.  Each
pattern is a precondition set over finding rule-ids (plus firmware intel); when
the preconditions are met, the engine emits a named multi-stage path with a
kill-chain narrative and a combined severity.  This is deterministic
correlation logic; an LLM layer can sit on top to narrate, but the chaining
itself is rule-based so results are explainable and reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from ..rules.engine import Finding


@dataclass
class AttackPath:
    path_id: str
    name: str
    severity: str
    stages: List[Dict[str, str]]
    narrative: str
    contributing_rules: List[str]
    recommended_priority: str

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _present(ids: Set[str], *needed: str) -> bool:
    return all(n in ids for n in needed)


def correlate(findings: List[Finding], firmware_intel: Dict[str, Any]) -> List[AttackPath]:
    by_id: Dict[str, Finding] = {f.rule_id: f for f in findings}
    ids = set(by_id)
    fw_vuln = firmware_intel.get("advisory_count", 0) > 0
    fw_max = firmware_intel.get("max_cvss", 0.0)
    paths: List[AttackPath] = []

    # 1: Internet -> management-plane takeover
    if "FW-MGT-001" in ids:
        stages = [{"stage": "Discovery",
                   "detail": "Attacker scans the WAN IP and finds the firewall management service exposed (FW-MGT-001)."}]
        contributing = ["FW-MGT-001"]
        if fw_vuln:
            stages.append({"stage": "Exploitation",
                           "detail": f"A firmware advisory (max CVSS {fw_max}) is applicable to the running build, providing a remote exploitation primitive."})
            contributing.append("FIRMWARE")
        if "FW-MGT-004" in ids or "FW-MGT-003" in ids:
            stages.append({"stage": "Credential Access",
                           "detail": "Weak password policy and/or absent MFA on the admin account lowers the bar for authentication bypass or brute force (FW-MGT-003/FW-MGT-004)."})
            contributing += [r for r in ("FW-MGT-003", "FW-MGT-004") if r in ids]
        stages.append({"stage": "Impact",
                       "detail": "Administrative control of the firewall enables rule changes, traffic interception, and pivoting into protected zones."})
        sev = "Critical"
        paths.append(AttackPath(
            "AP-001", "Internet-facing management-plane compromise", sev, stages,
            "An internet-based attacker discovers the exposed management interface, "
            + ("leverages an applicable firmware vulnerability, " if fw_vuln else "")
            + ("exploits weak or single-factor authentication, " if ("FW-MGT-003" in ids or "FW-MGT-004" in ids) else "")
            + "and gains administrative control of the firewall.",
            contributing, "Immediate"))

    # 2: SSL VPN -> management-plane
    if "FW-SSL-001" in ids and "FW-SSL-003" in ids:
        stages = [
            {"stage": "Initial Access", "detail": "Attacker targets the WAN-exposed SSL VPN portal with credential stuffing or post-disclosure exploitation (FW-SSL-001)."},
            {"stage": "Privilege Path", "detail": "Web management is reachable over SSL VPN, so a valid VPN session reaches the firewall admin UI (FW-SSL-003)."},
        ]
        contributing = ["FW-SSL-001", "FW-SSL-003"]
        if "FW-MGT-004" in ids:
            stages.append({"stage": "Credential Access", "detail": "No admin MFA means a single captured/guessed credential completes the takeover (FW-MGT-004)."})
            contributing.append("FW-MGT-004")
        stages.append({"stage": "Impact", "detail": "Administrative access to the firewall from a remote-access foothold."})
        paths.append(AttackPath(
            "AP-002", "SSL VPN foothold escalating to firewall management", "High", stages,
            "An attacker compromises an SSL VPN credential, reaches the firewall web "
            "management interface that is exposed over the VPN, and escalates to "
            "administrative control"
            + (" because the admin account lacks MFA." if "FW-MGT-004" in ids else "."),
            contributing, "High"))

    # 3: Encrypted-traffic blind spot
    if "FW-SVC-001" in ids and any(r in ids for r in ("FW-SVC-003", "FW-SVC-004", "FW-SVC-005", "FW-SVC-006")):
        contributing = [r for r in ("FW-SVC-001", "FW-SVC-003", "FW-SVC-004", "FW-SVC-005", "FW-SVC-006") if r in ids]
        stages = [
            {"stage": "Delivery", "detail": "Malware is delivered inside a TLS session; with DPI-SSL off the firewall cannot inspect the payload (FW-SVC-001)."},
            {"stage": "Evasion", "detail": "Reduced or disabled inline services widen the gap for the payload to reach the host uninspected."},
            {"stage": "Command & Control", "detail": "Encrypted C2 leaves the network unseen, enabling persistence and data exfiltration."},
        ]
        paths.append(AttackPath(
            "AP-003", "Encrypted-traffic inspection blind spot", "High", stages,
            "Because encrypted traffic is not inspected and one or more inline "
            "engines are reduced, malware delivery and command-and-control over TLS "
            "pass through the firewall undetected.",
            contributing, "High"))

    # 4: Flat-zone lateral movement
    if any(r in ids for r in ("FW-ACL-001", "FW-ACL-002")) and "FW-SVC-008" in ids:
        contributing = [r for r in ("FW-ACL-001", "FW-ACL-002", "FW-SVC-008") if r in ids]
        stages = [
            {"stage": "Foothold", "detail": "Attacker compromises a host in a weakly segmented zone."},
            {"stage": "Lateral Movement", "detail": "Overly permissive inter-zone rules allow free movement across segments (FW-ACL-001/002)."},
            {"stage": "Evasion", "detail": "Zones lacking inline inspection let lateral traffic move without detection (FW-SVC-008)."},
        ]
        paths.append(AttackPath(
            "AP-004", "Flat-network lateral movement", "High", stages,
            "Broad inter-zone allow rules combined with zones that do not enforce "
            "inspection let an attacker move laterally from an initial foothold to "
            "high-value segments with little resistance or visibility.",
            contributing, "High"))

    paths.sort(key=lambda p: _SEV_RANK.get(p.severity, 0), reverse=True)
    return paths
