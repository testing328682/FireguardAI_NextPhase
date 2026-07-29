"""Configuration drift detection.

Compares a current snapshot against a previously stored snapshot and emits a
list of ``DriftAlert`` records describing what changed. The comparison covers
the dimensions named in the product specification: access rules, NAT policies,
VPN policies, security services, firmware, administrator accounts and
interfaces.

Drift is computed purely from the structured snapshot dictionaries produced by
``parse_tsr``; no device access is required. Each alert carries a severity so
that the dashboard can surface critical regressions (for example a security
service being turned off) ahead of routine additions.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

DRIFT_SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


@dataclass
class DriftAlert:
    category: str
    change_type: str          # added | removed | changed | upgraded | downgraded
    severity: str
    title: str
    detail: str
    previous_state: Optional[str] = None
    current_state: Optional[str] = None
    identifier: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Keying helpers
# ---------------------------------------------------------------------------

def _rule_key(r: Dict[str, Any]) -> str:
    return (f"{r.get('src_zone')}->{r.get('dst_zone')}|{r.get('service')}|"
            f"{r.get('src')}->{r.get('dst')}|{r.get('name')}")


def _rule_repr(r: Dict[str, Any]) -> str:
    state = "enabled" if r.get("enabled") else "disabled"
    return (f"{r.get('action')} {r.get('src_zone')}->{r.get('dst_zone')} "
            f"{r.get('service')} ({r.get('src')} -> {r.get('dst')}) [{state}]")


def _nat_key(n: Dict[str, Any]) -> str:
    return (f"{n.get('orig_src')}|{n.get('orig_dst')}|{n.get('orig_service')}|"
            f"{n.get('trans_src')}|{n.get('trans_dst')}")


def _vpn_key(v: Dict[str, Any]) -> str:
    return str(v.get("name") or v.get("sa"))


# ---------------------------------------------------------------------------
# Per-dimension comparisons
# ---------------------------------------------------------------------------

def _diff_collection(prev, curr, key_fn, repr_fn, category,
                     add_sev, remove_sev) -> List[DriftAlert]:
    alerts: List[DriftAlert] = []
    prev_map = {key_fn(x): x for x in prev}
    curr_map = {key_fn(x): x for x in curr}
    for k, item in curr_map.items():
        if k not in prev_map:
            alerts.append(DriftAlert(
                category=category, change_type="added", severity=add_sev,
                title=f"New {category.lower()} added", detail=repr_fn(item),
                current_state=repr_fn(item), identifier=k))
    for k, item in prev_map.items():
        if k not in curr_map:
            alerts.append(DriftAlert(
                category=category, change_type="removed", severity=remove_sev,
                title=f"{category} removed", detail=repr_fn(item),
                previous_state=repr_fn(item), identifier=k))
    # Same key, different enabled-state.
    for k in set(prev_map) & set(curr_map):
        p, c = prev_map[k], curr_map[k]
        if p.get("enabled") != c.get("enabled"):
            now = "enabled" if c.get("enabled") else "disabled"
            was = "enabled" if p.get("enabled") else "disabled"
            sev = "Medium" if c.get("enabled") else "Low"
            alerts.append(DriftAlert(
                category=category, change_type="changed", severity=sev,
                title=f"{category} state changed",
                detail=f"{repr_fn(c)} was {was}, now {now}",
                previous_state=was, current_state=now, identifier=k))
    return alerts


def _diff_security_services(prev: Dict[str, Any],
                            curr: Dict[str, Any]) -> List[DriftAlert]:
    alerts: List[DriftAlert] = []
    # (field, friendly name, severity-when-disabled)
    toggles = [
        ("ips_enabled", "Intrusion Prevention (IPS)", "Critical"),
        ("gav_enabled", "Gateway Anti-Virus", "Critical"),
        ("anti_spyware_enabled", "Anti-Spyware", "High"),
        ("content_filter_enabled", "Content Filtering", "Medium"),
        ("dpi_ssl_client_enabled", "DPI-SSL Client Inspection", "High"),
    ]
    for field_name, friendly, sev in toggles:
        was = prev.get(field_name)
        now = curr.get(field_name)
        if was == now:
            continue
        if was and not now:
            alerts.append(DriftAlert(
                category="Security Services", change_type="changed",
                severity=sev, title=f"{friendly} was disabled",
                detail=f"{friendly} changed from Enabled to Disabled.",
                previous_state="Enabled", current_state="Disabled",
                identifier=field_name))
        elif now and not was:
            alerts.append(DriftAlert(
                category="Security Services", change_type="changed",
                severity="Info", title=f"{friendly} was enabled",
                detail=f"{friendly} changed from Disabled to Enabled.",
                previous_state="Disabled", current_state="Enabled",
                identifier=field_name))
    if prev.get("profile") != curr.get("profile"):
        alerts.append(DriftAlert(
            category="Security Services", change_type="changed", severity="Low",
            title="Security services profile changed",
            detail=f"Profile changed from {prev.get('profile')} to {curr.get('profile')}.",
            previous_state=str(prev.get("profile")),
            current_state=str(curr.get("profile")), identifier="profile"))
    return alerts


def _diff_firmware(prev: Dict[str, Any], curr: Dict[str, Any]) -> List[DriftAlert]:
    pf, cf = prev.get("firmware"), curr.get("firmware")
    if not pf or not cf or pf == cf:
        return []
    return [DriftAlert(
        category="Firmware", change_type="changed", severity="Info",
        title="Firmware version changed",
        detail=f"Firmware changed from {pf} to {cf}. Re-evaluate against PSIRT intelligence.",
        previous_state=pf, current_state=cf, identifier="firmware")]


def _diff_admins(prev: Dict[str, Any], curr: Dict[str, Any]) -> List[DriftAlert]:
    alerts: List[DriftAlert] = []
    fields = [
        ("admin_otp", "Administrator one-time password / MFA"),
        ("min_password_length", "Minimum password length"),
        ("password_complexity_level", "Password complexity level"),
        ("http_port", "HTTP management port"),
        ("https_port", "HTTPS management port"),
        ("admin_name", "Primary administrator account name"),
    ]
    for f_name, friendly in fields:
        p, c = prev.get(f_name), curr.get(f_name)
        if p == c:
            continue
        # Heuristic: weakening MFA or shrinking password policy is higher risk.
        sev = "Low"
        if f_name == "admin_otp" and str(p).lower() == "enabled" and str(c).lower() != "enabled":
            sev = "High"
        alerts.append(DriftAlert(
            category="Administration", change_type="changed", severity=sev,
            title=f"{friendly} changed",
            detail=f"{friendly} changed from {p} to {c}.",
            previous_state=str(p), current_state=str(c), identifier=f_name))
    return alerts


def _diff_interfaces(prev: List[Dict[str, Any]],
                     curr: List[Dict[str, Any]]) -> List[DriftAlert]:
    alerts: List[DriftAlert] = []
    prev_map = {i.get("name"): i for i in prev}
    curr_map = {i.get("name"): i for i in curr}
    for name in curr_map.keys() - prev_map.keys():
        i = curr_map[name]
        alerts.append(DriftAlert(
            category="Interfaces", change_type="added", severity="Low",
            title=f"Interface {name} added",
            detail=f"Interface {name} ({i.get('zone')}, {i.get('ip')}) is new.",
            current_state=f"{i.get('zone')} {i.get('ip')}", identifier=name))
    for name in prev_map.keys() - curr_map.keys():
        alerts.append(DriftAlert(
            category="Interfaces", change_type="removed", severity="Low",
            title=f"Interface {name} removed",
            detail=f"Interface {name} is no longer present.", identifier=name))
    for name in prev_map.keys() & curr_map.keys():
        p, c = prev_map[name], curr_map[name]
        if p.get("ip") != c.get("ip") or p.get("zone") != c.get("zone"):
            alerts.append(DriftAlert(
                category="Interfaces", change_type="changed", severity="Medium",
                title=f"Interface {name} re-addressed or re-zoned",
                detail=f"{name}: {p.get('zone')}/{p.get('ip')} -> {c.get('zone')}/{c.get('ip')}.",
                previous_state=f"{p.get('zone')} {p.get('ip')}",
                current_state=f"{c.get('zone')} {c.get('ip')}", identifier=name))
    return alerts


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def detect_drift(previous: Dict[str, Any],
                 current: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two snapshots and return drift alerts plus a summary."""
    alerts: List[DriftAlert] = []

    alerts += _diff_collection(
        previous.get("access_rules", []), current.get("access_rules", []),
        _rule_key, _rule_repr, "Access Rule", add_sev="Medium", remove_sev="Low")
    alerts += _diff_collection(
        previous.get("nat_policies", []), current.get("nat_policies", []),
        _nat_key, lambda n: f"{n.get('name') or n.get('orig_src')} -> {n.get('trans_src')}",
        "NAT Policy", add_sev="Low", remove_sev="Low")
    alerts += _diff_collection(
        previous.get("vpn", {}).get("policies", []),
        current.get("vpn", {}).get("policies", []),
        _vpn_key, lambda v: f"{v.get('name')} ({v.get('type')})",
        "VPN Policy", add_sev="High", remove_sev="Medium")

    alerts += _diff_security_services(
        previous.get("security_services", {}), current.get("security_services", {}))
    alerts += _diff_firmware(previous.get("system", {}), current.get("system", {}))
    alerts += _diff_admins(
        previous.get("administration", {}), current.get("administration", {}))
    alerts += _diff_interfaces(
        previous.get("interfaces", []), current.get("interfaces", []))

    order = {s: i for i, s in enumerate(DRIFT_SEVERITIES)}
    alerts.sort(key=lambda a: order.get(a.severity, 99))

    counts: Dict[str, int] = {s: 0 for s in DRIFT_SEVERITIES}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1

    return {
        "previous_source": previous.get("meta", {}).get("source_name"),
        "current_source": current.get("meta", {}).get("source_name"),
        "alert_count": len(alerts),
        "severity_counts": counts,
        "alerts": [a.to_dict() for a in alerts],
    }
