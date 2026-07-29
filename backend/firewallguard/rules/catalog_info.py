"""Informational inventory checks.

These mirror the competitor's ``-I`` data-point checks: they do not represent
risks, they record facts about the device (counts, modes, coverage) so the
report carries a complete inventory and the operator can sanity-check the
environment. All are Info severity and contribute zero score penalty.

Each returns a single Finding (or none if the relevant section is absent).
"""

from __future__ import annotations

from typing import Any, Dict, List

from .engine import Finding, Snapshot, registry


def _info(code: str, title: str, category: str, value: str,
          description: str) -> List[Finding]:
    return [Finding(
        rule_id=code, title=title, severity="Info", category=category,
        description=description, evidence=[f"{title}: {value}"],
        business_impact="", technical_impact="",
        remediation="No action required; informational only.",
        verification=[], risk_reduction="n/a",
        likelihood=1, impact=1, exposure=1, affected_count=1,
        object_type="Inventory", object_name=value[:60])]


@registry.rule(id="ACR-I001", title="Access Rules Total", severity="Info",
               category="Access Rules")
def i_acr_total(snap: Snapshot) -> List[Finding]:
    rules = snap.get("access_rules", [])
    if not rules:
        return []
    enabled = sum(1 for r in rules if r.get("enabled"))
    wan_allow = sum(1 for r in rules if r.get("src_zone") == "WAN" and r.get("action") == "Allow")
    return _info("ACR-I001", "Access Rules Total", "Access Rules",
                 f"{len(rules)} total, {enabled} enabled, {wan_allow} WAN allow",
                 "Count of access rules parsed from the configuration.")


@registry.rule(id="AOB-I001", title="Address Objects Total", severity="Info",
               category="Address Objects")
def i_aob_total(snap: Snapshot) -> List[Finding]:
    ao = snap.get("address_objects", {})
    objs = ao.get("objects", [])
    if not objs:
        return []
    custom = sum(1 for o in objs if str(o.get("obj_class", "")).lower() == "custom")
    return _info("AOB-I001", "Address Objects Total", "Address Objects",
                 f"{ao.get('count', len(objs))} objects ({custom} custom), {len(ao.get('groups', []))} groups",
                 "Count of address objects and groups.")


@registry.rule(id="SVC-I001", title="Service Objects Total", severity="Info",
               category="Service Objects")
def i_svc_total(snap: Snapshot) -> List[Finding]:
    sv = snap.get("services", {})
    objs = sv.get("objects", [])
    if not objs:
        return []
    return _info("SVC-I001", "Service Objects Total", "Service Objects",
                 f"{len(objs)} objects, {len(sv.get('groups', []))} groups",
                 "Count of service objects and groups.")


@registry.rule(id="NAT-I001", title="NAT Policies Total", severity="Info",
               category="NAT Policies")
def i_nat_total(snap: Snapshot) -> List[Finding]:
    nats = snap.get("nat_policies", [])
    if not nats:
        return []
    enabled = sum(1 for n in nats if n.get("enabled"))
    system = sum(1 for n in nats if n.get("system"))
    return _info("NAT-I001", "NAT Policies Total", "NAT Policies",
                 f"{len(nats)} total, {enabled} enabled, {system} system, {len(nats) - system} custom",
                 "Count of NAT policies.")


@registry.rule(id="IPSEC-I001", title="VPN Total Policies", severity="Info",
               category="IPsec VPN")
def i_vpn_total(snap: Snapshot) -> List[Finding]:
    pols = snap.get("vpn", {}).get("policies", [])
    if not pols:
        return []
    enabled = sum(1 for p in pols if p.get("enabled"))
    s2s = sum(1 for p in pols if str(p.get("type", "")).lower().startswith("site"))
    return _info("IPSEC-I001", "VPN Total Policies", "IPsec VPN",
                 f"{len(pols)} total, {enabled} enabled, {s2s} site-to-site",
                 "Count of IPsec VPN policies.")


@registry.rule(id="USER-I001", title="Local Users Count", severity="Info",
               category="Authentication")
def i_users(snap: Snapshot) -> List[Finding]:
    lu = snap.get("local_users_detail", {})
    if not lu.get("count"):
        return []
    return _info("USER-I001", "Local Users Count", "Authentication",
                 f"{lu['count']} users, {lu.get('mfa_enabled_count', 0)} with MFA",
                 "Count of local user accounts and MFA coverage.")


@registry.rule(id="IPS-I001", title="IPS License / Signatures", severity="Info",
               category="Security Services")
def i_ips(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    if "ips_enabled" not in ss:
        return []
    return _info("IPS-I001", "IPS License / Signatures", "Security Services",
                 f"IPS {'enabled' if ss.get('ips_enabled') else 'disabled'}, expires {ss.get('ips_expires', 'n/a')}",
                 "Intrusion Prevention license/state.")


@registry.rule(id="GAV-I001", title="GAV License / Signatures", severity="Info",
               category="Security Services")
def i_gav(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    if "gav_enabled" not in ss:
        return []
    return _info("GAV-I001", "GAV License / Signatures", "Security Services",
                 f"GAV {'enabled' if ss.get('gav_enabled') else 'disabled'}, expires {ss.get('gav_expires', 'n/a')}",
                 "Gateway Anti-Virus license/state.")


@registry.rule(id="SYSTEM-I001", title="Firmware & Platform", severity="Info",
               category="System")
def i_system(snap: Snapshot) -> List[Finding]:
    sysd = snap.get("system", {})
    if not sysd.get("model"):
        return []
    return _info("SYSTEM-I001", "Firmware & Platform", "System",
                 f"{sysd.get('model')} / {sysd.get('firmware')} / HA {sysd.get('ha_mode', 'n/a')}",
                 "Device model, firmware and HA mode.")


@registry.rule(id="WLAN-I001", title="Wireless SSID Count", severity="Info",
               category="Wireless")
def i_wlan(snap: Snapshot) -> List[Finding]:
    w = snap.get("wlan", {})
    if not w.get("present"):
        return []
    return _info("WLAN-I001", "Wireless SSID Count", "Wireless",
                 f"{w.get('interface_count', 0)} wireless interfaces, {len(w.get('ssids', []))} SSIDs",
                 "Wireless interface and SSID count.")
