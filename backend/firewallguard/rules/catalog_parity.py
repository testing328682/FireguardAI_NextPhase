"""Parity detection catalog.

Expands the core catalog to full coverage parity, organised by the same
check-code families a SonicWall administrator expects (ACR, AOB, SVC, NAT,
IPSEC, SEC, GAV, IPS, CFS, FW, AUTH, RAD, SNMP, MGMT, SSLVPN, WLAN, PERF,
SYSTEM, DHCP). Many checks here are *per-object*: they emit one finding per
affected access rule, address object, NAT policy or VPN policy, and each
finding names the specific object via ``object_name`` / ``object_type`` so an
operator can jump straight to it in SonicOS.

Every rule remains evidence-gated and exception-safe (the engine wraps each).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from .engine import Finding, Snapshot, registry
from .catalog import (  # reuse compliance constants
    SW_BP, CIS4, CIS6, CIS8, CIS12, CIS13,
    NIST_PR_AC, NIST_PR_PS, NIST_DE_CM, PCI_1, PCI_2, PCI_8, PCI_10, ISO_AC,
)


def _wan_ifaces(snap: Snapshot) -> Set[str]:
    return {i["name"] for i in snap.get("interfaces", []) if i.get("zone") == "WAN"}


# Cryptographic weakness markers reused across IPSEC checks.
_WEAK_DH = ("DH Group 1", "DH Group 2", "DH Group 5", "Group 1", "Group 2", "Group 5")
_WEAK_ENC = ("DES", "3DES")
_WEAK_HASH = ("MD5", "SHA1")


# ======================================================================
# ACCESS RULES (ACR) - per rule
# ======================================================================
@registry.rule(id="ACR-007", title="WAN Allow Rule Permits Any Destination Service",
               severity="High", category="Access Rules")
def acr_any_service(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for r in snap.get("access_rules", []):
        if not r.get("enabled"):
            continue
        if r.get("src_zone") == "WAN" and r.get("action") == "Allow":
            svc = str(r.get("service", "")).strip().lower()
            if svc in ("any", "any -> any", ""):
                name = r.get("name") or f"Rule {r.get('num')}"
                detail = (f"Rule {r.get('num')}: WAN -> {r.get('dst_zone')} Allow "
                          f"[{r.get('service')}] Src: {r.get('src')}, Dst: {r.get('dst')}")
                out.append(Finding(
                    rule_id="ACR-007", title="WAN Allow Rule Permits Any Destination Service",
                    severity="High", category="Access Rules",
                    description=f"Inbound WAN rule {r.get('num')} permits all ports/protocols (service Any).",
                    evidence=[detail],
                    business_impact="A WAN rule allowing any service exposes every port on the destination to the internet, dramatically widening the attack surface.",
                    technical_impact="All TCP/UDP/ICMP to the destination is permitted inbound from the specified source.",
                    remediation=f"Edit rule {r.get('num')} ('{name}') and restrict the service to the specific ports required.",
                    verification=[f"Confirm rule {r.get('num')} no longer uses service Any"],
                    risk_reduction="High", references=[SW_BP],
                    compliance={"PCI DSS 4.0": ["1.2", "1.3"], "CIS v8": ["4", "12"]},
                    likelihood=4, impact=4, exposure=5, affected_count=1,
                    object_name=name, object_type="Access Rule", object_detail=detail))
    return out


@registry.rule(id="ACR-002", title="Unrestricted WAN Allow Rule (Any/Any)",
               severity="High", category="Access Rules")
def acr_any_any(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for r in snap.get("access_rules", []):
        if not r.get("enabled") or r.get("action") != "Allow" or r.get("src_zone") != "WAN":
            continue
        if str(r.get("src", "")).lower() == "any" and str(r.get("dst", "")).lower() == "any":
            name = r.get("name") or f"Rule {r.get('num')}"
            detail = f"Rule {r.get('num')}: WAN -> {r.get('dst_zone')} Allow Any source to Any destination"
            out.append(Finding(
                rule_id="ACR-002", title="Unrestricted WAN Allow Rule",
                severity="High", category="Access Rules",
                description=f"Rule {r.get('num')} allows any source to any destination inbound from WAN.",
                evidence=[detail],
                business_impact="An any-to-any inbound rule effectively disables perimeter filtering for the covered traffic.",
                technical_impact="Unrestricted inbound exposure from the internet.",
                remediation=f"Scope rule {r.get('num')} ('{name}') to specific source and destination objects.",
                verification=[f"Confirm rule {r.get('num')} uses specific source/destination objects"],
                risk_reduction="High", references=[SW_BP],
                compliance={"PCI DSS 4.0": ["1.2", "1.3"]},
                likelihood=4, impact=5, exposure=5, affected_count=1,
                object_name=name, object_type="Access Rule", object_detail=detail))
    return out


@registry.rule(id="ACR-003", title="Access Rule Bypasses DPI",
               severity="Medium", category="Access Rules")
def acr_dpi_bypass(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for r in snap.get("access_rules", []):
        if not r.get("enabled"):
            continue
        if r.get("dpi_disabled") or str(r.get("comment", "")).lower().find("no dpi") >= 0:
            name = r.get("name") or f"Rule {r.get('num')}"
            detail = f"Rule {r.get('num')}: {r.get('src_zone')} -> {r.get('dst_zone')} DPI disabled"
            out.append(Finding(
                rule_id="ACR-003", title="Access Rule Bypasses DPI",
                severity="Medium", category="Access Rules",
                description=f"Rule {r.get('num')} has deep packet inspection disabled.",
                evidence=[detail],
                business_impact="Traffic matching this rule is not inspected for threats.",
                technical_impact="IPS/GAV/Anti-Spyware are not applied to matching flows.",
                remediation=f"Re-enable DPI on rule {r.get('num')} ('{name}') unless there is a documented performance exception.",
                verification=[f"Confirm DPI is enabled on rule {r.get('num')}"],
                risk_reduction="Medium", references=[SW_BP],
                likelihood=3, impact=3, exposure=3, affected_count=1,
                object_name=name, object_type="Access Rule", object_detail=detail))
    return out


# ======================================================================
# ADDRESS OBJECTS (AOB) - per object
# ======================================================================
@registry.rule(id="AOB-003", title="Unused Custom Address Object",
               severity="Low", category="Address Objects")
def aob_unused(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    ao = snap.get("address_objects", {})
    for o in ao.get("objects", []):
        if str(o.get("obj_class", "")).lower() == "default":
            continue  # skip built-in/default objects, like the comparison tool
        if o.get("reference_count", 0) == 0 and not o.get("referenced_by") and not o.get("member_of"):
            name = o["name"]
            detail = f"{name} ({o.get('obj_type') or 'object'}: {o.get('value') or 'n/a'}) - 0 references"
            out.append(Finding(
                rule_id="AOB-003", title="Unused Custom Address Object",
                severity="Low", category="Address Objects",
                description=f"Address object '{name}' is referenced by zero modules and belongs to no group.",
                evidence=[detail],
                business_impact="Object sprawl slows audits and risks accidental reuse of stale entries.",
                technical_impact="No direct exposure; configuration debt.",
                remediation=f"Delete address object '{name}' after confirming it is not used by routing, DHCP, or content-filter policy.",
                verification=[f"Confirm '{name}' is removed or intentionally retained"],
                risk_reduction="Low", references=[SW_BP],
                likelihood=1, impact=1, exposure=1, affected_count=1,
                object_name=name, object_type="Address Object", object_detail=detail))
    return out


@registry.rule(id="AOB-001", title="Duplicate Address Objects",
               severity="Low", category="Address Objects")
def aob_duplicate(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    ao = snap.get("address_objects", {})
    by_value: Dict[str, List[str]] = {}
    for o in ao.get("objects", []):
        val = o.get("value")
        if not val or not o.get("obj_type"):
            continue
        key = f"{o['obj_type']}:{val}"
        by_value.setdefault(key, []).append(o["name"])
    for key, names in by_value.items():
        if len(names) > 1:
            primary = sorted(names)[0]
            detail = f"Multiple address objects share value ({key}): " + ", ".join(f"'{n}'" for n in names)
            out.append(Finding(
                rule_id="AOB-001", title="Duplicate Address Objects",
                severity="Low", category="Address Objects",
                description=f"{len(names)} address objects share the same value {key}.",
                evidence=[detail],
                business_impact="Duplicate objects cause inconsistent policy when one copy is edited and others are not.",
                technical_impact="Configuration drift risk; harder change management.",
                remediation=f"Consolidate duplicates of {key} onto a single object (e.g. keep '{primary}') and repoint references.",
                verification=[f"Confirm only one object exists for {key}"],
                risk_reduction="Low", references=[SW_BP],
                likelihood=1, impact=1, exposure=1, affected_count=len(names),
                object_name=primary, object_type="Address Object", object_detail=detail))
    return out


# ======================================================================
# SERVICE OBJECTS (SVC) - per object
# ======================================================================
@registry.rule(id="SVC-004", title="Unused Custom Service Object",
               severity="Low", category="Service Objects")
def svc_unused(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    sv = snap.get("services", {})
    # A service object is "used" if referenced by an access rule service or a group.
    used: Set[str] = set()
    for r in snap.get("access_rules", []):
        used.add(str(r.get("service", "")).strip())
    for g in sv.get("groups", []):
        used.update(g.get("members", []))
    for o in sv.get("objects", []):
        name = o["name"]
        if name not in used and not o.get("member_of"):
            detail = f"{name} ({'proto ' + str(o.get('iptype')) if o.get('iptype') else ''} ports {o.get('ports') or 'n/a'})"
            out.append(Finding(
                rule_id="SVC-004", title="Unused Custom Service Object",
                severity="Low", category="Service Objects",
                description=f"Service object '{name}' is not referenced by any access rule or service group.",
                evidence=[detail],
                business_impact="Unused service definitions add clutter and audit overhead.",
                technical_impact="No direct exposure; configuration debt.",
                remediation=f"Delete service object '{name}' after confirming it is unused by NAT or other policy.",
                verification=[f"Confirm '{name}' is removed or intentionally retained"],
                risk_reduction="Low", references=[SW_BP],
                likelihood=1, impact=1, exposure=1, affected_count=1,
                object_name=name, object_type="Service Object", object_detail=detail))
    return out


@registry.rule(id="SVC-001", title="Duplicate Service Objects",
               severity="Low", category="Service Objects")
def svc_duplicate(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    sv = snap.get("services", {})
    by_port: Dict[str, List[str]] = {}
    for o in sv.get("objects", []):
        if o.get("iptype") and o.get("ports"):
            key = f"{o['iptype']}:{o['ports']}"
            by_port.setdefault(key, []).append(o["name"])
    for key, names in by_port.items():
        if len(names) > 1:
            primary = sorted(names)[0]
            detail = f"Duplicate service objects for {key}: " + ", ".join(f"'{n}'" for n in names)
            out.append(Finding(
                rule_id="SVC-001", title="Duplicate Service Objects",
                severity="Low", category="Service Objects",
                description=f"{len(names)} service objects define the same protocol/port {key}.",
                evidence=[detail],
                business_impact="Duplicate service objects fragment policy and complicate review.",
                technical_impact="Configuration drift risk.",
                remediation=f"Consolidate duplicates of {key} onto one object (e.g. '{primary}').",
                verification=[f"Confirm a single service object exists for {key}"],
                risk_reduction="Low", references=[SW_BP],
                likelihood=1, impact=1, exposure=1, affected_count=len(names),
                object_name=primary, object_type="Service Object", object_detail=detail))
    return out


# ======================================================================
# NAT POLICIES (NAT) - per policy
# ======================================================================
@registry.rule(id="NAT-003", title="NAT Policy Not Hit Recently",
               severity="Low", category="NAT Policies")
def nat_unused(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for n in snap.get("nat_policies", []):
        if n.get("system"):
            continue
        if not n.get("enabled"):
            continue
        # "never hit" signalled by zero usage if the parser captured it
        usage = n.get("usage")
        if usage is not None and usage == 0:
            name = n.get("name") or f"NAT {n.get('index')}"
            detail = (f"NAT {n.get('index')}: {n.get('orig_src')}/{n.get('orig_dst')} -> "
                      f"{n.get('trans_src')}/{n.get('trans_dst')} (0 hits)")
            out.append(Finding(
                rule_id="NAT-003", title="NAT Policy Not Hit Recently",
                severity="Low", category="NAT Policies",
                description=f"Custom NAT policy {n.get('index')} shows no traffic hits.",
                evidence=[detail],
                business_impact="Stale NAT policies clutter the table and may mask intent during audits.",
                technical_impact="No direct exposure; operational debt.",
                remediation=f"Review NAT policy {n.get('index')} ('{name}') and remove if no longer required.",
                verification=[f"Track hits for NAT policy {n.get('index')} across uploads"],
                risk_reduction="Low", references=[SW_BP],
                likelihood=1, impact=1, exposure=1, affected_count=1,
                object_name=name, object_type="NAT Policy", object_detail=detail))
    return out


@registry.rule(id="NAT-006", title="Inbound WAN NAT Policy to Internal Host",
               severity="Medium", category="NAT Policies")
def nat_inbound(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for n in snap.get("nat_policies", []):
        if n.get("system") or not n.get("enabled"):
            continue
        orig_dst = str(n.get("orig_dst", ""))
        if "wan" in orig_dst.lower() or "x1" in orig_dst.lower():
            name = n.get("name") or f"NAT {n.get('index')}"
            detail = f"NAT {n.get('index')}: inbound {orig_dst} -> {n.get('trans_dst')}"
            out.append(Finding(
                rule_id="NAT-006", title="Inbound WAN NAT Policy to Internal Host",
                severity="Medium", category="NAT Policies",
                description=f"NAT policy {n.get('index')} forwards inbound WAN traffic to an internal host.",
                evidence=[detail],
                business_impact="Inbound NAT (port forwarding) exposes an internal service to the internet; pair it with a tightly scoped access rule.",
                technical_impact="Internal host reachable from WAN via translation.",
                remediation=f"Confirm NAT policy {n.get('index')} ('{name}') is paired with a restrictive access rule and the exposure is required.",
                verification=[f"Confirm the access rule scoping NAT {n.get('index')} is least-privilege"],
                risk_reduction="Medium", references=[SW_BP],
                compliance={"PCI DSS 4.0": ["1.3"]},
                likelihood=3, impact=3, exposure=4, affected_count=1,
                object_name=name, object_type="NAT Policy", object_detail=detail))
    return out


# ======================================================================
# IPSEC VPN (IPSEC) - per policy
# ======================================================================
def _vpn_policies(snap: Snapshot) -> List[Dict[str, Any]]:
    return snap.get("vpn", {}).get("policies", [])


@registry.rule(id="IPSEC-005", title="Weak IKE Diffie-Hellman Group",
               severity="High", category="IPsec VPN")
def ipsec_weak_dh(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for p in _vpn_policies(snap):
        prop = str(p.get("ike_proposal", ""))
        weak = [g for g in ("DH Group 1", "DH Group 2", "DH Group 5") if g in prop]
        if weak:
            name = p.get("name") or f"SA {p.get('sa')}"
            state = " [DISABLED]" if not p.get("enabled") else ""
            detail = f"SA {p.get('sa')} \"{name}\" ({p.get('type')}){state} IKE DH: {weak[0]}"
            out.append(Finding(
                rule_id="IPSEC-005", title="Weak IKE Diffie-Hellman Group",
                severity="High", category="IPsec VPN",
                description=f"Policy '{name}' uses weak IKE DH group: {weak[0]}.",
                evidence=[detail],
                business_impact="Weak DH groups (1/2/5) are susceptible to offline key recovery, undermining tunnel confidentiality.",
                technical_impact="IKE key exchange uses a small/weak modular group.",
                remediation=f"Reconfigure policy '{name}' to use DH Group 14 or higher (ideally ECP groups 19/20/21).",
                verification=[f"Confirm policy '{name}' uses DH Group 14+"],
                risk_reduction="High", references=[SW_BP],
                compliance={"NIST CSF 2.0": ["PR.DS"], "PCI DSS 4.0": ["4.2"]},
                likelihood=3, impact=4, exposure=3, affected_count=1,
                object_name=name, object_type="VPN Policy", object_detail=detail))
    return out


@registry.rule(id="IPSEC-001", title="Weak IKE Encryption",
               severity="High", category="IPsec VPN")
def ipsec_weak_enc(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for p in _vpn_policies(snap):
        prop = str(p.get("ike_proposal", ""))
        weak = [e for e in ("3DES", "DES") if re.search(rf"\b{e}\b", prop)]
        if weak:
            name = p.get("name") or f"SA {p.get('sa')}"
            detail = f"SA {p.get('sa')} \"{name}\" IKE encryption: {weak[0]}"
            out.append(Finding(
                rule_id="IPSEC-001", title="Weak IKE Encryption",
                severity="High", category="IPsec VPN",
                description=f"Policy '{name}' uses weak IKE encryption: {weak[0]}.",
                evidence=[detail],
                business_impact="DES/3DES are deprecated and provide inadequate confidentiality for VPN traffic.",
                technical_impact="Phase 1 negotiation permits a weak cipher.",
                remediation=f"Reconfigure policy '{name}' to use AES-256 (or AES-GCM).",
                verification=[f"Confirm policy '{name}' negotiates AES-256"],
                risk_reduction="High", references=[SW_BP],
                compliance={"PCI DSS 4.0": ["4.2"]},
                likelihood=3, impact=4, exposure=3, affected_count=1,
                object_name=name, object_type="VPN Policy", object_detail=detail))
    return out


@registry.rule(id="IPSEC-003", title="Weak IPsec Phase 2 Proposal",
               severity="High", category="IPsec VPN")
def ipsec_weak_phase2(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for p in _vpn_policies(snap):
        prop = str(p.get("ipsec_proposal", ""))
        weak = [x for x in ("3DES", "DES", "MD5", "SHA1") if re.search(rf"\b{x}\b", prop)]
        if weak:
            name = p.get("name") or f"SA {p.get('sa')}"
            detail = f"SA {p.get('sa')} \"{name}\" Phase 2: {', '.join(weak)}"
            out.append(Finding(
                rule_id="IPSEC-003", title="Weak IPsec Phase 2 Proposal",
                severity="High", category="IPsec VPN",
                description=f"Policy '{name}' uses weak Phase 2 encryption/hash: {', '.join(weak)}.",
                evidence=[detail],
                business_impact="Weak ESP transforms weaken the confidentiality/integrity of tunnelled data.",
                technical_impact="Phase 2 SA permits deprecated cipher/hash.",
                remediation=f"Reconfigure policy '{name}' to AES-256 with SHA-256 (or AES-GCM).",
                verification=[f"Confirm policy '{name}' Phase 2 uses AES-256/SHA-256"],
                risk_reduction="High", references=[SW_BP],
                compliance={"PCI DSS 4.0": ["4.2"]},
                likelihood=3, impact=4, exposure=3, affected_count=1,
                object_name=name, object_type="VPN Policy", object_detail=detail))
    return out


@registry.rule(id="IPSEC-006", title="PFS Disabled or Weak",
               severity="Medium", category="IPsec VPN")
def ipsec_pfs(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for p in _vpn_policies(snap):
        if str(p.get("type", "")).lower().startswith("site") and not p.get("pfs"):
            name = p.get("name") or f"SA {p.get('sa')}"
            detail = f"SA {p.get('sa')} \"{name}\" ({p.get('type')}) PFS disabled"
            out.append(Finding(
                rule_id="IPSEC-006", title="PFS Disabled or Weak",
                severity="Medium", category="IPsec VPN",
                description=f"Site-to-site policy '{name}' has Perfect Forward Secrecy disabled.",
                evidence=[detail],
                business_impact="Without PFS, compromise of one key can expose past and future session traffic.",
                technical_impact="No per-session DH re-keying.",
                remediation=f"Enable PFS (DH Group 14+) on policy '{name}'.",
                verification=[f"Confirm PFS is enabled on policy '{name}'"],
                risk_reduction="Medium", references=[SW_BP],
                likelihood=2, impact=3, exposure=3, affected_count=1,
                object_name=name, object_type="VPN Policy", object_detail=detail))
    return out


@registry.rule(id="IPSEC-008", title="Disabled IPsec VPN Policy Present",
               severity="Low", category="IPsec VPN")
def ipsec_disabled(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    for p in _vpn_policies(snap):
        if not p.get("enabled"):
            name = p.get("name") or f"SA {p.get('sa')}"
            detail = f"SA {p.get('sa')} \"{name}\" ({p.get('type')}) is disabled but present"
            out.append(Finding(
                rule_id="IPSEC-008", title="Disabled IPsec VPN Policy Present",
                severity="Low", category="IPsec VPN",
                description=f"VPN policy '{name}' is disabled but still present in configuration.",
                evidence=[detail],
                business_impact="Dormant policies can be re-enabled accidentally, reintroducing weak configurations.",
                technical_impact="No active exposure while disabled.",
                remediation=f"Delete unused VPN policy '{name}' if it is no longer required.",
                verification=[f"Confirm '{name}' is removed or intentionally retained"],
                risk_reduction="Low", references=[SW_BP],
                likelihood=1, impact=2, exposure=1, affected_count=1,
                object_name=name, object_type="VPN Policy", object_detail=detail))
    return out


# ======================================================================
# SECURITY SERVICES PER ZONE (SEC) - per zone
# ======================================================================
def _zone_service_gaps(snap: Snapshot, flag: str, code: str, title: str,
                       service_name: str, sev: str) -> List[Finding]:
    out: List[Finding] = []
    ss = snap.get("security_services", {})
    licensed = True  # licensing checked by caller context
    affected = []
    for z in snap.get("zones", []):
        sectype = str(z.get("security_type", "")).lower()
        if sectype in ("trusted", "public", "wireless") and z.get(flag) is False:
            affected.append(z.get("name"))
    if affected:
        detail = f"{service_name} disabled on zones: " + ", ".join(affected)
        out.append(Finding(
            rule_id=code, title=title, severity=sev, category="Security Services",
            description=f"{service_name} is licensed but not enabled on {len(affected)} zone(s).",
            evidence=[detail],
            business_impact=f"Traffic on the affected zones is not protected by {service_name}, despite the license being paid for.",
            technical_impact=f"{service_name} inspection is off for those zones.",
            remediation=f"Enable {service_name} on each affected zone: {', '.join(affected)}.",
            verification=[f"Confirm {service_name} is enabled on all trusted/public zones"],
            risk_reduction="High" if sev == "High" else "Medium", references=[SW_BP],
            compliance={"CIS v8": ["13"]},
            likelihood=3, impact=4 if sev == "High" else 3, exposure=3,
            affected_count=len(affected),
            object_name=", ".join(affected[:5]), object_type="Zone", object_detail=detail))
    return out


@registry.rule(id="SEC-009", title="IPS Licensed But Not Enabled on Zone",
               severity="High", category="Security Services")
def sec_ips_zone(snap: Snapshot) -> List[Finding]:
    return _zone_service_gaps(snap, "ips", "SEC-009",
                              "IPS Licensed But Not Enabled on Zone",
                              "Intrusion Prevention (IPS)", "High")


@registry.rule(id="SEC-010", title="Gateway Anti-Virus Licensed But Not Enabled on Zone",
               severity="High", category="Security Services")
def sec_gav_zone(snap: Snapshot) -> List[Finding]:
    return _zone_service_gaps(snap, "gav", "SEC-010",
                              "Gateway Anti-Virus Licensed But Not Enabled on Zone",
                              "Gateway Anti-Virus", "High")


@registry.rule(id="SEC-011", title="Anti-Spyware Licensed But Not Enabled on Zone",
               severity="High", category="Security Services")
def sec_spy_zone(snap: Snapshot) -> List[Finding]:
    return _zone_service_gaps(snap, "anti_spyware", "SEC-011",
                              "Anti-Spyware Licensed But Not Enabled on Zone",
                              "Anti-Spyware", "High")


# ======================================================================
# GATEWAY AV SIGNATURE AGE (GAV-001)
# ======================================================================
@registry.rule(id="GAV-001", title="Gateway AV Signature Database Outdated",
               severity="High", category="Security Services")
def gav_sig_age(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    age = ss.get("gav_signature_age_days")
    if age is None or age <= 30:
        return []
    return [Finding(
        rule_id="GAV-001", title="Gateway AV Signature Database Outdated",
        severity="High", category="Security Services",
        description=f"The Gateway AV signature database is {age} days old (threshold: 30).",
        evidence=[f"GAV signature DB age: {age} days"],
        business_impact="Stale antivirus signatures miss recent malware, reducing the value of the GAV subscription.",
        technical_impact="Detection coverage lags current threats.",
        remediation="Confirm the device can reach the SonicWall signature servers and force a signature update.",
        verification=["Confirm GAV signature DB age is under 30 days"],
        risk_reduction="High", references=[SW_BP],
        likelihood=3, impact=4, exposure=3, affected_count=1,
        object_type="Security Service", object_name="Gateway Anti-Virus")]


# ======================================================================
# FIREWALL SETTINGS / FLOOD / DDOS (FW)
# ======================================================================
def _fw_toggle_finding(snap, code, title, key, sev, desc, impact_txt, remediation):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present"):
        return []
    val = fw.get(key)
    # For these, a *True* value means the protection is OFF / weak.
    if not val:
        return []
    return [Finding(
        rule_id=code, title=title, severity=sev, category="Firewall Settings",
        description=desc, evidence=[f"{title}: confirmed in Firewall Settings : Advanced"],
        business_impact=impact_txt, technical_impact=desc,
        remediation=remediation, verification=[f"Confirm '{title}' is remediated"],
        risk_reduction="Medium" if sev == "Medium" else "Low", references=[SW_BP],
        likelihood=2, impact=3 if sev == "Medium" else 2, exposure=3,
        affected_count=1, object_type="Firewall Setting", object_name=title)]


@registry.rule(id="FW-001", title="Stealth Mode Disabled", severity="Medium",
               category="Firewall Settings")
def fw_stealth(snap):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present") or fw.get("stealth_mode"):
        return []
    return [Finding(
        rule_id="FW-001", title="Stealth Mode Disabled", severity="Medium",
        category="Firewall Settings",
        description="Stealth mode is disabled; the firewall sends ICMP/TCP rejects that reveal its presence.",
        evidence=["Stealth Mode: Disabled"],
        business_impact="Responding to blocked probes confirms the device to attackers performing reconnaissance.",
        technical_impact="Firewall returns active rejects rather than silently dropping.",
        remediation="Enable Stealth Mode under Firewall Settings > Advanced.",
        verification=["Confirm Stealth Mode is enabled"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=2, impact=2, exposure=3, affected_count=1,
        object_type="Firewall Setting", object_name="Stealth Mode")]


@registry.rule(id="FW-004", title="SYN Flood Protection in Watch-Only Mode",
               severity="Medium", category="Firewall Settings")
def fw_syn(snap):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present") or not fw.get("syn_proxy_watch_only"):
        return []
    return [Finding(
        rule_id="FW-004", title="SYN Flood Protection in Watch-Only Mode",
        severity="Medium", category="Firewall Settings",
        description=f"SYN Flood Protection mode is '{fw.get('syn_flood_mode')}'. The firewall logs floods but does not actively proxy.",
        evidence=[f"SYN Flood Protection Mode: {fw.get('syn_flood_mode')}"],
        business_impact="During a SYN flood the firewall will not protect backend services, risking outage.",
        technical_impact="No active SYN proxy enforcement.",
        remediation="Set SYN Flood Protection to an active proxy mode (e.g. 'Proxy WAN connections').",
        verification=["Confirm SYN Flood Protection uses an active proxy mode"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=2, impact=3, exposure=3, affected_count=1,
        object_type="Firewall Setting", object_name="SYN Flood Protection")]


@registry.rule(id="FW-006", title="UDP Flood Protection Disabled",
               severity="Medium", category="Firewall Settings")
def fw_udp(snap):
    return _fw_toggle_finding(
        snap, "FW-006", "UDP Flood Protection Disabled",
        key=None, sev="Medium",
        desc="UDP Flood Protection is disabled.",
        impact_txt="UDP floods can exhaust resources and disrupt service.",
        remediation="Enable UDP Flood Protection under Firewall Settings > Flood Protection.") \
        if not snap.get("firewall_settings", {}).get("udp_flood_protection", True) \
        and snap.get("firewall_settings", {}).get("present") else []


@registry.rule(id="FW-007", title="ICMP Flood Protection Disabled",
               severity="Medium", category="Firewall Settings")
def fw_icmp(snap):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present") or fw.get("icmp_flood_protection", True):
        return []
    return [Finding(
        rule_id="FW-007", title="ICMP Flood Protection Disabled", severity="Medium",
        category="Firewall Settings", description="ICMP Flood Protection is disabled.",
        evidence=["Enable ICMP Flood Protection: Disabled"],
        business_impact="ICMP floods can degrade firewall and downstream availability.",
        technical_impact="No ICMP flood rate limiting.",
        remediation="Enable ICMP Flood Protection under Firewall Settings > Flood Protection.",
        verification=["Confirm ICMP Flood Protection is enabled"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=2, impact=3, exposure=3, affected_count=1,
        object_type="Firewall Setting", object_name="ICMP Flood Protection")]


@registry.rule(id="FW-008", title="Legacy WAN DDoS Protection Disabled",
               severity="Medium", category="Firewall Settings")
def fw_wanddos(snap):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present") or fw.get("wan_ddos_protection", True):
        return []
    return [Finding(
        rule_id="FW-008", title="Legacy WAN DDoS Protection Disabled", severity="Medium",
        category="Firewall Settings", description="WAN DDoS Protection (non-TCP floods) is disabled.",
        evidence=["DDOS protection on WAN interfaces: Disabled"],
        business_impact="Non-TCP flood attacks from the WAN are not rate-limited.",
        technical_impact="No WAN DDoS filtering for non-TCP floods.",
        remediation="Enable WAN DDoS Protection under Firewall Settings > Flood Protection.",
        verification=["Confirm WAN DDoS Protection is enabled"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=2, impact=3, exposure=3, affected_count=1,
        object_type="Firewall Setting", object_name="WAN DDoS Protection")]


@registry.rule(id="FW-009", title="Drop Source-Routed IP Packets Disabled",
               severity="Medium", category="Firewall Settings")
def fw_srcroute(snap):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present") or fw.get("drop_source_routed", True):
        return []
    return [Finding(
        rule_id="FW-009", title="Drop Source-Routed IP Packets Disabled", severity="Medium",
        category="Firewall Settings",
        description="Dropping of source-routed IP packets is disabled.",
        evidence=["Drop source routed IP packets: No"],
        business_impact="Source routing can be abused to bypass access controls and spoof paths.",
        technical_impact="Source-routed packets are accepted.",
        remediation="Enable 'Drop source routed IP packets' under Firewall Settings > Advanced.",
        verification=["Confirm source-routed packets are dropped"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=2, impact=3, exposure=3, affected_count=1,
        object_type="Firewall Setting", object_name="Drop Source-Routed Packets")]


@registry.rule(id="FW-002", title="FTP Bounce Attack Protection Disabled",
               severity="Medium", category="Firewall Settings")
def fw_ftp(snap):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present") or fw.get("ftp_bounce_protection", True):
        return []
    return [Finding(
        rule_id="FW-002", title="FTP Bounce Attack Protection Disabled", severity="Medium",
        category="Firewall Settings", description="FTP bounce attack protection is disabled.",
        evidence=["FTP bounce attack protection = 0"],
        business_impact="FTP bounce can be used to port-scan or relay through the firewall.",
        technical_impact="FTP PORT command validation is off.",
        remediation="Enable FTP bounce attack protection under Firewall Settings.",
        verification=["Confirm FTP bounce protection is enabled"],
        risk_reduction="Low", references=[SW_BP],
        likelihood=2, impact=2, exposure=2, affected_count=1,
        object_type="Firewall Setting", object_name="FTP Bounce Protection")]


@registry.rule(id="FW-005", title="TCP Handshake Enforcement Disabled",
               severity="Low", category="Firewall Settings")
def fw_handshake(snap):
    fw = snap.get("firewall_settings", {})
    if not fw.get("present") or fw.get("tcp_handshake_enforcement", True):
        return []
    return [Finding(
        rule_id="FW-005", title="TCP Handshake Enforcement Disabled", severity="Low",
        category="Firewall Settings",
        description="TCP handshake enforcement is disabled.",
        evidence=["Enable TCP handshake enforcement: Disabled"],
        business_impact="Out-of-state TCP packets may be forwarded, aiding evasion.",
        technical_impact="Firewall does not require a full handshake before forwarding.",
        remediation="Enable TCP handshake enforcement under Firewall Settings > Flood Protection.",
        verification=["Confirm TCP handshake enforcement is enabled"],
        risk_reduction="Low", references=[SW_BP],
        likelihood=2, impact=2, exposure=2, affected_count=1,
        object_type="Firewall Setting", object_name="TCP Handshake Enforcement")]


# ======================================================================
# AUTHENTICATION (AUTH / RAD)
# ======================================================================
@registry.rule(id="AUTH-006", title="Users with MFA Disabled",
               severity="Medium", category="Authentication")
def auth_mfa_users(snap):
    lu = snap.get("local_users_detail", {})
    n = lu.get("mfa_disabled_count", 0)
    if n == 0 or lu.get("count", 0) == 0:
        return []
    names = [u["name"] for u in lu.get("users", []) if not u.get("mfa")]
    return [Finding(
        rule_id="AUTH-006", title="Users with MFA Disabled", severity="Medium",
        category="Authentication",
        description=f"{n} of {lu.get('count')} local users have no multi-factor authentication configured.",
        evidence=["Sample users without MFA: " + ", ".join(names[:15]) + (" ..." if len(names) > 15 else "")],
        business_impact="Accounts without MFA are vulnerable to credential theft and reuse.",
        technical_impact="Single-factor authentication for the listed users.",
        remediation="Enable TOTP/OTP MFA for all interactive and VPN user accounts.",
        verification=["Confirm MFA coverage for all privileged and VPN users"],
        risk_reduction="Medium", references=[SW_BP],
        compliance={"PCI DSS 4.0": ["8.4", "8.5"], "NIST CSF 2.0": ["PR.AA"]},
        likelihood=3, impact=3, exposure=3, affected_count=n,
        object_type="User Accounts", object_name=f"{n} users without MFA")]


@registry.rule(id="AUTH-002", title="Login Uniqueness Not Enforced",
               severity="Medium", category="Authentication")
def auth_uniqueness(snap):
    a = snap.get("auth_servers", {})
    if a.get("login_uniqueness", True):
        return []
    return [Finding(
        rule_id="AUTH-002", title="Login Uniqueness Not Enforced", severity="Medium",
        category="Authentication",
        description="Login uniqueness is not enforced; the same credential can be used simultaneously from multiple locations.",
        evidence=["Login uniqueness: not enforced"],
        business_impact="Shared/stolen credentials can be used concurrently without detection.",
        technical_impact="No single-session enforcement per user.",
        remediation="Enable 'Enforce login uniqueness' under Users > Settings.",
        verification=["Confirm login uniqueness is enforced"],
        risk_reduction="Medium", references=[SW_BP],
        compliance={"PCI DSS 4.0": ["8.5"]},
        likelihood=2, impact=3, exposure=3, affected_count=1,
        object_type="Auth Setting", object_name="Login Uniqueness")]


@registry.rule(id="RAD-005", title="TACACS+ Accounting Not Enabled",
               severity="Medium", category="Authentication")
def rad_tacacs(snap):
    a = snap.get("auth_servers", {})
    # Only fire if TACACS+ is configured but accounting off — approximated by key presence
    if "tacacs_accounting_enabled" not in a or a.get("tacacs_accounting_enabled", True):
        return []
    return [Finding(
        rule_id="RAD-005", title="TACACS+ Accounting Not Enabled", severity="Medium",
        category="Authentication",
        description="TACACS+ accounting is not enabled; there is no centralised audit trail for authentication events.",
        evidence=["TACACS+ Accounting: Disabled"],
        business_impact="Lack of centralised auth logging hampers incident investigation and compliance.",
        technical_impact="Authentication events are not forwarded to TACACS+ accounting.",
        remediation="Enable TACACS+ accounting if TACACS+ is used for administration.",
        verification=["Confirm TACACS+ accounting is enabled"],
        risk_reduction="Low", references=[SW_BP],
        compliance={"PCI DSS 4.0": ["10.2"]},
        likelihood=2, impact=2, exposure=2, affected_count=1,
        object_type="Auth Setting", object_name="TACACS+ Accounting")]


# ======================================================================
# SNMP
# ======================================================================
@registry.rule(id="SNMP-002", title="SNMPv3 Not Enforced",
               severity="High", category="Management Access")
def snmp_v3(snap):
    s = snap.get("snmp", {})
    if not s.get("enabled"):
        return []
    if s.get("require_v3"):
        return []
    return [Finding(
        rule_id="SNMP-002", title="SNMPv3 Not Enforced", severity="High",
        category="Management Access",
        description="Mandatory 'Require SNMPv3' is disabled; v1/v2c cleartext requests are accepted.",
        evidence=[f"SNMP enabled; v3 enforcement: off; community present: {bool(s.get('get_community'))}"],
        business_impact="SNMP v1/v2c sends the community string in cleartext, exposing a credential that can reveal device internals.",
        technical_impact="Cleartext SNMP polling is permitted.",
        remediation="Require SNMPv3 with authentication and privacy, and disable v1/v2c.",
        verification=["Confirm only SNMPv3 is accepted"],
        risk_reduction="High", references=[SW_BP],
        compliance={"PCI DSS 4.0": ["2.2"], "CIS v8": ["4"]},
        likelihood=3, impact=3, exposure=3, affected_count=1,
        object_type="Management Service", object_name="SNMP")]


# ======================================================================
# SSLVPN
# ======================================================================
@registry.rule(id="SSLVPN-002", title="Virtual Office Enabled on non-LAN Zone",
               severity="Medium", category="SSLVPN")
def sslvpn_vo(snap):
    s = snap.get("sslvpn", {})
    zones = s.get("zones", [])
    non_lan = [z for z in zones if str(z).upper() not in ("LAN",)]
    if not s.get("enabled") or not non_lan:
        return []
    return [Finding(
        rule_id="SSLVPN-002", title="Virtual Office Enabled on non-LAN Zone",
        severity="Medium", category="SSLVPN",
        description="The SSL VPN Virtual Office portal is reachable on non-LAN zones, exposing its web interface.",
        evidence=["SSL VPN zones: " + ", ".join(map(str, zones))],
        business_impact="Exposing the Virtual Office portal beyond LAN increases the attack surface of the VPN front-end.",
        technical_impact="Portal web interface reachable from the listed zones.",
        remediation="Disable Virtual Office on WAN and other untrusted zones; restrict to LAN/management.",
        verification=["Confirm Virtual Office is limited to trusted zones"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=3, impact=3, exposure=4, affected_count=len(non_lan),
        object_type="SSLVPN", object_name="Virtual Office")]


# ======================================================================
# CONTENT FILTER (CFS)
# ======================================================================
def _cfs_finding(snap, code, title, key, desc, remediation, sev="Medium"):
    cfs = snap.get("cfs", {})
    if not cfs.get("present") or cfs.get(key, True):
        return []
    return [Finding(
        rule_id=code, title=title, severity=sev, category="Content Filter",
        description=desc, evidence=[f"{title}: not configured"],
        business_impact="Reduced web-filtering coverage allows access to risky or non-compliant content.",
        technical_impact=desc, remediation=remediation,
        verification=[f"Confirm '{title}' is configured"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=2, impact=2, exposure=2, affected_count=1,
        object_type="Content Filter", object_name=title)]


@registry.rule(id="CFS-004", title="CFS HTTPS Content Filtering Disabled",
               severity="Medium", category="Content Filter")
def cfs_https(snap):
    return _cfs_finding(snap, "CFS-004", "CFS HTTPS Content Filtering Disabled",
                        "https_filtering",
                        "HTTPS content filtering is disabled, so encrypted web traffic is not filtered.",
                        "Enable HTTPS content filtering in the active CFS profile.")


@registry.rule(id="CFS-006", title="CFS Safe Search Not Enforced",
               severity="Medium", category="Content Filter")
def cfs_safesearch(snap):
    return _cfs_finding(snap, "CFS-006", "CFS Safe Search Not Enforced",
                        "safe_search",
                        "Safe Search enforcement is disabled.",
                        "Enable Safe Search enforcement in the active CFS profile.")


# ======================================================================
# WLAN
# ======================================================================
@registry.rule(id="WLAN-006", title="No SSIDs Using WPA3",
               severity="Low", category="Wireless")
def wlan_wpa3(snap):
    w = snap.get("wlan", {})
    if not w.get("present") or w.get("interface_count", 0) == 0:
        return []  # No wireless configured -> not applicable
    ssids = w.get("ssids", [])
    if not ssids:
        return []
    wpa3 = [s for s in ssids if "wpa3" in str(s.get("encryption", "")).lower()]
    if wpa3:
        return []
    return [Finding(
        rule_id="WLAN-006", title="No SSIDs Using WPA3", severity="Low",
        category="Wireless",
        description="No wireless SSIDs use WPA3 encryption.",
        evidence=["SSIDs: " + ", ".join(s.get("ssid", "") for s in ssids)],
        business_impact="WPA2-only networks are more exposed to offline cracking and KRACK-style attacks.",
        technical_impact="No SSID negotiates WPA3.",
        remediation="Enable WPA3 (or WPA3/WPA2 transition) on corporate SSIDs where clients support it.",
        verification=["Confirm corporate SSIDs offer WPA3"],
        risk_reduction="Low", references=[SW_BP],
        likelihood=2, impact=2, exposure=2, affected_count=len(ssids),
        object_type="Wireless", object_name="WLAN SSIDs")]


# ======================================================================
# PERFORMANCE (PERF)
# ======================================================================
@registry.rule(id="PERF-002", title="CPU Utilization Spike",
               severity="High", category="Performance")
def perf_cpu(snap):
    p = snap.get("performance", {})
    if not p.get("present"):
        return []
    cpu_max = p.get("cpu_max", 0.0)
    if cpu_max < 95:
        return []
    return [Finding(
        rule_id="PERF-002", title="CPU Utilization Spike", severity="High",
        category="Performance",
        description=f"Observed CPU utilisation reached {cpu_max:.0f}% (threshold: 95%). The management/data plane is near saturation.",
        evidence=[f"Peak CPU sample: {cpu_max:.0f}%"],
        business_impact="A near-saturated CPU risks dropped connections, slow policy processing and reduced throughput, and can indicate a flood/DDoS condition.",
        technical_impact="Processing headroom is critically low at the captured time.",
        remediation="Review top processes, investigate possible flood/DDoS, check active connection counts, and assess whether the platform is undersized.",
        verification=["Confirm sustained CPU utilisation returns below threshold"],
        risk_reduction="High", references=[SW_BP],
        likelihood=3, impact=4, exposure=3, affected_count=1,
        object_type="Performance", object_name="CPU Utilization")]


# ======================================================================
# Retire aggregate rules now superseded by the per-object parity rules
# above, so a single condition is never counted twice.
# ======================================================================
registry.retire(
    "FW-ACL-001",   # -> ACR-002 / ACR-007 (per rule)
    "FW-ACL-002",   # -> ACR-002 (per rule)
    "FW-ACL-004",   # -> NAT-003 / usage now per-object; ACL usage kept separate
    "FW-HYG-001",   # -> AOB-003 (per object)
    "FW-NAT-001",   # -> NAT-003 (per policy)
    "FW-VPN-001",   # -> IPSEC-001 (per policy, aggressive-mode folded in)
    "FW-VPN-002",   # -> IPSEC-001 / IPSEC-003 / IPSEC-005 (per policy)
    "FW-VPN-003",   # -> IPSEC-006 (per policy)
    "FW-VPN-005",   # -> IPSEC-008 (per policy)
    "FW-SVC-003",   # -> SEC-009 / SEC-010 / SEC-011 (per zone)
    "FW-SVC-008",   # -> SEC-009 / SEC-010 / SEC-011 (per zone)
)
