"""Detection catalog.

High-value SonicWall posture checks, grounded in real SonicOS 6.5/7.x TSR
layouts.  Every check is evidence-gated: a finding is emitted only when the
TSR explicitly demonstrates the condition, never inferred from absence of a
section (absence downgrades to an informational data-gap note at most).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from .engine import Finding, Snapshot, registry

SW_BP = "SonicWall SonicOS Best Practices"
CIS4 = "CIS Controls v8 - 4 (Secure Configuration)"
CIS6 = "CIS Controls v8 - 6 (Access Control Management)"
CIS8 = "CIS Controls v8 - 8 (Audit Log Management)"
CIS12 = "CIS Controls v8 - 12 (Network Infrastructure Management)"
CIS13 = "CIS Controls v8 - 13 (Network Monitoring and Defense)"
NIST_PR_AC = "NIST CSF 2.0 PR.AA (Identity & Access)"
NIST_PR_PS = "NIST CSF 2.0 PR.PS (Platform Security)"
NIST_DE_CM = "NIST CSF 2.0 DE.CM (Continuous Monitoring)"
PCI_1 = "PCI DSS 4.0 Req 1 (Network Security Controls)"
PCI_2 = "PCI DSS 4.0 Req 2 (Secure Configurations)"
PCI_8 = "PCI DSS 4.0 Req 8 (Identify Users & Authenticate Access)"
PCI_10 = "PCI DSS 4.0 Req 10 (Log & Monitor)"
ISO_AC = "ISO/IEC 27001:2022 A.8 (Technological Controls)"


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _wan_interfaces(snap: Snapshot) -> Set[str]:
    return {i["name"] for i in snap.get("interfaces", []) if i.get("zone") == "WAN"}


def _parse_tsr_time(snap: Snapshot) -> Optional[datetime]:
    t = snap.get("system", {}).get("time", "")
    m = re.match(r"(\d{2})/(\d{2})/(\d{4})", t)
    if m:
        return datetime(int(m.group(3)), int(m.group(1)), int(m.group(2)))
    return None


def _parse_expiry(text: str) -> Optional[datetime]:
    text = (text or "").strip()
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b  %d %H:%M:%S %Y GMT",
                "%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y"):
        try:
            return datetime.strptime(re.sub(r"\s+", " ", text), fmt)
        except ValueError:
            continue
    m = re.match(r"(\d{2})/(\d{2})/(\d{4})", text)
    if m:
        return datetime(int(m.group(3)), int(m.group(1)), int(m.group(2)))
    return None


# ======================================================================
# MANAGEMENT SECURITY
# ======================================================================
@registry.rule(id="FW-MGT-001", title="Firewall Management Reachable on WAN Interface",
               severity="Critical", category="Management Security")
def mgmt_on_wan(snap: Snapshot) -> List[Finding]:
    adm = snap.get("administration", {})
    wan = _wan_interfaces(snap)
    findings: List[Finding] = []
    for proto, key in (("HTTPS", "https_mgmt_interfaces"), ("HTTP", "http_mgmt_interfaces"),
                       ("SSH", "ssh_mgmt_interfaces"), ("SNMP", "snmp_interfaces")):
        exposed = sorted(set(adm.get(key, [])) & wan)
        if exposed:
            findings.append(Finding(
                rule_id="FW-MGT-001",
                title=f"{proto} management enabled on WAN interface(s)",
                severity="Critical", category="Management Security",
                description=f"{proto} management is permitted on interface(s) assigned to the WAN zone.",
                evidence=[f"{proto} Management Allowed On Interfaces includes WAN interface(s): {', '.join(exposed)}"],
                business_impact="The firewall administration plane is reachable from the internet, making the device a direct target for credential attacks and exploitation of management-plane vulnerabilities.",
                technical_impact="Internet-wide scanners will index the service; any authentication weakness or management-plane CVE becomes remotely exploitable, risking full device takeover.",
                remediation=f"Remove WAN interfaces from the {proto} management allow list. Administer the device via the dedicated MGMT interface, an internal management VLAN, or through a VPN. If remote vendor access is required, restrict by source address object and enforce MFA.",
                verification=[f"Device > Settings > Administration: confirm {proto} management is not permitted on WAN interfaces",
                              "Externally scan the WAN IP for the management port and confirm it is closed"],
                risk_reduction="High - removes direct internet exposure of the administration plane.",
                references=[SW_BP], compliance={"CIS": [CIS4, CIS12], "NIST CSF": [NIST_PR_AC], "PCI DSS": [PCI_1, PCI_2], "ISO 27001": [ISO_AC]},
                likelihood=5, impact=5, exposure=5, affected_count=len(exposed)))
    return findings


@registry.rule(id="FW-MGT-002", title="Cleartext HTTP Management Enabled",
               severity="High", category="Management Security")
def http_mgmt(snap: Snapshot) -> List[Finding]:
    adm = snap.get("administration", {})
    ifaces = adm.get("http_mgmt_interfaces", [])
    if not ifaces:
        return []
    return [Finding(
        rule_id="FW-MGT-002", title="Cleartext HTTP management enabled",
        severity="High", category="Management Security",
        description="HTTP (unencrypted) management is permitted on one or more interfaces.",
        evidence=[f"HTTP Management Allowed On Interfaces: {', '.join(ifaces)}",
                  f"HTTP Management Port: {adm.get('http_port')}"],
        business_impact="Administrative credentials and session tokens can be intercepted by anyone positioned on the management path.",
        technical_impact="Credentials traverse the network in cleartext; a single capture yields full administrative access.",
        remediation="Disable HTTP management on all interfaces and use HTTPS exclusively. Keep automatic HTTP-to-HTTPS redirection enabled.",
        verification=["Confirm 'HTTP Management Allowed On Interfaces' reports None"],
        risk_reduction="Medium - eliminates cleartext credential exposure.",
        references=[SW_BP], compliance={"CIS": [CIS4], "NIST CSF": [NIST_PR_AC], "PCI DSS": [PCI_2], "ISO 27001": [ISO_AC]},
        likelihood=3, impact=5, exposure=3, affected_count=len(ifaces))]


@registry.rule(id="FW-MGT-003", title="Weak Administrator Password Policy",
               severity="Critical", category="Authentication Security")
def weak_password_policy(snap: Snapshot) -> List[Finding]:
    adm = snap.get("administration", {})
    issues, ev = [], []
    min_len = adm.get("min_password_length")
    if min_len is not None and min_len < 12:
        issues.append("minimum length")
        ev.append(f"Minimum Password Length: {min_len} (recommended: 12+)")
    cplx = adm.get("password_complexity_level")
    if cplx is not None and cplx == 0:
        issues.append("complexity disabled")
        ev.append("Password Complexity Level: 0 (no complexity enforcement)")
    chg = adm.get("password_change_period_days")
    if chg == 0:
        ev.append("Password Change Period: 0 days (no rotation policy)")
    uniq = adm.get("password_uniqueness_changes")
    if uniq == 0:
        ev.append("Enforce Password Uniqueness For: 0 changes (reuse permitted)")
    if not issues:
        return []
    sev = "Critical" if (min_len is not None and min_len <= 4 and cplx == 0) else "High"
    return [Finding(
        rule_id="FW-MGT-003", title="Weak administrator password policy",
        severity=sev, category="Authentication Security",
        description="The device-level password policy permits trivially weak administrator passwords.",
        evidence=ev,
        business_impact="A single guessed or reused administrator password compromises the entire perimeter security control.",
        technical_impact="Password spraying and credential stuffing against management or user-auth surfaces have a high probability of success.",
        remediation="Set minimum password length to 12 or more, enable complexity level 2+, enforce uniqueness for at least 5 changes, and define a rotation period aligned with your password standard.",
        verification=["Device > Settings > Administration > Login Security: confirm new values",
                      "Attempt to set a 6-character password and confirm rejection"],
        risk_reduction="High - directly hardens the primary authentication control.",
        references=[SW_BP], compliance={"CIS": ["CIS Controls v8 - 5 (Account Management)"], "NIST CSF": [NIST_PR_AC], "PCI DSS": [PCI_8], "ISO 27001": [ISO_AC]},
        likelihood=4, impact=5, exposure=4)]


@registry.rule(id="FW-MGT-004", title="Administrator MFA Disabled",
               severity="High", category="Authentication Security")
def admin_mfa(snap: Snapshot) -> List[Finding]:
    adm = snap.get("administration", {})
    otp = adm.get("admin_otp", "")
    if otp.strip().lower() != "disabled":
        return []
    return [Finding(
        rule_id="FW-MGT-004", title="Administrator one-time password (MFA) disabled",
        severity="High", category="Authentication Security",
        description="The built-in administrator account does not require a one-time password at login.",
        evidence=[f"Administrator One Time Password Option: {otp}",
                  f"Administrator Name: {adm.get('admin_name', '')}"],
        business_impact="A leaked or guessed administrator password is sufficient for full device compromise; there is no second factor to stop the attacker.",
        technical_impact="Single-factor authentication on the management plane combined with any password weakness yields direct administrative access.",
        remediation="Enable TOTP-based one-time passwords for the admin account, or enforce MFA via the central identity provider (LDAP/RADIUS/SAML) for all administrative logins.",
        verification=["Log in as admin and confirm an OTP challenge is presented"],
        risk_reduction="High - blocks credential-only compromise of the admin account.",
        references=[SW_BP], compliance={"CIS": [CIS6], "NIST CSF": [NIST_PR_AC], "PCI DSS": [PCI_8], "ISO 27001": [ISO_AC]},
        likelihood=4, impact=5, exposure=3)]


@registry.rule(id="FW-MGT-005", title="Default Administrator Account Name In Use",
               severity="Low", category="Authentication Security")
def default_admin_name(snap: Snapshot) -> List[Finding]:
    name = snap.get("administration", {}).get("admin_name", "")
    if name.lower() != "admin":
        return []
    return [Finding(
        rule_id="FW-MGT-005", title="Default 'admin' account name in use",
        severity="Low", category="Authentication Security",
        description="The built-in administrator account retains the default name 'admin'.",
        evidence=["Administrator Name: admin"],
        business_impact="Attackers can skip username enumeration; brute-force tooling targets 'admin' by default.",
        technical_impact="Halves the effort of credential attacks against the management plane.",
        remediation="Rename the built-in administrator account to a non-obvious value and document it in your password vault.",
        verification=["Confirm login with the old 'admin' name fails"],
        risk_reduction="Low - removes a free hint for attackers.",
        references=[SW_BP], compliance={"CIS": [CIS4], "PCI DSS": [PCI_2]},
        likelihood=3, impact=2, exposure=3)]


@registry.rule(id="FW-MGT-006", title="SNMP v1/v2c Enabled",
               severity="Medium", category="Management Security")
def snmp_v2(snap: Snapshot) -> List[Finding]:
    snmp = snap.get("snmp", {})
    if not snmp.get("enabled"):
        return []
    ev = ["SNMP: Enabled"]
    if snmp.get("get_community_set"):
        ev.append("A v1/v2c Get community string is configured (community strings transit and are stored in cleartext; the TSR file itself discloses it)")
    ifaces = snap.get("administration", {}).get("snmp_interfaces", [])
    if ifaces:
        ev.append(f"SNMP Allowed On Interfaces: {', '.join(ifaces)}")
    return [Finding(
        rule_id="FW-MGT-006", title="SNMP enabled with community-string authentication",
        severity="Medium", category="Management Security",
        description="SNMP is enabled using community-string (v1/v2c) authentication.",
        evidence=ev,
        business_impact="Device and network topology details can be harvested by anyone who learns the community string, aiding attack planning. TSR files shared with third parties disclose the string.",
        technical_impact="v1/v2c provides no encryption or per-user authentication; a sniffed or leaked community string grants read access to full device state.",
        remediation="Migrate to SNMPv3 with authPriv (SHA-256/AES). Rotate the existing community string now because it is embedded in this TSR. Restrict SNMP to dedicated monitoring interfaces and sources.",
        verification=["Confirm SNMPv3 users are configured and v1/v2c communities are removed",
                      "Verify polling works from the NMS using SNMPv3 authPriv"],
        risk_reduction="Medium - removes a cleartext recon channel.",
        references=[SW_BP], compliance={"CIS": [CIS4, CIS12], "NIST CSF": [NIST_PR_PS], "PCI DSS": [PCI_2]},
        likelihood=3, impact=3, exposure=3)]


@registry.rule(id="FW-MGT-007", title="SonicOS API Weak Digest Algorithm",
               severity="Low", category="Management Security")
def api_md5(snap: Snapshot) -> List[Finding]:
    adm = snap.get("administration", {})
    if not (adm.get("sonicos_api_enabled") and adm.get("sonicos_api_md5_digest")):
        return []
    return [Finding(
        rule_id="FW-MGT-007", title="SonicOS API accepts MD5 digest authentication",
        severity="Low", category="Management Security",
        description="The SonicOS API has RFC-7616 digest authentication enabled with the MD5 algorithm permitted.",
        evidence=["SonicOS API: Enabled", "Enabled digest algorithms - MD5: Yes"],
        business_impact="API authentication can be downgraded to a cryptographically broken hash, weakening automation credentials.",
        technical_impact="MD5 digests are vulnerable to collision and accelerated brute-force attacks.",
        remediation="Disable the MD5 digest algorithm for the SonicOS API, leaving SHA-256 only. Prefer token-based (Bearer) authentication for automation.",
        verification=["Confirm 'MD5: No' under enabled digest algorithms"],
        risk_reduction="Low - removes a weak-crypto authentication path.",
        references=[SW_BP], compliance={"CIS": [CIS4]},
        likelihood=2, impact=3, exposure=2)]


@registry.rule(id="FW-MGT-008", title="Enhanced Audit Logging Disabled",
               severity="Low", category="Configuration Hygiene")
def audit_logging(snap: Snapshot) -> List[Finding]:
    if snap.get("administration", {}).get("enhanced_audit_logging") is not False:
        return []
    return [Finding(
        rule_id="FW-MGT-008", title="Enhanced audit logging disabled",
        severity="Low", category="Configuration Hygiene",
        description="Enhanced audit logging of configuration changes is disabled.",
        evidence=["Enhanced Audit Logging: Disabled"],
        business_impact="Configuration changes lack a detailed audit trail, complicating incident response and change accountability.",
        technical_impact="Per-parameter change attribution is unavailable during forensics.",
        remediation="Enable Enhanced Audit Logging and forward events to the central log platform.",
        verification=["Make a benign change and confirm an audit event is produced"],
        risk_reduction="Low - improves accountability and forensics.",
        references=[SW_BP], compliance={"CIS": [CIS8], "PCI DSS": [PCI_10], "NIST CSF": [NIST_DE_CM]},
        likelihood=2, impact=2, exposure=1)]


@registry.rule(id="FW-MGT-009", title="Broad Management Interface Surface",
               severity="Medium", category="Management Security")
def broad_mgmt_surface(snap: Snapshot) -> List[Finding]:
    adm = snap.get("administration", {})
    ifaces = [i for i in adm.get("https_mgmt_interfaces", []) if i != "MGMT"]
    if len(ifaces) <= 3:
        return []
    return [Finding(
        rule_id="FW-MGT-009", title="HTTPS management permitted on a broad set of interfaces",
        severity="Medium", category="Management Security",
        description=f"HTTPS management is reachable from {len(ifaces)} interfaces/VLANs beyond the dedicated MGMT port.",
        evidence=[f"HTTPS Management Allowed On Interfaces: {', '.join(adm.get('https_mgmt_interfaces', []))}"],
        business_impact="Every additional management-reachable segment is another foothold from which a compromised host can attack the firewall.",
        technical_impact="Lateral movement from any of these segments can directly target the administration plane.",
        remediation="Restrict HTTPS management to the dedicated MGMT interface and a single hardened management VLAN. Pair with access rules limiting source addresses to administrator workstations.",
        verification=["Confirm the management allow list contains only MGMT and the management VLAN"],
        risk_reduction="Medium - shrinks the internal attack surface of the management plane.",
        references=[SW_BP], compliance={"CIS": [CIS12], "PCI DSS": [PCI_1], "NIST CSF": [NIST_PR_AC]},
        likelihood=3, impact=4, exposure=3, affected_count=len(ifaces))]


# ======================================================================
# SECURITY SERVICES
# ======================================================================
def _svc_disabled_finding(rid: str, name: str, evidence: List[str], sev: str,
                          biz: str, tech: str, fix: str, verify: List[str],
                          rr: str, lik: int, imp: int, exp: int) -> Finding:
    return Finding(rule_id=rid, title=f"{name} disabled", severity=sev,
                   category="Firewall Security",
                   description=f"{name} is licensed/available but not enabled.",
                   evidence=evidence, business_impact=biz, technical_impact=tech,
                   remediation=fix, verification=verify, risk_reduction=rr,
                   references=[SW_BP],
                   compliance={"CIS": [CIS13], "NIST CSF": [NIST_DE_CM], "PCI DSS": [PCI_1]},
                   likelihood=lik, impact=imp, exposure=exp)


@registry.rule(id="FW-SVC-001", title="DPI-SSL Client Inspection Disabled",
               severity="High", category="Firewall Security")
def dpi_ssl_disabled(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    if ss.get("dpi_ssl_client_enabled") is not False:
        return []
    return [_svc_disabled_finding(
        "FW-SVC-001", "DPI-SSL client inspection",
        [f"Client DPI-SSL: {ss.get('dpi_ssl_client_licensed', '')}", "Enable SSL Client Inspection: Disabled"],
        "High",
        "The large majority of malware delivery and command-and-control now rides inside TLS; with DPI-SSL off, IPS/GAV/CFS cannot see that traffic.",
        "Encrypted sessions bypass signature inspection entirely, creating a blind spot for exfiltration and C2.",
        "Enable SSL Client Inspection with a staged rollout: deploy the re-signing CA to managed endpoints, start with high-risk categories, and maintain the exclusion list for pinned applications (banking, OS updates).",
        ["Confirm 'Enable SSL Client Inspection: Enabled'", "Validate a test HTTPS download of the EICAR file is blocked"],
        "High - restores visibility over encrypted traffic.", 4, 4, 3)]


@registry.rule(id="FW-SVC-002", title="Content Filtering Disabled",
               severity="Medium", category="Firewall Security")
def cfs_disabled(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    if ss.get("content_filter_enabled") is not False:
        return []
    return [_svc_disabled_finding(
        "FW-SVC-002", "Content Filtering Service (CFS)",
        [f"CFS License: {ss.get('content_filter_license', '')}", "Enable Content Filtering Service: Disabled"],
        "Medium",
        "Users can reach known-malicious, phishing, and policy-violating destinations without interference.",
        "Reputation/category-based web blocking is inactive even though it is licensed.",
        "Enable CFS, apply the default profile blocking Malware, Phishing, Botnet, and Proxy-Avoidance categories, then tune per-zone policies.",
        ["Browse to a test category URL and confirm the block page"],
        "Medium - blocks a common initial-access channel.", 3, 3, 3)]


@registry.rule(id="FW-SVC-003", title="IPS / GAV / Anti-Spyware State",
               severity="Critical", category="Firewall Security")
def core_services(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    out: List[Finding] = []
    table = (("ips_enabled", "Intrusion Prevention (IPS)", "FW-SVC-003"),
             ("gav_enabled", "Gateway Anti-Virus", "FW-SVC-004"),
             ("anti_spyware_enabled", "Anti-Spyware", "FW-SVC-005"))
    for key, name, rid in table:
        if ss.get(key) is False:
            out.append(_svc_disabled_finding(
                rid, name, [f"{name}: Disabled (global setting)"], "Critical",
                f"{name} is a core inline protection; disabling it removes exploit/malware blocking for all traffic.",
                "Known exploits and malware traverse the firewall uninspected.",
                f"Enable {name} globally and confirm per-zone enforcement.",
                [f"Confirm '{name}' reports Enabled and signatures are current"],
                "High - restores core inline protection.", 4, 5, 4))
    if ss.get("ips_enabled") and ss.get("ips_prevent_low") is False:
        out.append(Finding(
            rule_id="FW-SVC-003a", title="IPS low-priority signatures in detect-only mode",
            severity="Info", category="Firewall Security",
            description="IPS prevention is disabled for low-priority signatures (a common, balanced default).",
            evidence=["Prevent All Low Priority Attacks: Disabled"],
            business_impact="Low-priority attacks are logged but not blocked.",
            technical_impact="Minor; high/medium-priority prevention is active.",
            remediation="Review periodically; enable low-priority prevention where the false-positive budget allows.",
            verification=["Review IPS settings quarterly"], risk_reduction="Low",
            references=[SW_BP], likelihood=2, impact=2, exposure=2))
    return out


@registry.rule(id="FW-SVC-006", title="Capture ATP Not In Use",
               severity="Medium", category="Firewall Security")
def capture_atp(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    if ss.get("capture_atp_evidence"):
        return []
    return [Finding(
        rule_id="FW-SVC-006", title="Capture ATP sandboxing shows no evidence of use",
        severity="Medium", category="Firewall Security",
        description="The TSR contains no evidence of an active Capture ATP configuration (DEA section is empty).",
        evidence=["Security Services : DEA section present but empty - no Capture ATP policy data"],
        business_impact="Zero-day and unknown malware in file transfers is not detonated in a sandbox before delivery.",
        technical_impact="Protection is limited to signature-based GAV; novel payloads pass.",
        remediation="If licensed, enable Capture ATP with 'Block until verdict' for supported file types on internet-facing flows. If unlicensed, evaluate adding it for zero-day coverage.",
        verification=["Confirm Capture ATP status page shows files being submitted and verdicts returned"],
        risk_reduction="Medium - adds zero-day file analysis.",
        references=[SW_BP], compliance={"CIS": [CIS13], "NIST CSF": [NIST_DE_CM]},
        likelihood=3, impact=4, exposure=3)]


@registry.rule(id="FW-SVC-007", title="Security Services Performance-Optimized Profile",
               severity="Medium", category="Firewall Security")
def perf_optimized(snap: Snapshot) -> List[Finding]:
    profile = snap.get("security_services", {}).get("profile", "")
    if "performance" not in profile.lower():
        return []
    return [Finding(
        rule_id="FW-SVC-007", title="Security services set to Performance Optimized instead of Maximum Security",
        severity="Medium", category="Firewall Security",
        description="The global security-services profile favors throughput over inspection depth.",
        evidence=[f"Security Services Setting: {profile}"],
        business_impact="A reduced signature set is applied inline, lowering detection coverage to gain performance.",
        technical_impact="Lower-frequency signatures are excluded from inline inspection.",
        remediation="Switch to 'Maximum Security' and validate throughput headroom; current connection usage in this TSR is under 2% of capacity, indicating ample headroom.",
        verification=["Confirm Security Services Setting reports Maximum Security",
                      "Monitor CPU/throughput for one business week after the change"],
        risk_reduction="Medium - widens inline signature coverage.",
        references=[SW_BP], compliance={"CIS": [CIS13]},
        likelihood=3, impact=3, exposure=3)]


@registry.rule(id="FW-SVC-008", title="Zone-Level Security Enforcement Gaps",
               severity="Medium", category="Firewall Security")
def zone_enforcement(snap: Snapshot) -> List[Finding]:
    gaps = []
    for z in snap.get("zones", []):
        if z.get("security_type") not in {"Trusted", "Public", "Wireless"}:
            continue
        missing = [label for key, label in (("gav", "GAV"), ("ips", "IPS"),
                                            ("anti_spyware", "Anti-Spyware"))
                   if z.get(key) is False]
        if missing:
            gaps.append(f"Zone '{z['name']}' ({z.get('security_type')}): {', '.join(missing)} off")
    if not gaps:
        return []
    return [Finding(
        rule_id="FW-SVC-008", title="Security services not enforced on one or more zones",
        severity="Medium", category="Firewall Security",
        description=f"{len(gaps)} zone(s) have core inspection services disabled at the zone level, so traffic in those zones bypasses inspection even though the services are globally enabled.",
        evidence=gaps[:15] + ([f"... and {len(gaps) - 15} more zones"] if len(gaps) > 15 else []),
        business_impact="Threats moving laterally through unenforced zones are invisible to the firewall's inspection engines.",
        technical_impact="Zone-level service flags override global enablement; affected segments receive no IPS/GAV/Anti-Spyware coverage.",
        remediation="Enable GAV, IPS, and Anti-Spyware on every production zone, prioritising Trusted and Wireless zones carrying user traffic.",
        verification=["Object > Zones: confirm service checkboxes per zone"],
        risk_reduction="Medium - extends inspection to internal segments.",
        references=[SW_BP], compliance={"CIS": [CIS13], "PCI DSS": [PCI_1]},
        likelihood=3, impact=4, exposure=2, affected_count=len(gaps))]


@registry.rule(id="FW-SVC-009", title="GAV HTTP Outbound Inspection Disabled",
               severity="Low", category="Firewall Security")
def gav_outbound(snap: Snapshot) -> List[Finding]:
    ss = snap.get("security_services", {})
    if not (ss.get("gav_enabled") and ss.get("gav_http_outbound") is False):
        return []
    return [Finding(
        rule_id="FW-SVC-009", title="Gateway Anti-Virus HTTP outbound inspection disabled",
        severity="Low", category="Firewall Security",
        description="GAV is enabled, but outbound HTTP uploads are not inspected.",
        evidence=["HTTP Outbound Inspection: NOT Enabled"],
        business_impact="Malware uploads/exfiltration over HTTP leave the network uninspected.",
        technical_impact="Outbound HTTP payloads bypass anti-virus scanning.",
        remediation="Enable HTTP outbound inspection in Gateway Anti-Virus settings.",
        verification=["Confirm 'HTTP Outbound Inspection: Enabled'"],
        risk_reduction="Low", references=[SW_BP],
        likelihood=2, impact=3, exposure=2)]


# ======================================================================
# VPN SECURITY
# ======================================================================
_WEAK_ENC = re.compile(r"\b(DES|3DES)\b")
_WEAK_HASH = re.compile(r"\b(MD5|SHA1)\b")
_WEAK_DH = re.compile(r"DH Group (1|2|5)\b")


@registry.rule(id="FW-VPN-001", title="Weak IPsec/IKE Cryptography on Enabled Policies",
               severity="High", category="VPN Security")
def weak_vpn_crypto(snap: Snapshot) -> List[Finding]:
    out: List[Finding] = []
    enabled = [p for p in snap.get("vpn", {}).get("policies", []) if p.get("enabled")]
    aggressive = [p for p in enabled if "aggressive" in p.get("exchange", "").lower()]
    if aggressive:
        out.append(Finding(
            rule_id="FW-VPN-001", title="IKEv1 Aggressive Mode on enabled VPN policy",
            severity="High", category="VPN Security",
            description="Enabled VPN policies negotiate IKEv1 Aggressive Mode, which transmits identity hashes that enable offline PSK cracking.",
            evidence=[f"{p['name']}: IKE Exchange = {p['exchange']}" for p in aggressive][:10],
            business_impact="Site-to-site or client tunnels protected by a crackable PSK can be impersonated, exposing internal networks.",
            technical_impact="Aggressive Mode hash capture plus offline dictionary attack can recover the pre-shared key.",
            remediation="Migrate the listed policies to IKEv2 (or IKEv1 Main Mode where IKEv2 is unsupported) and rotate the pre-shared keys.",
            verification=["Confirm IKE Exchange shows IKEv2/Main Mode on each policy"],
            risk_reduction="High - removes offline PSK-cracking exposure.",
            references=[SW_BP], compliance={"PCI DSS": [PCI_2], "NIST CSF": [NIST_PR_PS]},
            likelihood=3, impact=5, exposure=4, affected_count=len(aggressive)))
    weak = []
    for p in enabled:
        blob = f"{p.get('ike_proposal', '')} {p.get('ipsec_proposal', '')}"
        tags = sorted({*_WEAK_ENC.findall(blob), *_WEAK_HASH.findall(blob),
                       *("DH" + g for g in _WEAK_DH.findall(blob))})
        if tags:
            weak.append((p, tags))
    if weak:
        out.append(Finding(
            rule_id="FW-VPN-002", title="Deprecated VPN encryption/hash/DH groups on enabled policies",
            severity="High", category="VPN Security",
            description="Enabled VPN policies use deprecated cryptographic primitives (DES/3DES, MD5/SHA1, DH groups 1/2/5).",
            evidence=[f"{p['name']}: {p.get('ike_proposal', '')} | {p.get('ipsec_proposal', '')} (weak: {', '.join(t)})"
                      for p, t in weak][:10],
            business_impact="Tunnel confidentiality and integrity rest on algorithms with known practical weaknesses, jeopardising data in transit.",
            technical_impact="3DES (Sweet32), SHA1 collisions, and small DH groups materially weaken the tunnels.",
            remediation="Re-negotiate all listed policies to AES-256/SHA-256 with DH group 14 or higher (prefer ECP groups 19/20) and enable PFS.",
            verification=["Confirm proposals show AES-256/SHA-256/DH14+ on each policy"],
            risk_reduction="High - brings tunnels to current cryptographic baseline.",
            references=[SW_BP], compliance={"PCI DSS": [PCI_2], "NIST CSF": [NIST_PR_PS]},
            likelihood=2, impact=5, exposure=3, affected_count=len(weak)))
    no_pfs = [p for p in enabled if p.get("pfs") is False]
    if no_pfs:
        out.append(Finding(
            rule_id="FW-VPN-003", title="Perfect Forward Secrecy disabled on enabled policies",
            severity="Low", category="VPN Security",
            description="PFS is disabled on enabled VPN policies.",
            evidence=[f"{p['name']}: PFS off" for p in no_pfs][:10],
            business_impact="Compromise of a long-term key would expose previously captured tunnel traffic.",
            technical_impact="Session keys are derived without ephemeral DH, removing forward secrecy.",
            remediation="Enable PFS (DH14+) on each listed policy in coordination with the peer.",
            verification=["Confirm PFS: on per policy"], risk_reduction="Low",
            references=[SW_BP], likelihood=2, impact=3, exposure=2,
            affected_count=len(no_pfs)))
    return out


@registry.rule(id="FW-VPN-004", title="Weak IKEv2 Dynamic Client Proposal",
               severity="Medium", category="VPN Security")
def ikev2_dynamic(snap: Snapshot) -> List[Finding]:
    prop = snap.get("vpn", {}).get("ikev2_dynamic_proposal", "")
    if not prop or not (_WEAK_ENC.search(prop) or _WEAK_HASH.search(prop) or _WEAK_DH.search(prop)):
        return []
    return [Finding(
        rule_id="FW-VPN-004", title="IKEv2 dynamic client proposal uses deprecated cryptography",
        severity="Medium", category="VPN Security",
        description="The global IKEv2 dynamic client proposal advertises deprecated algorithms to connecting clients.",
        evidence=[f"Dynamic Client Proposal: {prop}"],
        business_impact="Mobile/third-party IKEv2 clients may negotiate down to weak cryptography.",
        technical_impact="3DES/SHA1/DH2 are accepted for dynamically proposed client tunnels.",
        remediation="Update the IKEv2 dynamic client proposal to AES-256/SHA-256 with DH group 14 or higher.",
        verification=["Confirm the dynamic client proposal shows modern algorithms"],
        risk_reduction="Medium", references=[SW_BP],
        compliance={"PCI DSS": [PCI_2]}, likelihood=2, impact=4, exposure=3)]


@registry.rule(id="FW-VPN-005", title="Disabled VPN Policies Present",
               severity="Low", category="Configuration Hygiene")
def disabled_vpns(snap: Snapshot) -> List[Finding]:
    disabled = [p for p in snap.get("vpn", {}).get("policies", []) if not p.get("enabled")]
    if not disabled:
        return []
    legacy = [p for p in disabled
              if _WEAK_ENC.search(p.get("ike_proposal", "") + p.get("ipsec_proposal", ""))]
    ev = [f"{p['name']} (disabled; {p.get('ike_proposal', '')})" for p in disabled][:10]
    return [Finding(
        rule_id="FW-VPN-005", title=f"{len(disabled)} disabled VPN policies present (including legacy GroupVPN defaults)",
        severity="Low", category="Configuration Hygiene",
        description="Disabled VPN policies remain in the configuration; several retain legacy proposals and could be re-enabled as-is.",
        evidence=ev,
        business_impact="Dormant policies with weak settings are one click away from production and clutter audits.",
        technical_impact=f"{len(legacy)} of the disabled policies carry deprecated proposals.",
        remediation="Delete VPN policies that are no longer required; if retained for future use, update their proposals to the modern baseline first.",
        verification=["Confirm the policy list contains only required tunnels"],
        risk_reduction="Low", references=[SW_BP],
        likelihood=2, impact=2, exposure=1, affected_count=len(disabled))]


# ======================================================================
# SSL VPN
# ======================================================================
@registry.rule(id="FW-SSL-001", title="SSL VPN Exposure Review",
               severity="Medium", category="VPN Security")
def sslvpn_exposure(snap: Snapshot) -> List[Finding]:
    ssl = snap.get("sslvpn", {})
    zones = ssl.get("zones", {})
    out: List[Finding] = []
    if zones.get("WAN"):
        ev = ["SSL VPN Status on Zones: WAN = Enabled",
              f"SSL VPN Port: {ssl.get('port')}",
              f"SSL VPN User Domain: {ssl.get('user_domain', '')}"]
        out.append(Finding(
            rule_id="FW-SSL-001", title="SSL VPN service exposed on WAN",
            severity="Medium", category="VPN Security",
            description="The SSL VPN portal is enabled on the WAN zone. This is normal for remote access but is the most attacked SonicWall service and demands compensating controls.",
            evidence=ev,
            business_impact="SSL VPN portals are the leading initial-access vector in recent SonicWall-related incidents (credential stuffing and post-disclosure exploit campaigns).",
            technical_impact="Internet-reachable authentication surface; resilience depends on MFA, patch level, and source restrictions.",
            remediation="Enforce MFA for every SSL VPN user (the configured SAML domain suggests IdP-side MFA - verify it is mandatory), restrict source countries via Geo-IP policy, disable the portal on zones that do not need it, keep firmware current, and monitor login failures.",
            verification=["Attempt SSL VPN login without MFA and confirm it is refused",
                          "Review Geo-IP policy applied to the SSL VPN listener"],
            risk_reduction="Medium - hardens the most-targeted exposed service.",
            references=[SW_BP], compliance={"CIS": [CIS6], "PCI DSS": [PCI_8], "NIST CSF": [NIST_PR_AC]},
            likelihood=4, impact=4, exposure=5))
    internal = [z for z, en in zones.items() if en and z not in {"WAN", "SSLVPN"}]
    if len(internal) > 2:
        out.append(Finding(
            rule_id="FW-SSL-002", title="SSL VPN enabled on multiple internal zones",
            severity="Low", category="VPN Security",
            description=f"The SSL VPN service listens on {len(internal)} internal zones: {', '.join(internal)}.",
            evidence=[f"Zones with SSL VPN enabled: {', '.join(internal)}"],
            business_impact="Unnecessary listeners enlarge the internal attack surface of a high-value service.",
            technical_impact="Internal hosts can reach the SSL VPN portal and attack its authentication.",
            remediation="Disable SSL VPN on zones that do not require portal access.",
            verification=["Confirm the zone list matches the intended access model"],
            risk_reduction="Low", references=[SW_BP],
            likelihood=2, impact=3, exposure=2, affected_count=len(internal)))
    if ssl.get("web_mgmt_over_sslvpn"):
        out.append(Finding(
            rule_id="FW-SSL-003", title="Firewall web management reachable over SSL VPN",
            severity="Medium", category="Management Security",
            description="Web management of the firewall is permitted across SSL VPN sessions.",
            evidence=["Enable Web Management over SSL VPN: Enabled"],
            business_impact="Any compromised SSL VPN credential becomes a path to the firewall administration plane.",
            technical_impact="Chains remote-access compromise directly into management-plane access.",
            remediation="Disable web management over SSL VPN unless strictly required; if required, restrict to a dedicated admin user group with MFA.",
            verification=["Confirm management over SSL VPN is disabled or group-restricted"],
            risk_reduction="Medium", references=[SW_BP],
            compliance={"CIS": [CIS6], "PCI DSS": [PCI_1]},
            likelihood=3, impact=5, exposure=3))
    return out


# ======================================================================
# ACCESS RULES
# ======================================================================
@registry.rule(id="FW-ACL-001", title="Overly Permissive Access Rules",
               severity="Critical", category="Firewall Security")
def permissive_rules(snap: Snapshot) -> List[Finding]:
    rules = snap.get("access_rules", [])
    out: List[Finding] = []

    def is_any(v: str) -> bool:
        return v.strip().lower() in {"any", "all", "<all>"}

    wan_any = [r for r in rules if r["enabled"] and r["action"] == "Allow"
               and r["src_zone"] == "WAN" and is_any(r.get("src", ""))
               and is_any(r.get("service", "")) ]
    if wan_any:
        out.append(Finding(
            rule_id="FW-ACL-001", title="WAN inbound rules allowing Any source and Any service",
            severity="Critical", category="Firewall Security",
            description="Enabled WAN-inbound allow rules accept any source with any service.",
            evidence=[f"Rule {r['num']} {r['src_zone']}->{r['dst_zone']} {r.get('src')}->{r.get('dst')} svc {r.get('service')} ({r.get('name')})"
                      for r in wan_any][:10],
            business_impact="The entire internet can reach the listed destinations on all ports - effectively bypassing the firewall for those hosts.",
            technical_impact="Full-port exposure of internal/DMZ assets to untrusted sources.",
            remediation="Replace with least-privilege rules: explicit destination hosts, explicit service objects, and where possible source restrictions or Geo-IP policy.",
            verification=["Re-run analysis and confirm no WAN Any/Any allow rules remain"],
            risk_reduction="High", references=[SW_BP],
            compliance={"CIS": [CIS4, CIS12], "PCI DSS": [PCI_1], "NIST CSF": [NIST_PR_AC]},
            likelihood=5, impact=5, exposure=5, affected_count=len(wan_any)))

    broad = [r for r in rules if r["enabled"] and r["action"] == "Allow"
             and r["src_zone"] != r["dst_zone"] and r["src_zone"] != "WAN"
             and is_any(r.get("src", "")) and is_any(r.get("dst", ""))
             and is_any(r.get("service", "")) and not r.get("auto_rule")]
    if broad:
        out.append(Finding(
            rule_id="FW-ACL-002", title="Inter-zone Any/Any/Any allow rules",
            severity="High", category="Firewall Security",
            description=f"{len(broad)} enabled inter-zone rules allow any source to any destination on any service, dissolving zone segmentation.",
            evidence=[f"Rule {r['num']} {r['src_zone']}->{r['dst_zone']} ({r.get('name') or r.get('comment') or 'unnamed'})"
                      for r in broad][:10],
            business_impact="Zone boundaries provide no containment along these paths; a compromise in one zone propagates freely.",
            technical_impact="Lateral movement between the listed zones is unrestricted.",
            remediation="Decompose each rule into explicit source/destination/service tuples that reflect actual flows (use the rule-usage counters in this report to identify real traffic).",
            verification=["Confirm replacement rules and disable the broad originals for a soak period before deletion"],
            risk_reduction="High", references=[SW_BP],
            compliance={"CIS": [CIS12], "PCI DSS": [PCI_1]},
            likelihood=4, impact=4, exposure=3, affected_count=len(broad)))
    return out


@registry.rule(id="FW-ACL-003", title="Access Rule Hygiene",
               severity="Low", category="Configuration Hygiene")
def rule_hygiene(snap: Snapshot) -> List[Finding]:
    rules = snap.get("access_rules", [])
    out: List[Finding] = []
    disabled = [r for r in rules if not r["enabled"]]
    if disabled:
        out.append(Finding(
            rule_id="FW-ACL-003", title=f"{len(disabled)} disabled access rules present",
            severity="Low", category="Configuration Hygiene",
            description="Disabled rules accumulate in the policy table and obscure the effective policy.",
            evidence=[f"Rule {r['num']} {r['src_zone']}->{r['dst_zone']} ({r.get('name') or r.get('comment') or 'unnamed'})"
                      for r in disabled][:10] + ([f"... and {len(disabled) - 10} more"] if len(disabled) > 10 else []),
            business_impact="Audit complexity and risk of accidental re-enablement of stale access.",
            technical_impact="None while disabled; latent risk only.",
            remediation="Review and delete disabled rules that have been inactive for more than one change cycle.",
            verification=["Confirm the disabled-rule count trends to zero"],
            risk_reduction="Low", references=[SW_BP],
            likelihood=1, impact=2, exposure=1, affected_count=len(disabled)))
    unused = [r for r in rules if r["enabled"] and not r.get("auto_rule")
              and (r.get("usage") in (0, None) and (r.get("last_hit", "").startswith("00/00") or not r.get("last_hit")))]
    if len(unused) >= 5:
        out.append(Finding(
            rule_id="FW-ACL-004", title=f"{len(unused)} enabled access rules show no usage",
            severity="Low", category="Operational Risk",
            description="Enabled, manually created rules with zero hit counts indicate stale policy entries (note: counters reset at reboot; this device reports limited uptime, so validate over a longer window).",
            evidence=[f"Rule {r['num']} {r['src_zone']}->{r['dst_zone']} svc {r.get('service')} ({r.get('name') or 'unnamed'})"
                      for r in unused][:10] + [f"Device uptime at TSR capture: {snap.get('system', {}).get('uptime', 'unknown')}"],
            business_impact="Stale allows widen the attack surface beyond business need.",
            technical_impact="Unneeded permitted paths persist in the policy.",
            remediation="Track usage across consecutive TSR uploads (FireLint drift view) and decommission rules unused for 90+ days.",
            verification=["Compare hit counters across the next monthly TSR"],
            risk_reduction="Low", references=[SW_BP],
            likelihood=2, impact=2, exposure=2, affected_count=len(unused)))
    return out


# ======================================================================
# NAT
# ======================================================================
@registry.rule(id="FW-NAT-001", title="NAT Policy Hygiene",
               severity="Low", category="Configuration Hygiene")
def nat_hygiene(snap: Snapshot) -> List[Finding]:
    nats = snap.get("nat_policies", [])
    out: List[Finding] = []
    user = [n for n in nats if not n.get("system")]
    disabled = [n for n in user if n.get("enabled") is False]
    if disabled:
        out.append(Finding(
            rule_id="FW-NAT-001", title=f"{len(disabled)} disabled custom NAT policies present",
            severity="Low", category="Configuration Hygiene",
            description="Disabled custom NAT policies remain in the table.",
            evidence=[f"#{n['index']} {n.get('name', '')}: {n.get('orig_src')}->{n.get('orig_dst')} svc {n.get('orig_svc')}"
                      for n in disabled][:10],
            business_impact="Policy clutter and risk of unintended re-enablement.",
            technical_impact="Latent translation paths.",
            remediation="Delete NAT policies that are no longer required.",
            verification=["Confirm only required NAT entries remain"],
            risk_reduction="Low", references=[SW_BP],
            likelihood=1, impact=2, exposure=1, affected_count=len(disabled)))
    seen: Dict[str, List[int]] = {}
    for n in user:
        key = "|".join(str(n.get(k, "")) for k in
                       ("orig_src", "orig_dst", "orig_svc", "trans_src", "trans_dst", "trans_svc"))
        seen.setdefault(key, []).append(n["index"])
    dups = {k: v for k, v in seen.items() if len(v) > 1 and k.strip("|")}
    if dups:
        ev = [f"Indexes {v}: {k.replace('|', ' / ')}" for k, v in list(dups.items())[:8]]
        out.append(Finding(
            rule_id="FW-NAT-002", title=f"{len(dups)} duplicate NAT policy tuples detected",
            severity="Medium", category="Configuration Hygiene",
            description="Multiple NAT policies share identical original/translated tuples; only the highest-priority entry takes effect, and the rest shadow it.",
            evidence=ev,
            business_impact="Unpredictable translation behaviour during changes; troubleshooting cost.",
            technical_impact="Shadowed NAT entries can mask intended changes.",
            remediation="Consolidate each duplicate set into a single authoritative policy.",
            verification=["Re-run analysis and confirm zero duplicate tuples"],
            risk_reduction="Low", references=[SW_BP],
            likelihood=2, impact=2, exposure=1, affected_count=len(dups)))
    return out


# ======================================================================
# OBJECT HYGIENE
# ======================================================================
@registry.rule(id="FW-HYG-001", title="Unused Address Objects",
               severity="Low", category="Configuration Hygiene")
def unused_objects(snap: Snapshot) -> List[Finding]:
    ao = snap.get("address_objects", {})
    objects = ao.get("objects", [])
    groups = ao.get("groups", [])
    if not objects:
        return []
    referenced: Set[str] = set()
    for r in snap.get("access_rules", []):
        referenced.add(r.get("src", "")); referenced.add(r.get("dst", ""))
    for n in snap.get("nat_policies", []):
        for k in ("orig_src", "orig_dst", "trans_src", "trans_dst"):
            referenced.add(n.get(k, ""))
    for g in groups:
        referenced.update(g.get("members", []))
    unused = [o["name"] for o in objects
              if o.get("reference_count", 0) == 0
              and not o.get("referenced_by")
              and not o.get("member_of")
              and o["name"] not in referenced]
    if len(unused) < 10:
        return []
    return [Finding(
        rule_id="FW-HYG-001", title=f"{len(unused)} address objects appear unreferenced",
        severity="Low", category="Configuration Hygiene",
        description=f"Of {ao.get('count', len(objects))} address objects, {len(unused)} are reported by the firewall as referenced by zero modules and belong to no group.",
        evidence=["Sample: " + ", ".join(sorted(unused)[:15]) + " ..."],
        business_impact="Object sprawl slows change management and audits, and stale objects get reused incorrectly.",
        technical_impact="No direct exposure; operational debt.",
        remediation="Export the unreferenced-object list (CSV export in this report) and delete after owner review. Note: objects referenced only by routing, DHCP, or content-filter policies require manual confirmation before deletion.",
        verification=["Re-run analysis and confirm the unreferenced count drops"],
        risk_reduction="Low", references=[SW_BP],
        likelihood=1, impact=1, exposure=1, affected_count=len(unused))]


@registry.rule(id="FW-HYG-002", title="Empty Address Groups",
               severity="Low", category="Configuration Hygiene")
def empty_groups(snap: Snapshot) -> List[Finding]:
    groups = snap.get("address_objects", {}).get("groups", [])
    empty = [g["name"] for g in groups if not g.get("members")]
    if not empty:
        return []
    return [Finding(
        rule_id="FW-HYG-002", title=f"{len(empty)} empty address groups",
        severity="Low", category="Configuration Hygiene",
        description="Address groups with no members exist; rules referencing them match nothing, which can silently break intended policy.",
        evidence=["Empty groups: " + ", ".join(sorted(empty)[:15])],
        business_impact="Rules that depend on these groups silently fail to apply.",
        technical_impact="Possible unintended deny/allow behaviour.",
        remediation="Populate or delete each empty group after confirming referencing rules.",
        verification=["Confirm no empty groups remain"],
        risk_reduction="Low", references=[SW_BP],
        likelihood=2, impact=2, exposure=1, affected_count=len(empty))]


# ======================================================================
# CERTIFICATES & LICENSING
# ======================================================================
@registry.rule(id="FW-CRT-001", title="Certificate Validity",
               severity="High", category="Firewall Security")
def cert_checks(snap: Snapshot) -> List[Finding]:
    now = _parse_tsr_time(snap) or datetime.utcnow()
    out: List[Finding] = []
    expired, soon = [], []
    for c in snap.get("certificates", []):
        exp = _parse_expiry(c.get("expires", ""))
        if not exp:
            continue
        if exp < now:
            expired.append(f"{c['alias']} (expired {c['expires']})")
        elif exp < now + timedelta(days=90):
            soon.append(f"{c['alias']} (expires {c['expires']})")
    if expired:
        out.append(Finding(
            rule_id="FW-CRT-001", title=f"{len(expired)} expired certificates on device",
            severity="High", category="Firewall Security",
            description="Expired certificates are present in the device PKI store.",
            evidence=expired[:10],
            business_impact="Services bound to expired certificates trigger browser/client trust failures and train users to ignore warnings.",
            technical_impact="TLS validation failures; potential service interruption for portals/VPN.",
            remediation="Renew or remove each expired certificate; confirm no active service (management, SSL VPN, DPI-SSL) is bound to one.",
            verification=["Confirm all in-use certificates show a future expiry"],
            risk_reduction="Medium", references=[SW_BP],
            compliance={"PCI DSS": [PCI_2]},
            likelihood=3, impact=3, exposure=3, affected_count=len(expired)))
    if soon:
        out.append(Finding(
            rule_id="FW-CRT-002", title=f"{len(soon)} certificates expire within 90 days",
            severity="Medium", category="Operational Risk",
            description="Certificates approach expiry; plan renewal to avoid outage.",
            evidence=soon[:10],
            business_impact="Unplanned expiry of the management/SSL VPN certificate interrupts remote access.",
            technical_impact="TLS services fail validation at expiry.",
            remediation="Schedule renewal now; automate expiry alerting via FireLint email alerts.",
            verification=["Confirm renewed certificates are installed and bound"],
            risk_reduction="Low", references=[SW_BP],
            likelihood=3, impact=3, exposure=2, affected_count=len(soon)))
    return out


@registry.rule(id="FW-LIC-001", title="Security Service Subscriptions Expiring",
               severity="Medium", category="Operational Risk")
def license_expiry(snap: Snapshot) -> List[Finding]:
    now = _parse_tsr_time(snap) or datetime.utcnow()
    ss = snap.get("security_services", {})
    soon = []
    for key, label in (("ips_expires", "IPS"), ("gav_expires", "Gateway Anti-Virus"),
                       ("anti_spyware_expires", "Anti-Spyware"),
                       ("content_filter_expires", "Content Filter Premium")):
        exp = _parse_expiry(ss.get(key, ""))
        if exp and exp < now + timedelta(days=60):
            soon.append(f"{label}: expires {ss.get(key)}")
    if not soon:
        return []
    return [Finding(
        rule_id="FW-LIC-001", title="Security service subscriptions expire within 60 days",
        severity="Medium", category="Operational Risk",
        description="One or more inline-security subscriptions lapse soon; on expiry the corresponding protections stop updating or functioning.",
        evidence=soon + [f"TSR capture date: {snap.get('system', {}).get('time', '')}"],
        business_impact="Signature updates and inline protection cease at expiry, silently degrading the security posture.",
        technical_impact="Stale signatures; some services disable entirely on lapse.",
        remediation="Renew the subscriptions (or the security bundle) before the earliest expiry date.",
        verification=["Confirm expiry dates extend at least 12 months after renewal"],
        risk_reduction="Medium", references=[SW_BP],
        likelihood=4, impact=4, exposure=2, affected_count=len(soon))]


# ======================================================================
# HA / LOGGING
# ======================================================================
@registry.rule(id="FW-HA-001", title="High Availability Hardening",
               severity="Low", category="Operational Risk")
def ha_checks(snap: Snapshot) -> List[Finding]:
    ha = snap.get("ha", {})
    if not ha or not ha.get("mode") or ha.get("mode", "").lower() == "none":
        return []
    out: List[Finding] = []
    if ha.get("encryption") is False:
        out.append(Finding(
            rule_id="FW-HA-001", title="HA control-link encryption disabled",
            severity="Low", category="Operational Risk",
            description="State synchronisation between HA peers is not encrypted.",
            evidence=[f"HA Mode: {ha.get('mode')}", "Enable Encryption: No"],
            business_impact="Session/state data on the HA link is readable by anyone with access to that segment.",
            technical_impact="HA sync traffic, including connection state, transits in cleartext.",
            remediation="Enable HA encryption, or guarantee the HA link is a dedicated, physically secured point-to-point connection.",
            verification=["Confirm 'Enable Encryption: Yes' under HA settings"],
            risk_reduction="Low", references=[SW_BP],
            likelihood=1, impact=3, exposure=1))
    return out


@registry.rule(id="FW-LOG-001", title="Remote Logging Inactive",
               severity="Medium", category="Operational Risk")
def remote_logging(snap: Snapshot) -> List[Finding]:
    lg = snap.get("logging", {})
    servers = lg.get("syslog_servers", [])
    if not servers:
        return []
    if lg.get("active_syslog_servers", 0) > 0:
        return []
    return [Finding(
        rule_id="FW-LOG-001", title="No active remote syslog destination",
        severity="Medium", category="Operational Risk",
        description=f"{len(servers)} syslog server(s) are defined but all are disabled; logs exist only on-device.",
        evidence=[f"Syslog server {s['name']}: {s['enabled'] or 'Disabled'}" for s in servers][:5],
        business_impact="If the firewall is compromised or fails, the evidence needed for incident response disappears with it.",
        technical_impact="No off-device log retention; on-box buffers are small and overwrite quickly.",
        remediation="Enable at least one syslog destination to the SIEM/collector and verify event delivery; enable login/IPS event classes at minimum.",
        verification=["Confirm events arrive at the collector with correct timestamps"],
        risk_reduction="Medium", references=[SW_BP],
        compliance={"CIS": [CIS8], "PCI DSS": [PCI_10], "NIST CSF": [NIST_DE_CM]},
        likelihood=3, impact=4, exposure=2)]