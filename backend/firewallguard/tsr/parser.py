"""TSR parser engine.

Transforms a raw TSR into a structured, JSON-serialisable *snapshot* used by
the rule engine, drift detection, and reporting layers.  Each ``parse_*``
function is independent and defensive: a missing or malformed section yields
an empty structure rather than an exception, because TSR layout varies across
SonicOS releases (6.5 vs 7.x) and platforms (TZ/NSa/NSsp/NSv).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from .reader import Section, TSRDocument, iter_blocks

Snapshot = Dict[str, Any]


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _to_bool(value: str) -> Optional[bool]:
    v = value.strip().lower()
    if v in {"enabled", "yes", "on", "1", "true", "activated"}:
        return True
    if v in {"disabled", "not enabled", "no", "off", "0", "false", "none"}:
        return False
    return None


def _to_int(value: str) -> Optional[int]:
    m = re.search(r"-?\d+", value or "")
    return int(m.group()) if m else None


def _split_ifaces(value: str) -> List[str]:
    v = (value or "").strip()
    if not v or v.lower() == "none":
        return []
    return v.split()


def _strip_firmware_branding(fw: str) -> str:
    """Remove product branding prefixes so only the version number remains.

    "SonicOS Enhanced 6.5.4.15-117n" -> "6.5.4.15-117n"
    "SonicOS 7.1.2-7019-R6288"      -> "7.1.2-7019-R6288"
    """
    import re
    return re.sub(r"^SonicOS\s*(?:Enhanced\s*)?", "", fw).strip()


# ----------------------------------------------------------------------
# section parsers
# ----------------------------------------------------------------------
def parse_system(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Blade_\d+_STATUS$") or doc.first_like(r"System : Status")
    if not sec:
        return {}
    kv = sec.kv()
    return {
        "model": kv.get("Model", ""),
        "firmware": _strip_firmware_branding(kv.get("Firmware Version", "")),
        "rom_version": kv.get("ROM Version", ""),
        "serial": kv.get("Serial number", ""),
        "uptime": kv.get("SonicWall has been up", ""),
        "ha_mode": kv.get("HA Mode", ""),
        "time": kv.get("Time", ""),
        "memory": kv.get("Memory", ""),
        "max_connections": _to_int(kv.get("Max Allowed Connections", "")),
        "current_connections": _to_int(kv.get("Current Connections", "")),
        "firewall_uptime_raw": kv.get("SonicWall has been up", ""),
    }


def parse_licenses(doc: TSRDocument) -> Dict[str, str]:
    sec = doc.first_like(r"LICENSE_INFO")
    return sec.kv() if sec else {}


def parse_administration(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Blade_\d+_Administration$")
    if not sec:
        return {}
    kv = sec.kv()
    api_md5 = None
    # Space-tolerant so it holds for a normalized API TSR where the
    # "Enabled digest algorithms" phrase was whitespace-collapsed.
    dm = re.search(r"Enabled\s*digest\s*algorithms.{0,120}?MD5\s*:\s*(\w+)",
                   "\n".join(sec.lines), re.IGNORECASE | re.DOTALL)
    if dm:
        api_md5 = _to_bool(dm.group(1))
    return {
        "firewall_name": kv.get("Firewall Name", ""),
        "admin_name": kv.get("Administrator Name", ""),
        "admin_otp": kv.get("Administrator One Time Password Option", ""),
        "password_change_period_days": _to_int(kv.get("Password Change Period(in days)", "")),
        "min_password_length": _to_int(kv.get("Minimum Password Length", "")),
        "password_complexity_level": _to_int(kv.get("Password Complexity Level", "")),
        "password_uniqueness_changes": _to_int(kv.get("Enforce Password Uniqueness For", "")),
        "admin_timeout_minutes": _to_int(kv.get("Administrator Timeout", "")),
        "lockout_enabled": _to_bool(kv.get("Enable User Lockout On Login Failure", "")),
        "http_port": _to_int(kv.get("HTTP Management Port", "")),
        "https_port": _to_int(kv.get("HTTPS Management Port", "")),
        "https_cert_name": kv.get("Https Cert Name", ""),
        "http_mgmt_interfaces": _split_ifaces(kv.get("HTTP Management Allowed On Interfaces", "")),
        "https_mgmt_interfaces": _split_ifaces(kv.get("HTTPS Management Allowed On Interfaces", "")),
        "ssh_mgmt_interfaces": _split_ifaces(kv.get("SSH Management Allowed On Interfaces", "")),
        "snmp_interfaces": _split_ifaces(kv.get("SNMP Allowed On Interfaces", "")),
        "ping_interfaces": _split_ifaces(kv.get("Ping Allowed On Interfaces", "")),
        "sonicos_api_enabled": _to_bool(kv.get("SonicOS API", "")),
        "sonicos_api_md5_digest": api_md5,
        "enhanced_audit_logging": _to_bool(kv.get("Enhanced Audit Logging", "")),
    }


def parse_snmp(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Blade_\d+_SNMP$")
    if not sec:
        return {}
    kv = sec.kv()
    return {
        "enabled": _to_bool(kv.get("SNMP", "")),
        "get_community_set": bool(kv.get("Get Community Name", "").strip()),
        "trap_community_set": bool(kv.get("Trap Community Name", "").strip()),
        "system_name": kv.get("System Name", ""),
    }


def parse_interfaces(doc: TSRDocument) -> List[Dict[str, Any]]:
    sec = doc.first_like(r"^Blade_\d+_INTERFACES$")
    if not sec:
        return []
    out: List[Dict[str, Any]] = []
    header = r"^Interface Name\s+:\s+(?P<name>\S+)"
    for m, block in iter_blocks(sec.lines, header):
        rec: Dict[str, Any] = {"name": m.group("name"), "zone": "", "ip": "", "mask": "",
                               "link_status": "", "comment": "", "vlans": []}
        for line in block:
            zm = re.match(r"^Zone\s+:\s+(\S+)", line)
            if zm and not rec["zone"]:
                rec["zone"] = zm.group(1)
            km = re.match(r"^(IP Address|Network Mask|Comment|MTU)\s+:\s+(.*)$", line)
            if km:
                key, val = km.group(1), km.group(2).strip()
                if key == "IP Address" and not rec["ip"]:
                    rec["ip"] = val
                elif key == "Network Mask" and not rec["mask"]:
                    rec["mask"] = val
                elif key == "Comment" and not rec["comment"]:
                    rec["comment"] = val
            lm = re.match(r"^Link Status:\s*(\S+)", line)
            if lm and not rec["link_status"]:
                rec["link_status"] = lm.group(1)
        out.append(rec)
    return out


def parse_zones(doc: TSRDocument) -> List[Dict[str, Any]]:
    sec = doc.first_like(r"^Network : Zones$")
    if not sec:
        return []
    out: List[Dict[str, Any]] = []
    header = r"^-{5,}\s*(?P<name>.+?)\((?P<inner>.+?)\)\s*-{5,}\s*$"
    for m, block in iter_blocks(sec.lines, header):
        rec: Dict[str, Any] = {"name": m.group("name").strip()}
        kv: Dict[str, str] = {}
        for line in block:
            km = re.match(r"^\s*([^:]{2,60}?)\s*:\s*(.+)$", line)
            if km and km.group(1).strip() not in kv:
                kv[km.group(1).strip()] = km.group(2).strip()
        rec.update({
            "security_type": kv.get("Security Type", ""),
            "gav": _to_bool(kv.get("Enable Gateway Anti-Virus Service", "")),
            "ips": _to_bool(kv.get("Enable IPS", "")),
            "anti_spyware": _to_bool(kv.get("Enable Anti-Spyware Service", "")),
            "app_control": _to_bool(kv.get("Enable App Control Service", "")),
            "dpi_ssl_client": _to_bool(kv.get("Enable SSL Client Inspection", "")),
            "sslvpn_access": _to_bool(kv.get("Enable SSLVPN Access", "")),
        })
        out.append(rec)
    return out


def parse_address_objects(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Network : Address Objects$")
    if not sec:
        return {"count": 0, "objects": [], "groups": []}
    count = _to_int(sec.value("Number of objects", "")) or 0
    objects: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    in_group_table = False
    header = r"^-{5,}\s*(?P<name>.+?)\s*-{5,}\s*$"
    current: Optional[Dict[str, Any]] = None
    for line in sec.lines:
        if "--Address Group Table--" in line:
            in_group_table = True
            continue
        if "--Address Object Table--" in line:
            in_group_table = False
            continue
        m = re.match(header, line)
        if m:
            raw = m.group("name").strip()
            name = re.sub(r"\((.*)\)$", "", raw).strip()
            current = {"name": name, "members": [], "member_of": [],
                       "obj_type": None, "value": None, "obj_class": None,
                       "reference_count": 0, "referenced_by": []}
            (groups if in_group_table else objects).append(current)
            continue
        if current is None:
            continue
        cm = re.match(r"\s*Class\s*:\s*(?P<c>\w+)", line)
        if cm:
            current["obj_class"] = cm.group("c").strip()
            continue
        mm = re.match(r"\s*member\s*:\s*Name\s*:\s*(?P<mn>.+?)\s+(?:Subnet\s+)?Handle\s*:\s*\d+", line)
        if mm:
            current["members"].append(mm.group("mn").strip())
            continue
        tm = re.match(r"\s*(?P<t>HOST|NETWORK|RANGE|MAC|FQDN)\s*:\s*(?P<v>.+)$", line)
        if tm:
            current["obj_type"] = tm.group("t")
            current["value"] = tm.group("v").strip()
            continue
        rm = re.match(r"\s*(?P<n>\d+)\s+times\s+referenced by Module:\s*(?P<mod>.+)$", line)
        if rm:
            current["reference_count"] += _to_int(rm.group("n")) or 0
            current["referenced_by"].append(rm.group("mod").strip())
            continue
        gm = re.match(r"\s*Group\s*\(Member of\)\s*:\s*(?P<g>.+)$", line)
        if gm:
            current["member_of"] = [g.strip() for g in gm.group("g").split(",") if g.strip()]
    return {"count": count, "objects": objects, "groups": groups}


def parse_services(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Network : Services$")
    if not sec:
        return {"count": 0, "objects": [], "groups": []}
    res = {"count": _to_int(sec.value("Number of objects", "")) or 0,
           "objects": [], "groups": []}
    header = r"^-{5,}\s*(?P<name>.+?)\s*-{5,}\s*$"
    in_groups = False
    current = None
    for line in sec.lines:
        if "--Service Group Table--" in line:
            in_groups = True
            continue
        if "--Service Object Table--" in line:
            in_groups = False
            continue
        m = re.match(header, line)
        if m:
            raw = m.group("name").strip()
            name = re.sub(r"\((.*)\)$", "", raw).strip()
            current = {"name": name, "members": [], "member_of": [],
                       "iptype": None, "ports": None}
            res["groups" if in_groups else "objects"].append(current)
            continue
        if current is None:
            continue
        pm = re.match(r"\s*Ip\s*Type\s*:\s*(?P<ip>\d+)\s*,\s*Ports\s*:\s*(?P<p>.+)$", line)
        if pm:
            current["iptype"] = _to_int(pm.group("ip"))
            current["ports"] = pm.group("p").strip()
            continue
        mm = re.match(r"\s*member\s*:\s*Name\s*:\s*(?P<mn>.+?)\s+Handle\s*:\s*\d+", line)
        if mm:
            current["members"].append(mm.group("mn").strip())
            continue
        gm = re.match(r"\s*Group\s*\(Member of\)\s*:\s*(?P<g>.+)$", line)
        if gm:
            current["member_of"] = [g.strip() for g in gm.group("g").split(",") if g.strip()]
    return res


_RULE_HEADER = (
    r"^Rule\s+(?P<num>\d+)\s+(?P<src_zone>\S+)\s*->\s*(?P<dst_zone>\S+)\s+"
    r"(?P<action>Allow|Deny|Discard)\s+Service\s+(?P<svc_src>.*?)\s*->\s*"
    r"(?P<svc_dst>.*?)\s+\((?P<state>Enabled|Disabled)\)\s*$"
)


def parse_access_rules(doc: TSRDocument) -> List[Dict[str, Any]]:
    sec = doc.first_like(r"^Blade_\d+_ACCESS_RULES$")
    if not sec:
        return []
    out: List[Dict[str, Any]] = []
    for m, block in iter_blocks(sec.lines, _RULE_HEADER):
        rec: Dict[str, Any] = {
            "num": int(m.group("num")),
            "src_zone": m.group("src_zone"),
            "dst_zone": m.group("dst_zone"),
            "action": m.group("action"),
            "service": m.group("svc_dst").strip(),
            "enabled": m.group("state") == "Enabled",
            "src": "", "dst": "", "name": "", "comment": "",
            "auto_rule": False, "management": False,
            "usage": None, "last_hit": "", "ipver": "IPv4",
        }
        for line in block:
            ipm = re.match(r"\s*IP\s*:\s*(?P<s>.+?)\s*->\s*(?P<d>.+?)(?:\s+Iface\b|\s*$)", line)
            if ipm:
                rec["src"], rec["dst"] = ipm.group("s").strip(), ipm.group("d").strip()
                continue
            # Normalized API records may split the Management flag onto its own line.
            mgmt = re.match(r"^\s*Management\s*:\s*(\S+)\s*$", line)
            if mgmt:
                rec["management"] = mgmt.group(1) == "Enabled"
                continue
            for key, field_, cast in (
                ("Policy Name", "name", str), ("Comment", "comment", str),
                ("Usage", "usage", int), ("Time Last Hit", "last_hit", str),
                ("IP Version", "ipver", str),
            ):
                km = re.match(rf"^{key}\s*:\s*(.*)$", line)
                if km:
                    val = km.group(1).strip()
                    rec[field_] = _to_int(val) if cast is int else val
            if re.match(r"^Auto Rule:\s*Enabled", line):
                rec["auto_rule"] = True
            lm = re.match(r"^Logging:\s*\S+\s+Management:\s*(\S+)", line)
            if lm:
                rec["management"] = lm.group(1) == "Enabled"
        out.append(rec)
    return out


def parse_nat_policies(doc: TSRDocument) -> List[Dict[str, Any]]:
    sec = doc.first_like(r"^Blade_\d+_NAT_POLICY_TABLE$")
    if not sec:
        return []
    out: List[Dict[str, Any]] = []
    header = r"^Index\s+:\s+(?P<idx>\d+)\s*$"
    for m, block in iter_blocks(sec.lines, header):
        rec: Dict[str, Any] = {"index": int(m.group("idx"))}
        for line in block:
            km = re.match(r"^([A-Za-z][A-Za-z0-9 /_().-]{2,40}?)\s*:\s*(.*)$", line)
            if not km:
                continue
            key, val = km.group(1).strip(), km.group(2).strip()
            mapping = {
                "Name": "name", "Original Source": "orig_src",
                "Translated Source": "trans_src", "Original Destination": "orig_dst",
                "Translated Destination": "trans_dst", "Original Service": "orig_svc",
                "Translated Service": "trans_svc", "Comment": "comment",
                "Inbound Interface": "in_iface", "Outbound Interface": "out_iface",
            }
            if key in mapping and mapping[key] not in rec:
                rec[mapping[key]] = val
            elif key == "Enable NAT Policy":
                rec["enabled"] = val.strip() == "1"
            elif key == "System Policy":
                rec["system"] = val.strip() == "1"
            elif key == "Usage" and "usage" not in rec:
                rec["usage"] = _to_int(val)
        out.append(rec)
    return out


def parse_vpn(doc: TSRDocument) -> Dict[str, Any]:
    top = doc.first_like(r"^VPN : Settings$")
    if not top:
        return {"policies": [], "ikev2_dynamic_proposal": ""}
    sec = doc.nth_like(r"^Blade_\d+_SETTINGS$", top) or top
    policies: List[Dict[str, Any]] = []
    ikev2_dyn = ""
    for line in sec.lines:
        dm = re.match(r"^Dynamic Client Proposal\s*:\s*(.*)$", line)
        if dm:
            ikev2_dyn = dm.group(1).strip()
    header = r"^--- SA (?P<n>\d+) ---\s*$"
    for m, block in iter_blocks(sec.lines, header):
        rec: Dict[str, Any] = {"sa": int(m.group("n")), "name": "", "enabled": True,
                               "type": "", "exchange": "", "ike_proposal": "",
                               "ipsec_proposal": "", "pfs": None, "zone": "",
                               "auth_method": ""}
        for line in block:
            nm = re.match(r"^VPN Policy Name\s*:\s*\"(?P<n>.+?)\";\s*(?P<st>\w+)", line)
            if nm:
                rec["name"] = nm.group("n")
                rec["enabled"] = nm.group("st").lower() == "enabled"
                continue
            for key, field_ in (("Authentication Method", "auth_method"),
                                ("Policy Type", "type"), ("IKE Exchange", "exchange"),
                                ("IKE Proposal", "ike_proposal"),
                                ("IPsec Proposal", "ipsec_proposal")):
                km = re.match(rf"^{key}\s*:\s*(.*)$", line)
                if km and not rec[field_]:
                    rec[field_] = km.group(1).strip()
            pm = re.search(r"PFS:\s*(\w+)", line)
            if pm and rec["pfs"] is None:
                rec["pfs"] = pm.group(1).lower() == "on"
            zm = re.match(r"^VPN policy\s*:\s*Bound to zone\s+(\S+)", line)
            if zm:
                rec["zone"] = zm.group(1)
        if rec["name"] or rec["ike_proposal"]:
            policies.append(rec)
    return {"policies": policies, "ikev2_dynamic_proposal": ikev2_dyn}


def parse_sslvpn(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^SSL VPN : Server Settings$")
    if not sec:
        return {}
    zones: Dict[str, bool] = {}
    in_zones = False
    kv = sec.kv()
    for line in sec.lines:
        if "--SSL VPN Status on Zones--" in line:
            in_zones = True
            continue
        if line.startswith("--") and in_zones and "Zones" not in line:
            in_zones = False
        if in_zones:
            m = re.match(r"^(?P<z>.+?)\s{2,}:\s*(?P<st>Enabled|Disabled)\s*$", line)
            if m:
                zones[m.group("z").strip()] = m.group("st") == "Enabled"
    return {
        "zones": zones,
        "port": _to_int(kv.get("SSL VPN Port", "")),
        "certificate": kv.get("Certificate Selection", ""),
        "user_domain": kv.get("SSL VPN User Domain", ""),
        "web_mgmt_over_sslvpn": _to_bool(kv.get("Enable Web Management over SSL VPN", "")),
        "ssh_mgmt_over_sslvpn": _to_bool(kv.get("Enable SSH Management over SSL VPN", "")),
        "inactivity_timeout": _to_int(kv.get("Inactivity Timeout", "")),
    }


def parse_user_settings(doc: TSRDocument) -> Dict[str, Any]:
    top = doc.first_like(r"^Users : Settings$")
    if not top:
        return {}
    kv = top.kv()
    return {
        "auth_method": kv.get("Authentication method for login", ""),
        "case_sensitive_usernames": kv.get("Case-sensitive user names", ""),
        "otp_complexity": kv.get("Enforce password complexity for OTP", ""),
    }


def parse_local_users(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Users : Local Users$")
    if not sec:
        return {"count": 0, "admins": []}
    names = re.findall(r"^-{3,}\s*(.+?)\s*-{3,}\s*$", sec.text, re.M)
    admin_hits = [n for n in names if "admin" in n.lower()]
    return {"count": len(names), "admins": admin_hits[:25]}


def parse_certificates(doc: TSRDocument) -> List[Dict[str, Any]]:
    sec = doc.first_like(r"^Blade_\d+_PKI$")
    if not sec:
        return []
    out: List[Dict[str, Any]] = []
    header = r"^\s*Certificate Alias:\s*(?P<alias>.+?)\s*$"
    for m, block in iter_blocks(sec.lines, header):
        rec: Dict[str, Any] = {"alias": m.group("alias"), "issuer": "", "subject": "",
                               "expires": "", "invalid": None}
        for line in block:
            for key, field_ in (("Issuer", "issuer"), ("Subject Name", "subject")):
                km = re.match(rf"^\s*{key}\s*=\s*(.*)$", line)
                if km and not rec[field_]:
                    rec[field_] = km.group(1).strip()
            em = re.match(r"^\s*Expires\s*=\s*(.*)$", line)
            if em and not rec["expires"]:
                rec["expires"] = em.group(1).strip()
            im = re.match(r"^\s*Certificate is Invalid:\s*(\S+)", line)
            if im and rec["invalid"] is None:
                rec["invalid"] = im.group(1).lower() == "yes"
        rec["self_signed"] = bool(rec["issuer"]) and rec["issuer"] == rec["subject"]
        out.append(rec)
    return out


def parse_ha(doc: TSRDocument) -> Dict[str, Any]:
    top = doc.first_like(r"^High Availability : Settings$")
    if not top:
        return {}
    kv = top.kv()
    return {
        "mode": kv.get("Mode", ""),
        "stateful_sync": _to_bool(kv.get("Enable Stateful Synchronization", "")),
        "preempt": _to_bool(kv.get("Enable Preempt Mode", "")),
        "virtual_mac": _to_bool(kv.get("Enable Virtual MAC", "")),
        "encryption": _to_bool(kv.get("Enable Encryption", "")),
    }


def parse_security_services(doc: TSRDocument) -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    summary = doc.first_like(r"^Security Services : Summary$")
    if summary:
        res["profile"] = summary.value("Security Services Setting")
    cfs = doc.first_like(r"^Blade_\d+_Content Filter$")
    if cfs:
        res["content_filter_enabled"] = _to_bool(cfs.value("Enable Content Filtering Service"))
        res["content_filter_license"] = cfs.value("CFS License")
        res["content_filter_expires"] = cfs.value("Premium Subscription Expires On")
    gav = doc.first_like(r"^Blade_\d+_Gateway Anti-Virus$")
    if gav:
        res["gav_enabled"] = _to_bool(gav.value("Enable Gateway Anti-Virus"))
        res["gav_http_outbound"] = _to_bool(gav.value("HTTP Outbound Inspection"))
        res["gav_expires"] = gav.value("Gateway Anti-Virus Expiration Date")
    ips = doc.first_like(r"^Blade_\d+_Intrusion Prevention$")
    if ips:
        res["ips_enabled"] = _to_bool(ips.value("Enable IPS"))
        res["ips_prevent_high"] = _to_bool(ips.value("Prevent All High Priority Attacks"))
        res["ips_prevent_medium"] = _to_bool(ips.value("Prevent All Medium Priority Attacks"))
        res["ips_prevent_low"] = _to_bool(ips.value("Prevent All Low Priority Attacks"))
        res["ips_expires"] = ips.value("IPS Expiration Date")
    asw = doc.first_like(r"^Blade_\d+_ANTI_SPYWARE$")
    if asw:
        res["anti_spyware_enabled"] = _to_bool(asw.value("Enable Anti-Spyware"))
        res["anti_spyware_expires"] = asw.value("Anti-Spyware Expiration Date")
    dpi = doc.first_like(r"^Blade_\d+_Client SSL$")
    if dpi:
        res["dpi_ssl_client_licensed"] = dpi.value("Client DPI-SSL")
        res["dpi_ssl_client_enabled"] = _to_bool(dpi.value("Enable SSL Client Inspection"))
    dea = doc.first_like(r"^Blade_\d+_DEA$")
    res["capture_atp_evidence"] = bool(dea and len(dea.text.strip()) > 40)
    gb = doc.first_like(r"Geo-?IP")
    res["geoip_section_present"] = gb is not None
    bn = doc.first_like(r"Botnet Filter")
    res["botnet_section_present"] = bn is not None
    return res


def parse_logging(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Blade_\d+_Syslog$")
    if not sec:
        return {}
    servers: List[Dict[str, str]] = []
    header = r"^Server Name\s+:\s+(?P<n>\S+)\s*$"
    for m, block in iter_blocks(sec.lines, header):
        rec = {"name": m.group("n"), "enabled": ""}
        for line in block:
            sm = re.match(r"^\s*Server\s+:\s+(\S+)", line)
            if sm and not rec["enabled"]:
                rec["enabled"] = sm.group(1)
        servers.append(rec)
    active = [s for s in servers if s["enabled"].lower() == "enabled"]
    return {"syslog_servers": servers, "active_syslog_servers": len(active)}


# ----------------------------------------------------------------------
# orchestrator
# ----------------------------------------------------------------------
def parse_tsr(text: str, source_name: str = "tsr") -> Snapshot:
    doc = TSRDocument(text)
    snapshot: Snapshot = {
        "meta": {
            "source": source_name,
            "parsed_at": datetime.utcnow().isoformat() + "Z",
            "section_count": len(doc.sections),
            "engine_version": "0.10.0",
        },
        "system": parse_system(doc),
        "licenses": parse_licenses(doc),
        "administration": parse_administration(doc),
        "snmp": parse_snmp(doc),
        "interfaces": parse_interfaces(doc),
        "zones": parse_zones(doc),
        "address_objects": parse_address_objects(doc),
        "services": parse_services(doc),
        "access_rules": parse_access_rules(doc),
        "nat_policies": parse_nat_policies(doc),
        "vpn": parse_vpn(doc),
        "sslvpn": parse_sslvpn(doc),
        "user_settings": parse_user_settings(doc),
        "local_users": parse_local_users(doc),
        "certificates": parse_certificates(doc),
        "ha": parse_ha(doc),
        "security_services": parse_security_services(doc),
        "logging": parse_logging(doc),
    }
    from .parser_ext import enrich_snapshot
    enrich_snapshot(doc, snapshot)
    # Structure-preserving sweep of the *entire* document, so every TSR
    # section — including ones no curated parser knows about — is browsable
    # in the CEL Rule Builder and addressable as snapshot.config[...] in
    # rules. Added last; it never touches the curated keys above.
    from .generic import build_config_tree
    snapshot["config"] = build_config_tree(text)
    return snapshot
