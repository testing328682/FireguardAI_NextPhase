"""Parser extensions for full check-catalog parity.

These functions parse the additional TSR sections needed by the expanded rule
catalog (firewall/flood/DDoS settings, local users and MFA coverage, WLAN/SSID
security, content-filter detail, performance/CPU, and authentication servers).
They follow the same defensive conventions as ``parser.py``: every function
tolerates a missing section and returns an empty structure rather than raising.

``enrich_snapshot`` is called by ``parse_tsr`` to fold these into the snapshot.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .reader import TSRDocument, iter_blocks


def _b(val: str) -> bool:
    return str(val).strip().lower() in ("enabled", "yes", "on", "true", "1")


def _onoff(line: str, label: str) -> str:
    m = re.search(re.escape(label) + r"\s*[:=]\s*(.+)$", line)
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# Firewall settings: stealth, flood protection, DDoS, FTP, source routing
# ---------------------------------------------------------------------------
def parse_firewall_settings(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"Firewall Settings : Advanced") or doc.first_like(r"^Blade_\d+_FW.*ADVANCED")
    res: Dict[str, Any] = {"present": sec is not None}
    if not sec:
        return res
    text = "\n".join(sec.lines)

    def find(pattern: str, default: str = "") -> str:
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    # Phrase keys are matched with \s* between words so they hold for both the GUI
    # TSR (spaced) and a normalized API TSR (whitespace-collapsed within keys).
    res["stealth_mode"] = _b(find(r"Stealth\s*Mode\s*:\s*(\w+)"))
    res["drop_source_routed"] = find(r"Drop\s*source\s*routed\s*IP\s*packets\s*:\s*(\w+)").lower() in ("yes", "enabled")
    res["ftp_bounce_protection"] = find(r"FTP\s*bounce\s*attack\s*protection\s*=\s*(\d+)") == "1"
    res["tcp_handshake_enforcement"] = _b(find(r"Enable\s*TCP\s*handshake\s*enforcement\s*:\s*(\w+)"))
    res["strict_tcp_rfc"] = _b(find(r"Enforce\s*strict\s*TCP\s*compliance.*?:\s*(\w+)"))
    res["always_allow_sonicwall_mgmt"] = _b(find(r"Always\s*allow\s*SonicWall\s*management\s*traffic\s*:\s*(\w+)"))

    # Flood protection block
    res["syn_flood_mode"] = find(r"SYN\s*Flood\s*Protection\s*Mode\s*:\s*(.+)")
    res["syn_proxy_watch_only"] = "watch" in res["syn_flood_mode"].lower()
    res["udp_flood_protection"] = _b(find(r"Enable\s*UDP\s*Flood\s*Protection\s*:\s*(\w+)"))
    res["icmp_flood_protection"] = _b(find(r"Enable\s*ICMP\s*Flood\s*Protection\s*:\s*(\w+)"))
    res["wan_ddos_protection"] = _b(find(r"DDOS\s*protection\s*on\s*WAN\s*interfaces\s*:\s*(\w+)"))
    res["security_services_enforcement"] = find(r"Security\s*Services\s*Enforcements\s*:\s*(\w+)")
    return res


# ---------------------------------------------------------------------------
# Local users and MFA coverage
# ---------------------------------------------------------------------------
def parse_local_users_detailed(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Blade_\d+_Local Users$") or doc.first_like(r"Users : Local Users")
    res: Dict[str, Any] = {"users": [], "count": 0,
                           "mfa_enabled_count": 0, "mfa_disabled_count": 0}
    if not sec:
        return res
    text = "\n".join(sec.lines)
    res["apply_password_constraints_all"] = bool(
        re.search(r"Apply password constraints for all local users\s*:\s*yes", text, re.IGNORECASE))
    # Each user starts " N,  <name>"
    header = r"^\s*(?P<idx>\d+),\s+(?P<name>.+?)\s*$"
    users: List[Dict[str, Any]] = []
    for m, block in iter_blocks(sec.lines, header):
        btext = "\n".join(block)
        name = m.group("name").strip()
        # OTP/TOTP indicates MFA. SonicOS shows "One Time Password ... Enabled"
        # or a TOTP binding. Absence => MFA disabled.
        mfa = bool(re.search(r"(One Time Password|TOTP|OTP).*?(Enabled|Configured|Yes)", btext, re.IGNORECASE)) \
            or bool(re.search(r"MFA\s*:\s*(Enabled|Yes)", btext, re.IGNORECASE))
        created = ""
        cm = re.search(r"Time Created:\s*([0-9/: .]+)", btext)
        if cm:
            created = cm.group(1).strip()
        updated = ""
        um = re.search(r"Last Updated:\s*([0-9/: .]+)", btext)
        if um:
            updated = um.group(1).strip()
        is_admin = bool(re.search(r"Full=yes", btext))
        users.append({"name": name, "mfa": mfa, "is_admin": is_admin,
                      "created": created, "updated": updated})
    res["users"] = users
    res["count"] = len(users)
    res["mfa_enabled_count"] = sum(1 for u in users if u["mfa"])
    res["mfa_disabled_count"] = sum(1 for u in users if not u["mfa"])
    return res


# ---------------------------------------------------------------------------
# WLAN / SSID security
# ---------------------------------------------------------------------------
def parse_wlan(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Blade_\d+_WLAN$") or doc.first_like(r"Wireless : Wlan")
    res: Dict[str, Any] = {"present": sec is not None, "ssids": [], "interface_count": 0}
    if not sec:
        return res
    text = "\n".join(sec.lines)
    m = re.search(r"Interface count:\s*(\d+)", text)
    res["interface_count"] = int(m.group(1)) if m else 0
    res["allow_wpa"] = bool(re.search(r"Allow WPA:\s*Yes", text, re.IGNORECASE))
    # SSID/VAP detail lives in the VAP section; capture names + encryption if present
    vap = doc.first_like(r"WLAN Virtual Access Point") or doc.first_like(r"^Blade_\d+_WLAN_VAP$")
    ssids: List[Dict[str, Any]] = []
    if vap:
        for line in vap.lines:
            sm = re.search(r"SSID\s*:\s*(.+?)\s*(?:Encryption|Auth|$)", line)
            if sm:
                enc = ""
                em = re.search(r"Encryption\s*:\s*(\S+)", line)
                if em:
                    enc = em.group(1)
                ssids.append({"ssid": sm.group(1).strip(), "encryption": enc})
    res["ssids"] = ssids
    return res


# ---------------------------------------------------------------------------
# Content Filter Service detail
# ---------------------------------------------------------------------------
def parse_cfs(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"Security Services : Content Filter") or doc.first_like(r"Content Filter")
    res: Dict[str, Any] = {"present": sec is not None}
    if not sec:
        return res
    text = "\n".join(sec.lines)

    def has(p: str) -> bool:
        m = re.search(p, text, re.IGNORECASE)
        return _b(m.group(1)) if m else False

    res["https_filtering"] = has(r"HTTPS Content Filtering\s*[:=]\s*(\w+)")
    res["reputation_filtering"] = has(r"Reputation.*?\s*[:=]\s*(\w+)")
    res["safe_search"] = has(r"Safe Search\s*[:=]\s*(\w+)")
    res["youtube_restricted"] = has(r"YouTube Restrict\w*\s*[:=]\s*(\w+)")
    return res


# ---------------------------------------------------------------------------
# Performance / CPU
# ---------------------------------------------------------------------------
def parse_performance(doc: TSRDocument) -> Dict[str, Any]:
    sec = doc.first_like(r"^Blade_\d+_CPU_MONITOR$") or doc.first_like(r"CPU.*MONITOR")
    res: Dict[str, Any] = {"present": sec is not None, "cpu_samples": []}
    if not sec:
        return res
    text = "\n".join(sec.lines)
    # Capture any percentage utilisation figures
    pcts = [float(x) for x in re.findall(r"(\d{1,3}(?:\.\d+)?)\s*%", text)]
    res["cpu_samples"] = pcts[:50]
    res["cpu_max"] = max(pcts) if pcts else 0.0
    return res


# ---------------------------------------------------------------------------
# Authentication servers (RADIUS / TACACS+ / LDAP)
# ---------------------------------------------------------------------------
def parse_auth_servers(doc: TSRDocument) -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    radius = doc.first_like(r"Users : RADIUS") or doc.first_like(r"RADIUS")
    if radius:
        rtext = "\n".join(radius.lines)
        res["tacacs_accounting_enabled"] = bool(
            re.search(r"TACACS\+?\s+Accounting\s*:\s*Enabled", rtext, re.IGNORECASE))
        res["radius_accounting_enabled"] = bool(
            re.search(r"RADIUS\s+Accounting\s*:\s*Enabled", rtext, re.IGNORECASE))
    settings = doc.first_like(r"Users : Settings")
    if settings:
        stext = "\n".join(settings.lines)
        res["login_uniqueness"] = bool(
            re.search(r"Login Uniqueness\s*:\s*Enabled", stext, re.IGNORECASE)) or \
            bool(re.search(r"enforce login uniqueness.*?:\s*yes", stext, re.IGNORECASE))
    return res


def enrich_snapshot(doc: TSRDocument, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    snapshot["firewall_settings"] = parse_firewall_settings(doc)
    snapshot["local_users_detail"] = parse_local_users_detailed(doc)
    snapshot["wlan"] = parse_wlan(doc)
    snapshot["cfs"] = parse_cfs(doc)
    snapshot["performance"] = parse_performance(doc)
    snapshot["auth_servers"] = parse_auth_servers(doc)
    return snapshot
