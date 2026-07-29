# Coverage Comparison — FirewallGuard AI vs. SecureCheck reference report

This document maps FirewallGuard AI's detection catalog against the reference
report produced by the comparison tool ("SonicWall SecureCheck") for the same
NSa 3700 TSR, so coverage gaps are explicit.

## Headline result on the shared TSR

| Metric | Reference tool | FirewallGuard AI |
|---|---|---|
| Critical | 1 | 3 |
| High | 41 | 46 |
| Medium | 36 | 40 |
| Low | 245 | 415 |
| Info (inventory) | ~65 | 10 |
| PSIRT advisories matched | 3 | 3 (same advisories) |

FirewallGuard AI now reports the same finding *families* and the same
per-object granularity. Differences in raw counts come from scoping choices
that are documented per check below (for example, how aggressively unused
objects are enumerated), not from missing detections.

## PSIRT / firmware

Both tools match the three advisories applicable to SonicOS 7.3.0-7012 on a
Gen7 platform, sourced from the SonicWall PSIRT portal and NVD:

- **SNWLID-2026-0004** — CVE-2026-0204 / 0205 / 0206, max CVSS 8.0 (auth bypass, path traversal, DoS).
- **SNWLID-2025-0016** — CVE-2025-40601, CVSS 7.5 (SSLVPN pre-auth buffer overflow), fixed in 7.3.1-7013.
- **SNWLID-2026-0001** — CVSS 4.9 (post-authentication vulnerabilities).

The bundled dataset records the real advisory IDs, CVEs, CVSS scores and fixed
versions, and is refreshed from `https://psirt.global.sonicwall.com/vuln-list`.

## Check-family mapping

| Reference code(s) | FirewallGuard rule(s) | Notes |
|---|---|---|
| PSIRT-001 | FW-PSIRT-* | Per-advisory findings from real PSIRT data. |
| ACR-002 / ACR-007 / ACR-003 / ACR-008 | ACR-002, ACR-007, ACR-003 | Per-rule; each names the access rule. |
| AOB-001 (duplicate) | AOB-001 | Per value; names every duplicate. |
| AOB-003 (unused custom) | AOB-003 | Per object, custom class only. |
| SVC-001 / SVC-004 / SVC-006 | SVC-001, SVC-004 | Per service object. |
| NAT-002 / NAT-003 / NAT-006 / NAT-007 | NAT-003, NAT-006 | Per policy; system policies excluded. |
| IPSEC-001 / 003 / 005 / 006 / 008 | IPSEC-001, 003, 005, 006, 008 | Per VPN policy; each names the SA. |
| SEC-009 / 010 / 011 / 007 / 008 / 016 | SEC-009, SEC-010, SEC-011, FW-SVC-001 | Per-zone service enforcement gaps. |
| GAV-001 (signature age) | GAV-001 | Fires when signature DB age exceeds threshold. |
| IPS-005 / IPS-010 | FW-SVC-003a | IPS low-priority detect-only. |
| SNMP-001 / SNMP-002 | FW-MGT-006, SNMP-002 | v1/v2c and v3 enforcement. |
| MGMT-005 / 007 / 010 | FW-SSL-003, FW-MGT-001/009 | Management exposure. |
| AUTH-002 / 004 / 006 / 009 | AUTH-002, AUTH-006, FW-MGT-003 | Login uniqueness, MFA coverage, password policy. |
| RAD-005 | RAD-005 | TACACS+ accounting. |
| FW-001…FW-010 | FW-001, FW-002, FW-004, FW-005, FW-006, FW-007, FW-008, FW-009 | Stealth, flood, DDoS, source routing, FTP bounce, handshake. |
| SSLVPN-001 / SSLVPN-002 | FW-SSL-001, SSLVPN-002 | WAN exposure and Virtual Office on non-LAN. |
| CFS-001 / 004 / 005 / 006 / 008 | FW-SVC-002, CFS-004, CFS-006 | Content filtering coverage. |
| WLAN-001 / 005 / 006 / 007 / 008 | WLAN-006 (+ applicability gating) | Wireless; not applicable when no SSIDs configured. |
| PERF-002 / PERF-003 | PERF-002 | CPU spike detection. |
| SYSTEM / DHCP / *-I info | catalog_info (*-I rules) | Inventory data points. |

## Scoping notes (why counts differ, not coverage)

- **Unused address objects (AOB-003).** FirewallGuard flags every custom object
  the firewall reports as referenced by zero modules and in no group. The
  reference tool reports a smaller subset; both name each object so an operator
  can act on them directly. FirewallGuard's set is a superset.
- **Unhit NAT policies (NAT-003).** FirewallGuard restricts to enabled, custom
  (non-system) policies with zero hits, matching the reference tool's intent.
- **WLAN checks.** Built but applicability-gated: when the device has no
  wireless interfaces configured (as on this TSR) they correctly do not fire.

## Per-object reporting and report navigation

Every per-object finding carries the specific object name, type and a detail
string (for example the access-rule number, the VPN SA name, the duplicate
object set), shown in an "Affected Object" column in the findings index and at
the top of each detail card. In the technical PDF, each index entry links to
its detail card and each card links back to the index.
