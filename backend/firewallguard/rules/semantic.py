"""Semantic rule layer: TSR reference resolution + management-rule evaluation.

The CEL rule layer compares raw snapshot values (``x.dst == "GMS Addresses"``).
Management rules instead express *semantic* conditions that require resolving
references inside the TSR — e.g. ``Destination = All Interface IPs`` means:
take the access rule's destination *name*, resolve it through the address
objects/groups (recursively, groups can nest), extract the concrete
addresses, and compare them against the firewall's interface IPs using real
IP/network semantics. Services resolve the same way: a condition like
``Service = All Management Ports`` resolves the referenced service
object/group to protocol/port ranges and compares them against the
management ports the TSR reports (HTTP/HTTPS/SSH — dynamic, never assumed).

Layering (kept DB-agnostic so it can run anywhere the snapshot exists):

    parsed snapshot (parser.py — single source of truth)
        → SnapshotIndex          one-time name indexes, interface IPs,
                                 management ports, per-analysis caches
        → resolve_address_name / resolve_service_name
                                 recursive, cycle-safe, memoized resolution
        → SEMANTIC_TARGETS       registry of semantic matchers, each tagged
                                 with the domain(s) it applies to
        → evaluate_management_definition
        → AccessRuleMatch list   (the app layer turns these into Findings)

Adding a new semantic condition means registering a new target — never
special-casing inside the evaluator.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

Snapshot = Dict[str, Any]

# ---------------------------------------------------------------------------
# Condition vocabulary. The API validates against these and the UI renders
# its dropdowns from them (GET /rules/management/options).
# ---------------------------------------------------------------------------
DIRECT_FIELDS: Dict[str, str] = {
    # condition field -> access-rule key
    "src_zone": "src_zone", "dst_zone": "dst_zone", "action": "action",
    "service": "service", "src": "src", "dst": "dst", "name": "name",
    "comment": "comment", "ipver": "ipver",
}
BOOL_FIELDS: Dict[str, str] = {
    "enabled": "enabled", "management": "management", "auto_rule": "auto_rule",
}
# condition field -> (access-rule key holding the reference, resolver domain)
SEMANTIC_FIELDS: Dict[str, Tuple[str, str]] = {
    "src_address": ("src", "address"),
    "dst_address": ("dst", "address"),
    "service_ports": ("service", "service"),
}
DIRECT_OPERATORS = ("equals", "not_equals", "contains", "not_contains")
BOOL_OPERATORS = ("equals", "not_equals")

# Operators for semantic (resolved) fields. Collection semantics, applied to
# the RESOLVED values (never the raw reference name):
#   is      — ANY-match: at least one resolved value satisfies the target.
#   is_not  — NONE-match: the reference RESOLVES to concrete values (not
#             "Any", not an unknown name) and none of them satisfies the
#             target. "ANY resolved value differs" would be wrong for
#             multi-value references, so it is deliberately not offered.
# Legacy conditions stored "" / "equals" — normalized to "is".
SEMANTIC_OPERATORS = ("is", "is_not")


def normalize_semantic_operator(operator: str) -> str:
    return "is_not" if operator in ("is_not", "not_equals") else "is"

# "*" in an equals/not_equals condition is a wildcard (Any), never a literal.
WILDCARD = "*"

# Protocol numbers considered management-capable when matching service ports.
# Management protocols (HTTP/HTTPS/SSH) are TCP; services with an unknown
# protocol are included conservatively and labelled as such in the evidence.
_TCP = 6


# ---------------------------------------------------------------------------
# Resolved address model
# ---------------------------------------------------------------------------
@dataclass
class ResolvedAddress:
    """Concrete values represented by an address object/group reference."""

    # (network, source object name) — HOST as /32 (or /128), NETWORK as net
    networks: List[Tuple[Any, str]] = dc_field(default_factory=list)
    # (start_int, end_int, display, ip_version, source object name)
    ranges: List[Tuple[int, int, str, int, str]] = dc_field(default_factory=list)
    # non-IP values: (kind, value, source object name) — FQDN / MAC / unparsed
    others: List[Tuple[str, str, str]] = dc_field(default_factory=list)
    # object/group names traversed, in resolution order (evidence trail)
    trace: List[str] = dc_field(default_factory=list)
    is_any: bool = False        # the literal "Any" reference
    resolved: bool = False      # a matching object or group existed

    def merge(self, other: "ResolvedAddress") -> None:
        self.networks.extend(other.networks)
        self.ranges.extend(other.ranges)
        self.others.extend(other.others)
        for name in other.trace:
            if name not in self.trace:
                self.trace.append(name)
        self.resolved = self.resolved or other.resolved

    def value_count(self) -> int:
        return len(self.networks) + len(self.ranges) + len(self.others)

    def containing_entry(self, ip: Any) -> Optional[Tuple[str, str]]:
        """``(display, source_name)`` of the entry covering ``ip``, if any."""
        for net, source in self.networks:
            if ip.version == net.version and ip in net:
                return str(net), source
        ip_int = int(ip)
        for start, end, display, version, source in self.ranges:
            if ip.version == version and start <= ip_int <= end:
                return display, source
        return None


def _parse_object_value(obj_type: Optional[str], value: Optional[str],
                        source: str, out: ResolvedAddress) -> None:
    """Convert one address object's typed value into resolved entries."""
    text = (value or "").strip()
    if not text:
        return
    kind = (obj_type or "").upper()
    try:
        if kind == "HOST":
            out.networks.append((ipaddress.ip_network(text, strict=False), source))
        elif kind == "NETWORK":
            # GUI TSR renders "10.0.0.0 - 255.255.255.0" (network - netmask);
            # tolerate CIDR ("10.0.0.0/24") as well.
            if " - " in text:
                net, mask = (p.strip() for p in text.split(" - ", 1))
                out.networks.append(
                    (ipaddress.ip_network(f"{net}/{mask}", strict=False), source))
            else:
                out.networks.append((ipaddress.ip_network(text, strict=False), source))
        elif kind == "RANGE":
            start_s, end_s = (p.strip() for p in text.split(" - ", 1))
            start, end = ipaddress.ip_address(start_s), ipaddress.ip_address(end_s)
            if start.version == end.version:
                out.ranges.append((int(start), int(end), text, start.version, source))
        else:  # FQDN, MAC, unknown — kept for future semantic targets
            out.others.append((kind or "VALUE", text, source))
    except ValueError:
        out.others.append(("unparsed", text, source))


# ---------------------------------------------------------------------------
# Resolved service model
# ---------------------------------------------------------------------------
_PROTOCOL_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
                   47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 108: "IPComp"}


def protocol_name(iptype: Optional[int]) -> str:
    if iptype is None:
        return "unknown"
    return _PROTOCOL_NAMES.get(int(iptype), f"proto {iptype}")


@dataclass
class ResolvedService:
    """Concrete protocol/port ranges represented by a service reference."""

    # (start_port, end_port, iptype|None, display, source service name)
    port_ranges: List[Tuple[int, int, Optional[int], str, str]] = dc_field(default_factory=list)
    others: List[Tuple[str, str]] = dc_field(default_factory=list)  # (value, source)
    trace: List[str] = dc_field(default_factory=list)
    is_any: bool = False
    resolved: bool = False

    def merge(self, other: "ResolvedService") -> None:
        self.port_ranges.extend(other.port_ranges)
        self.others.extend(other.others)
        for name in other.trace:
            if name not in self.trace:
                self.trace.append(name)
        self.resolved = self.resolved or other.resolved

    def value_count(self) -> int:
        return len(self.port_ranges) + len(self.others)

    def covering_entry(self, port: int) -> Optional[Tuple[str, str, str]]:
        """``(display, source, protocol)`` of a TCP/unknown range covering ``port``."""
        for start, end, iptype, display, source in self.port_ranges:
            if iptype is not None and int(iptype) != _TCP:
                continue  # management protocols are TCP
            if start <= port <= end:
                return display, source, protocol_name(iptype)
        return None


def _parse_service_ports(iptype: Optional[int], ports: Optional[str],
                         source: str, out: ResolvedService) -> None:
    """Parse a service object's port field ("80~80", "1 - 65535", "443")."""
    text = (ports or "").strip()
    if not text:
        # Port-less protocols (ICMP, GRE, ...) still count as a resolved value.
        out.others.append((protocol_name(iptype), source))
        return
    sep = "~" if "~" in text else ("-" if "-" in text else None)
    try:
        if sep:
            start_s, end_s = (p.strip() for p in text.split(sep, 1))
            start, end = int(start_s), int(end_s)
        else:
            start = end = int(text)
        if start > end:
            start, end = end, start
        display = f"{protocol_name(iptype)}/{start}" if start == end \
            else f"{protocol_name(iptype)}/{start}-{end}"
        out.port_ranges.append((start, end, iptype, display, source))
    except ValueError:
        out.others.append((text, source))


# ---------------------------------------------------------------------------
# Snapshot index
# ---------------------------------------------------------------------------
def _index_by_name(entries: Optional[list]) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {}
    for entry in entries or []:
        name = str(entry.get("name") or "").strip()
        if name:
            out.setdefault(name, []).append(entry)
    return out


class SnapshotIndex:
    """One-time indexes over a parsed snapshot for efficient resolution.

    Objects and groups live in SEPARATE maps (for both addresses and
    services): SonicWall allows an object and a group to share a name, and
    an access rule's text reference does not disambiguate — so a name that
    exists as both resolves to the union of the two (deterministic
    superset). Duplicate names within one map are kept as lists and merged
    on resolution.
    """

    def __init__(self, snapshot: Snapshot):
        ao = snapshot.get("address_objects") or {}
        self.objects_by_name = _index_by_name(ao.get("objects"))
        self.groups_by_name = _index_by_name(ao.get("groups"))

        svc = snapshot.get("services") or {}
        self.services_by_name = _index_by_name(svc.get("objects"))
        self.service_groups_by_name = _index_by_name(svc.get("groups"))

        # (interface name, ip_address) — dynamic from the TSR, unconfigured
        # 0.0.0.0 interfaces excluded.
        self.interface_ips: List[Tuple[str, Any]] = []
        for iface in snapshot.get("interfaces") or []:
            raw = str(iface.get("ip") or "").strip()
            name = str(iface.get("name") or "").strip()
            if not raw or not name:
                continue
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if ip.is_unspecified:
                continue
            self.interface_ips.append((name, ip))

        # (label, port) — management ports as configured on THIS firewall.
        admin = snapshot.get("administration") or {}
        self.management_ports: List[Tuple[str, int]] = []
        for label, key in (("HTTP", "http_port"), ("HTTPS", "https_port"),
                           ("SSH", "ssh_port")):
            port = admin.get(key)
            if isinstance(port, int) and 0 < port <= 65535:
                self.management_ports.append((label, port))

        self._address_cache: Dict[str, ResolvedAddress] = {}
        self._service_cache: Dict[str, ResolvedService] = {}

    # -- recursive, cycle-safe, memoized resolution -------------------------
    def resolve_address_name(self, name: str,
                             _visiting: Optional[Set[str]] = None) -> ResolvedAddress:
        name = (name or "").strip()
        out = ResolvedAddress()
        if not name:
            return out
        if name.lower() == "any":
            out.is_any = True
            out.resolved = True
            return out

        visiting = _visiting if _visiting is not None else set()
        if name in visiting:            # circular group reference — cut branch
            return out
        cached = self._address_cache.get(name)
        if cached is not None:
            return cached

        visiting.add(name)
        out.trace.append(name)
        for obj in self.objects_by_name.get(name, []):
            out.resolved = True
            _parse_object_value(obj.get("obj_type"), obj.get("value"), name, out)
        for grp in self.groups_by_name.get(name, []):
            out.resolved = True
            for member in grp.get("members") or []:
                out.merge(self.resolve_address_name(str(member), visiting))
        visiting.discard(name)

        # Only fully-resolved (cycle-free entry) results are safe to memoize.
        if _visiting is None or not _visiting:
            self._address_cache[name] = out
        return out

    def resolve_service_name(self, name: str,
                             _visiting: Optional[Set[str]] = None) -> ResolvedService:
        name = (name or "").strip()
        out = ResolvedService()
        if not name:
            return out
        if name.lower() == "any":
            out.is_any = True
            out.resolved = True
            return out

        visiting = _visiting if _visiting is not None else set()
        if name in visiting:            # circular group reference — cut branch
            return out
        cached = self._service_cache.get(name)
        if cached is not None:
            return cached

        visiting.add(name)
        out.trace.append(name)
        for obj in self.services_by_name.get(name, []):
            out.resolved = True
            _parse_service_ports(obj.get("iptype"), obj.get("ports"), name, out)
        for grp in self.service_groups_by_name.get(name, []):
            out.resolved = True
            for member in grp.get("members") or []:
                out.merge(self.resolve_service_name(str(member), visiting))
        visiting.discard(name)

        if _visiting is None or not _visiting:
            self._service_cache[name] = out
        return out


def build_index(snapshot: Snapshot) -> SnapshotIndex:
    return SnapshotIndex(snapshot)


# ---------------------------------------------------------------------------
# Semantic target registry
# ---------------------------------------------------------------------------
@dataclass
class SemanticHit:
    """One concrete piece of match evidence produced by a semantic target."""

    kind: str = "interface"     # interface | ip | service_port
    label: str = ""             # e.g. the management-port label (HTTP/HTTPS/SSH)
    interface: str = ""
    ip: str = ""
    port: Optional[int] = None
    protocol: str = ""
    via: str = ""               # the resolved entry that covered the value
    source: str = ""            # the object the entry came from

    def summary(self) -> str:
        if self.kind == "service_port":
            what = f"{self.label} management port" if self.label else "service port"
            return (f"Matched {what} {self.port} via "
                    f"{self.via} from service '{self.source}'")
        if self.kind == "ip":
            return f"Matched IP {self.ip} via {self.via} from object '{self.source}'"
        return (f"Matched interface {self.interface} ({self.ip}) via "
                f"{self.via} from object '{self.source}'")


def _interface_hits(resolved: ResolvedAddress, index: SnapshotIndex,
                    only_interface: Optional[str] = None) -> List[SemanticHit]:
    hits: List[SemanticHit] = []
    want = (only_interface or "").strip().lower()
    for iface, ip in index.interface_ips:
        if want and iface.lower() != want:
            continue
        entry = resolved.containing_entry(ip)
        if entry:
            via, source = entry
            hits.append(SemanticHit(kind="interface", interface=iface,
                                    ip=str(ip), via=via, source=source))
    return hits


def _target_any(resolved, index: SnapshotIndex, param: str) -> Optional[List[SemanticHit]]:
    return []       # matches unconditionally, contributes no hits


def _target_all_interface_ips(resolved: ResolvedAddress, index: SnapshotIndex,
                              param: str) -> Optional[List[SemanticHit]]:
    return _interface_hits(resolved, index) or None


def _target_interface_ip(resolved: ResolvedAddress, index: SnapshotIndex,
                         param: str) -> Optional[List[SemanticHit]]:
    if not param.strip():
        return None
    return _interface_hits(resolved, index, only_interface=param) or None


def split_values(param: str) -> List[str]:
    """Split a multi-value condition parameter ("a, b c;d") into tokens.

    Multiple configured values are ALTERNATIVES (OR semantics): a condition is
    satisfied as soon as ANY configured value matches ANY resolved value.
    """
    return [tok for tok in re.split(r"[\s,;]+", param or "") if tok]


def _target_ip_address(resolved: ResolvedAddress, index: SnapshotIndex,
                       param: str) -> Optional[List[SemanticHit]]:
    """The reference resolves to something containing ANY of the given IPs.

    OR semantics across the configured list: one covered IP is sufficient;
    hits are reported for every configured IP that matched.
    """
    hits: List[SemanticHit] = []
    for token in split_values(param):
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue  # validated at save time; never turns the OR into an AND
        entry = resolved.containing_entry(ip)
        if entry:
            via, source = entry
            hits.append(SemanticHit(kind="ip", ip=str(ip), via=via, source=source))
    return hits or None


def _target_all_management_ports(resolved: ResolvedService, index: SnapshotIndex,
                                 param: str) -> Optional[List[SemanticHit]]:
    """The service resolves to a port range covering ANY configured
    management port (HTTP/HTTPS/SSH, read dynamically from the TSR)."""
    hits: List[SemanticHit] = []
    for label, port in index.management_ports:
        entry = resolved.covering_entry(port)
        if entry:
            via, source, proto = entry
            hits.append(SemanticHit(kind="service_port", label=label, port=port,
                                    protocol=proto, via=via, source=source))
    return hits or None


def _target_custom_ports(resolved: ResolvedService, index: SnapshotIndex,
                         param: str) -> Optional[List[SemanticHit]]:
    """The service resolves to a port range covering ANY of the given ports.

    OR semantics across the configured list — one matching port suffices,
    regardless of how many resolved ports the (possibly nested) service
    reference carries.
    """
    hits: List[SemanticHit] = []
    for token in split_values(param):
        try:
            port = int(token)
        except ValueError:
            continue
        if not 0 < port <= 65535:
            continue
        entry = resolved.covering_entry(port)
        if entry:
            via, source, proto = entry
            hits.append(SemanticHit(kind="service_port", port=port,
                                    protocol=proto, via=via, source=source))
    return hits or None


@dataclass(frozen=True)
class SemanticTarget:
    key: str
    label: str
    domains: FrozenSet[str]          # {"address"} and/or {"service"}
    needs_value: bool
    value_hint: str
    matcher: Callable[..., Optional[List[SemanticHit]]]


SEMANTIC_TARGETS: Dict[str, SemanticTarget] = {
    t.key: t for t in (
        SemanticTarget("any", "Any", frozenset({"address", "service"}),
                       False, "", _target_any),
        SemanticTarget("all_interface_ips", "All Interface IPs",
                       frozenset({"address"}), False, "", _target_all_interface_ips),
        SemanticTarget("interface_ip", "Specific Interface IP",
                       frozenset({"address"}), True, "Interface name, e.g. X1",
                       _target_interface_ip),
        SemanticTarget("ip_address", "Specific IP Address",
                       frozenset({"address"}), True,
                       "One or more IPs (any may match), e.g. 192.168.1.1, 10.0.0.5",
                       _target_ip_address),
        SemanticTarget("all_management_ports", "All Management Ports",
                       frozenset({"service"}), False, "", _target_all_management_ports),
        SemanticTarget("custom_ports", "Specific Ports",
                       frozenset({"service"}), True,
                       "One or more ports (any may match), e.g. 80, 443, 8443",
                       _target_custom_ports),
    )
}

# Retained for display convenience (rule list summaries, evidence labels).
SEMANTIC_TARGET_LABELS: Dict[str, str] = {
    key: target.label for key, target in SEMANTIC_TARGETS.items()
}


# ---------------------------------------------------------------------------
# Definition validation
# ---------------------------------------------------------------------------
def validate_definition(definition: Dict[str, Any]) -> List[str]:
    """Validate a management-rule definition; returns a list of problems."""
    errors: List[str] = []
    conditions = (definition or {}).get("conditions")
    if not isinstance(conditions, list) or not conditions:
        return ["definition must contain at least one condition"]
    for i, cond in enumerate(conditions):
        label = f"condition {i + 1}"
        if not isinstance(cond, dict):
            errors.append(f"{label}: must be an object")
            continue
        fld = str(cond.get("field") or "")
        op = str(cond.get("operator") or "equals")
        if fld in SEMANTIC_FIELDS:
            _key, domain = SEMANTIC_FIELDS[fld]
            if op not in ("", "equals", "not_equals", *SEMANTIC_OPERATORS):
                errors.append(f"{label}: operator '{op}' is not valid for resolved fields")
            target_key = str(cond.get("target") or "")
            target = SEMANTIC_TARGETS.get(target_key)
            if target is None:
                errors.append(f"{label}: unknown semantic target '{target_key}'")
            elif domain not in target.domains:
                errors.append(f"{label}: target '{target_key}' does not apply to {fld}")
            elif target.needs_value and not str(cond.get("value") or "").strip():
                errors.append(f"{label}: target '{target_key}' requires a value")
            elif target_key == "ip_address":
                # Every configured alternative must be a valid IP.
                for token in split_values(str(cond.get("value") or "")):
                    try:
                        ipaddress.ip_address(token)
                    except ValueError:
                        errors.append(f"{label}: '{token}' is not a valid IP address")
            elif target_key == "custom_ports":
                for token in split_values(str(cond.get("value") or "")):
                    if not token.isdigit() or not 0 < int(token) <= 65535:
                        errors.append(f"{label}: '{token}' is not a valid port (1-65535)")
        elif fld in BOOL_FIELDS:
            if op not in BOOL_OPERATORS:
                errors.append(f"{label}: operator '{op}' is not valid for boolean fields")
            if not str(cond.get("value") or "").strip():
                errors.append(f"{label}: value is required")
        elif fld in DIRECT_FIELDS:
            if op not in DIRECT_OPERATORS:
                errors.append(f"{label}: unknown operator '{op}'")
            if not str(cond.get("value") or "").strip():
                errors.append(f"{label}: value is required")
        else:
            errors.append(f"{label}: unknown field '{fld}'")
    return errors


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
@dataclass
class AccessRuleMatch:
    rule: dict
    evidence: List[str]
    hits: List[SemanticHit]


def _direct_matches(actual: Any, operator: str, expected: str) -> bool:
    e = expected.strip()
    # "*" is a wildcard: `equals *` matches anything (Any Zone etc.);
    # `not_equals *` therefore matches nothing. Never a literal comparison.
    if e == WILDCARD:
        if operator == "equals":
            return True
        if operator == "not_equals":
            return False
    a = str(actual if actual is not None else "").strip().lower()
    e = e.lower()
    if operator == "equals":
        return a == e
    if operator == "not_equals":
        return a != e
    if operator == "contains":
        return e in a
    if operator == "not_contains":
        return e not in a
    return False


def _bool_matches(actual: Any, operator: str, expected: str) -> bool:
    a = bool(actual)
    e = expected.strip().lower() in ("true", "yes", "1", "enabled")
    return (a == e) if operator != "not_equals" else (a != e)


def evaluate_management_definition(definition: Dict[str, Any], snapshot: Snapshot,
                                   index: Optional[SnapshotIndex] = None
                                   ) -> List[AccessRuleMatch]:
    """Evaluate one management-rule definition against a parsed snapshot.

    Returns one ``AccessRuleMatch`` per access rule satisfying ALL conditions.
    Disabled access rules are skipped unless the definition itself constrains
    the ``enabled`` field (a disabled rule is not an exposure).
    """
    conditions = [c for c in (definition or {}).get("conditions") or []
                  if isinstance(c, dict)]
    if not conditions:
        return []
    idx = index if index is not None else SnapshotIndex(snapshot)
    has_enabled_condition = any(c.get("field") == "enabled" for c in conditions)

    matches: List[AccessRuleMatch] = []
    for rule in snapshot.get("access_rules") or []:
        if not isinstance(rule, dict):
            continue
        if not has_enabled_condition and not rule.get("enabled"):
            continue
        evidence: List[str] = []
        hits: List[SemanticHit] = []
        ok = True
        for cond in conditions:
            fld = str(cond.get("field") or "")
            op = str(cond.get("operator") or "equals")
            value = str(cond.get("value") or "")
            if fld in SEMANTIC_FIELDS:
                rule_key, domain = SEMANTIC_FIELDS[fld]
                ref_name = str(rule.get(rule_key) or "")
                target = SEMANTIC_TARGETS.get(str(cond.get("target") or ""))
                if target is None or domain not in target.domains:
                    ok = False
                    break
                if domain == "service":
                    resolved: Any = idx.resolve_service_name(ref_name)
                else:
                    resolved = idx.resolve_address_name(ref_name)
                result = target.matcher(resolved, idx, value)
                trail = " > ".join(resolved.trace[:6]) or ref_name or "(empty)"
                suffix = f" ({value})" if target.needs_value else ""
                if normalize_semantic_operator(op) == "is_not":
                    # NONE-match: fire only when the reference resolved to
                    # concrete values and none of them satisfies the target.
                    # Unresolvable names and "Any" never satisfy IS NOT —
                    # findings stay evidence-gated.
                    if result is not None or not resolved.resolved or resolved.is_any:
                        ok = False
                        break
                    evidence.append(
                        f"{fld} '{ref_name}' does not match {target.label}{suffix}: "
                        f"none of {resolved.value_count()} resolved value(s) match "
                        f"(via {trail})")
                else:
                    if result is None:
                        ok = False
                        break
                    hits.extend(result)
                    evidence.append(
                        f"{fld} '{ref_name}' matches {target.label}{suffix}: resolves to "
                        f"{resolved.value_count()} value(s) via {trail}")
            elif fld in BOOL_FIELDS:
                if not _bool_matches(rule.get(BOOL_FIELDS[fld]), op, value):
                    ok = False
                    break
                evidence.append(f"{fld} is {rule.get(BOOL_FIELDS[fld])}")
            elif fld in DIRECT_FIELDS:
                actual = rule.get(DIRECT_FIELDS[fld])
                if not _direct_matches(actual, op, value):
                    ok = False
                    break
                evidence.append(f"{fld} = '{actual}'"
                                + (" (any)" if value.strip() == WILDCARD else ""))
            else:
                ok = False
                break
        if not ok:
            continue

        # Deterministic, de-duplicated evidence.
        seen: Set[str] = set()
        unique_hits: List[SemanticHit] = []
        for hit in hits:
            key = hit.summary()
            if key not in seen:
                seen.add(key)
                unique_hits.append(hit)
        for hit in unique_hits[:6]:
            evidence.append(hit.summary())
        if len(unique_hits) > 6:
            evidence.append(f"...and {len(unique_hits) - 6} more match(es)")

        header = (f"Access rule {rule.get('num')} '{rule.get('name') or ''}': "
                  f"{rule.get('src_zone')} -> {rule.get('dst_zone')}, "
                  f"service '{rule.get('service')}', src '{rule.get('src')}', "
                  f"dst '{rule.get('dst')}'"
                  f"{'' if rule.get('enabled') else ' (disabled)'}")
        matches.append(AccessRuleMatch(
            rule=rule, evidence=[header] + evidence, hits=unique_hits))
    return matches
