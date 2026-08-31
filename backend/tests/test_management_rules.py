"""Management Rules: semantic reference-resolving conditions over access rules.

Covers the resolver (recursive groups, cycles, object/group name collisions,
subnet/range semantics), the evaluator (same-object conditions, dedup,
multiple matches), the DB/finding layer, the superadmin API, the end-to-end
TSR-upload flow, and a file-gated acceptance check on a real reference TSR.
"""

from __future__ import annotations

import os

import pytest

from app.database import SessionLocal
from app.models import Rule, RuleSource, RuleState, User
from app.rule_engine import evaluate_management_rules
from firewallguard.rules.semantic import (
    SnapshotIndex, evaluate_management_definition, validate_definition,
)
from firewallguard.tsr.parser import parse_tsr


def _rule(num, src_zone="WAN", dst_zone="WAN", dst="X0 IP", enabled=True, **over):
    base = {"num": num, "src_zone": src_zone, "dst_zone": dst_zone, "action": "Allow",
            "service": "HTTPS Management", "enabled": enabled, "src": "Any", "dst": dst,
            "name": f"Rule {num}", "comment": "", "auto_rule": False,
            "management": True, "usage": 0, "last_hit": "", "ipver": "IPv4"}
    base.update(over)
    return base


def _snapshot(access_rules):
    return {
        "interfaces": [
            {"name": "X0", "ip": "192.168.1.1", "mask": "255.255.255.0", "zone": "LAN"},
            {"name": "X1", "ip": "10.10.10.1", "mask": "255.255.255.0", "zone": "WAN"},
            {"name": "X2", "ip": "0.0.0.0", "mask": "", "zone": "MGMT"},  # unconfigured
        ],
        "address_objects": {
            "objects": [
                {"name": "X0 IP", "obj_type": "HOST", "value": "192.168.1.1"},
                {"name": "Server 5", "obj_type": "HOST", "value": "203.0.113.5"},
                {"name": "LAN Net", "obj_type": "NETWORK",
                 "value": "192.168.1.0 - 255.255.255.0"},
                {"name": "Other Net", "obj_type": "NETWORK",
                 "value": "172.16.0.0 - 255.255.0.0"},
                {"name": "Near Miss", "obj_type": "NETWORK",
                 "value": "110.0.0.0 - 255.0.0.0"},   # string-prefix trap for 10.x
                {"name": "WAN Range", "obj_type": "RANGE",
                 "value": "10.10.10.0 - 10.10.10.20"},
                {"name": "Mgmt", "obj_type": "HOST", "value": "10.10.10.1"},
                {"name": "Host 2", "obj_type": "HOST", "value": "192.168.9.2"},
                {"name": "Host 100", "obj_type": "HOST", "value": "192.168.9.100"},
            ],
            "groups": [
                {"name": "Group C", "members": ["X0 IP"]},
                {"name": "Group B", "members": ["Group C"]},
                {"name": "Group A", "members": ["Group B"]},
                {"name": "Loop A", "members": ["Loop B"]},
                {"name": "Loop B", "members": ["Loop C"]},
                {"name": "Loop C", "members": ["Loop A", "X0 IP"]},
                {"name": "Mgmt", "members": ["Server 5"]},   # same name as object
                {"name": "Both Cover X0", "members": ["X0 IP", "LAN Net"]},
                {"name": "Two Hosts", "members": ["Host 2", "Host 100"]},
            ],
        },
        # Custom (non-default) management ports — the resolver must read these
        # from the TSR, never assume 80/443/22.
        "administration": {"http_port": 8080, "https_port": 8443, "ssh_port": 2222},
        "services": {
            "objects": [
                {"name": "HTTPS Custom", "iptype": 6, "ports": "8443~8443"},
                {"name": "HTTP Custom", "iptype": 6, "ports": "8080~8080"},
                {"name": "SSH Custom", "iptype": 6, "ports": "2222"},        # single format
                {"name": "Plain HTTPS", "iptype": 6, "ports": "443~443"},    # NOT a mgmt port here
                {"name": "DNS UDP", "iptype": 17, "ports": "53~53"},
                {"name": "UDP 8443", "iptype": 17, "ports": "8443~8443"},    # right port, wrong proto
                {"name": "Wide TCP", "iptype": 6, "ports": "8000 - 9000"},   # range covers 8443
            ],
            "groups": [
                {"name": "Remote Management", "members": ["SSH Custom", "DNS UDP"]},
                {"name": "Management Services",
                 "members": ["HTTPS Custom", "HTTP Custom", "Remote Management"]},
                {"name": "SvcLoop A", "members": ["SvcLoop B"]},
                {"name": "SvcLoop B", "members": ["SvcLoop A", "HTTPS Custom"]},
            ],
        },
        "access_rules": access_rules,
    }


MGMT_CONDITIONS = [
    {"field": "src_zone", "operator": "equals", "value": "WAN"},
    {"field": "dst_zone", "operator": "equals", "value": "WAN"},
    {"field": "dst_address", "target": "all_interface_ips"},
]
DEFN = {"conditions": MGMT_CONDITIONS}


def _matches(dst, extra_rules=(), conditions=None):
    snap = _snapshot([_rule(1, dst=dst), *extra_rules])
    return evaluate_management_definition(
        {"conditions": conditions or MGMT_CONDITIONS}, snap)


# ---- resolver + evaluator ---------------------------------------------------
def test_direct_object_match():
    out = _matches("X0 IP")
    assert len(out) == 1
    hits = out[0].hits
    assert [(h.interface, h.ip) for h in hits] == [("X0", "192.168.1.1")]
    assert any("Matched interface X0" in line for line in out[0].evidence)


def test_unrelated_ip_no_match():
    assert _matches("Server 5") == []


def test_zone_conditions_bind_to_same_rule():
    # dst resolves to an interface IP but the zones do not match.
    snap = _snapshot([_rule(1, src_zone="LAN", dst_zone="WAN", dst="X0 IP")])
    assert evaluate_management_definition(DEFN, snap) == []


def test_group_to_object():
    assert len(_matches("Group C")) == 1


def test_nested_groups():
    out = _matches("Group A")
    assert len(out) == 1
    # Trace shows the traversal for the evidence text.
    assert any("Group A" in line for line in out[0].evidence)


def test_circular_groups_terminate_and_match_valid_branch():
    out = _matches("Loop A")   # Loop A -> Loop B -> Loop C -> (Loop A cycle) + X0 IP
    assert len(out) == 1
    assert out[0].hits[0].interface == "X0"


def test_object_and_group_with_same_name_are_unioned():
    index = SnapshotIndex(_snapshot([]))
    resolved = index.resolve_address_name("Mgmt")
    # HOST 10.10.10.1 (object) + Server 5 via the group — both retained.
    assert resolved.value_count() == 2
    out = _matches("Mgmt")     # matches via X1 = 10.10.10.1
    assert [(h.interface, h.ip) for h in out[0].hits] == [("X1", "10.10.10.1")]


def test_subnet_membership():
    assert len(_matches("LAN Net")) == 1        # 192.168.1.0/24 contains X0
    assert _matches("Other Net") == []          # 172.16/16 contains no interface


def test_no_string_prefix_confusion():
    # "110.0.0.0/8" must not match interface 10.10.10.1.
    assert _matches("Near Miss") == []


def test_range_membership():
    out = _matches("WAN Range")                 # 10.10.10.0-20 contains X1
    assert [(h.interface, h.ip) for h in out[0].hits] == [("X1", "10.10.10.1")]


def test_specific_interface_target():
    cond = [
        {"field": "dst_address", "target": "interface_ip", "value": "X1"},
    ]
    assert len(_matches("Mgmt", conditions=cond)) == 1
    cond_x0 = [{"field": "dst_address", "target": "interface_ip", "value": "X0"}]
    assert _matches("Mgmt", conditions=cond_x0) == []


def test_disabled_rules_skipped_by_default():
    snap = _snapshot([_rule(1, dst="X0 IP", enabled=False)])
    assert evaluate_management_definition(DEFN, snap) == []
    # ...unless the definition addresses `enabled` explicitly.
    cond = MGMT_CONDITIONS + [{"field": "enabled", "operator": "equals", "value": "false"}]
    assert len(evaluate_management_definition({"conditions": cond}, snap)) == 1


def test_multiple_matching_access_rules():
    out = _matches("X0 IP", extra_rules=[_rule(2, dst="Group A"), _rule(3, dst="Server 5")])
    assert [m.rule["num"] for m in out] == [1, 2]


def test_multiple_covering_entries_dedupe_to_one_hit():
    out = _matches("Both Cover X0")   # object AND subnet both cover X0's IP
    assert len(out) == 1
    assert len(out[0].hits) == 1


def test_validate_definition():
    assert validate_definition({"conditions": MGMT_CONDITIONS}) == []
    assert validate_definition({}) != []
    assert validate_definition({"conditions": [{"field": "nope", "value": "x"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "dst_address", "target": "interface_ip", "value": ""}]}) != []
    # ip_address must carry a valid IP; targets must match the field's domain.
    assert validate_definition({"conditions": [
        {"field": "dst_address", "target": "ip_address", "value": "not-an-ip"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "dst_address", "target": "ip_address", "value": "192.168.1.1"}]}) == []
    assert validate_definition({"conditions": [
        {"field": "service_ports", "target": "all_interface_ips"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "dst_address", "target": "all_management_ports"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "service_ports", "target": "all_management_ports"}]}) == []


# ---- specific IP address target ----------------------------------------------
def _ip_cond(field, ip):
    return [{"field": field, "target": "ip_address", "value": ip}]


def test_specific_ip_direct_object():
    out = _matches("Server 5", conditions=_ip_cond("dst_address", "203.0.113.5"))
    assert len(out) == 1
    assert out[0].hits[0].kind == "ip" and out[0].hits[0].ip == "203.0.113.5"


def test_specific_ip_no_match_for_unrelated_address():
    assert _matches("Server 5", conditions=_ip_cond("dst_address", "203.0.113.99")) == []


def test_specific_ip_through_group_and_nested_groups():
    # Group C -> X0 IP, Group A -> Group B -> Group C.
    assert len(_matches("Group C", conditions=_ip_cond("dst_address", "192.168.1.1"))) == 1
    assert len(_matches("Group A", conditions=_ip_cond("dst_address", "192.168.1.1"))) == 1


def test_specific_ip_subnet_semantics():
    # Any host inside the subnet object matches; outside does not.
    assert len(_matches("LAN Net", conditions=_ip_cond("dst_address", "192.168.1.77"))) == 1
    assert _matches("LAN Net", conditions=_ip_cond("dst_address", "192.168.2.1")) == []


def test_specific_ip_on_source_address():
    snap = _snapshot([_rule(1, src="Server 5")])
    out = evaluate_management_definition(
        {"conditions": _ip_cond("src_address", "203.0.113.5")}, snap)
    assert len(out) == 1


# ---- multi-value OR semantics: multiple IPs -----------------------------------
def test_multiple_ips_any_one_match_suffices():
    # Only the FIRST configured IP resolves — OR semantics, never AND.
    ips = "192.168.1.1, 203.0.113.99, 10.99.99.99"
    out = _matches("X0 IP", conditions=_ip_cond("dst_address", ips))
    assert len(out) == 1
    assert [h.ip for h in out[0].hits] == ["192.168.1.1"]


def test_multiple_ips_partial_intersection_matches():
    # Doc example: configured {.1,.2,.3} vs resolved {.2,.100} → MATCH on .2.
    out = _matches("Two Hosts",
                   conditions=_ip_cond("dst_address",
                                       "192.168.9.1, 192.168.9.2, 192.168.9.3"))
    assert len(out) == 1
    assert [h.ip for h in out[0].hits] == ["192.168.9.2"]


def test_multiple_ips_several_configured_match():
    out = _matches("Two Hosts",
                   conditions=_ip_cond("dst_address", "192.168.9.2 192.168.9.100"))
    assert len(out) == 1
    assert sorted(h.ip for h in out[0].hits) == ["192.168.9.100", "192.168.9.2"]


def test_multiple_ips_none_match():
    out = _matches("Two Hosts",
                   conditions=_ip_cond("dst_address", "10.1.1.1, 10.2.2.2"))
    assert out == []


def test_multiple_ips_through_nested_groups():
    # Group A → Group B → Group C → X0 IP; any configured alternative matching
    # the fully-resolved set is enough.
    out = _matches("Group A",
                   conditions=_ip_cond("dst_address", "8.8.8.8, 192.168.1.1"))
    assert len(out) == 1 and out[0].hits[0].ip == "192.168.1.1"


# ---- service semantic matching -------------------------------------------------
def _svc_cond(extra=()):
    return [{"field": "service_ports", "target": "all_management_ports"}, *extra]


def _svc_matches(service, conditions=None):
    snap = _snapshot([_rule(1, service=service)])
    return evaluate_management_definition({"conditions": conditions or _svc_cond()}, snap)


def test_management_ports_match_each_configured_port():
    for service, label, port in (("HTTPS Custom", "HTTPS", 8443),
                                 ("HTTP Custom", "HTTP", 8080),
                                 ("SSH Custom", "SSH", 2222)):
        out = _svc_matches(service)
        assert len(out) == 1, service
        hit = out[0].hits[0]
        assert (hit.kind, hit.label, hit.port) == ("service_port", label, port)
        assert hit.protocol == "TCP"


def test_custom_ports_from_tsr_are_respected():
    # Port 443 is the DEFAULT HTTPS port, but this firewall manages on 8443 —
    # a 443 service must NOT match, proving ports come from the TSR.
    assert _svc_matches("Plain HTTPS") == []


def test_udp_service_on_management_port_does_not_match():
    assert _svc_matches("UDP 8443") == []


def test_non_management_service_does_not_match():
    assert _svc_matches("DNS UDP") == []


def test_service_port_range_covers_management_port():
    out = _svc_matches("Wide TCP")     # TCP 8000-9000 covers both 8080 and 8443
    assert len(out) == 1
    assert {h.port for h in out[0].hits} == {8080, 8443}


def test_service_group_and_nested_groups():
    out = _svc_matches("Management Services")
    assert len(out) == 1
    ports = sorted(h.port for h in out[0].hits)
    assert ports == [2222, 8080, 8443]   # nested Remote Management contributes SSH


def test_circular_service_groups_terminate():
    out = _svc_matches("SvcLoop A")     # loop cut, valid branch (HTTPS Custom) matches
    assert len(out) == 1 and out[0].hits[0].port == 8443


def test_no_management_ports_in_tsr_means_no_match():
    snap = _snapshot([_rule(1, service="HTTPS Custom")])
    snap["administration"] = {}
    assert evaluate_management_definition({"conditions": _svc_cond()}, snap) == []


# ---- multi-value OR semantics: custom service ports -----------------------------
def _port_cond(ports):
    return [{"field": "service_ports", "target": "custom_ports", "value": ports}]


def test_custom_ports_any_one_match_suffices():
    # Doc examples: resolved TCP/443 vs configured {80,443,8443} → MATCH, etc.
    assert len(_svc_matches("Plain HTTPS", conditions=_port_cond("80, 443, 8443"))) == 1
    assert len(_svc_matches("HTTPS Custom", conditions=_port_cond("80, 443, 8443"))) == 1
    hit = _svc_matches("Plain HTTPS", conditions=_port_cond("80, 443, 8443"))[0].hits[0]
    assert (hit.port, hit.protocol) == (443, "TCP")
    assert "service port 443" in hit.summary()


def test_custom_ports_no_match_when_port_not_listed():
    # Resolved TCP/8080 vs configured {80,443,8443} → NO MATCH.
    assert _svc_matches("HTTP Custom", conditions=_port_cond("80, 443, 8443")) == []


def test_custom_ports_multi_port_resolved_service():
    # Nested group resolves to {8443, 8080, 2222}; configured {443, 8443} —
    # one common port (8443) is sufficient.
    out = _svc_matches("Management Services", conditions=_port_cond("443, 8443"))
    assert len(out) == 1
    assert [h.port for h in out[0].hits] == [8443]


def test_custom_ports_protocol_still_enforced():
    assert _svc_matches("UDP 8443", conditions=_port_cond("8443")) == []


def test_custom_ports_through_circular_groups():
    out = _svc_matches("SvcLoop A", conditions=_port_cond("8443"))
    assert len(out) == 1 and out[0].hits[0].port == 8443


def test_multi_value_validation():
    assert validate_definition({"conditions": [
        {"field": "dst_address", "target": "ip_address",
         "value": "192.168.1.1, 10.0.0.5"}]}) == []
    assert validate_definition({"conditions": [
        {"field": "dst_address", "target": "ip_address",
         "value": "192.168.1.1, nope"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "service_ports", "target": "custom_ports",
         "value": "80, 443, 8443"}]}) == []
    assert validate_definition({"conditions": [
        {"field": "service_ports", "target": "custom_ports", "value": "80, abc"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "service_ports", "target": "custom_ports", "value": "99999"}]}) != []
    # custom_ports is a service-domain target only.
    assert validate_definition({"conditions": [
        {"field": "dst_address", "target": "custom_ports", "value": "443"}]}) != []


# ---- operators on resolved attributes --------------------------------------------
def _ip_op(op, ip):
    return [{"field": "dst_address", "operator": op, "target": "ip_address", "value": ip}]


def test_semantic_is_not_address():
    # dst "Server 5" resolves to 203.0.113.5 only. IS NOT = NONE-match.
    assert len(_matches("Server 5", conditions=_ip_op("is_not", "192.168.1.1"))) == 1
    assert _matches("Server 5", conditions=_ip_op("is_not", "203.0.113.5")) == []
    # Multi-value reference: ONE matching value blocks IS NOT (never
    # "any value differs" semantics).
    assert _matches("Two Hosts", conditions=_ip_op("is_not", "192.168.9.2, 10.9.9.9")) == []
    assert len(_matches("Two Hosts", conditions=_ip_op("is_not", "10.9.9.9"))) == 1
    # The operator applies AFTER nested-group resolution.
    assert len(_matches("Group A", conditions=_ip_op("is_not", "8.8.8.8"))) == 1
    assert _matches("Group A", conditions=_ip_op("is_not", "192.168.1.1")) == []


def test_semantic_is_not_requires_resolution():
    # Unresolvable names and "Any" never satisfy IS NOT (evidence-gated).
    assert _matches("Any", conditions=_ip_op("is_not", "1.2.3.4")) == []
    assert _matches("No Such Object", conditions=_ip_op("is_not", "1.2.3.4")) == []


def test_semantic_is_not_interface_target():
    cond = [{"field": "dst_address", "operator": "is_not", "target": "all_interface_ips"}]
    assert len(_matches("Server 5", conditions=cond)) == 1   # no interface exposure
    assert _matches("X0 IP", conditions=cond) == []


def test_semantic_is_not_service():
    mgmt = [{"field": "service_ports", "operator": "is_not", "target": "all_management_ports"}]
    assert _svc_matches("HTTPS Custom", conditions=mgmt) == []
    assert len(_svc_matches("Plain HTTPS", conditions=mgmt)) == 1   # 443 not a mgmt port here

    def custom(op, v):
        return [{"field": "service_ports", "operator": op, "target": "custom_ports", "value": v}]
    assert _svc_matches("Plain HTTPS", conditions=custom("is_not", "443")) == []
    assert len(_svc_matches("Plain HTTPS", conditions=custom("is_not", "8080"))) == 1
    # Protocol respected: UDP/8443 does not satisfy a TCP-port target → IS NOT fires.
    assert len(_svc_matches("UDP 8443", conditions=custom("is_not", "8443"))) == 1
    # Nested and circular service groups resolve before the operator applies.
    assert _svc_matches("Management Services", conditions=custom("is_not", "8443")) == []
    assert len(_svc_matches("SvcLoop A", conditions=custom("is_not", "9999"))) == 1


def test_direct_not_contains_operator():
    snap = _snapshot([_rule(1, dst="X0 IP", comment="temporary exception")])

    def cond(op, v):
        return {"conditions": [
            {"field": "comment", "operator": op, "value": v},
            {"field": "dst_address", "target": "all_interface_ips"}]}
    assert len(evaluate_management_definition(cond("not_contains", "no dpi"), snap)) == 1
    assert evaluate_management_definition(cond("not_contains", "exception"), snap) == []
    assert len(evaluate_management_definition(cond("contains", "exception"), snap)) == 1


def test_operator_validation():
    ok = [{"field": "dst_address", "operator": "is_not",
           "target": "ip_address", "value": "1.2.3.4"}]
    assert validate_definition({"conditions": ok}) == []
    # Nonsensical combinations are rejected.
    assert validate_definition({"conditions": [
        {"field": "dst_address", "operator": "contains",
         "target": "ip_address", "value": "1.2.3.4"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "enabled", "operator": "contains", "value": "true"}]}) != []
    assert validate_definition({"conditions": [
        {"field": "comment", "operator": "not_contains", "value": "x"}]}) == []


# ---- zone wildcard --------------------------------------------------------------
def _zone_cond(src, dst):
    return [{"field": "src_zone", "operator": "equals", "value": src},
            {"field": "dst_zone", "operator": "equals", "value": dst},
            {"field": "dst_address", "target": "all_interface_ips"}]


def test_zone_wildcards():
    snap = _snapshot([_rule(1, src_zone="SSLVPN", dst_zone="LAN", dst="X0 IP")])
    run = lambda src, dst: evaluate_management_definition(  # noqa: E731
        {"conditions": _zone_cond(src, dst)}, snap)
    assert len(run("*", "LAN")) == 1        # any source zone
    assert len(run("SSLVPN", "*")) == 1     # any destination zone
    assert len(run("*", "*")) == 1          # both wildcards
    assert run("WAN", "*") == []            # specific + wildcard still constrains
    assert run("*", "WAN") == []
    assert len(run("sslvpn", "lan")) == 1   # direct matching unchanged (ci)
    # "*" is never a literal zone name.
    snap_star = _snapshot([_rule(1, src_zone="*", dst_zone="LAN", dst="X0 IP")])
    out = evaluate_management_definition(
        {"conditions": _zone_cond("*", "LAN")}, snap_star)
    assert len(out) == 1   # wildcard matched the literal-star rule as "any", not as equality


# ---- combined conditions ---------------------------------------------------------
def test_combined_wildcard_interface_and_service():
    # Source Zone = *, Destination Zone = WAN,
    # Destination Address = X0 Interface IP, Service = All Management Ports.
    conditions = [
        {"field": "src_zone", "operator": "equals", "value": "*"},
        {"field": "dst_zone", "operator": "equals", "value": "WAN"},
        {"field": "dst_address", "target": "interface_ip", "value": "X0"},
        {"field": "service_ports", "target": "all_management_ports"},
    ]
    snap = _snapshot([
        _rule(1, src_zone="SSLVPN", dst="X0 IP", service="HTTPS Custom"),   # match
        _rule(2, src_zone="SSLVPN", dst="X0 IP", service="Plain HTTPS"),    # non-mgmt port
        _rule(3, src_zone="SSLVPN", dst="Mgmt", service="HTTPS Custom"),    # X1, not X0
    ])
    out = evaluate_management_definition({"conditions": conditions}, snap)
    assert [m.rule["num"] for m in out] == [1]
    kinds = {h.kind for h in out[0].hits}
    assert kinds == {"interface", "service_port"}


def test_combined_specific_ips_and_service():
    conditions = [
        {"field": "src_address", "target": "ip_address", "value": "203.0.113.5"},
        {"field": "dst_address", "target": "ip_address", "value": "192.168.1.1"},
        {"field": "service_ports", "target": "all_management_ports"},
    ]
    snap = _snapshot([
        _rule(1, src="Server 5", dst="Group A", service="Management Services"),  # match
        _rule(2, src="Server 5", dst="Group A", service="DNS UDP"),
        _rule(3, src="LAN Net", dst="Group A", service="Management Services"),
    ])
    out = evaluate_management_definition({"conditions": conditions}, snap)
    assert [m.rule["num"] for m in out] == [1]


# ---- DB layer: findings inherit rule metadata -------------------------------
def _add_management_rule(key, conditions, severity="Critical",
                         category="Firewall Management", enabled=True):
    db = SessionLocal()
    try:
        db.add(Rule(organization_id=None, key=key,
                    title="Firewall Management Exposed to WAN",
                    category=category, severity=severity,
                    description="Management reachable from WAN.",
                    condition="", remediation="Restrict management sources.",
                    compliance={}, references=[], source=RuleSource.system,
                    state=RuleState.approved, enabled=enabled,
                    kind="management",
                    definition={"match": "access_rules", "conditions": conditions}))
        db.commit()
    finally:
        db.close()


def test_evaluate_management_rules_builds_findings(client, org_a):
    _add_management_rule("MGMT-T-1", MGMT_CONDITIONS)
    _add_management_rule("MGMT-T-OFF", MGMT_CONDITIONS, enabled=False)
    snap = _snapshot([_rule(1, dst="X0 IP"), _rule(2, dst="Group A")])
    db = SessionLocal()
    try:
        findings = evaluate_management_rules(db, snap)
    finally:
        db.close()
    assert len(findings) == 2                      # one per matching access rule
    f = findings[0]
    assert f.rule_id == "MGMT-T-1"
    assert f.title == "Firewall Management Exposed to WAN"
    assert f.severity == "Critical"
    assert f.category == "Firewall Management"
    assert f.remediation == "Restrict management sources."
    assert f.object_type == "Access Rule"
    assert any("Matched interface" in line for line in f.evidence)


# ---- API endpoints -----------------------------------------------------------
def _superadmin_headers(client, org):
    db = SessionLocal()
    try:
        db.get(User, org["owner_id"]).is_superadmin = True
        db.commit()
    finally:
        db.close()
    res = client.post("/api/v1/auth/login",
                      json={"email": org["email"], "password": org["password"]})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_management_rule_crud_and_validation(client, org_a):
    h = _superadmin_headers(client, org_a)
    body = {"key": "MGMT-API-1", "title": "Exposed Mgmt", "severity": "High",
            "category": "Firewall Management", "description": "d",
            "remediation": "r", "enabled": True,
            "conditions": [
                {"field": "src_zone", "operator": "equals", "value": "WAN"},
                {"field": "dst_address", "operator": "", "value": "",
                 "target": "all_interface_ips"}]}
    res = client.post("/api/v1/rules/management", headers=h, json=body)
    assert res.status_code == 201, res.text
    rule_id = res.json()["id"]
    assert res.json()["conditions"][1]["target"] == "all_interface_ips"

    # duplicate key
    assert client.post("/api/v1/rules/management", headers=h, json=body).status_code == 409
    # invalid condition
    bad = dict(body, key="MGMT-API-2",
               conditions=[{"field": "bogus", "value": "x"}])
    assert client.post("/api/v1/rules/management", headers=h, json=bad).status_code == 400

    # list + options
    rules = client.get("/api/v1/rules/management", headers=h).json()
    assert any(r["key"] == "MGMT-API-1" for r in rules)
    options = client.get("/api/v1/rules/management/options", headers=h).json()
    assert "dst_address" in options["semantic_fields"]
    assert any(t["key"] == "all_interface_ips" for t in options["targets"])

    # update
    body["severity"] = "Critical"
    res = client.put(f"/api/v1/rules/management/{rule_id}", headers=h, json=body)
    assert res.status_code == 200 and res.json()["severity"] == "Critical"

    # delete
    assert client.delete(f"/api/v1/rules/management/{rule_id}", headers=h).status_code == 204
    assert client.get("/api/v1/rules/management", headers=h).json() == []


def test_management_endpoints_require_superadmin(client, org_b):
    res = client.post("/api/v1/auth/login",
                      json={"email": org_b["email"], "password": org_b["password"]})
    h = {"Authorization": f"Bearer {res.json()['access_token']}"}
    assert client.get("/api/v1/rules/management", headers=h).status_code == 403


def test_management_test_endpoint_uses_saved_snapshot(client, org_a):
    h = _superadmin_headers(client, org_a)
    from app.models import BuilderSnapshot
    db = SessionLocal()
    try:
        db.add(BuilderSnapshot(user_id=org_a["owner_id"], filename="ref.wri",
                               snapshot=_snapshot([_rule(1, dst="Group A")])))
        db.commit()
    finally:
        db.close()
    res = client.post("/api/v1/rules/management/test", headers=h,
                      json={"conditions": MGMT_CONDITIONS})
    assert res.status_code == 200, res.text
    out = res.json()
    assert out["error"] == "" and len(out["matches"]) == 1
    assert out["matches"][0]["hits"][0]["interface"] == "X0"


# ---- end to end: TSR upload → analysis → finding -----------------------------
MGMT_TSR = """\
#System : Status_START
#Blade_1_STATUS_START
Model : TZ 470
Firmware Version : SonicOS 7.1.1-7047
Serial number : SN-MGMT-1
#Blade_1_STATUS_END
#System : Status_END
#Network : Interfaces_START
#Blade_1_INTERFACES_START
Interface Name : X0
Zone : LAN
IP Address : 192.168.1.1
Network Mask : 255.255.255.0
Interface Name : X1
Zone : WAN
IP Address : 10.10.10.1
Network Mask : 255.255.255.0
#Blade_1_INTERFACES_END
#Network : Interfaces_END
#Network : Address Objects_START
Number of objects: 2
--Address Object Table--
-----X1 IP(X1 IP)-----
HOST : 10.10.10.1
Class : Default
--Address Group Table--
-----WAN Interface IP(WAN Interface IP)-----
member: Name:X1 IP Handle:5
#Network : Address Objects_END
#Firewall : Access Rules_START
#Blade_1_ACCESS_RULES_START
Rule 1 LAN -> LAN Allow Service Any -> Any (Enabled)
IP : Any -> Any
Rule 2 WAN -> WAN Allow Service HTTPS Management -> HTTPS Management (Enabled)
IP : Any -> WAN Interface IP
#Blade_1_ACCESS_RULES_END
#Firewall : Access Rules_END
"""


def test_synthetic_mgmt_tsr_parses():
    snap = parse_tsr(MGMT_TSR, "t")
    assert [i["name"] for i in snap["interfaces"]] == ["X0", "X1"]
    assert snap["address_objects"]["groups"][0]["members"] == ["X1 IP"]
    assert snap["access_rules"][1]["dst"] == "WAN Interface IP"


def test_management_rule_creates_finding_via_upload(client, org_a):
    h = _superadmin_headers(client, org_a)
    body = {"key": "MGMT-E2E-1", "title": "Firewall Management Exposed to WAN",
            "severity": "Critical", "category": "Firewall Management",
            "description": "Management reachable from WAN.",
            "remediation": "Restrict management sources.", "enabled": True,
            "conditions": MGMT_CONDITIONS}
    assert client.post("/api/v1/rules/management", headers=h, json=body).status_code == 201

    from app.models import Device
    db = SessionLocal()
    try:
        device = Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                        serial="SN-MGMT-1", friendly_name="mgmt test", configured=False)
        db.add(device)
        db.commit()
        device_id = device.id
    finally:
        db.close()

    res = client.post(f"/api/v1/customers/{org_a['customer_id']}/tsrs",
                      headers=h, params={"device_id": device_id},
                      files={"file": ("mgmt.wri", MGMT_TSR.encode(), "text/plain")})
    assert res.status_code in (200, 201, 202), res.text

    rows = client.get("/api/v1/findings", headers=h,
                      params={"device_id": device_id}).json()
    hits = [f for f in rows if f["rule_id"] == "MGMT-E2E-1"]
    assert len(hits) == 1, [f["rule_id"] for f in rows]
    f = hits[0]
    assert f["title"] == "Firewall Management Exposed to WAN"
    assert f["severity"] == "Critical"
    assert f["category"] == "Firewall Management"
    assert f["status"] == "open"


# ---- finding identity & lifecycle (duplicate regression) ---------------------
def test_findings_unique_identity_for_same_named_access_rules(client, org_a):
    """SonicWall names many rules identically ("Default Access Rule"); each
    matching access rule must still get its OWN finding identity."""
    _add_management_rule("MGMT-ID-1", MGMT_CONDITIONS)
    snap = _snapshot([
        _rule(58, dst="X0 IP", name="Default Access Rule"),
        _rule(60, dst="Group A", name="Default Access Rule"),
    ])
    db = SessionLocal()
    try:
        findings = evaluate_management_rules(db, snap)
    finally:
        db.close()
    assert [f.object_name for f in findings] == [
        "Rule 58: Default Access Rule", "Rule 60: Default Access Rule"]
    # Distinct identities → distinct fingerprints in the workflow table.
    from app.findings_sync import fingerprint
    fps = {fingerprint(f.rule_id, f.object_type, f.object_name) for f in findings}
    assert len(fps) == 2


def test_two_rules_same_access_rule_are_separate_findings(client, org_a):
    _add_management_rule("MGMT-A", MGMT_CONDITIONS)
    _add_management_rule("MGMT-B", MGMT_CONDITIONS)
    snap = _snapshot([_rule(60, dst="X0 IP", name="Default Access Rule")])
    db = SessionLocal()
    try:
        findings = evaluate_management_rules(db, snap)
    finally:
        db.close()
    assert sorted(f.rule_id for f in findings) == ["MGMT-A", "MGMT-B"]
    assert all(f.object_name == "Rule 60: Default Access Rule" for f in findings)


def test_sync_never_inserts_duplicate_fingerprints_in_one_batch(client, org_a):
    """Even if two pipeline findings collapse to one identity, one analysis
    must yield exactly one row for that identity."""
    from app.database import SessionLocal as SL
    from app.findings_sync import sync_findings
    from app.models import Analysis, AnalysisStatus, Device, Finding
    d = {"rule_id": "R-1", "title": "t", "severity": "High", "category": "c",
         "object_type": "Access Rule", "object_name": "SAME", "evidence": ["e"]}
    db = SL()
    try:
        device = Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                        serial="SN-SYNC-1", friendly_name="s", configured=True)
        db.add(device)
        db.flush()
        analysis = Analysis(organization_id=org_a["org_id"], device_id=device.id,
                            tsr_id="t-sync-1", status=AnalysisStatus.complete,
                            result_json={"findings": [dict(d), dict(d)]})
        db.add(analysis)
        db.commit()
        summary = sync_findings(db, analysis)
        rows = db.scalars(select_findings(device.id)).all()
        assert summary["created"] == 1
        assert len(rows) == 1
    finally:
        db.close()


def test_sync_heals_preexisting_duplicate_identity_rows(client, org_a):
    """Historical same-fingerprint duplicates: the newest row stays live and
    reconciles; the shadowed one is auto-resolved instead of lingering open."""
    from datetime import datetime, timedelta, timezone
    from app.database import SessionLocal as SL
    from app.findings_sync import sync_findings
    from app.models import Analysis, AnalysisStatus, Device, Finding, FindingStatus
    now = datetime.now(timezone.utc)
    db = SL()
    try:
        device = Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                        serial="SN-SYNC-2", friendly_name="s", configured=True)
        db.add(device)
        db.flush()
        for i, age in enumerate((2, 1)):  # two rows, same fingerprint, older first
            db.add(Finding(
                organization_id=org_a["org_id"], device_id=device.id,
                analysis_id=None, fingerprint="R-1::Access Rule::SAME",
                rule_id="R-1", title="t", severity="High", category="c",
                object_type="Access Rule", object_name="SAME",
                status=FindingStatus.open,
                first_seen_at=now - timedelta(days=age),
                last_seen_at=now - timedelta(days=age)))
        analysis = Analysis(organization_id=org_a["org_id"], device_id=device.id,
                            tsr_id="t-sync-2", status=AnalysisStatus.complete,
                            result_json={"findings": [
                                {"rule_id": "R-1", "title": "t", "severity": "High",
                                 "category": "c", "object_type": "Access Rule",
                                 "object_name": "SAME", "evidence": ["e"]}]})
        db.add(analysis)
        db.commit()
        sync_findings(db, analysis)
        rows = db.scalars(select_findings(device.id)).all()
        assert len(rows) == 2
        statuses = sorted(r.status.value for r in rows)
        assert statuses == ["fixed", "open"]          # shadowed one resolved
        live = next(r for r in rows if r.status == FindingStatus.open)
        assert live.analysis_id == analysis.id
    finally:
        db.close()


def select_findings(device_id: str):
    from sqlalchemy import select
    from app.models import Finding
    return select(Finding).where(Finding.device_id == device_id)


MGMT_TSR_TWO_MATCHES = MGMT_TSR.replace(
    """Rule 2 WAN -> WAN Allow Service HTTPS Management -> HTTPS Management (Enabled)
IP : Any -> WAN Interface IP""",
    """Rule 2 WAN -> WAN Allow Service HTTPS Management -> HTTPS Management (Enabled)
IP : Any -> WAN Interface IP
Rule 3 WAN -> WAN Allow Service HTTPS Management -> HTTPS Management (Enabled)
IP : Any -> X1 IP""")


def test_reanalysis_does_not_duplicate_findings(client, org_a):
    """One rule + two matching access rules = two findings; re-uploading the
    same TSR must update those two rows, never create duplicates."""
    h = _superadmin_headers(client, org_a)
    body = {"key": "MGMT-E2E-2", "title": "MANAGEMENT PORTS ACCESS",
            "severity": "Critical", "category": "Firewall Management",
            "description": "d", "remediation": "r", "enabled": True,
            "conditions": MGMT_CONDITIONS}
    assert client.post("/api/v1/rules/management", headers=h, json=body).status_code == 201

    from app.models import Device
    db = SessionLocal()
    try:
        device = Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                        serial="SN-MGMT-1", friendly_name="mgmt", configured=False)
        db.add(device)
        db.commit()
        device_id = device.id
    finally:
        db.close()

    def upload():
        res = client.post(f"/api/v1/customers/{org_a['customer_id']}/tsrs",
                          headers=h, params={"device_id": device_id},
                          files={"file": ("m.wri", MGMT_TSR_TWO_MATCHES.encode(), "text/plain")})
        assert res.status_code in (200, 201, 202), res.text

    def rule_findings():
        rows = client.get("/api/v1/findings", headers=h,
                          params={"device_id": device_id}).json()
        return sorted((f["object_name"], f["id"], f["status"]) for f in rows
                      if f["rule_id"] == "MGMT-E2E-2")

    upload()
    first = rule_findings()
    assert [(o, s) for o, _i, s in first] == [("Rule 2", "open"), ("Rule 3", "open")]

    upload()   # re-analysis of the same configuration
    second = rule_findings()
    assert second == first     # same two rows — updated in place, not duplicated


# ---- acceptance on the reference TSR (gated) ---------------------------------
_TSR_DIR = os.environ.get(
    "FGAI_TSR_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "TSRs"))
_REFERENCE = os.path.join(_TSR_DIR, "techSupport_2CB8EDA47A18_9-12.wri")


@pytest.mark.skipif(not os.path.exists(_REFERENCE), reason="Reference TSR not available")
def test_reference_tsr_management_rule():
    from firewallguard.tsr.normalize import normalize_tsr
    text, _fmt = normalize_tsr(open(_REFERENCE, encoding="utf-8", errors="replace").read())
    snap = parse_tsr(text, "ref")
    out = evaluate_management_definition(DEFN, snap)
    assert out, "expected WAN->WAN management exposure matches in the reference TSR"
    by_num = {m.rule["num"]: m for m in out}
    # Rule 29: dst "WAN Interface IP" (a GROUP) → member "X1:V95 IP" → the
    # live WAN interface IP — resolved through a real group chain.
    assert 29 in by_num
    hit = by_num[29].hits[0]
    assert hit.interface == "X1:V95" and hit.ip == "50.235.113.122"


@pytest.mark.skipif(not os.path.exists(_REFERENCE), reason="Reference TSR not available")
def test_reference_tsr_service_management_ports():
    from firewallguard.tsr.normalize import normalize_tsr
    text, _fmt = normalize_tsr(open(_REFERENCE, encoding="utf-8", errors="replace").read())
    snap = parse_tsr(text, "ref")
    # This firewall manages HTTPS on the CUSTOM port 50554 (not 443) and SSH
    # on 22 — All Management Ports must resolve those from the TSR itself.
    assert snap["administration"]["https_port"] == 50554
    assert snap["administration"]["ssh_port"] == 22
    out = evaluate_management_definition(
        {"conditions": [{"field": "service_ports", "target": "all_management_ports"}]},
        snap)
    assert out, "expected access rules exposing management ports"
    ports = {h.port for m in out for h in m.hits}
    assert 50554 in ports
