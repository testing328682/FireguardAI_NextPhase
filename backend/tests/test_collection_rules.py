"""Collection-aware CEL rules: exists() over snapshot collections.

Covers the CEL Rule Builder change that replaces hardcoded array indexes
(``snapshot.access_rules[0].src_zone``) with collection wildcards that the UI
folds into a single ``exists()`` per collection, so every condition binds to
the SAME element. Also covers the evaluation-context pruning that keeps
collection predicates fast (celpy macro cost grows with activation size).
"""

from __future__ import annotations

import os

import pytest

from app.rule_engine import _condition_context, evaluate_condition
from firewallguard.tsr.parser import parse_tsr

SNAPSHOT = {
    "access_rules": [
        {"num": 1, "src_zone": "LAN", "dst_zone": "LAN",
         "dst": "All X0 Management IP", "action": "Allow", "enabled": True},
        {"num": 2, "src_zone": "DMZ", "dst_zone": "WAN",
         "dst": "Any", "action": "Allow", "enabled": True},
        {"num": 3, "src_zone": "WAN", "dst_zone": "WAN",
         "dst": "WAN Interface IP", "action": "Deny", "enabled": False},
    ],
    "nat_policies": [
        {"index": 1, "name": "x"},
        {"index": 2, "name": "Default NAT Policy"},
    ],
    "address_objects": {"objects": [
        {"name": "a", "value": "10.0.0.1"},
        {"name": "b", "value": "10.200.200.1"},
    ]},
    "config": {"big": {"filler": ["z"] * 10}},
}


@pytest.mark.parametrize("condition,expected", [
    # ANY-element match; the matching rule is at index 2, not 0.
    ('snapshot.access_rules.exists(x, x.src_zone == "WAN" && x.dst_zone == "WAN" '
     '&& x.dst == "WAN Interface IP")', True),
    # Same fields checked at index 0 — demonstrates why indexes are fragile.
    ('snapshot.access_rules[0].src_zone == "WAN"', False),
    # Indexed expressions keep working (backward compatibility).
    ('snapshot.access_rules[0].dst == "All X0 Management IP"', True),
    # SAME-object semantics: each value exists on SOME rule (LAN on #1,
    # WAN dst_zone on #2/#3, Deny on #3) but no single rule has all three.
    ('snapshot.access_rules.exists(x, x.src_zone == "LAN" && x.dst_zone == "WAN" '
     '&& x.action == "Deny")', False),
    # Booleans and negation inside the predicate.
    ('snapshot.access_rules.exists(x, x.enabled == false && x.action == "Deny")', True),
    ('snapshot.access_rules.exists(x, !(x.action == "Allow"))', True),
    # Other collections, including one nested under a dict.
    ('snapshot.nat_policies.exists(x, x.name == "Default NAT Policy")', True),
    ('snapshot.address_objects.objects.exists(x, x.value == "10.200.200.1")', True),
    ('snapshot.address_objects.objects.exists(x, x.value == "1.2.3.4")', False),
])
def test_exists_conditions(condition, expected):
    fired, error = evaluate_condition(condition, SNAPSHOT)
    assert error == ""
    assert fired is expected


# ---- evaluation-context pruning ---------------------------------------------
def test_condition_context_prunes_to_referenced_keys():
    ctx = _condition_context('snapshot.access_rules.exists(x, x.num == 1) '
                             '&& snapshot.nat_policies[0].index == 1', SNAPSHOT)
    assert set(ctx) == {"access_rules", "nat_policies"}
    ctx = _condition_context('snapshot["config"].big.filler[0] == "z"', SNAPSHOT)
    assert set(ctx) == {"config"}


def test_condition_context_falls_back_to_full_snapshot():
    # Bare `snapshot` reference — cannot prune.
    assert _condition_context("size(snapshot) > 0", SNAPSHOT) is SNAPSHOT
    # Escapes we do not parse — cannot prune confidently.
    assert _condition_context('snapshot.access_rules[0].dst == "a\\"b"', SNAPSHOT) is SNAPSHOT


def test_pruning_preserves_missing_key_errors():
    fired, error = evaluate_condition("snapshot.nonexistent_key == 1", SNAPSHOT)
    assert fired is None
    assert "evaluation error" in error


# ---- end to end: authored global rule with exists() -------------------------
COLLECTION_TSR = """\
#System : Status_START
#Blade_1_STATUS_START
Model : TZ 470
Firmware Version : SonicOS 7.1.1-7047
Serial number : SN-COLL-1
#Blade_1_STATUS_END
#System : Status_END
#Firewall : Access Rules_START
#Blade_1_ACCESS_RULES_START
Rule 1 LAN -> LAN Allow Service Any -> Any (Enabled)
IP : Any -> All X0 Management IP
Rule 2 WAN -> WAN Deny Service Any -> Any (Enabled)
IP : Any -> WAN Interface IP
#Blade_1_ACCESS_RULES_END
#Firewall : Access Rules_END
"""

EXISTS_CONDITION = ('snapshot.access_rules.exists(x, x.src_zone == "WAN" '
                    '&& x.dst_zone == "WAN" && x.dst == "WAN Interface IP")')


def test_synthetic_tsr_parses_two_rules_with_match_not_at_zero():
    snap = parse_tsr(COLLECTION_TSR, "t")
    rules = snap["access_rules"]
    assert len(rules) == 2
    assert rules[0]["src_zone"] == "LAN"          # index 0 does NOT match
    assert rules[1]["dst"] == "WAN Interface IP"  # index 1 DOES match


def test_collection_rule_creates_finding_when_match_is_not_index_zero(client, org_a):
    from tests.test_global_rules import _run_flow
    out = _run_flow(client, org_a, COLLECTION_TSR.encode(), "coll.wri",
                    serial="SN-COLL-1", rule_key="GBL-COLL-E2E",
                    condition=EXISTS_CONDITION, title="WAN TO WAN MGMT RULE")
    finding = out["findings"].get("WAN TO WAN MGMT RULE")
    assert finding is not None, f"finding missing; got {list(out['findings'])}"
    assert finding["rule_id"] == "GBL-COLL-E2E"
    assert finding["status"] == "open"


def test_collection_rule_no_finding_when_values_span_different_rules(client, org_a):
    from tests.test_global_rules import _run_flow
    # LAN src (rule 1), WAN dst_zone (rule 2), Deny (rule 2): no single rule
    # carries all three, so the same-object exists() must not fire.
    cond = ('snapshot.access_rules.exists(x, x.src_zone == "LAN" '
            '&& x.dst_zone == "WAN" && x.action == "Deny")')
    out = _run_flow(client, org_a, COLLECTION_TSR.encode(), "coll.wri",
                    serial="SN-COLL-1", rule_key="GBL-COLL-NEG",
                    condition=cond, title="CROSS OBJECT MUST NOT FIRE")
    assert "CROSS OBJECT MUST NOT FIRE" not in out["findings"]


# ---- acceptance on the reference TSR (gated) ---------------------------------
_TSR_DIR = os.environ.get(
    "FGAI_TSR_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "TSRs"))
_REFERENCE = os.path.join(_TSR_DIR, "techSupport_2CB8EDA47A18_9-12.wri")


@pytest.mark.skipif(not os.path.exists(_REFERENCE), reason="Reference TSR not available")
def test_reference_tsr_collection_conditions():
    from firewallguard.tsr.normalize import normalize_tsr
    text, _fmt = normalize_tsr(open(_REFERENCE, encoding="utf-8", errors="replace").read())
    snap = parse_tsr(text, "ref")

    # The matching access rule sits at index 28 in this report — an indexed
    # [0] check misses it, the collection form finds it.
    checks = [
        ('snapshot.access_rules.exists(x, x.src_zone == "WAN" && x.dst_zone == "WAN" '
         '&& x.dst == "WAN Interface IP")', True),
        ('snapshot.access_rules[0].src_zone == "WAN" && '
         'snapshot.access_rules[0].dst_zone == "WAN"', False),
        ('snapshot.nat_policies.exists(x, x.name == "Default NAT Policy")', True),
        ('snapshot.address_objects.objects.exists(x, x.value == "10.200.200.1")', True),
    ]
    for condition, expected in checks:
        fired, error = evaluate_condition(condition, snap)
        assert error == "", (condition, error)
        assert fired is expected, condition
