"""Tests for dual-format (GUI vs API) TSR support.

Covers the normalizer (``firewallguard.tsr.normalize``) that reconstructs
GUI-equivalent text from an API-collected TSR, the format auto-detector, and the
rule API-support classification in ``app.rule_engine`` that drives suppression of
table-dependent rules on API TSRs.
"""

from __future__ import annotations

import pytest

from firewallguard.tsr.normalize import (
    detect_tsr_format,
    normalize_api_tsr,
    normalize_tsr,
    _demerge_interfaces,
    _fixups,
    _load_keys,
)
from app.rule_engine import (
    rule_api_support,
    api_unsupported_system_keys,
    seed_system_rules,
)


# --- sample TSRs ----------------------------------------------------------
def _gui_tsr() -> str:
    """12 sections with markers on their own lines (GUI shape)."""
    out = []
    for i in range(12):
        out.append(f"#SECTION {i}_START")
        out.append(f"Firewall Name : fw-{i}")
        out.append(f"#SECTION {i}_END")
    return "\n".join(out)


def _api_tsr() -> str:
    """12 sections with markers run inline (API shape)."""
    parts = []
    for i in range(12):
        parts.append(f"FirewallName: fw-{i}#Section {i}: Status_START "
                     f"CPU: 5#Section {i}: Status_END")
    return "".join(parts)


# --- detection ------------------------------------------------------------
def test_detect_gui():
    assert detect_tsr_format(_gui_tsr()) == "gui"


def test_detect_api():
    assert detect_tsr_format(_api_tsr()) == "api"


def test_detect_below_threshold_defaults_gui():
    # Fewer than 10 markers: insufficient signal, treat as GUI (the safe path).
    assert detect_tsr_format("#One_START\nx : y\n#One_END") == "gui"


# --- normalize_tsr dispatch ----------------------------------------------
def test_normalize_gui_passthrough():
    gui = _gui_tsr()
    text, fmt = normalize_tsr(gui)
    assert fmt == "gui"
    assert text == gui  # GUI TSRs are never rewritten


def test_normalize_api_detected():
    _text, fmt = normalize_tsr(_api_tsr())
    assert fmt == "api"


# --- marker restoration ---------------------------------------------------
def test_restore_markers_to_own_lines():
    out = normalize_api_tsr(_api_tsr())
    lines = out.split("\n")
    starts = [ln for ln in lines if ln.startswith("#") and ln.rstrip().endswith("_START")]
    # Every START marker is now on its own line, and there are 12 of them.
    assert len(starts) == 12
    # After normalization the result is itself detected as GUI.
    assert detect_tsr_format(out) == "gui"


# --- value fixups ---------------------------------------------------------
def test_fixups_respace_model_and_firmware():
    out = _fixups("Model: NSa6700 firmware SonicOS7.1.1")
    assert "NSa 6700" in out
    assert "SonicOS 7.1.1" in out


def test_fixups_preserve_numeric_times():
    # "space after every colon" is undone inside numeric values.
    assert _fixups("Uptime: 08: 27: 50") == "Uptime: 08:27:50"


def test_demerge_interfaces():
    assert _demerge_interfaces("X0X1MGMT") == "X0 X1 MGMT"
    assert _demerge_interfaces("None") == "None"
    assert _demerge_interfaces("X0 X1") == "X0 X1"  # already separated


# --- key re-segmentation --------------------------------------------------
def test_segment_kv_restores_known_key():
    mapping, _maxlen = _load_keys()
    if not mapping:
        pytest.skip("sonicos_keys.txt dictionary not present")
    # Pick a multi-word canonical key so the restoration is observable.
    canon = next((c for s, c in mapping.items() if " " in c and 6 <= len(s) <= 40), None)
    if canon is None:
        pytest.skip("no suitable multi-word key in dictionary")
    stripped = canon.replace(" ", "")
    # A run-on line: junk prefix immediately followed by the merged key + value.
    out = normalize_api_tsr(
        "#Diag: Info_START\nzzz" + stripped + ": hello-value\n#Diag: Info_END")
    assert f"{canon} : hello-value" in out


# --- rule API-support classification -------------------------------------
# The normalizer reconstructs every config section, so the full rule set is
# evaluable on API TSRs: rule_api_support returns "full" for all rules and no
# system rule is suppressed. The classification mechanism is retained for any
# future irrecoverable rule (none today).
def test_rule_api_support_table_rules_are_full():
    # Per-object table sections (address objects, access rules) used to be
    # suppressed; they now reconstruct, so these are evaluable.
    assert rule_api_support("AOB-003",
                            "size(snapshot.address_objects) > 0") == "full"
    assert rule_api_support("ACR-001",
                            "snapshot.access_rules[0].action == 'allow'") == "full"


def test_rule_api_support_lossless_section_is_full():
    assert rule_api_support(
        "SVC-X", "snapshot.security_services.ips_enabled == false") == "full"


def test_rule_api_support_custom_defaults_full():
    assert rule_api_support("CUSTOM-XYZ",
                            "snapshot.firmware.version == '7.0.0'") == "full"


# --- DB-backed: no system rules are suppressed on API TSRs ----------------
def test_api_unsupported_system_keys_empty(db_schema):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        seed_system_rules(db)
        keys = api_unsupported_system_keys(db)
        assert keys == []  # full parity — nothing is suppressed on API
    finally:
        db.close()


# --- end-to-end parity on the reference TSR pair (gated on file presence) ---
# Set FGAI_GUI_TSR and FGAI_API_TSR to the same firewall's GUI- and API-collected
# reports to assert the two analyses agree. Skipped when unset/absent.
def test_gui_api_findings_parity():
    import os
    from collections import Counter
    from firewallguard.pipeline import analyze_text
    from firewallguard.tsr.normalize import normalize_tsr

    gui_path = os.environ.get("FGAI_GUI_TSR")
    api_path = os.environ.get("FGAI_API_TSR")
    if not (gui_path and api_path and os.path.exists(gui_path) and os.path.exists(api_path)):
        pytest.skip("FGAI_GUI_TSR / FGAI_API_TSR not set")

    gui = open(gui_path, encoding="utf-8", errors="replace").read()
    napi, fmt = normalize_tsr(open(api_path, encoding="utf-8", errors="replace").read())
    assert fmt == "api"
    rg = analyze_text(gui, "gui")
    ra = analyze_text(napi, "api")

    sg, sa = rg["score"]["severity_counts"], ra["score"]["severity_counts"]
    # Critical/High/Medium/Info must match exactly; allow a small Low delta from
    # IPv6 address-object hygiene (colons in IPv6 literals are mangled by the API).
    for sev in ("Critical", "High", "Medium", "Info"):
        assert sg.get(sev, 0) == sa.get(sev, 0), f"{sev}: GUI={sg} API={sa}"
    assert abs(sg.get("Low", 0) - sa.get("Low", 0)) <= 5
    # Scores should be within a couple of points.
    assert abs(rg["score"]["score"] - ra["score"]["score"]) <= 3

    cg = Counter(f["rule_id"] for f in rg["findings"])
    ca = Counter(f["rule_id"] for f in ra["findings"])
    # No rule should be entirely lost on the API side.
    lost = [k for k in cg if ca.get(k, 0) == 0]
    assert lost == [], f"rules lost on API: {lost}"
