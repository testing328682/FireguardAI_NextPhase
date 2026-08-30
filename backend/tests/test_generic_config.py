"""Tests for the generic full-configuration capture (snapshot["config"]).

The synthetic-TSR tests cover every representation the CEL Rule Builder needs
(scalars, booleans, numbers, empty values, lists, records, named blocks, raw
lines, nesting, duplicate section names) plus the marker quirks observed in
real SonicOS reports (misspelled / renamed END markers, stray ENDs).

The reference-TSR tests are gated on a directory of real reports
(``FGAI_TSR_DIR``, defaulting to ``<repo>/TSRs``) and assert that *every*
marker-delimited section of a real TSR is represented in the tree.
"""

from __future__ import annotations

import glob
import os

import pytest

from firewallguard.tsr.generic import MAX_RAW_LINES, build_config_tree
from firewallguard.tsr.parser import parse_tsr
from firewallguard.tsr.reader import TSRDocument
from app.rule_engine import evaluate_condition

SYNTHETIC_TSR = """\
#System : Status_START
#Blade_1_STATUS_START
Model : TZ 470
Firmware Version : SonicOS 7.1.1-7047
Serial number : 0040103CXXXX
#Blade_1_STATUS_END
#System : Status_END
#Mystery Feature : Frobnicator_START
Enable Frobnication : Enabled
Retry Count : 42
Threshold : -7
Description : Widget "alpha"
Empty Value :
#Nested Detail_START
Mode : off
member : one
member : two
member : three
#Nested Detail_END
#Mystery Feature : Frobnicator_END
#Records Demo_START
Number of things: 2
Interface : X0
Speed : 1G
Enabled : yes
Interface : X1
Speed : 10G
Enabled : no
#Records Demo_END
#Blocks Demo_START
--Object Table--
-----Alpha(Alpha)-----
HOST : 10.0.0.1
Class : Default
-----Beta-----
NETWORK : 10.0.0.0/24
--Group Table--
-----G1-----
member : Name:Alpha Handle:1
#Blocks Demo_END
#Typo Section_START
Key A : 1
#Typo Sectoin_END
#Outer Thing_START
Pre : 1
#Inner Thing_START
Val : 2
#Inner Thing_END
#Outer_Thing_END
#Dup_START
X : 1
#Dup_END
#Dup_START
X : 2
#Dup_END
#Raw Stuff_START
this line is not a kv
| col1 | col2 |
10.1.1.1 00:11:22:33:44:55 dynamic
#Raw Stuff_END
#Wireless : Ghost_END
"""


@pytest.fixture(scope="module")
def tree() -> dict:
    return build_config_tree(SYNTHETIC_TSR)


# ---- structure -------------------------------------------------------------
def test_all_sections_present(tree):
    for name in ("System : Status", "Mystery Feature : Frobnicator",
                 "Records Demo", "Blocks Demo", "Typo Section",
                 "Outer Thing", "Dup", "Dup_2", "Raw Stuff"):
        assert name in tree, f"missing section {name}"
    assert "Wireless : Ghost" not in tree  # stray END, never opened


def test_nested_sections_and_scalar_typing(tree):
    frob = tree["Mystery Feature : Frobnicator"]
    fields = frob["fields"]
    assert fields["Enable Frobnication"] is True      # boolean
    assert fields["Retry Count"] == 42                # int
    assert fields["Threshold"] == -7                  # negative int
    assert fields["Description"] == 'Widget "alpha"'  # string kept verbatim
    assert fields["Empty Value"] == ""                # empty value preserved
    nested = frob["sections"]["Nested Detail"]
    assert nested["fields"]["Mode"] is False
    assert nested["fields"]["member"] == ["one", "two", "three"]  # list

    status = tree["System : Status"]["sections"]["Blade_1_STATUS"]
    assert status["fields"]["Model"] == "TZ 470"


def test_repeated_key_records(tree):
    demo = tree["Records Demo"]
    assert demo["fields"]["Number of things"] == 2
    items = demo["items"]
    assert len(items) == 2
    assert items[0]["Interface"] == "X0"
    assert items[0]["Enabled"] is True
    assert items[1]["Speed"] == "10G"
    assert items[1]["Enabled"] is False


def test_dash_blocks_and_group_markers(tree):
    blocks = tree["Blocks Demo"]["blocks"]
    obj_table = blocks["Object Table"]["blocks"]
    assert obj_table["Alpha"]["fields"]["HOST"] == "10.0.0.1"   # Foo(Foo) → Foo
    assert obj_table["Beta"]["fields"]["NETWORK"] == "10.0.0.0/24"
    grp_table = blocks["Group Table"]["blocks"]
    assert grp_table["G1"]["fields"]["member"] == "Name:Alpha Handle:1"


def test_mismatched_end_markers_do_not_swallow_document(tree):
    # "#Typo Sectoin_END" must close "Typo Section"; the sections that follow
    # stay top-level instead of nesting underneath it.
    assert tree["Typo Section"]["fields"]["Key A"] == 1
    assert "sections" not in tree["Typo Section"]
    # "#Outer_Thing_END" (underscore variant) closes "Outer Thing".
    outer = tree["Outer Thing"]
    assert outer["fields"]["Pre"] == 1
    assert outer["sections"]["Inner Thing"]["fields"]["Val"] == 2


def test_duplicate_section_names_deduplicated(tree):
    assert tree["Dup"]["fields"]["X"] == 1
    assert tree["Dup_2"]["fields"]["X"] == 2


def test_raw_lines_preserved(tree):
    lines = tree["Raw Stuff"]["lines"]
    assert "this line is not a kv" in lines
    assert "| col1 | col2 |" in lines
    assert "10.1.1.1 00:11:22:33:44:55 dynamic" in lines  # MAC row is not a KV


def test_raw_line_cap_is_explicit():
    body = "\n".join(f"raw dump line {i} with no colon" for i in range(MAX_RAW_LINES + 50))
    tree = build_config_tree(f"#Big Dump_START\n{body}\n#Big Dump_END\n")
    node = tree["Big Dump"]
    assert len(node["lines"]) == MAX_RAW_LINES
    assert node["lines_total"] == MAX_RAW_LINES + 50  # truncation is marked


# ---- snapshot integration & CEL --------------------------------------------
@pytest.fixture(scope="module")
def snapshot() -> dict:
    return parse_tsr(SYNTHETIC_TSR, "synthetic")


def test_parse_tsr_adds_config_without_touching_curated_keys(snapshot):
    assert snapshot["system"]["model"] == "TZ 470"       # curated path intact
    assert snapshot["config"]["Records Demo"]["items"]   # generic path added
    for key in ("administration", "access_rules", "security_services"):
        assert key in snapshot


@pytest.mark.parametrize("condition,expected", [
    # legacy curated path — unchanged conventions
    ('snapshot.system.model == "TZ 470"', True),
    # boolean in an unknown section, index syntax for non-identifier keys
    ('snapshot.config["Mystery Feature : Frobnicator"].fields["Enable Frobnication"] == true', True),
    # numeric comparison
    ('snapshot.config["Mystery Feature : Frobnicator"].fields["Retry Count"] > 40', True),
    # deeply nested list membership
    ('"two" in snapshot.config["Mystery Feature : Frobnicator"].sections["Nested Detail"].fields.member', True),
    # record item access with dot syntax for identifier-like keys
    ('snapshot.config["Records Demo"].items[0].Interface == "X0"', True),
    ('snapshot.config["Records Demo"].items[1].Enabled == false', True),
    # named block lookup
    ('snapshot.config["Blocks Demo"].blocks["Object Table"].blocks.Alpha.fields.HOST == "10.0.0.1"', True),
    # existence / emptiness
    ('size(snapshot.config["Raw Stuff"].lines) > 0', True),
    ('snapshot.config["Mystery Feature : Frobnicator"].fields["Empty Value"] == ""', True),
    # negative case
    ('snapshot.config["Records Demo"].items[0].Speed == "10G"', False),
])
def test_cel_paths_evaluate(snapshot, condition, expected):
    fired, error = evaluate_condition(condition, snapshot)
    assert error == ""
    assert fired is expected


# ---- builder endpoints ------------------------------------------------------
def _superadmin_headers(client, org):
    from app.database import SessionLocal
    from app.models import User
    db = SessionLocal()
    try:
        db.get(User, org["owner_id"]).is_superadmin = True
        db.commit()
    finally:
        db.close()
    res = client.post("/api/v1/auth/login",
                      json={"email": org["email"], "password": org["password"]})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_builder_upload_returns_complete_snapshot(client, org_a):
    headers = _superadmin_headers(client, org_a)
    res = client.post(
        "/api/v1/rules/builder/upload", headers=headers,
        files={"file": ("synthetic.wri", SYNTHETIC_TSR.encode(), "text/plain")})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["tsr_format"] == "gui"
    config = body["snapshot"]["config"]
    assert config["Records Demo"]["items"][0]["Interface"] == "X0"
    assert config["Mystery Feature : Frobnicator"]["fields"]["Retry Count"] == 42

    # The test endpoint falls back to the persisted builder snapshot when
    # neither an inline snapshot nor an analysis id is supplied.
    res = client.post(
        "/api/v1/rules/builder/test", headers=headers,
        json={"analysis_id": "", "condition":
              'snapshot.config["Records Demo"].items[0].Interface == "X0"'})
    assert res.status_code == 200, res.text
    assert res.json() == {"fired": True, "error": ""}


@pytest.mark.skipif(
    not glob.glob(os.path.join(
        os.environ.get("FGAI_TSR_DIR",
                       os.path.join(os.path.dirname(__file__), "..", "..", "TSRs")),
        "*.wri")),
    reason="No reference TSRs available")
def test_builder_upload_real_tsr_end_to_end(client, org_a):
    """Upload a real multi-megabyte TSR through the endpoint and confirm the
    complete config tree comes back and is testable via the saved snapshot."""
    headers = _superadmin_headers(client, org_a)
    path = _reference_tsrs()[0]
    with open(path, "rb") as fh:
        res = client.post("/api/v1/rules/builder/upload", headers=headers,
                          files={"file": (os.path.basename(path), fh, "text/plain")})
    assert res.status_code == 200, res.text
    config = res.json()["snapshot"]["config"]
    assert len(config) > 100          # full breadth of the report
    assert "System : Status" in config

    res = client.post("/api/v1/rules/builder/test", headers=headers,
                      json={"analysis_id": "", "condition":
                            'size(snapshot.config["System : Status"].sections) > 0'})
    assert res.status_code == 200, res.text
    assert res.json() == {"fired": True, "error": ""}


def test_builder_upload_requires_superadmin(client, org_b):
    res = client.post("/api/v1/auth/login",
                      json={"email": org_b["email"], "password": org_b["password"]})
    headers = {"Authorization": f"Bearer {res.json()['access_token']}"}
    res = client.post(
        "/api/v1/rules/builder/upload", headers=headers,
        files={"file": ("synthetic.wri", SYNTHETIC_TSR.encode(), "text/plain")})
    assert res.status_code == 403


# ---- reference TSRs (gated) -------------------------------------------------
TSR_DIR = os.environ.get(
    "FGAI_TSR_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "TSRs"))


def _reference_tsrs() -> list[str]:
    return sorted(glob.glob(os.path.join(TSR_DIR, "*.wri")))


@pytest.mark.skipif(not _reference_tsrs(), reason="No reference TSRs available")
def test_reference_tsrs_fully_captured():
    from firewallguard.tsr.normalize import normalize_tsr

    def count_nodes(sections: dict) -> int:
        return sum(1 + count_nodes(node.get("sections", {}))
                   for node in sections.values())

    for path in _reference_tsrs():
        text, _fmt = normalize_tsr(
            open(path, encoding="utf-8", errors="replace").read())
        doc = TSRDocument(text)
        tree = build_config_tree(text)
        # Every marker-delimited section must appear as a node in the tree.
        assert count_nodes(tree) == len(doc.sections), path
        # Real TSRs carry ~170 top-level sections once mismatched END markers
        # are healed; far fewer means one section swallowed the document.
        assert len(tree) > 100, path
        # The known firmware quirk: Access Rules is closed by a renamed END.
        if "Firewall : Access Rules" in tree:
            swallowed = tree["Firewall : Access Rules"].get("sections", {})
            assert "Amazon Web Services API : AWS API Details" not in swallowed, path
