"""API-TSR normalization.

SonicWall TSRs collected through the SonicOS API arrive in a *whitespace-collapsed*
form: all whitespace is removed and a single space is inserted after every colon.
So ``Firewall Name : value`` becomes ``FirewallName: value``, section markers run
inline (``#System: Status_START``), times become ``08: 27: 50`` and space-separated
lists merge (``X0 X1`` -> ``X0X1``).

This module detects that format and reconstructs GUI-equivalent text so the
existing reader/parser/rule engine work unchanged (the *normalizer + reuse rules*
approach). Reconstruction is dictionary-driven:

* Section markers are put back on their own lines and their names re-spaced from a
  harvested catalog (``sonicos_sections.txt``).
* Run-on ``key: value`` records are re-segmented by finding, before each ``": "``,
  the longest preceding substring that is a known key (``sonicos_keys.txt``), and
  the canonical spaced key is restored.
* Known space-only-separated values (management interface lists, model/firmware)
  are de-merged with SonicOS-aware heuristics. These are inherently lossy; see the
  module-level note in the rule UI.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Dict, List, Set, Tuple

_DATA_DIR = os.path.dirname(__file__)
_KEYS_FILE = os.path.join(_DATA_DIR, "sonicos_keys.txt")
_SECTIONS_FILE = os.path.join(_DATA_DIR, "sonicos_sections.txt")

# Characters that may appear inside a (whitespace-stripped) key token.
_KEYCHARS = "A-Za-z0-9&()?./_+,'\"%-"
_RUN_RE = re.compile(rf"[{_KEYCHARS}]+$")
_COLON_SPACE_RE = re.compile(r": ")

# Management interface list keys whose values were space-separated (now merged).
_INTERFACE_KEYS = {
    "HTTP Management Allowed On Interfaces",
    "HTTPS Management Allowed On Interfaces",
    "SSH Management Allowed On Interfaces",
    "SNMP Allowed On Interfaces",
    "Ping Allowed On Interfaces",
    "HTTP User Login Allowed On Interfaces",
    "HTTPS User Login Allowed On Interfaces",
}
# SonicOS interface token shapes, matched greedily left-to-right.
_IFACE_TOKEN_RE = re.compile(
    r"(MGMT|LAG\d+|VLAN\d+|X\d+(?::V\d+)?|U\d+|W\d+|M\d+|APOnboarding|None)")


@lru_cache(maxsize=1)
def _load_keys() -> Tuple[Dict[str, str], int]:
    """Return (stripped_key -> canonical_key, max_stripped_len)."""
    mapping: Dict[str, str] = {}
    try:
        with open(_KEYS_FILE, encoding="utf-8") as fh:
            for raw in fh:
                k = raw.rstrip("\n")
                if not k:
                    continue
                stripped = k.replace(" ", "")
                if len(stripped) < 3:
                    continue
                # On collision prefer the more spelled-out (more spaces) form.
                cur = mapping.get(stripped)
                if cur is None or k.count(" ") > cur.count(" "):
                    mapping[stripped] = k
    except FileNotFoundError:
        return {}, 0
    maxlen = max((len(s) for s in mapping), default=0)
    return mapping, maxlen


@lru_cache(maxsize=1)
def _load_sections() -> Dict[str, str]:
    """Return stripped(section name) -> canonical section name."""
    mapping: Dict[str, str] = {}
    try:
        with open(_SECTIONS_FILE, encoding="utf-8") as fh:
            for raw in fh:
                name = raw.rstrip("\n")
                if name:
                    mapping[name.replace(" ", "")] = name
    except FileNotFoundError:
        pass
    return mapping


# ----------------------------------------------------------------------
# detection
# ----------------------------------------------------------------------
def detect_tsr_format(text: str) -> str:
    """Return ``"api"`` or ``"gui"`` for a raw TSR.

    GUI TSRs carry section markers on their own lines; the API form runs them
    inline. We compare own-line ``#…_START`` markers against the total count.
    """
    own_line = len(re.findall(r"(?m)^#.{1,80}?_START[ \t]*$", text))
    total = len(re.findall(r"#[^\n#]{1,80}?_START", text))
    if total >= 10 and own_line <= max(1, total) * 0.25:
        return "api"
    return "gui"


# ----------------------------------------------------------------------
# normalization
# ----------------------------------------------------------------------
def _restore_markers(text: str) -> str:
    sections = _load_sections()

    def sub(m: "re.Match[str]") -> str:
        name, suffix = m.group(1), m.group(2)
        canon = sections.get(name.replace(" ", ""), name)
        return f"\n#{canon}_{suffix}\n"

    return re.sub(r"#([^\n#]{1,80}?)_(START|END)", sub, text)


def _segment_kv(line: str) -> str:
    """Re-insert newlines + canonical keys into a run-on content line."""
    mapping, maxlen = _load_keys()
    if not mapping or ": " not in line:
        return line

    splits: List[Tuple[int, int, str]] = []  # (key_start, value_start, canonical)
    for m in _COLON_SPACE_RE.finditer(line):
        p = m.start()
        lo = max(0, p - maxlen)
        rm = _RUN_RE.search(line, lo, p)
        if not rm:
            continue
        run = line[rm.start():p]
        # longest suffix of run that is a known key (start=0 is the whole run)
        for start in range(len(run)):
            cand = run[start:]
            canon = mapping.get(cand)
            if canon is not None:
                splits.append((rm.start() + start, p + 2, canon))
                break

    if not splits:
        return line

    out: List[str] = []
    cursor = 0
    for key_start, value_start, canon in splits:
        if key_start < cursor:
            continue  # overlaps a value already consumed
        out.append(line[cursor:key_start])
        out.append(f"\n{canon} : ")
        cursor = value_start
    out.append(line[cursor:])
    return "".join(out)


def _demerge_interfaces(value: str) -> str:
    v = value.strip()
    if not v or v.lower() == "none":
        return v
    if " " in v:  # already separated
        return v
    toks = _IFACE_TOKEN_RE.findall(v)
    return " ".join(toks) if toks else v


def _fixups(text: str) -> str:
    # Undo "space after colon" inside numeric values (times/IPs): "08: 27: 50".
    text = re.sub(r"(\d):\s(?=\d)", r"\1:", text)
    # Re-space model and firmware tokens used by rules / PSIRT matching.
    text = re.sub(r"\bSonicOS(\d)", r"SonicOS \1", text)
    text = re.sub(r"\b(NSA|NSa|NSsp|NSv|TZ|SOHO|SuperMassive)(\d)", r"\1 \2", text)
    # Re-space VPN proposal tokens the rules match on (e.g. weak DH groups,
    # aggressive-mode IKE) — the API export merged "DH Group 2" -> "DHGroup2".
    text = re.sub(r"\bDH\s*Group(\d)", r"DH Group \1", text)
    text = re.sub(r"\bAggressive\s*Mode\b", "Aggressive Mode", text)
    text = re.sub(r"\bMain\s*Mode\b", "Main Mode", text)
    return text


# ----------------------------------------------------------------------
# record-block reconstruction
# ----------------------------------------------------------------------
# Per-object sections (zones, address/service objects, NAT, VPN SAs) are *block*
# structured in the GUI TSR: a delimiter line introduces each record, followed by
# its key/value detail. The API form collapses the whole section onto one line,
# so the parsers' ``iter_blocks`` finds no record boundaries. These patterns put
# the structure back; they are inert on flat key/value sections because the
# tokens (``--X Table--`` markers, ``-----name-----`` headers, merged
# ``Handle:NN`` member boundaries) do not occur there.
# Object/group table markers only ("--Service Group Table--", "--Address Object
# Table Info--"). Constrained to names ending in "Table"/"TableInfo" so we do NOT
# match the 2-dash core of a long sub-header run like "----------Advanced----------"
# (which would leave dash fragments glued to the preceding value).
_TABLE_MARKER_RE = re.compile(r"--([A-Za-z][A-Za-z]{1,40}?Table(?:Info)?)--")
# Length cap is generous because record headers double the name in parens
# ("-----Foo(Foo)-----"); the colon-exclusion still bounds each header to one
# record (the KV body between headers always contains a colon). "=" is excluded
# too so a dash-wrapped stats footer ("----#FQDN_AOs=3,...----") is not mistaken
# for a record header (real object names contain neither ":" nor "=").
_DASH_HEADER_RE = re.compile(r"-{5,}[^\n:=]{1,200}?-{5,}")
_HANDLE_SPLIT_RE = re.compile(r"(?<=\S)(Handle:\s*\d+)")


def _respace_marker(m: "re.Match[str]") -> str:
    # "--ServiceGroupTable--" -> "\n--Service Group Table--\n" (parsers match the
    # spaced form). Re-insert a space at each lower→upper camel-case boundary.
    inner = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", m.group(1))
    return f"\n--{inner}--\n"


_TYPE_MARKER_RE = re.compile(r"(?<=\S)((?:HOST|NETWORK|RANGE|MAC|FQDN)\s*:)")
# Matches the collapsed "<N>timesreferencedbyModule:" too (\s* between words).
_REFCOUNT_RE = re.compile(r"(?<=\S)(\d+)\s*times\s*referenced\s*by\s*Module\s*:")
# VPN SA record header uses 3 dashes ("--- SA 1 ---"), which the 5+-dash rule
# above intentionally misses; re-space it to the form parse_vpn expects.
# Group/object membership lines: "member: Name:<n> Handle:<h>". The API export
# adds a space after every colon, so segmentation would otherwise split this into
# three lines ("member :", "Name :", "Handle :") and the membership would be lost.
# Rebuild it as a single colon-space-free line that _segment_kv leaves intact and
# the (space-tolerant) member regexes still match.
_MEMBER_RE = re.compile(r"member\s*:\s*Name\s*:\s*(?P<v>.+?)\s*Handle\s*:\s*(?P<h>\d+)")
_SA_HEADER_RE = re.compile(r"-{2,}\s*SA\s*(\d+)\s*-{2,}")
# Access-rule header packs space-separated tokens that the API export merged:
# "Rule1LAN->LANAllowServiceAny->Ping(Enabled)". The arrows and the
# Allow/Deny/Discard + Service keywords survive, so the fields are recoverable.
_RULE_HDR_RE = re.compile(
    r"(?<![A-Za-z])Rule(\d+)(.+?)->(.+?)(Allow|Deny|Discard)Service(.*?)->(.*?)\((Enabled|Disabled)\)")


def _rule_hdr_sub(m: "re.Match[str]") -> str:
    num, z1, z2, act, s1, s2, st = m.groups()
    return (f"\nRule {num} {z1.strip()} -> {z2.strip()} {act} "
            f"Service {s1.strip()} -> {s2.strip()} ({st})\n")


def _reconstruct_blocks(line: str) -> str:
    """Re-insert record structure collapsed by the API export onto one line."""
    line = _TABLE_MARKER_RE.sub(_respace_marker, line)
    line = _DASH_HEADER_RE.sub(lambda m: "\n" + m.group(0) + "\n", line)
    # Membership lines first (kept whole), then de-merge any remaining Handle runs.
    line = _MEMBER_RE.sub(lambda m: f"\nmember:Name:{m.group('v').strip()} Handle:{m.group('h')}\n", line)
    line = _HANDLE_SPLIT_RE.sub(r" \1", line)
    # Address-object detail: break the type marker (HOST/NETWORK/...) and the
    # "N times referenced by Module:" line onto their own lines so obj_class,
    # type/value, and reference state parse cleanly (else a default object reads
    # as "DefaultHOST" and unreferenced, over-firing the unused-object rule).
    line = _TYPE_MARKER_RE.sub(r"\n\1", line)
    line = _REFCOUNT_RE.sub(r"\n\1 times referenced by Module:", line)
    # VPN SA + access-rule record headers.
    line = _SA_HEADER_RE.sub(r"\n--- SA \1 ---\n", line)
    line = _RULE_HDR_RE.sub(_rule_hdr_sub, line)
    # Access-rule body: detach the Iface run and the Logging/Management run.
    line = re.sub(r"(?<=\S)(Iface\s*:)", r" \1", line)
    line = re.sub(r"(Enabled|Disabled)(Management\s*:)", r"\1 \2", line)
    return line


def normalize_api_tsr(text: str) -> str:
    """Convert an API-format (whitespace-collapsed) TSR into GUI-equivalent text."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # The API export breaks comma-separated values onto new lines ("a,\nb"); rejoin
    # them so single-line records (e.g. "IpType: 6, Ports: 80~80") parse intact.
    text = re.sub(r",[ \t]*\n", ", ", text)
    # Collapse bracketed IPv6/MAC literals the export split across lines and spaced
    # after every colon: "[\n  fe80: : 2eb8: edff: ...\n]" -> "[fe80::2eb8:edff:...]".
    # Without this an IPv6 address object's value parses as just "[", making
    # distinct IPv6 objects look like duplicates.
    text = re.sub(r"\[\s*([0-9A-Fa-f:][0-9A-Fa-f:\s]*?)\s*\]",
                  lambda m: "[" + re.sub(r"\s+", "", m.group(1)) + "]", text)
    text = _restore_markers(text)
    lines_out: List[str] = []
    for line in text.split("\n"):
        if line.startswith("#") and (
                line.rstrip().endswith("_START") or line.rstrip().endswith("_END")):
            lines_out.append(line)
            continue
        if not line:
            lines_out.append(line)
            continue
        # Restore record boundaries first, then re-segment each resulting line.
        for sub in _reconstruct_blocks(line).split("\n"):
            lines_out.append(_segment_kv(sub) if sub else sub)
    text = "\n".join(lines_out)
    # Per-line value de-merge for interface lists.
    final: List[str] = []
    for line in text.split("\n"):
        mm = re.match(r"^([^:#][^:]{1,79}?) : (.*)$", line)
        if mm and mm.group(1).strip() in _INTERFACE_KEYS:
            final.append(f"{mm.group(1)} : {_demerge_interfaces(mm.group(2))}")
        else:
            final.append(line)
    return _fixups("\n".join(final))


def normalize_tsr(text: str) -> Tuple[str, str]:
    """Return ``(normalized_text, detected_format)``.

    GUI TSRs pass through unchanged; API TSRs are normalized to GUI-equivalent
    text so the existing parser/rule engine apply identically.
    """
    fmt = detect_tsr_format(text)
    if fmt == "api":
        return normalize_api_tsr(text), "api"
    return text, "gui"
