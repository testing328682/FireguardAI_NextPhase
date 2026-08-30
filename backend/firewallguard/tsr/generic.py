"""Generic full-configuration capture.

The curated ``parse_*`` functions in ``parser.py`` extract the specific fields
the rule catalog needs, but they cover only a fraction of the ~300 sections a
real TSR contains.  This module complements them with a *structure-preserving
sweep of the entire document*: every ``#..._START/_END`` section becomes a node
in a JSON tree, driven purely by the markers and layout conventions found in
the uploaded TSR — never by a hardcoded list of known sections.

The tree is attached to the snapshot as ``snapshot["config"]`` and is what the
CEL Rule Builder browses.  Because the same snapshot is used when rules are
evaluated in the analysis pipeline, any path discovered in the builder
(``snapshot.config[...]...``) also fires during real scans.

Node shape (all keys optional; omitted when empty):

``fields``      ``Key : Value`` pairs with unique keys (typed scalars; a key
                repeated outside a record layout becomes a list of values).
``items``       list of records detected from repeated-key blocks
                (e.g. ``Interface: X0 ... Interface: X1 ...``).
``blocks``      named dash-delimited blocks: ``--Group Marker--`` and
                ``-----Record Name-----`` headers, keyed by name.
``lines``       raw lines that did not parse as any of the above, capped at
                ``MAX_RAW_LINES`` per node (``lines_total`` records the real
                count when truncated — nothing is *silently* discarded).
``sections``    nested ``#..._START`` sections.

Everything is plain JSON (str / int / bool / dict / list), so the tree passes
through ``celpy.json_to_cel`` unchanged and keys that are not CEL identifiers
remain addressable with index syntax, e.g.::

    snapshot.config["System : Time"].fields["Use NTP"] == true
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Section markers — identical grammar to reader.py.
_START_RE = re.compile(r"^#(?P<name>.+?)_START\s*$")
_END_RE = re.compile(r"^#(?P<name>.+?)_END\s*$")

# `Key : Value` with whitespace (or end of line) after the colon.
_KV_SPACED_RE = re.compile(r"^\s*(?P<key>[^:]{1,80}?)[ \t]*:(?:[ \t]+(?P<value>.*)|[ \t]*$)")
# `Key:Value` with no space after the colon (e.g. "Interface:X0").  Only
# accepted when the key looks like a label — see _parse_kv.
_KV_TIGHT_RE = re.compile(r"^\s*(?P<key>[^:]{2,80}?):(?P<value>\S.*)$")
# Keys whose last token is a short hex/decimal group are almost always the
# left half of a MAC address, IPv6 literal or timestamp — not a label.
_HEX_TAIL_RE = re.compile(r"(?:^|[\s.])[0-9a-fA-F]{1,4}$")
_LETTER_RE = re.compile(r"[A-Za-z]")

# Dash-delimited headers.  Exactly two dashes = a table/group marker
# ("--Address Object Table--"); three or more = a record header
# ("-----HostName-----", "--- SA 1 ---").
_GROUP_RE = re.compile(r"^\s*--(?P<name>[^-](?:.*?[^-])?)--\s*$")
_RECORD_RE = re.compile(r"^\s*-{3,}\s*(?P<name>[^-](?:.*?[^-])?)\s*-{3,}\s*$")
# Lines that are pure table borders / separators carry no information.
_BORDER_RE = re.compile(r"^\s*[-=+_*\s]+\s*$")

MAX_RAW_LINES = 200          # per-node cap on verbatim unparsed lines
_MAX_HEADER_NAME = 120       # longer "names" are content, not headers

_TRUE_WORDS = frozenset({"enabled", "yes", "on", "true"})
_FALSE_WORDS = frozenset({"disabled", "no", "off", "false"})


# ---------------------------------------------------------------------------
# scalar handling
# ---------------------------------------------------------------------------
def _coerce(value: str) -> Any:
    """Conservative typing: exact booleans and plain integers only."""
    s = value.strip()
    if not s:
        return ""
    # SonicOS quotes some string values ("Europe (GMT+1:00)") — unwrap one
    # symmetric pair so CEL comparisons match what the operator reads.
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"' and '"' not in s[1:-1]:
        s = s[1:-1].strip()
        if not s:
            return ""
    low = s.lower()
    if low in _TRUE_WORDS:
        return True
    if low in _FALSE_WORDS:
        return False
    # Integers without leading zeros, bounded to JS-safe magnitude (15 digits)
    # so values survive a JSON round-trip through the browser untouched.
    if re.fullmatch(r"-?\d{1,15}", s):
        digits = s.lstrip("-")
        if len(digits) == 1 or digits[0] != "0":
            return int(s)
    return s


def _parse_kv(line: str) -> Optional[Tuple[str, str]]:
    """Return ``(key, value)`` when the line reads as a config assignment."""
    m = _KV_SPACED_RE.match(line)
    if m:
        key = re.sub(r"\s+", " ", m.group("key").strip())
        if key and _LETTER_RE.search(key) and not key.startswith(("#", "-")):
            return key, (m.group("value") or "").strip()
        return None
    m = _KV_TIGHT_RE.match(line)
    if m:
        key = re.sub(r"\s+", " ", m.group("key").strip())
        if (_LETTER_RE.search(key) and not _HEX_TAIL_RE.search(key)
                and not key.startswith(("#", "-"))):
            return key, m.group("value").strip()
    return None


def _add_field(target: Dict[str, Any], key: str, value: str) -> None:
    """Add a pair to a dict; a repeated key grows into a list of values."""
    coerced = _coerce(value)
    if key in target:
        existing = target[key]
        if isinstance(existing, list):
            existing.append(coerced)
        else:
            target[key] = [existing, coerced]
    else:
        target[key] = coerced


def _put_named(container: Dict[str, Any], name: str, node: Any) -> None:
    """Insert under ``name``, deduplicating repeats as ``name_2``, ``name_3``…"""
    if name not in container:
        container[name] = node
        return
    n = 2
    while f"{name}_{n}" in container:
        n += 1
    container[f"{name}_{n}"] = node


def _clean_header_name(raw: str) -> str:
    """SonicOS doubles names in record headers: ``Foo(Foo)`` → ``Foo``."""
    m = re.match(r"^(?P<a>.+?)\((?P<b>.*)\)$", raw)
    if m and m.group("a").strip() == m.group("b").strip():
        return m.group("a").strip()
    return raw.strip()


def _header_match(line: str) -> Optional[Tuple[str, str]]:
    """Classify a dash header line as ``("group"|"record", name)``."""
    m = _GROUP_RE.match(line)
    kind = "group"
    if not m:
        m = _RECORD_RE.match(line)
        kind = "record"
    if not m:
        return None
    name = m.group("name").strip()
    # Stats footers ("----#FQDN_AOs=3,...----") and over-long lines are content.
    if not name or len(name) > _MAX_HEADER_NAME or "=" in name:
        return None
    if not re.search(r"[A-Za-z0-9]", name):
        return None
    return kind, _clean_header_name(name)


# ---------------------------------------------------------------------------
# body parsing
# ---------------------------------------------------------------------------
def _pairs_to_struct(pairs: List[Tuple[str, str]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Split an ordered key/value stream into scalar fields and record items.

    When a key repeats, its occurrences delimit records (the dominant TSR
    layout for per-object listings).  A key that repeats with no other keys
    around it collapses to a list value instead.
    """
    first_dup: Optional[str] = None
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            first_dup = key
            break
        seen.add(key)

    if first_dup is None:
        fields: Dict[str, Any] = {}
        for key, value in pairs:
            _add_field(fields, key, value)
        return fields, []

    boundary_idx = [i for i, (key, _) in enumerate(pairs) if key == first_dup]
    fields = {}
    for key, value in pairs[: boundary_idx[0]]:
        _add_field(fields, key, value)

    items: List[Dict[str, Any]] = []
    bounds = boundary_idx + [len(pairs)]
    for a, b in zip(bounds, bounds[1:]):
        record: Dict[str, Any] = {}
        for key, value in pairs[a:b]:
            _add_field(record, key, value)
        items.append(record)

    # Pure repetition of a single key is a list, not a record set.
    if all(len(r) == 1 and first_dup in r for r in items):
        fields[first_dup] = [r[first_dup] for r in items]
        return fields, []
    return fields, items


def _fill(node: Dict[str, Any], lines: List[str]) -> None:
    """Parse a run of body lines into ``fields`` / ``items`` / ``lines``."""
    pairs: List[Tuple[str, str]] = []
    raw: List[str] = []
    for line in lines:
        if not line.strip() or _BORDER_RE.match(line):
            continue
        kv = _parse_kv(line)
        if kv is not None:
            pairs.append(kv)
        else:
            raw.append(line.strip())
    fields, items = _pairs_to_struct(pairs)
    if fields:
        node["fields"] = fields
    if items:
        node["items"] = items
    if raw:
        node["lines"] = raw[:MAX_RAW_LINES]
        if len(raw) > MAX_RAW_LINES:
            node["lines_total"] = len(raw)


def _parse_body(lines: List[str]) -> Dict[str, Any]:
    """Parse one section's own lines (child sections already removed)."""
    node: Dict[str, Any] = {}

    # Split the body at dash headers into a preamble plus named segments.
    segments: List[Tuple[str, str, List[str]]] = []
    preamble: List[str] = []
    current: Optional[List[str]] = None
    for line in lines:
        header = _header_match(line)
        if header:
            kind, name = header
            current = []
            segments.append((kind, name, current))
        elif current is not None:
            current.append(line)
        else:
            preamble.append(line)

    _fill(node, preamble)
    active = node  # records attach to the most recent group marker, if any
    for kind, name, seg_lines in segments:
        sub: Dict[str, Any] = {}
        _fill(sub, seg_lines)
        if kind == "group":
            _put_named(node.setdefault("blocks", {}), name, sub)
            active = sub
        else:
            _put_named(active.setdefault("blocks", {}), name, sub)
    return node


# ---------------------------------------------------------------------------
# document walking
# ---------------------------------------------------------------------------
class _Frame:
    __slots__ = ("name", "lines", "children")

    def __init__(self, name: str):
        self.name = name
        self.lines: List[str] = []
        self.children: List[Tuple[str, Dict[str, Any]]] = []


def _frame_to_node(frame: _Frame) -> Dict[str, Any]:
    node = _parse_body(frame.lines)
    if frame.children:
        sections: Dict[str, Any] = {}
        for child_name, child_node in frame.children:
            _put_named(sections, child_name, child_node)
        node["sections"] = sections
    return node


def _norm_name(name: str) -> str:
    """Marker-name comparison key: casefold and drop all non-alphanumerics."""
    return re.sub(r"[^a-z0-9]+", "", name.casefold())


def build_config_tree(text: str) -> Dict[str, Any]:
    """Build the complete configuration tree for a (normalized) TSR text.

    Sections nest exactly as their markers nest in the document.  Content
    lines belong to the innermost open section only, so a parent node never
    duplicates its children's data.

    Real TSRs contain mismatched markers (firmware quirks observed in the
    field: ``FIRWARE`` for ``FIRMWARE``, ``PKTIO NIC`` for ``PKTIO_NIC``,
    an ``AWS API_END`` closing ``AWS API Details``, and a ``Security Policy
    Table_END`` closing ``Firewall : Access Rules``).  An END that matches no
    open section — exactly or after normalization — therefore closes the
    innermost open section; an END arriving while nothing is open is a stray
    and is ignored.  Without this, one unterminated section swallows the rest
    of the document.
    """
    root: Dict[str, Any] = {}
    stack: List[_Frame] = []

    def _attach(frame: _Frame) -> None:
        node = _frame_to_node(frame)
        if stack:
            stack[-1].children.append((frame.name, node))
        else:
            _put_named(root, frame.name, node)

    def _close_through(index: int) -> None:
        """Close every frame above ``index`` and the frame at ``index``."""
        while len(stack) > index:
            frame = stack[-1]
            del stack[-1]
            _attach(frame)

    for line in text.splitlines():
        m = _START_RE.match(line)
        if m:
            stack.append(_Frame(m.group("name").strip()))
            continue
        m = _END_RE.match(line)
        if m:
            if not stack:
                continue  # stray END with no open section
            name = m.group("name").strip()
            match_idx: Optional[int] = None
            for i in range(len(stack) - 1, -1, -1):
                if stack[i].name == name:
                    match_idx = i
                    break
            if match_idx is None:
                norm = _norm_name(name)
                for i in range(len(stack) - 1, -1, -1):
                    if _norm_name(stack[i].name) == norm:
                        match_idx = i
                        break
            # Misnamed END: attribute it to the innermost open section.
            _close_through(match_idx if match_idx is not None else len(stack) - 1)
            continue
        if stack:
            stack[-1].lines.append(line)

    _close_through(0)  # unterminated sections at EOF
    return root
