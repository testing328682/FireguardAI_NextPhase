"""TSR section reader.

A SonicWall Tech Support Report (TSR) is a flat text file organised into
sections delimited by markers of the form::

    #<Section Name>_START
    ...
    #<Section Name>_END

Top-level sections (e.g. ``#Network : Interfaces``) frequently contain nested
``#Blade_N_...`` sub-sections.  This module splits the document into an
ordered list of sections and offers helpers for the dominant ``Key : Value``
layout used throughout the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

_START_RE = re.compile(r"^#(?P<name>.+?)_START\s*$")
_END_RE = re.compile(r"^#(?P<name>.+?)_END\s*$")
_KV_RE = re.compile(r"^\s*(?P<key>[^:]{1,80}?)\s*:\s?(?P<value>.*)$")


@dataclass
class Section:
    """A single delimited TSR section."""

    name: str
    start_line: int
    end_line: int
    lines: List[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    def kv(self) -> Dict[str, str]:
        """Best-effort ``Key : Value`` extraction (first occurrence wins)."""
        out: Dict[str, str] = {}
        for line in self.lines:
            m = _KV_RE.match(line)
            if m:
                key = m.group("key").strip()
                if key and key not in out:
                    out[key] = m.group("value").strip()
        return out

    def value(self, key: str, default: str = "") -> str:
        """Return the value for the first line whose key matches exactly."""
        for line in self.lines:
            m = _KV_RE.match(line)
            if m and m.group("key").strip() == key:
                return m.group("value").strip()
        return default


class TSRDocument:
    """Parsed-but-unstructured view over a TSR: ordered named sections."""

    def __init__(self, text: str):
        self.raw = text
        self.sections: List[Section] = []
        self._index: Dict[str, List[Section]] = {}
        self._split(text)

    # ------------------------------------------------------------------
    def _split(self, text: str) -> None:
        stack: List[Section] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = _START_RE.match(line)
            if m:
                sec = Section(name=m.group("name").strip(), start_line=lineno, end_line=-1)
                self.sections.append(sec)
                self._index.setdefault(sec.name, []).append(sec)
                stack.append(sec)
                continue
            m = _END_RE.match(line)
            if m:
                name = m.group("name").strip()
                # close the innermost matching open section
                for i in range(len(stack) - 1, -1, -1):
                    if stack[i].name == name:
                        stack[i].end_line = lineno
                        del stack[i]
                        break
                continue
            for sec in stack:
                sec.lines.append(line)
        for sec in stack:  # unterminated sections
            sec.end_line = lineno

    # ------------------------------------------------------------------
    def find(self, name: str) -> Optional[Section]:
        hits = self._index.get(name)
        return hits[0] if hits else None

    def find_all(self, name: str) -> List[Section]:
        return list(self._index.get(name, []))

    def find_like(self, pattern: str) -> List[Section]:
        rx = re.compile(pattern)
        return [s for s in self.sections if rx.search(s.name)]

    def first_like(self, pattern: str) -> Optional[Section]:
        hits = self.find_like(pattern)
        return hits[0] if hits else None

    def nth_like(self, pattern: str, after_section: "Section") -> Optional[Section]:
        """First section matching ``pattern`` that begins inside ``after_section``."""
        rx = re.compile(pattern)
        for s in self.sections:
            if rx.search(s.name) and after_section.start_line <= s.start_line <= after_section.end_line:
                return s
        return None


def iter_blocks(lines: List[str], header_re: str) -> Iterator[Tuple[re.Match, List[str]]]:
    """Yield ``(header_match, block_lines)`` for repeating record layouts."""
    rx = re.compile(header_re)
    current: Optional[Tuple[re.Match, List[str]]] = None
    for line in lines:
        m = rx.match(line)
        if m:
            if current:
                yield current
            current = (m, [])
        elif current:
            current[1].append(line)
    if current:
        yield current
