"""Firmware & PSIRT intelligence engine.

Correlates the device's SonicOS firmware against a curated advisory dataset
(PSIRT/CVE/EoL). The dataset (``data/psirt.json``) is curated from the SonicWall
PSIRT portal (https://psirt.global.sonicwall.com/vuln-list) and NVD; in
production it is refreshed on a schedule from those sources. Version comparison
is SonicOS-aware: a build such as ``7.3.0-7012`` is compared on both its
dotted release (7.3.0) and its build number (7012), so an advisory fixed in
``7.3.1-7013`` correctly flags ``7.3.0-7012`` as affected.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_DATA = os.path.join(os.path.dirname(__file__), "data", "psirt.json")


def _normalise(version: str) -> Tuple[int, int, int, int]:
    """Turn 'SonicOS 7.3.0-7012-R4521-HF54816' into (7, 3, 0, 7012).

    Always returns a 4-tuple (major, minor, patch, build) so comparisons are
    well-defined regardless of how many components the source string carries.
    """
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:-(\d+))?", version or "")
    if not m:
        return (0, 0, 0, 0)
    major, minor, patch, build = m.groups()
    return (int(major), int(minor), int(patch), int(build) if build else 0)


def _in_range(version: Tuple[int, int, int, int], lo: str, hi: str) -> bool:
    return _normalise(lo) <= version <= _normalise(hi)


def _generation(version: Tuple[int, int, int, int]) -> str:
    return {6: "Gen6", 7: "Gen7", 8: "Gen8"}.get(version[0], "")


@dataclass
class Advisory:
    advisory_id: str
    title: str
    cve: List[str]
    cvss: float
    severity: str
    affected_lo: str
    affected_hi: str
    fixed_in: str
    summary: str
    reference: str
    published: str = ""
    generations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d["url"] = self.reference
        return d


class FirmwareIntelligence:
    def __init__(self, data_path: str = _DATA):
        with open(data_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        self.advisories = [Advisory(**a) for a in raw.get("advisories", [])]
        self.eol = raw.get("eol", {})
        self.disclaimer = raw.get("disclaimer", "")
        self.source = raw.get("source", "")
        self.last_refreshed = raw.get("last_refreshed", "")
        self.latest_known_firmware = raw.get("latest_known_firmware", {})

    def evaluate(self, firmware: str, model: str = "") -> Dict[str, Any]:
        version = _normalise(firmware)
        gen = _generation(version)
        matched: List[Dict[str, Any]] = []
        for adv in self.advisories:
            if adv.generations and gen and gen not in adv.generations:
                continue
            if _in_range(version, adv.affected_lo, adv.affected_hi):
                rec = adv.to_dict()
                rec["upgrade_recommendation"] = (
                    f"Upgrade to {adv.fixed_in} or later to remediate "
                    f"{', '.join(adv.cve) or adv.advisory_id}."
                )
                matched.append(rec)
        matched.sort(key=lambda a: a["cvss"], reverse=True)
        eol = self._eol_status(model)
        return {
            "firmware": firmware,
            "normalised_version": ".".join(map(str, version[:3])) + f"-{version[3]}",
            "generation": gen,
            "model": model,
            "matched_advisories": matched,
            "advisory_count": len(matched),
            "max_cvss": matched[0]["cvss"] if matched else 0.0,
            "all_cves": sorted({c for a in matched for c in a.get("cve", [])}),
            "recommended_firmware": self.latest_known_firmware.get(gen, ""),
            "eol": eol,
            "source": self.source,
            "last_refreshed": self.last_refreshed,
            "disclaimer": self.disclaimer,
        }

    def _eol_status(self, model: str) -> Dict[str, Any]:
        for key, info in self.eol.items():
            if key.lower() in (model or "").lower():
                return {"series": key, **info}
        return {"series": "", "status": "unknown",
                "note": "No end-of-life record matched; verify on the SonicWall lifecycle portal."}


_singleton: Optional[FirmwareIntelligence] = None


def get_intel() -> FirmwareIntelligence:
    global _singleton
    if _singleton is None:
        _singleton = FirmwareIntelligence()
    return _singleton
