"""Risk scoring and grading.

Translates a set of findings into a 0-100 security score and an A-F grade,
following the scoring model in the product specification:

    100        = Secure
    90 - 99    = A
    80 - 89    = B
    70 - 79    = C
    60 - 69    = D
    below 60   = F

The score is deterministic and fully explainable. It starts at 100 and
subtracts a weighted penalty for every finding. Penalties are damped with a
square-root curve on the per-severity count so that the score degrades
quickly for the first few serious findings but does not collapse to zero on
configurations that have many low-severity hygiene items.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List

from ..rules.engine import Finding, SEVERITIES, SEVERITY_WEIGHTS

# Maximum total penalty each severity band may remove from the score. This
# prevents a long tail of Low/Info findings from dominating the result while
# still ensuring Critical findings can, on their own, force a failing grade.
_SEVERITY_CAP = {
    "Critical": 60.0,
    "High": 40.0,
    "Medium": 24.0,
    "Low": 12.0,
    "Info": 0.0,
}


def _grade(score: float) -> str:
    if score >= 100:
        return "Secure"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _grade_label(grade: str) -> str:
    return {
        "Secure": "Secure",
        "A": "Strong",
        "B": "Good",
        "C": "Fair",
        "D": "Weak",
        "F": "Critical",
    }.get(grade, grade)


def severity_breakdown(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def category_breakdown(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def score_findings(findings: List[Finding]) -> Dict[str, Any]:
    """Compute the security score, grade and supporting breakdowns."""
    counts = severity_breakdown(findings)

    penalty_by_severity: Dict[str, float] = {}
    total_penalty = 0.0
    for sev in SEVERITIES:
        n = counts.get(sev, 0)
        if n == 0:
            penalty_by_severity[sev] = 0.0
            continue
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        # Square-root damping on count: first findings hurt most.
        raw = weight * math.sqrt(n)
        capped = min(raw, _SEVERITY_CAP.get(sev, 0.0))
        penalty_by_severity[sev] = round(capped, 2)
        total_penalty += capped

    score = max(0.0, 100.0 - total_penalty)
    # A configuration with any Critical finding cannot score above 59 (grade F),
    # and any High finding caps the score at 79 (no better than grade C).
    if counts.get("Critical", 0) > 0:
        score = min(score, 59.0)
    elif counts.get("High", 0) > 0:
        score = min(score, 79.0)

    score = round(score, 1)
    grade = _grade(score)

    return {
        "score": score,
        "grade": grade,
        "grade_label": _grade_label(grade),
        "severity_counts": counts,
        "category_counts": category_breakdown(findings),
        "penalty_by_severity": penalty_by_severity,
        "total_penalty": round(total_penalty, 2),
        "total_findings": len(findings),
        "scoring_model": {
            "weights": SEVERITY_WEIGHTS,
            "severity_caps": _SEVERITY_CAP,
            "rule": "score = 100 - sum(min(weight * sqrt(count), cap)); "
                    "Critical present -> max 59; High present -> max 79.",
        },
    }


def exploitability_distribution(findings: List[Finding]) -> Dict[str, int]:
    dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        band = f.exploitability
        dist[band] = dist.get(band, 0) + 1
    return dist
