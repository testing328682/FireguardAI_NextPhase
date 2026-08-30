"""Rule engine core.

A *rule* is a declarative metadata record plus a ``check(snapshot)`` callable
returning zero or more *findings*.  Findings carry evidence extracted from the
TSR, business/technical impact, remediation, verification steps, compliance
mappings, and an exploitability triplet (likelihood / impact / exposure) used
by the analytics layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

Snapshot = Dict[str, Any]

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_WEIGHTS = {"Critical": 15.0, "High": 8.0, "Medium": 3.0, "Low": 1.0, "Info": 0.0}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: List[str]
    business_impact: str
    technical_impact: str
    remediation: str
    verification: List[str]
    risk_reduction: str
    references: List[str] = field(default_factory=list)
    compliance: Dict[str, List[str]] = field(default_factory=dict)
    likelihood: int = 3   # 1-5
    impact: int = 3       # 1-5
    exposure: int = 3     # 1-5
    affected_count: int = 1
    # Per-object reporting: the specific named object/rule/policy this finding
    # is about (e.g. the access-rule name, address-object name, VPN policy
    # name), so an operator can jump straight to it in SonicOS. ``object_type``
    # labels what kind of object it is (Access Rule, Address Object, ...).
    object_name: str = ""
    object_type: str = ""
    object_detail: str = ""

    @property
    def exploitability(self) -> str:
        score = self.likelihood * 0.4 + self.exposure * 0.35 + self.impact * 0.25
        if score >= 4.2:
            return "Critical"
        if score >= 3.4:
            return "High"
        if score >= 2.4:
            return "Medium"
        return "Low"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["exploitability"] = self.exploitability
        return d


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    check: Callable[[Snapshot], List[Finding]]
    description: str = ""
    references: List[str] = field(default_factory=list)

    def run(self, snapshot: Snapshot) -> List[Finding]:
        try:
            return self.check(snapshot) or []
        except Exception as exc:  # a rule must never break the scan
            return [Finding(
                rule_id=self.id, title=f"Rule execution error: {self.title}",
                severity="Info", category="Engine",
                description=f"Rule raised {type(exc).__name__}: {exc}",
                evidence=[], business_impact="", technical_impact="",
                remediation="Report this parser/rule defect to FireLint support.",
                verification=[], risk_reduction="n/a", likelihood=1, impact=1, exposure=1,
            )]


class RuleRegistry:
    def __init__(self) -> None:
        self.rules: List[Rule] = []
        # Rule IDs retired because a finer-grained (e.g. per-object) rule now
        # supersedes them. Retired rules stay defined for reference but do not
        # run, so a single condition is never double-counted.
        self.retired: set = set()

    def register(self, rule: Rule) -> None:
        self.rules.append(rule)

    def retire(self, *rule_ids: str) -> None:
        self.retired.update(rule_ids)

    def active_rules(self) -> List[Rule]:
        return [r for r in self.rules if r.id not in self.retired]

    def rule(self, **meta):
        """Decorator: ``@registry.rule(id=..., title=..., severity=..., category=...)``."""
        def wrap(fn: Callable[[Snapshot], List[Finding]]) -> Callable:
            self.register(Rule(check=fn, **meta))
            return fn
        return wrap

    def run_all(self, snapshot: Snapshot) -> List[Finding]:
        findings: List[Finding] = []
        for r in self.active_rules():
            findings.extend(r.run(snapshot))
        order = {s: i for i, s in enumerate(SEVERITIES)}
        findings.sort(key=lambda f: (order.get(f.severity, 99), f.rule_id))
        return findings


registry = RuleRegistry()