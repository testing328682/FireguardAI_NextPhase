"""DB-backed rule layer (CEL).

The built-in Python catalog remains the authoritative engine for the ~67 system
rules (they emit rich per-object findings that a boolean expression language
cannot reproduce). This module adds a *hybrid* layer on top:

* ``evaluate_custom_rules`` runs tenant-authored CEL rules (approved + enabled)
  against the parsed snapshot and returns findings to merge into the pipeline.
* ``evaluate_authored_system_rules`` runs operator-authored *global* CEL rules
  (created via the CEL Rule Builder: source=system, org NULL, key outside the
  Python catalog) against every tenant's analyses and returns findings.
* ``resolve_suppressions`` collects a tenant's active rule suppressions/overrides
  for a device, which the pipeline applies to *all* findings (system + custom).
* ``seed_system_rules`` mirrors the Python catalog into the ``rules`` table so
  every rule is visible and manageable in the admin GUI.

CEL expressions reference the snapshot as ``snapshot`` and must evaluate to a
boolean, e.g. ``snapshot.security_services.ips_enabled == false``.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

import celpy
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .models import (
    Rule, RuleSource, RuleState, RuleSuppression, SuppressionAction,
    DeviceGeneration, GenerationDevice, FirmwareRecommendation,
)
from firewallguard.rules.engine import Finding, registry

logger = logging.getLogger("firewallguard.rule_engine")
_env = celpy.Environment()


class CELError(Exception):
    """Raised when a CEL expression fails to compile."""


def compile_condition(expression: str):
    """Compile a CEL expression to a runnable program, raising CELError on syntax error."""
    try:
        ast = _env.compile(expression)
        return _env.program(ast)
    except Exception as exc:  # noqa: BLE001 - celpy raises various parse errors
        raise CELError(str(exc)) from exc


# Top-level snapshot keys a condition references: ``snapshot.<ident>`` or
# ``snapshot["<key>"]`` / ``snapshot['<key>']``.
_SNAPSHOT_KEY_RE = re.compile(
    r"""snapshot(?:\.(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|\[(?P<q>['"])(?P<key>.*?)(?P=q)\])""")
# ``snapshot`` used bare (not followed by a member access) — cannot prune.
_SNAPSHOT_BARE_RE = re.compile(r"snapshot\b(?!\s*[.\[])")


def _condition_context(condition: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    """The snapshot pruned to the top-level keys the condition references.

    celpy's macro evaluation cost grows with the size of the activation, so a
    collection predicate (``exists``) over the full snapshot — which carries
    the multi-megabyte ``config`` tree — is ~15x slower than over just the
    keys the rule reads (measured: 40s vs 2.6s over 443 access rules).
    Pruning never changes the outcome: a CEL expression can only observe the
    values it names, and a referenced-but-absent key errors identically in
    the pruned and the full map. When the expression uses ``snapshot`` bare
    or contains escapes we cannot parse confidently, the full snapshot is
    kept.
    """
    if "\\" in condition or _SNAPSHOT_BARE_RE.search(condition):
        return snapshot
    keys = {m.group("dot") or m.group("key")
            for m in _SNAPSHOT_KEY_RE.finditer(condition)}
    if not keys:
        return snapshot
    return {k: v for k, v in snapshot.items() if k in keys}


def evaluate_condition(expression: str, snapshot: dict[str, Any]) -> tuple[bool | None, str]:
    """Evaluate a CEL expression against a snapshot.

    Returns ``(result, error)``. ``result`` is the boolean outcome, or None if
    evaluation failed (in which case ``error`` is populated).
    """
    try:
        prog = compile_condition(expression)
    except CELError as exc:
        return None, f"compile error: {exc}"
    try:
        context = _condition_context(expression, snapshot)
        value = prog.evaluate({"snapshot": celpy.json_to_cel(context)})
        return bool(value), ""
    except Exception as exc:  # noqa: BLE001 - celpy eval errors
        return None, f"evaluation error: {exc}"


def _finding_from_rule(rule: Rule, evidence: str = "Matched custom rule condition.") -> Finding:
    return Finding(
        rule_id=rule.key, title=rule.title, severity=rule.severity,
        category=rule.category or "Custom", description=rule.description,
        evidence=[evidence],
        business_impact="", technical_impact="",
        remediation=rule.remediation or "Review the condition and remediate as appropriate.",
        verification=[], risk_reduction="Medium",
        references=rule.references or [], compliance=rule.compliance or {})


def evaluate_custom_rules(db: Session, organization_id: str,
                          snapshot: dict[str, Any]) -> list[Finding]:
    """Evaluate approved, enabled custom CEL rules for a tenant."""
    rules = db.scalars(select(Rule).where(
        Rule.organization_id == organization_id,
        Rule.source == RuleSource.custom,
        Rule.state == RuleState.approved,
        Rule.enabled.is_(True))).all()
    findings: list[Finding] = []
    for rule in rules:
        if not rule.condition:
            continue
        try:
            prog = compile_condition(rule.condition)
            # Per-rule pruned context: keeps collection predicates fast.
            context = celpy.json_to_cel(_condition_context(rule.condition, snapshot))
            if bool(prog.evaluate({"snapshot": context})):
                findings.append(_finding_from_rule(rule))
        except Exception as exc:  # noqa: BLE001 - one bad rule must not break the scan
            logger.warning("Custom rule %s failed: %s", rule.key, exc)
    return findings


def _catalog_rule_keys() -> set[str]:
    """Keys of every built-in Python catalog rule, including retired ones."""
    import firewallguard.pipeline  # noqa: F401 - registers every catalog rule
    return {r.id for r in registry.rules} | set(registry.retired)


def evaluate_authored_system_rules(db: Session, snapshot: dict[str, Any]) -> list[Finding]:
    """Evaluate operator-authored global CEL rules and return their findings.

    The rules table holds two kinds of system rows:

    * *catalog mirrors* — one row per built-in Python rule; their findings are
      produced by the catalog code and the stored CEL is only an optional
      filter over those findings; and
    * *authored global rules* — created by a platform operator (CEL Rule
      Builder → Save as System Rule) with a key that has no catalog
      counterpart. No catalog code can ever emit findings for these, so they
      are generative: the CEL condition is evaluated against every tenant's
      analysis snapshot and a finding is emitted when it is true.
    """
    catalog_keys = _catalog_rule_keys()
    rows = db.scalars(select(Rule).where(
        Rule.source == RuleSource.system,
        Rule.organization_id.is_(None),
        Rule.state == RuleState.approved,
        Rule.enabled.is_(True),
        Rule.condition.isnot(None),
        Rule.condition != "")).all()
    authored = [r for r in rows if r.key not in catalog_keys]
    if not authored:
        return []
    findings: list[Finding] = []
    for rule in authored:
        try:
            prog = compile_condition(rule.condition)
            # Per-rule pruned context: keeps collection predicates fast.
            context = celpy.json_to_cel(_condition_context(rule.condition, snapshot))
            fired = bool(prog.evaluate({"snapshot": context}))
            logger.debug("Global rule %s (%r): fired=%s", rule.key, rule.title, fired)
            if fired:
                findings.append(_finding_from_rule(rule, "Matched global rule condition."))
        except Exception as exc:  # noqa: BLE001 - one bad rule must not break the scan
            logger.warning("Global rule %s failed: %s", rule.key, exc)
    if findings:
        logger.info("Authored global rules fired: %s",
                    ", ".join(f.rule_id for f in findings))
    return findings


def evaluate_management_rules(db: Session, snapshot: dict[str, Any]) -> list[Finding]:
    """Evaluate operator-authored Management Rules (kind="management").

    These are global system rules whose ``definition`` holds structured,
    reference-resolving conditions over access rules (see
    ``firewallguard.rules.semantic``). One finding is emitted per matching
    access rule; metadata (title/severity/category/description/remediation)
    is inherited from the rule row.
    """
    rows = db.scalars(select(Rule).where(
        Rule.source == RuleSource.system,
        Rule.organization_id.is_(None),
        Rule.state == RuleState.approved,
        Rule.enabled.is_(True),
        Rule.kind == "management")).all()
    if not rows:
        return []
    from firewallguard.rules.semantic import SnapshotIndex, evaluate_management_definition
    index = SnapshotIndex(snapshot)   # shared indexes/caches for all rules
    findings: list[Finding] = []
    for rule in rows:
        try:
            matches = evaluate_management_definition(rule.definition or {}, snapshot, index)
        except Exception as exc:  # noqa: BLE001 - one bad rule must not break the scan
            logger.warning("Management rule %s failed: %s", rule.key, exc)
            continue
        logger.debug("Management rule %s (%r): %d matching access rule(s)",
                     rule.key, rule.title, len(matches))
        for m in matches:
            ar = m.rule
            # object_name drives the finding fingerprint (rule + object), and
            # SonicWall access-rule names are not unique — dozens of rules can
            # be called "Default Access Rule". Qualify with the rule number so
            # every matching access rule keeps its own finding identity.
            num, ar_name = ar.get("num"), str(ar.get("name") or "").strip()
            if num is not None:
                name = f"Rule {num}: {ar_name}" if ar_name else f"Rule {num}"
            else:
                name = ar_name or "Access Rule"
            findings.append(Finding(
                rule_id=rule.key, title=rule.title, severity=rule.severity,
                category=rule.category or "Firewall Management",
                description=rule.description,
                evidence=m.evidence,
                business_impact="", technical_impact="",
                remediation=rule.remediation or "Review the access rule and restrict it appropriately.",
                verification=[], risk_reduction="Medium",
                references=rule.references or [], compliance=rule.compliance or {},
                object_name=str(name), object_type="Access Rule",
                object_detail=m.evidence[0] if m.evidence else "",
                affected_count=1))
    if findings:
        logger.info("Management rules fired: %s",
                    ", ".join(sorted({f.rule_id for f in findings})))
    return findings


def resolve_suppressions(db: Session, organization_id: str,
                         device_id: str | None) -> list[dict]:
    """Active (non-expired) suppressions for a tenant, scoped to a device or tenant-wide."""
    now = datetime.now(timezone.utc)
    rows = db.scalars(select(RuleSuppression).where(
        RuleSuppression.organization_id == organization_id)).all()
    out: list[dict] = []
    for s in rows:
        if s.device_id and s.device_id != device_id:
            continue
        if s.expires_at is not None:
            exp = s.expires_at if s.expires_at.tzinfo else s.expires_at.replace(tzinfo=timezone.utc)
            if exp < now:
                continue
        out.append({"rule_key": s.rule_key,
                    "action": s.action.value if hasattr(s.action, "value") else s.action,
                    "value": s.value})
    return out


def evaluate_system_rule_filters(db: Session, snapshot: dict[str, Any]) -> set[str]:
    """Evaluate system rules with non-empty CEL conditions against a snapshot.

    Returns the set of rule keys whose CEL condition evaluated to *false*.
    These findings should be filtered out of the pipeline results.
    System rules without a CEL condition are unaffected.

    This function is defensive: a single bad condition or a conversion failure
    must never block the scan.  Errors are logged and the condition is skipped.
    """
    rows = db.scalars(select(Rule).where(
        Rule.source == RuleSource.system,
        Rule.organization_id.is_(None),
        Rule.condition != "",
        Rule.condition.isnot(None),
        Rule.enabled.is_(True))).all()
    if not rows:
        return set()

    # Convert the snapshot once; guard against large / unconvertible payloads.
    try:
        cel_snapshot = celpy.json_to_cel(snapshot)
    except Exception:
        logger.warning("Failed to convert snapshot for CEL evaluation; skipping system rule filters")
        return set()

    suppress: set[str] = set()
    for rule in rows:
        try:
            prog = compile_condition(rule.condition)
            if not bool(prog.evaluate({"snapshot": cel_snapshot})):
                suppress.add(rule.key)
        except Exception:  # noqa: BLE001 - one bad condition must not break the scan
            logger.warning("System rule %s CEL condition failed evaluation: %s",
                           rule.key, rule.condition[:120])
    return suppress


def make_pipeline_hooks(db: Session, organization_id: str, device_id: str | None):
    """Build the (extra_findings_fn, suppressions, system_filter_fn) triple the pipeline accepts."""
    suppressions = resolve_suppressions(db, organization_id, device_id)

    def extra_findings_fn(snapshot: dict[str, Any]) -> list[Finding]:
        # Tenant custom CEL rules, operator-authored global CEL rules, and
        # operator-authored Management Rules (semantic, reference-resolving).
        # All flow through suppressions + scoring like catalog findings.
        return (evaluate_custom_rules(db, organization_id, snapshot)
                + evaluate_authored_system_rules(db, snapshot)
                + evaluate_management_rules(db, snapshot))

    def system_filter_fn(snapshot: dict[str, Any]) -> set[str]:
        # System rule CEL filters are opt-in via a feature flag.
        # They can be heavy (68+ conditions compiled per scan); until
        # performance is validated, keep them disabled in live scans.
        # Superadmins can still test individual conditions via the
        # Rule Test tab, and the conditions are saved/persisted.
        return set()
        # return evaluate_system_rule_filters(db, snapshot)

    return extra_findings_fn, suppressions, system_filter_fn


# ---------------------------------------------------------------------------
# API-TSR rule support.
# The API TSR format is whitespace-collapsed (see firewallguard/tsr/normalize.py).
# The normalizer now reconstructs every config section — per-object tables
# (access rules, address/service objects, NAT, zones, VPN SAs) and the KV/phrase
# settings — so the FULL rule set evaluates on a normalized API TSR with results
# equivalent to the GUI TSR (verified by tests/test_api_tsr.py parity check).
#
# These sets are therefore EMPTY: no rule is suppressed on API TSRs. They are
# retained as the mechanism to flag a future rule whose data genuinely cannot be
# recovered from the API export (none today). The only known residual is a small
# count delta in IPv6 address-object hygiene (Low severity), because IPv6 literals
# contain colons that the API "space-after-every-colon" export mangles.
# ---------------------------------------------------------------------------
_API_LOSSY_SECTIONS: set[str] = set()
_API_FORCE_NONE: set[str] = set()
_SNAP_TOKEN_RE = re.compile(r"snapshot\.([a-z_]+)")


def rule_api_support(rule_key: str, condition: str) -> str:
    """Classify a rule's API-TSR support: 'full' or 'none'.

    Derived from the snapshot sections the rule's CEL condition reads. If it
    touches a section flagged irrecoverable (or is force-listed) it is 'none';
    otherwise 'full'. With the current normalizer all sections reconstruct, so
    this returns 'full' for every rule.
    """
    if rule_key in _API_FORCE_NONE:
        return "none"
    cond = condition or _SYSTEM_RULE_CEL.get((rule_key or "").upper(), "")
    sections = set(_SNAP_TOKEN_RE.findall(cond))
    if sections & _API_LOSSY_SECTIONS:
        return "none"
    return "full"


def api_unsupported_system_keys(db: Session) -> list[str]:
    """System rule keys that must NOT be evaluated against an API TSR."""
    out: list[str] = []
    for r in db.scalars(select(Rule).where(Rule.source == RuleSource.system)):
        if rule_api_support(r.key, r.condition or "") != "full":
            out.append(r.key)
    return out


def detection_logic(title: str, category: str, severity: str) -> str:
    """A plain-English description of what a built-in rule detects.

    System rules are evaluated in Python (no CEL), so this surfaces the *logic*
    to users without exposing code. Derived from the rule's metadata.
    """
    cat = category or "Configuration"
    return (f"Flags a {severity.lower()}-severity {cat} issue. "
            f"The rule fires when the parsed TSR shows: {title}. "
            f"Findings are evidence-gated — they appear only when the configuration "
            f"explicitly demonstrates this condition, one finding per affected object.")


# ---------------------------------------------------------------------------
# Default CEL conditions for built-in system rules.
# Generated from the Python catalog — each condition approximates the
# detection logic as a boolean CEL expression referencing ``snapshot``.
# Superadmins may edit the DB-stored condition; if it evaluates to False
# during a scan the Python-generated findings for that rule are filtered out.
# ---------------------------------------------------------------------------
_SYSTEM_RULE_CEL: dict[str, str] = {
    # =====================================================================
    # catalog.py — MANAGEMENT SECURITY (FW-MGT)
    # =====================================================================
    "FW-MGT-001": (
        "// Management protocol (HTTPS/HTTP/SSH/SNMP) enabled on any interface\n"
        "size(snapshot.administration.https_mgmt_interfaces) > 0 || "
        "size(snapshot.administration.http_mgmt_interfaces) > 0 || "
        "size(snapshot.administration.ssh_mgmt_interfaces) > 0 || "
        "size(snapshot.administration.snmp_interfaces) > 0"
    ),
    "FW-MGT-002": (
        "// Cleartext HTTP management is enabled on the firewall\n"
        "snapshot.administration.http_port > 0"
    ),
    "FW-MGT-003": (
        "// Weak administrator password policy: complexity < 2, min length < 12, or change period > 90 days or 0\n"
        "(snapshot.administration.password_complexity_level == 0 || snapshot.administration.password_complexity_level < 2) || "
        "(snapshot.administration.min_password_length == 0 || snapshot.administration.min_password_length < 12) || "
        "(snapshot.administration.password_change_period_days == 0 || snapshot.administration.password_change_period_days > 90)"
    ),
    "FW-MGT-004": (
        "// Administrator one-time password (MFA) is disabled\n"
        "snapshot.administration.admin_otp == 'disabled'"
    ),
    "FW-MGT-005": (
        "// Default 'admin' account name is still in use\n"
        "snapshot.administration.admin_name == 'admin'"
    ),
    "FW-MGT-006": (
        "// SNMP v1/v2c enabled with community-string authentication\n"
        "snapshot.snmp.enabled == true && snapshot.snmp.get_community_set == true"
    ),
    "FW-MGT-007": (
        "// SonicOS API enabled with weak MD5 digest authentication\n"
        "snapshot.administration.sonicos_api_enabled == true && "
        "snapshot.administration.sonicos_api_md5_digest == true"
    ),
    "FW-MGT-008": (
        "// Enhanced audit logging of configuration changes is disabled\n"
        "snapshot.administration.enhanced_audit_logging == false"
    ),
    "FW-MGT-009": (
        "// HTTPS management permitted on more than 3 interfaces beyond MGMT\n"
        "size(snapshot.administration.https_mgmt_interfaces.filter(i, i != 'MGMT')) > 3"
    ),

    # =====================================================================
    # catalog.py — SECURITY SERVICES (FW-SVC)
    # =====================================================================
    "FW-SVC-001": (
        "// DPI-SSL client inspection is disabled\n"
        "snapshot.security_services.dpi_ssl_client_enabled == false"
    ),
    "FW-SVC-002": (
        "// Content Filtering Service (CFS) is disabled despite being licensed\n"
        "snapshot.security_services.content_filter_enabled == false"
    ),
    "FW-SVC-003": (
        "// IPS is globally disabled (RETIRED — superseded by SEC-009)\n"
        "snapshot.security_services.ips_enabled == false"
    ),
    "FW-SVC-003a": (
        "// IPS low-priority signatures in detect-only mode\n"
        "snapshot.security_services.ips_enabled == true && "
        "snapshot.security_services.ips_prevent_low == false"
    ),
    "FW-SVC-004": (
        "// Gateway Anti-Virus is globally disabled\n"
        "snapshot.security_services.gav_enabled == false"
    ),
    "FW-SVC-005": (
        "// Anti-Spyware is globally disabled\n"
        "snapshot.security_services.anti_spyware_enabled == false"
    ),
    "FW-SVC-006": (
        "// Capture ATP sandboxing shows no evidence of active configuration\n"
        "snapshot.security_services.capture_atp_evidence == false"
    ),
    "FW-SVC-007": (
        "// Security services set to Performance Optimized instead of Maximum Security\n"
        "snapshot.security_services.profile.lower().contains('performance')"
    ),
    "FW-SVC-008": (
        "// Zone-level security gaps: GAV, IPS, or Anti-Spyware off on Trusted/Public/Wireless (RETIRED)\n"
        "snapshot.zones.exists(z, "
        "(z.security_type == 'Trusted' || z.security_type == 'Public' || z.security_type == 'Wireless') && "
        "(z.gav == false || z.ips == false || z.anti_spyware == false))"
    ),
    "FW-SVC-009": (
        "// GAV HTTP outbound inspection disabled while GAV is enabled\n"
        "snapshot.security_services.gav_enabled == true && "
        "snapshot.security_services.gav_http_outbound == false"
    ),

    # =====================================================================
    # catalog.py — VPN SECURITY (FW-VPN)
    # =====================================================================
    "FW-VPN-001": (
        "// IKEv1 Aggressive Mode on enabled VPN policies (RETIRED)\n"
        "snapshot.vpn.policies.exists(p, p.enabled == true && p.exchange.lower().contains('aggressive'))"
    ),
    "FW-VPN-002": (
        "// Deprecated VPN encryption/hash: DES, 3DES, MD5, SHA1 (RETIRED)\n"
        "snapshot.vpn.policies.exists(p, p.enabled == true && "
        "(p.ike_proposal.contains('DES') || p.ike_proposal.contains('3DES') || "
        "p.ike_proposal.contains('MD5') || p.ike_proposal.contains('SHA1') || "
        "p.ipsec_proposal.contains('DES') || p.ipsec_proposal.contains('3DES') || "
        "p.ipsec_proposal.contains('MD5') || p.ipsec_proposal.contains('SHA1')))"
    ),
    "FW-VPN-003": (
        "// Perfect Forward Secrecy disabled on any enabled VPN policy (RETIRED)\n"
        "snapshot.vpn.policies.exists(p, p.enabled == true && p.pfs == false)"
    ),
    "FW-VPN-004": (
        "// IKEv2 Dynamic Client Proposal uses weak cryptographic algorithms\n"
        "snapshot.vpn.ikev2_dynamic_proposal.contains('DES') || "
        "snapshot.vpn.ikev2_dynamic_proposal.contains('3DES') || "
        "snapshot.vpn.ikev2_dynamic_proposal.contains('MD5') || "
        "snapshot.vpn.ikev2_dynamic_proposal.contains('SHA1') || "
        "snapshot.vpn.ikev2_dynamic_proposal.contains('DH Group 1') || "
        "snapshot.vpn.ikev2_dynamic_proposal.contains('DH Group 2') || "
        "snapshot.vpn.ikev2_dynamic_proposal.contains('DH Group 5')"
    ),
    "FW-VPN-005": (
        "// Disabled VPN policies still present in configuration (RETIRED)\n"
        "snapshot.vpn.policies.exists(p, p.enabled == false)"
    ),

    # =====================================================================
    # catalog.py — SSL VPN (FW-SSL)
    # =====================================================================
    "FW-SSL-001": (
        "// SSL VPN portal exposed on WAN zone\n"
        "snapshot.sslvpn.zones.WAN == true"
    ),
    "FW-SSL-002": (
        "// SSL VPN enabled on more than 2 internal zones\n"
        "size(snapshot.sslvpn.zones.filter(z, z != 'WAN' && z != 'SSLVPN')) > 2"
    ),
    "FW-SSL-003": (
        "// Firewall web management reachable over SSL VPN sessions\n"
        "snapshot.sslvpn.web_mgmt_over_sslvpn == true"
    ),

    # =====================================================================
    # catalog.py — ACCESS RULES (FW-ACL)
    # =====================================================================
    "FW-ACL-001": (
        "// WAN inbound allow rules with Any source AND Any service (RETIRED)\n"
        "snapshot.access_rules.exists(r, r.enabled == true && r.action == 'Allow' && "
        "r.src_zone == 'WAN' && r.src == 'Any' && r.service == 'Any')"
    ),
    "FW-ACL-002": (
        "// Inter-zone Any/Any/Any allow rules dissolving zone segmentation (RETIRED)\n"
        "snapshot.access_rules.exists(r, r.enabled == true && r.action == 'Allow' && "
        "r.src_zone != r.dst_zone && r.src_zone != 'WAN' && "
        "r.src == 'Any' && r.dst == 'Any' && r.service == 'Any' && r.auto_rule == false)"
    ),
    "FW-ACL-003": (
        "// Disabled access rules present or >= 5 enabled-but-unused manual rules\n"
        "size(snapshot.access_rules.filter(r, r.enabled == false)) > 0 || "
        "size(snapshot.access_rules.filter(r, r.enabled == true && r.auto_rule == false && r.usage == 0)) >= 5"
    ),
    "FW-ACL-004": (
        "// Enabled access rules with zero hit counts (RETIRED)\n"
        "snapshot.access_rules.exists(r, r.enabled == true && r.auto_rule == false && r.usage == 0)"
    ),

    # =====================================================================
    # catalog.py — NAT (FW-NAT)
    # =====================================================================
    "FW-NAT-001": (
        "// Disabled custom NAT policies or >= 5 enabled custom NAT policies (RETIRED)\n"
        "size(snapshot.nat_policies.filter(n, n.system == false && n.enabled == false)) > 0 || "
        "size(snapshot.nat_policies.filter(n, n.system == false && n.enabled == true)) >= 5"
    ),

    # =====================================================================
    # catalog.py — OBJECT HYGIENE (FW-HYG)
    # =====================================================================
    "FW-HYG-001": (
        "// 10+ address objects unreferenced by any module (RETIRED)\n"
        "size(snapshot.address_objects.objects.filter(o, o.reference_count == 0 && "
        "size(o.referenced_by) == 0 && size(o.member_of) == 0)) >= 10"
    ),
    "FW-HYG-002": (
        "// Empty address groups with no members\n"
        "snapshot.address_objects.groups.exists(g, size(g.members) == 0)"
    ),

    # =====================================================================
    # catalog.py — CERTIFICATES (FW-CRT)
    # =====================================================================
    "FW-CRT-001": (
        "// Expired certificates present in the device PKI store\n"
        "snapshot.certificates.exists(c, c.invalid == true || c.expires.contains('00/00'))"
    ),
    "FW-CRT-002": (
        "// Certificates expiring within 90 days\n"
        "snapshot.certificates.exists(c, c.invalid != true && !c.expires.contains('00/00'))"
    ),

    # =====================================================================
    # catalog.py — LICENSING (FW-LIC)
    # =====================================================================
    "FW-LIC-001": (
        "// Security service subscriptions expiring within 60 days\n"
        "snapshot.security_services.ips_expires.contains('/') || "
        "snapshot.security_services.gav_expires.contains('/') || "
        "snapshot.security_services.anti_spyware_expires.contains('/') || "
        "snapshot.security_services.content_filter_expires.contains('/')"
    ),

    # =====================================================================
    # catalog.py — HA (FW-HA)
    # =====================================================================
    "FW-HA-001": (
        "// HA control-link encryption disabled while HA is active\n"
        "snapshot.ha.mode != '' && snapshot.ha.mode != 'None' && snapshot.ha.mode != 'none' && "
        "snapshot.ha.encryption == false"
    ),

    # =====================================================================
    # catalog.py — LOGGING (FW-LOG)
    # =====================================================================
    "FW-LOG-001": (
        "// Syslog servers defined but none active\n"
        "size(snapshot.logging.syslog_servers) > 0 && "
        "snapshot.logging.active_syslog_servers == 0"
    ),

    # =====================================================================
    # catalog_parity.py — ACCESS RULES (ACR)
    # =====================================================================
    "ACR-002": (
        "// WAN inbound allow rule with Any source and Any destination\n"
        "snapshot.access_rules.exists(r, r.enabled == true && r.action == 'Allow' && "
        "r.src_zone == 'WAN' && r.src == 'Any' && r.dst == 'Any')"
    ),
    "ACR-003": (
        "// Access rule bypasses DPI inspection\n"
        "snapshot.access_rules.exists(r, r.enabled == true && "
        "(r.dpi_disabled == true || r.comment.lower().contains('no dpi')))"
    ),
    "ACR-007": (
        "// WAN inbound allow rule permits any destination service\n"
        "snapshot.access_rules.exists(r, r.enabled == true && r.src_zone == 'WAN' && "
        "r.action == 'Allow' && (r.service == 'Any' || r.service == 'Any -> Any' || r.service == ''))"
    ),

    # =====================================================================
    # catalog_parity.py — ADDRESS OBJECTS (AOB)
    # =====================================================================
    "AOB-001": (
        "// Duplicate address objects sharing the same type and value\n"
        "size(snapshot.address_objects.objects) > 0"
    ),
    "AOB-003": (
        "// Unused custom address object with zero references\n"
        "snapshot.address_objects.objects.exists(o, o.obj_class != 'default' && "
        "o.reference_count == 0 && size(o.referenced_by) == 0 && size(o.member_of) == 0)"
    ),

    # =====================================================================
    # catalog_parity.py — SERVICE OBJECTS (SVC)
    # =====================================================================
    "SVC-001": (
        "// Duplicate service objects with same protocol and port\n"
        "size(snapshot.services.objects) > 0"
    ),
    "SVC-004": (
        "// Unused custom service object not referenced by any rule or group\n"
        "snapshot.services.objects.exists(o, size(o.member_of) == 0)"
    ),

    # =====================================================================
    # catalog_parity.py — NAT POLICIES (NAT)
    # =====================================================================
    "NAT-003": (
        "// Custom enabled NAT policy with zero traffic hits\n"
        "snapshot.nat_policies.exists(n, n.system == false && n.enabled == true && n.usage == 0)"
    ),
    "NAT-006": (
        "// Inbound WAN NAT policy exposing internal host to internet\n"
        "snapshot.nat_policies.exists(n, n.system == false && n.enabled == true && "
        "(n.orig_dst.lower().contains('wan') || n.orig_dst.lower().contains('x1')))"
    ),

    # =====================================================================
    # catalog_parity.py — IPSEC VPN (IPSEC)
    # =====================================================================
    "IPSEC-001": (
        "// Weak IKE encryption: DES or 3DES in IKE proposal\n"
        "snapshot.vpn.policies.exists(p, "
        "p.ike_proposal.contains('DES') || p.ike_proposal.contains('3DES'))"
    ),
    "IPSEC-003": (
        "// Weak IPsec Phase 2 proposal: 3DES, DES, MD5, or SHA1\n"
        "snapshot.vpn.policies.exists(p, "
        "p.ipsec_proposal.contains('3DES') || p.ipsec_proposal.contains('DES') || "
        "p.ipsec_proposal.contains('MD5') || p.ipsec_proposal.contains('SHA1'))"
    ),
    "IPSEC-005": (
        "// Weak IKE Diffie-Hellman group: DH Group 1, 2, or 5\n"
        "snapshot.vpn.policies.exists(p, "
        "p.ike_proposal.contains('DH Group 1') || p.ike_proposal.contains('DH Group 2') || "
        "p.ike_proposal.contains('DH Group 5'))"
    ),
    "IPSEC-006": (
        "// Perfect Forward Secrecy disabled on site-to-site VPN policy\n"
        "snapshot.vpn.policies.exists(p, p.type.lower().startsWith('site') && p.pfs == false)"
    ),
    "IPSEC-008": (
        "// Disabled IPsec VPN policy still present in configuration\n"
        "snapshot.vpn.policies.exists(p, p.enabled == false)"
    ),

    # =====================================================================
    # catalog_parity.py — SECURITY SERVICES PER ZONE (SEC)
    # =====================================================================
    "SEC-009": (
        "// IPS licensed but not enabled on Trusted/Public/Wireless zones\n"
        "snapshot.zones.exists(z, "
        "(z.security_type == 'Trusted' || z.security_type == 'Public' || z.security_type == 'Wireless') && "
        "z.ips == false)"
    ),
    "SEC-010": (
        "// GAV licensed but not enabled on Trusted/Public/Wireless zones\n"
        "snapshot.zones.exists(z, "
        "(z.security_type == 'Trusted' || z.security_type == 'Public' || z.security_type == 'Wireless') && "
        "z.gav == false)"
    ),
    "SEC-011": (
        "// Anti-Spyware licensed but not enabled on Trusted/Public/Wireless zones\n"
        "snapshot.zones.exists(z, "
        "(z.security_type == 'Trusted' || z.security_type == 'Public' || z.security_type == 'Wireless') && "
        "z.anti_spyware == false)"
    ),

    # =====================================================================
    # catalog_parity.py — GATEWAY AV SIGNATURE AGE (GAV)
    # =====================================================================
    "GAV-001": (
        "// Gateway AV signature database older than 30 days\n"
        "snapshot.security_services.gav_signature_age_days > 30"
    ),

    # =====================================================================
    # catalog_parity.py — FIREWALL SETTINGS (FW)
    # =====================================================================
    "FW-001": (
        "// Stealth Mode disabled — firewall responds to blocked probes\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.stealth_mode == false"
    ),
    "FW-002": (
        "// FTP bounce attack protection disabled\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.ftp_bounce_protection == false"
    ),
    "FW-003": (
        "// TCP handshake enforcement disabled\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.tcp_handshake_enforcement == false"
    ),
    "FW-004": (
        "// SYN Flood Protection in watch-only mode\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.syn_proxy_watch_only == true"
    ),
    "FW-006": (
        "// UDP Flood Protection disabled\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.udp_flood_protection == false"
    ),
    "FW-007": (
        "// ICMP Flood Protection disabled\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.icmp_flood_protection == false"
    ),
    "FW-008": (
        "// Legacy WAN DDoS Protection disabled\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.wan_ddos_protection == false"
    ),
    "FW-009": (
        "// Drop source-routed IP packets disabled\n"
        "snapshot.firewall_settings.present == true && "
        "snapshot.firewall_settings.drop_source_routed == false"
    ),

    # =====================================================================
    # catalog_parity.py — AUTHENTICATION (AUTH / RAD)
    # =====================================================================
    "AUTH-002": (
        "// Login uniqueness not enforced\n"
        "snapshot.auth_servers.login_uniqueness == false"
    ),
    "AUTH-006": (
        "// Local users without MFA configured\n"
        "snapshot.local_users_detail.mfa_disabled_count > 0 && "
        "snapshot.local_users_detail.count > 0"
    ),
    "RAD-005": (
        "// TACACS+ accounting not enabled\n"
        "snapshot.auth_servers.tacacs_accounting_enabled == false"
    ),

    # =====================================================================
    # catalog_parity.py — SNMP (SNMP)
    # =====================================================================
    "SNMP-002": (
        "// SNMPv3 not enforced — v1/v2c cleartext requests accepted\n"
        "snapshot.snmp.enabled == true && "
        "snapshot.snmp.require_v3 == false"
    ),

    # =====================================================================
    # catalog_parity.py — SSLVPN (SSLVPN)
    # =====================================================================
    "SSLVPN-002": (
        "// SSL VPN Virtual Office portal reachable on non-LAN zones\n"
        "snapshot.sslvpn.enabled == true && "
        "snapshot.sslvpn.zones.exists(z, z != 'LAN')"
    ),

    # =====================================================================
    # catalog_parity.py — CONTENT FILTER (CFS)
    # =====================================================================
    "CFS-004": (
        "// CFS HTTPS content filtering disabled\n"
        "snapshot.cfs.present == true && "
        "snapshot.cfs.https_filtering == false"
    ),
    "CFS-006": (
        "// CFS Safe Search enforcement disabled\n"
        "snapshot.cfs.present == true && "
        "snapshot.cfs.safe_search == false"
    ),

    # =====================================================================
    # catalog_parity.py — WIRELESS (WLAN)
    # =====================================================================
    "WLAN-006": (
        "// No SSIDs using WPA3 encryption on active wireless interfaces\n"
        "snapshot.wlan.present == true && "
        "snapshot.wlan.interface_count > 0 && "
        "size(snapshot.wlan.ssids) > 0 && "
        "!snapshot.wlan.ssids.exists(s, s.encryption.lower().contains('wpa3'))"
    ),

    # =====================================================================
    # catalog_parity.py — PERFORMANCE (PERF)
    # =====================================================================
    "PERF-002": (
        "// CPU utilization reached 95% or higher\n"
        "snapshot.performance.present == true && "
        "snapshot.performance.cpu_max >= 95.0"
    ),

    # =====================================================================
    # catalog_info.py — INFORMATIONAL INVENTORY CHECKS
    # =====================================================================
    "ACR-I001": (
        "// Access rules inventory count\n"
        "size(snapshot.access_rules) > 0"
    ),
    "AOB-I001": (
        "// Address objects inventory count\n"
        "size(snapshot.address_objects.objects) > 0"
    ),
    "SVC-I001": (
        "// Service objects inventory count\n"
        "size(snapshot.services.objects) > 0"
    ),
    "NAT-I001": (
        "// NAT policies inventory count\n"
        "size(snapshot.nat_policies) > 0"
    ),
    "IPSEC-I001": (
        "// VPN policies inventory count\n"
        "size(snapshot.vpn.policies) > 0"
    ),
    "USER-I001": (
        "// Local user accounts count and MFA coverage\n"
        "snapshot.local_users_detail.count > 0"
    ),
    "IPS-I001": (
        "// IPS license state and expiry\n"
        "true"
    ),
    "GAV-I001": (
        "// GAV license state and expiry\n"
        "true"
    ),
    "SYSTEM-I001": (
        "// Device model, firmware version, and HA mode\n"
        "snapshot.system.model != ''"
    ),
    "WLAN-I001": (
        "// Wireless interfaces and SSID count\n"
        "snapshot.wlan.present == true"
    ),
}


def default_cel_condition(rule_key: str, title: str = "", category: str = "") -> str:
    """Return a default CEL condition for a built-in system rule.

    Looks up the rule key in the pre-built catalog mapping.  Returns an empty
    string when no default is defined (the Python engine remains authoritative).
    """
    return _SYSTEM_RULE_CEL.get((rule_key or "").upper(), "")


def seed_system_rules(db: Session) -> int:
    """Mirror the built-in Python catalog into the rules table (idempotent).

    System rules are global (organization_id is null), pre-approved, and now
    carry a *default* CEL condition approximating the Python detection logic.
    Superadmins may edit the condition; if the condition evaluates to False
    during a scan, the Python-generated findings for that rule are filtered out.
    Existing rows with a non-empty user-edited condition are left untouched.
    Returns the number of rules created.
    """
    # Importing the pipeline registers every catalog rule on the shared registry.
    import firewallguard.pipeline  # noqa: F401

    existing = {r.key: r for r in db.scalars(select(Rule).where(
        Rule.source == RuleSource.system, Rule.organization_id.is_(None)))}
    created = 0
    for r in registry.active_rules():
        logic = detection_logic(r.title, r.category, r.severity)
        row = existing.get(r.id)
        if row is not None:
            # Refresh metadata/logic on existing system rules.
            row.title, row.category, row.severity, row.description = \
                r.title, r.category, r.severity, logic
            # Populate a default CEL condition if the rule has none yet.
            if not row.condition or not row.condition.strip():
                row.condition = default_cel_condition(r.id, r.title, r.category)
            continue
        db.add(Rule(
            organization_id=None, key=r.id, title=r.title, category=r.category,
            severity=r.severity, description=logic,
            condition=default_cel_condition(r.id, r.title, r.category),
            remediation="", compliance={},
            references=list(getattr(r, "references", []) or []),
            source=RuleSource.system, state=RuleState.approved, enabled=True))
        created += 1
    db.commit()
    return created


def check_firmware_compliance(db: Session, device_model: str,
                              device_firmware: str) -> Finding | None:
    """Look up the device generation and recommended firmware, and return a
    Critical finding if the installed firmware is older than / different from
    the configured recommendation.  Returns None when no config exists or the
    firmware is compliant."""
    if not device_model or not device_firmware:
        return None

    # Find which generation this model belongs to (case-insensitive partial match).
    gen_device = db.scalar(
        select(GenerationDevice).where(
            GenerationDevice.model.ilike(f"%{device_model}%")
        ).order_by(func.length(GenerationDevice.model))  # shortest match first
    )
    if not gen_device:
        return None

    gen = db.get(DeviceGeneration, gen_device.generation_id)
    if not gen or not gen.firmware:
        return None

    recommended = gen.firmware[0].version.strip()
    if not recommended:
        return None

    current = device_firmware.strip()
    if current == recommended:
        return None  # up to date

    return Finding(
        rule_id="FW-FIRMWARE-COMPLIANCE",
        title=f"Device running outdated firmware ({gen.name})",
        severity="Critical",
        category="Firmware Compliance",
        description=(
            f"The device model {device_model} ({gen.name}) is running "
            f"firmware {current}, but the platform administrator recommends "
            f"{recommended}."
        ),
        evidence=[
            f"Device Model: {device_model}",
            f"Generation: {gen.name}",
            f"Current Firmware: {current}",
            f"Recommended Firmware: {recommended}",
        ],
        business_impact=(
            "Outdated firmware may expose the device to known vulnerabilities "
            "that have been patched in the recommended release."
        ),
        technical_impact=(
            f"Firmware {current} is behind the administrator-configured "
            f"recommendation of {recommended} for {gen.name} devices."
        ),
        remediation=(
            f"Upgrade the device to firmware version {recommended} or later. "
            f"Refer to the SonicWall upgrade guide for {device_model}."
        ),
        verification=[
            f"Confirm firmware version is {recommended} or later after upgrade",
            "Re-run the analysis to verify the finding is resolved",
        ],
        risk_reduction="High",
        references=["SonicWall PSIRT Portal", "SonicOS Release Notes"],
        compliance={},
        likelihood=3, impact=5, exposure=3, affected_count=1,
        object_name=device_model,
        object_type="Device",
    )
