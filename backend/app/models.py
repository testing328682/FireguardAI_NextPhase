"""Database models (SQLAlchemy 2.0 style).

The schema is multi-tenant. The top-level entity is an ``Organization`` which
may be a direct customer or an MSP. An MSP organization owns multiple
``Customer`` records (its managed clients); a direct customer has a single
implicit customer record. ``Device`` rows belong to a customer, and every
``Tsr`` upload and ``Analysis`` is scoped to a device, so tenant isolation is
enforced by always filtering on ``organization_id``.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, ForeignKey, Enum, JSON, Text, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class PlanTier(str, enum.Enum):
    free = "free"
    professional = "professional"
    msp = "msp"


# ── Dynamic Plans ──────────────────────────────────────────────────────
class Plan(Base):
    """A licensable plan with configurable features and pricing.

    - ``plan_type``: "professional" (flat per-device pricing) or "msp" (tier-based pricing).
    - ``features``: JSON dict of feature_key → bool, referencing the FeatureRegistry.
    - ``price_per_device``: flat monthly price per device — used for Professional plans.
    - ``pricing_tiers``: for MSP plans only: {"10": 49, "25": 99, ...} — flat monthly
      price per device-count tier. A license conveys the right to register and
      analyze a device; it no longer carries an analysis-frequency dimension.
    """
    __tablename__ = "plans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    plan_type: Mapped[str] = mapped_column(String(32), default="professional")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_visible: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    price_per_device: Mapped[float] = mapped_column(Float, default=0.0)
    pricing_tiers: Mapped[dict] = mapped_column(JSON, default=dict)
    yearly_discount_pct: Mapped[int] = mapped_column(Integer, default=20)  # e.g., 20 = 20% off yearly
    is_testing: Mapped[bool] = mapped_column(Boolean, default=False)
    validity_minutes: Mapped[int] = mapped_column(Integer, default=0)  # 0 = standard; e.g. 5, 30, 60, 1440
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class LicensePurchase(Base):
    """Individual license purchase record with date tracking.

    A license represents the right to register and continuously analyze a
    fixed number of devices — it carries no analysis-frequency dimension.
    """
    __tablename__ = "license_purchases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    subscription_term: Mapped[str] = mapped_column(String(32), default="monthly")  # monthly | yearly
    tier: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # MSP tier key e.g. "10"
    tier_device_count: Mapped[int] = mapped_column(Integer, default=0)  # devices per tier unit
    count: Mapped[int] = mapped_column(Integer, default=1)  # units purchased
    total_devices: Mapped[int] = mapped_column(Integer, default=0)  # count × tier_device_count (or count for pro)
    purchased_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class FeatureRegistry(Base):
    """Global feature definitions that admins create and assign to plans."""
    __tablename__ = "features_registry"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Role(str, enum.Enum):
    owner = "owner"          # full control of the organization
    admin = "admin"          # manage devices, users, run analyses
    analyst = "analyst"      # upload TSRs, view findings
    viewer = "viewer"        # read-only
    msp_operator = "msp_operator"  # operate across managed customers


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_msp: Mapped[bool] = mapped_column(Boolean, default=False)
    plan: Mapped[PlanTier] = mapped_column(Enum(PlanTier), default=PlanTier.free)
    # Dynamic plan reference (preferred over the enum above).
    plan_id: Mapped[Optional[str]] = mapped_column(ForeignKey("plans.id"), nullable=True)
    # Billing (Phase 3). ``subscription_status`` is one of
    # trialing | active | past_due | canceled | none.
    subscription_status: Mapped[str] = mapped_column(String(32), default="none")
    trial_ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    stripe_customer_id: Mapped[str] = mapped_column(String(64), default="")
    stripe_subscription_id: Mapped[str] = mapped_column(String(64), default="")
    # Data residency (Phase 4)
    region: Mapped[str] = mapped_column(String(16), default="us")
    # Per-org retention override in days; null => plan default.
    data_retention_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Findings visibility: severities to hide (JSON list, e.g. ["Low","Info"]).
    hidden_severities: Mapped[list] = mapped_column(JSON, default=list)
    # Dynamic plan configuration — device count chosen by customer.
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    # License allocations, keyed by subscription term ("monthly" / "yearly"):
    #   Professional: {"monthly": {"licenses": 5}}
    #   MSP:          {"monthly": {"10": 3, "25": 1}}   (tier -> purchased count)
    license_allocations: Mapped[dict] = mapped_column(JSON, default=dict)
    # Default subscription term chosen at plan selection: "monthly" or "yearly"
    subscription_term: Mapped[str] = mapped_column(String(32), default="monthly")
    # White-label branding (Phase 4)
    brand_company_name: Mapped[str] = mapped_column(String(255), default="")
    brand_logo_url: Mapped[str] = mapped_column(String(1024), default="")
    brand_primary_color: Mapped[str] = mapped_column(String(16), default="")
    brand_contact: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    customers: Mapped[list["Customer"]] = relationship(back_populates="organization")
    active_plan: Mapped[Optional["Plan"]] = relationship(foreign_keys=[plan_id])


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    phone: Mapped[str] = mapped_column(String(64), default="")
    address: Mapped[str] = mapped_column(String(512), default="")
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Platform operator (cross-tenant). Distinct from the per-org ``role``; only
    # ever set out-of-band (bootstrap), never via the tenant-facing API.
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # MFA (TOTP). ``totp_secret`` is the base32 shared secret; it is only
    # considered enforced once ``mfa_enabled`` is True (set on first successful
    # verification). ``backup_codes`` holds bcrypt-hashed single-use codes.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str] = mapped_column(String(64), default="")
    backup_codes: Mapped[list] = mapped_column(JSON, default=list)

    # Account lockout: failed logins accumulate; once the threshold is reached
    # ``locked_until`` is set and logins are refused until it elapses.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Per-user notification preferences (delivered to this user's email).
    notify_new_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_scan_failed: Mapped[bool] = mapped_column(Boolean, default=True)

    organization: Mapped[Organization] = relationship(back_populates="users")


class Customer(Base):
    """A managed client. For a direct customer this is 1:1 with the org."""
    __tablename__ = "customers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    # MSP metadata (Phase 3)
    location: Mapped[str] = mapped_column(String(255), default="")
    business_unit: Mapped[str] = mapped_column(String(255), default="")
    contact_email: Mapped[str] = mapped_column(String(255), default="")
    primary_contact: Mapped[str] = mapped_column(String(255), default="")
    phone: Mapped[str] = mapped_column(String(64), default="")
    country: Mapped[str] = mapped_column(String(128), default="")
    timezone: Mapped[str] = mapped_column(String(64), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    organization: Mapped[Organization] = relationship(back_populates="customers")
    devices: Mapped[list["Device"]] = relationship(back_populates="customer")


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    serial: Mapped[str] = mapped_column(String(64), index=True)
    model: Mapped[str] = mapped_column(String(64), default="")
    firmware: Mapped[str] = mapped_column(String(128), default="")
    friendly_name: Mapped[str] = mapped_column(String(255), default="")
    latest_score: Mapped[float] = mapped_column(Float, default=0.0)
    latest_grade: Mapped[str] = mapped_column(String(8), default="")
    # Connectivity: how TSRs arrive for this device, and the last API-pull result.
    connection_method: Mapped[str] = mapped_column(String(16), default="manual")  # manual | api
    analyze_mode: Mapped[str] = mapped_column(String(16), default="manual")      # manual | auto
    configured: Mapped[bool] = mapped_column(Boolean, default=False)
    last_connection_status: Mapped[str] = mapped_column(String(32), default="")    # ok | failed | ""
    last_connection_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_connection_error: Mapped[str] = mapped_column(String(512), default="")
    last_analysis_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    # Per-device findings visibility override (JSON list, e.g. ["Low","Info"]).
    hidden_severities: Mapped[list] = mapped_column(JSON, default=list)
    # Which license purchase this device consumed from (null for pre-license devices).
    license_purchase_id: Mapped[Optional[str]] = mapped_column(ForeignKey("license_purchases.id"), nullable=True)
    # Cached license info (populated at registration; survives LicensePurchase deletion)
    license_info: Mapped[dict] = mapped_column(JSON, default=dict)
    # Decommissioning: a configured device is decommissioned rather than deleted
    # so the license stays consumed until it naturally expires.
    decommissioned: Mapped[bool] = mapped_column(Boolean, default=False)
    decommissioned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Set to True the first time the device is configured; never reset.
    # Drives the decommission-vs-delete decision regardless of current status.
    was_ever_configured: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    customer: Mapped[Customer] = relationship(back_populates="devices")
    tsrs: Mapped[list["Tsr"]] = relationship(back_populates="device")


class Tsr(Base):
    __tablename__ = "tsrs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    filename: Mapped[str] = mapped_column(String(512))
    storage_key: Mapped[str] = mapped_column(String(1024))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_by: Mapped[str] = mapped_column(String(36))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    favorite: Mapped[bool] = mapped_column(Boolean, default=False)

    device: Mapped[Device] = relationship(back_populates="tsrs")
    analysis: Mapped["Analysis"] = relationship(back_populates="tsr", uselist=False)


class AnalysisStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    complete = "complete"
    failed = "failed"


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    tsr_id: Mapped[str] = mapped_column(ForeignKey("tsrs.id"), index=True)
    status: Mapped[AnalysisStatus] = mapped_column(Enum(AnalysisStatus), default=AnalysisStatus.queued)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    grade: Mapped[str] = mapped_column(String(8), default="")
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tsr: Mapped[Tsr] = relationship(back_populates="analysis")


class DriftEvent(Base):
    __tablename__ = "drift_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    previous_analysis_id: Mapped[str] = mapped_column(String(36))
    current_analysis_id: Mapped[str] = mapped_column(String(36))
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    severity_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    alerts: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertChannel(str, enum.Enum):
    email = "email"
    webhook = "webhook"


class AlertSubscription(Base):
    __tablename__ = "alert_subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    channel: Mapped[AlertChannel] = mapped_column(Enum(AlertChannel), default=AlertChannel.email)
    target: Mapped[str] = mapped_column(String(512))   # email address or webhook URL
    on_new_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    on_service_disabled: Mapped[bool] = mapped_column(Boolean, default=True)
    on_firmware_vuln: Mapped[bool] = mapped_column(Boolean, default=True)
    on_critical_drift: Mapped[bool] = mapped_column(Boolean, default=True)


# ---------------------------------------------------------------------------
# Finding workflow
# ---------------------------------------------------------------------------
class FindingStatus(str, enum.Enum):
    """Lifecycle of a single finding.

    ``open`` -> ``acknowledged`` -> ``in_progress`` -> ``fixed`` is the normal
    remediation path. ``fixed`` findings are auto-verified on the next scan and
    reopened if still detected. ``false_positive`` and ``accepted_risk`` are
    terminal-ish states that require a justification; ``accepted_risk`` also
    requires admin sign-off and an expiry, after which it auto-reopens.
    ``suppressed`` is an admin-only rule/instance silence.
    """
    open = "open"
    acknowledged = "acknowledged"
    in_progress = "in_progress"
    fixed = "fixed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    suppressed = "suppressed"


class Finding(Base):
    """A single detection produced by one analysis, with a triage workflow.

    Findings are persisted from the pipeline result so they can be assigned,
    commented on and tracked over time. ``fingerprint`` (rule + affected object)
    gives a finding a stable identity across scans of the same device, which is
    what lets a ``fixed`` finding auto-reopen when it reappears.
    """
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    fingerprint: Mapped[str] = mapped_column(String(255), index=True)

    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(512))
    category: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    business_impact: Mapped[str] = mapped_column(Text, default="")
    technical_impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    verification: Mapped[list] = mapped_column(JSON, default=list)
    compliance: Mapped[dict] = mapped_column(JSON, default=dict)
    exploitability: Mapped[str] = mapped_column(String(16), default="")

    object_name: Mapped[str] = mapped_column(String(255), default="")
    object_type: Mapped[str] = mapped_column(String(64), default="")
    object_detail: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.open, index=True)
    assignee_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ticket_ref: Mapped[str] = mapped_column(String(255), default="")
    ticket_system: Mapped[str] = mapped_column(String(32), default="")   # jira | servicenow
    ticket_url: Mapped[str] = mapped_column(String(512), default="")
    ticket_status: Mapped[str] = mapped_column(String(64), default="")
    justification: Mapped[str] = mapped_column(Text, default="")
    accepted_risk_expiry: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)
    signed_off_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    comments: Mapped[list["FindingComment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan")


class CommentType(str, enum.Enum):
    comment = "comment"
    status_change = "status_change"
    assignment = "assignment"
    attachment = "attachment"


class FindingComment(Base):
    __tablename__ = "finding_comments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    author_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    author_email: Mapped[str] = mapped_column(String(255), default="")
    comment_type: Mapped[CommentType] = mapped_column(Enum(CommentType), default=CommentType.comment)
    body: Mapped[str] = mapped_column(Text, default="")
    from_status: Mapped[str] = mapped_column(String(32), default="")
    to_status: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding: Mapped[Finding] = relationship(back_populates="comments")


# ---------------------------------------------------------------------------
# Scheduled scans
# ---------------------------------------------------------------------------
class ScheduleFrequency(str, enum.Enum):
    manual = "manual"
    hourly = "hourly"
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class Schedule(Base):
    """Per-device scan schedule consumed by the Celery Beat reader."""
    __tablename__ = "schedules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), unique=True, index=True)
    frequency: Mapped[ScheduleFrequency] = mapped_column(
        Enum(ScheduleFrequency), default=ScheduleFrequency.manual)
    hour: Mapped[int] = mapped_column(Integer, default=3)          # 0-23, local to timezone
    minute: Mapped[int] = mapped_column(Integer, default=0)        # 0-59
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    day_of_week: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)   # 0=Mon..6=Sun
    day_of_month: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 1-31
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    blackout_windows: Mapped[list] = mapped_column(JSON, default=list)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Audit log (append-only)
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    user_email: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str] = mapped_column(String(64), default="")
    before: Mapped[dict] = mapped_column(JSON, default=dict)
    after: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


# ---------------------------------------------------------------------------
# Phase 2 — API pull credentials
# ---------------------------------------------------------------------------
class DeviceCredential(Base):
    """Encrypted SonicOS API credentials for an API-pull device.

    The password is stored Fernet-encrypted (see ``app.crypto``) and is never
    returned by the API in plaintext.
    """
    __tablename__ = "device_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=443)
    username: Mapped[str] = mapped_column(String(255))
    encrypted_password: Mapped[str] = mapped_column(Text)
    last_test_status: Mapped[str] = mapped_column(String(32), default="")  # ok | failed
    last_test_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Phase 2 — DB-stored rule catalog (CEL)
# ---------------------------------------------------------------------------
class RuleSource(str, enum.Enum):
    system = "system"   # ships with the product; evaluated by the Python engine
    custom = "custom"   # tenant-authored; evaluated via CEL against the snapshot


class RuleState(str, enum.Enum):
    draft = "draft"
    submitted = "submitted"
    approved = "approved"


class Rule(Base):
    """A detection rule record.

    System rules mirror the built-in Python catalog (so they appear in the admin
    GUI and can be suppressed/overridden). Custom rules carry a CEL ``condition``
    evaluated against the parsed snapshot. ``organization_id`` is null for
    global/system rules and set for tenant-authored ones.
    """
    __tablename__ = "rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True)
    key: Mapped[str] = mapped_column(String(64), index=True)   # e.g. FW-MGT-001 or CUSTOM-xxxx
    title: Mapped[str] = mapped_column(String(512))
    category: Mapped[str] = mapped_column(String(128), default="")
    severity: Mapped[str] = mapped_column(String(16), default="Medium")
    description: Mapped[str] = mapped_column(Text, default="")
    condition: Mapped[str] = mapped_column(Text, default="")        # CEL expression
    remediation: Mapped[str] = mapped_column(Text, default="")
    compliance: Mapped[dict] = mapped_column(JSON, default=dict)
    references: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[RuleSource] = mapped_column(Enum(RuleSource), default=RuleSource.custom)
    state: Mapped[RuleState] = mapped_column(Enum(RuleState), default=RuleState.draft)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    versions: Mapped[list["RuleVersion"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan")


class RuleVersion(Base):
    """Immutable snapshot of a rule's editable fields, one per edit."""
    __tablename__ = "rule_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    condition: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    change_note: Mapped[str] = mapped_column(Text, default="")
    edited_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    edited_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    rule: Mapped[Rule] = relationship(back_populates="versions")


class SuppressionAction(str, enum.Enum):
    disable = "disable"
    override_severity = "override_severity"


class RuleSuppression(Base):
    """Per-tenant rule disablement or severity override.

    ``device_id`` null means the suppression applies tenant-wide; otherwise it is
    scoped to one device. ``rule_key`` matches the rule identifier (works for both
    system and custom rules).
    """
    __tablename__ = "rule_suppressions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_key: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[Optional[str]] = mapped_column(ForeignKey("devices.id"), nullable=True)
    action: Mapped[SuppressionAction] = mapped_column(Enum(SuppressionAction))
    value: Mapped[str] = mapped_column(String(32), default="")   # new severity when overriding
    reason: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Phase 2 — integrations and API tokens
# ---------------------------------------------------------------------------
class IntegrationType(str, enum.Enum):
    slack = "slack"
    teams = "teams"
    webhook = "webhook"
    jira = "jira"
    servicenow = "servicenow"
    splunk = "splunk"
    sentinel = "sentinel"
    pagerduty = "pagerduty"


class Integration(Base):
    """External system connection. Non-secret options live in ``config``; secrets
    (e.g. a Slack webhook URL) are Fernet-encrypted in ``encrypted_secret``.
    """
    __tablename__ = "integrations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    type: Mapped[IntegrationType] = mapped_column(Enum(IntegrationType))
    name: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)        # event toggles, etc.
    encrypted_secret: Mapped[str] = mapped_column(Text, default="")  # webhook URL / token
    last_status: Mapped[str] = mapped_column(String(32), default="")
    last_delivery_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApiToken(Base):
    """Programmatic API token. Only the bcrypt hash is stored; the plaintext is
    shown once at creation. ``prefix`` is a short non-secret display fragment.
    """
    __tablename__ = "api_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    hashed_token: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Phase 3 — SSO and PSIRT refresh
# ---------------------------------------------------------------------------
class SSOProtocol(str, enum.Enum):
    oidc = "oidc"
    saml = "saml"


class SSOConfig(Base):
    """Per-organization single sign-on configuration.

    OIDC fields drive an authorization-code flow with JWKS id_token validation.
    SAML fields drive the ACS endpoint. ``group_role_map`` maps IdP group names to
    application role values; ``default_role`` is used when no group matches.
    Secrets (OIDC client secret) are Fernet-encrypted.
    """
    __tablename__ = "sso_configs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    protocol: Mapped[SSOProtocol] = mapped_column(Enum(SSOProtocol), default=SSOProtocol.oidc)
    # OIDC
    oidc_discovery_url: Mapped[str] = mapped_column(String(512), default="")
    oidc_client_id: Mapped[str] = mapped_column(String(255), default="")
    oidc_encrypted_client_secret: Mapped[str] = mapped_column(Text, default="")
    # SAML
    saml_idp_entity_id: Mapped[str] = mapped_column(String(512), default="")
    saml_idp_sso_url: Mapped[str] = mapped_column(String(512), default="")
    saml_idp_x509_cert: Mapped[str] = mapped_column(Text, default="")
    # Mapping
    groups_attribute: Mapped[str] = mapped_column(String(128), default="groups")
    group_role_map: Mapped[dict] = mapped_column(JSON, default=dict)
    default_role: Mapped[str] = mapped_column(String(32), default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PsirtRefreshLog(Base):
    """Record of a PSIRT advisory refresh run (changelog for admins)."""
    __tablename__ = "psirt_refresh_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    source: Mapped[str] = mapped_column(String(32), default="scheduled")  # scheduled | manual
    content_hash: Mapped[str] = mapped_column(String(64), default="")
    changed: Mapped[bool] = mapped_column(Boolean, default=False)
    advisory_count: Mapped[int] = mapped_column(Integer, default=0)
    added: Mapped[list] = mapped_column(JSON, default=list)
    updated: Mapped[list] = mapped_column(JSON, default=list)
    affected_devices: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------------------
# CEL Rule Builder — persisted reference TSR snapshot per user
# ---------------------------------------------------------------------------
class BuilderSnapshot(Base):
    """A superadmin's uploaded reference TSR snapshot for the CEL rule builder.
    One row per user; re-uploading replaces the previous snapshot."""
    __tablename__ = "builder_snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255), default="")
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ---------------------------------------------------------------------------
# API connection logs (per-device troubleshooting)
# ---------------------------------------------------------------------------
class ApiConnectionLog(Base):
    """Record of every API connection attempt for a device.

    Stores trigger, host, endpoint, HTTP status, timing, error details, and
    serial validation so customers can troubleshoot connectivity issues
    without inspecting backend logs.
    """
    __tablename__ = "api_connection_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    trigger: Mapped[str] = mapped_column(String(32), default="")        # test_connect | pull_now | scheduled_pull | api_connect
    host: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    endpoint: Mapped[str] = mapped_column(String(512), default="")      # API path that was called
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    error_message: Mapped[str] = mapped_column(Text, default="")
    connected_serial: Mapped[str] = mapped_column(String(64), default="")   # firewall serial from TSR
    registered_serial: Mapped[str] = mapped_column(String(64), default="")  # device serial in platform
    result_summary: Mapped[str] = mapped_column(String(512), default="")


# ---------------------------------------------------------------------------
# Product & Platform Configuration (superadmin-managed)
# ---------------------------------------------------------------------------
class ApiFlowConfig(Base):
    """A platform-global, configurable SonicOS API workflow (superadmin-managed).

    Drives the 'Connect via API' flow without code changes: ``steps`` is an
    ordered JSON list (authenticate -> export TSR -> logout, etc.), each step a
    dict of method/path/headers/query/body/success/extract (see app.api_flow).
    Exactly one config is ``is_active``; tenants use it automatically.
    """
    __tablename__ = "api_flow_configs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    version_label: Mapped[str] = mapped_column(String(64), default="")  # e.g. "Gen7"
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    auth_type: Mapped[str] = mapped_column(String(32), default="basic")  # basic|bearer|none
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    api_base: Mapped[str] = mapped_column(String(128), default="/api/sonicos")
    steps: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DeviceGeneration(Base):
    """A device generation (e.g. Gen 7, Gen 8)."""
    __tablename__ = "device_generations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    devices: Mapped[list["GenerationDevice"]] = relationship(
        back_populates="generation", cascade="all, delete-orphan")
    firmware: Mapped[list["FirmwareRecommendation"]] = relationship(
        back_populates="generation", cascade="all, delete-orphan")


class GenerationDevice(Base):
    """A device model belonging to a generation (e.g. NSA 3700 in Gen 7)."""
    __tablename__ = "generation_devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    generation_id: Mapped[str] = mapped_column(ForeignKey("device_generations.id"), index=True)
    model: Mapped[str] = mapped_column(String(128))

    generation: Mapped[DeviceGeneration] = relationship(back_populates="devices")


class FirmwareRecommendation(Base):
    """Recommended firmware version for a generation."""
    __tablename__ = "firmware_recommendations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    generation_id: Mapped[str] = mapped_column(
        ForeignKey("device_generations.id"), unique=True, index=True)
    version: Mapped[str] = mapped_column(String(64), default="")

    generation: Mapped[DeviceGeneration] = relationship(back_populates="firmware")
