"""Pydantic v2 schemas for API requests and responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field

from .models import (
    PlanTier, Role, AnalysisStatus, AlertChannel, FindingStatus, CommentType,
    ScheduleFrequency, RuleSource, RuleState, SuppressionAction, IntegrationType,
    SSOProtocol,
)


# ---- page control (global Server Admin visibility switches) --------------
class PageControlOut(BaseModel):
    key: str
    label: str
    description: str = ""
    enabled: bool


class PageControlUpdate(BaseModel):
    enabled: bool


# ---- auth ----------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginResult(BaseModel):
    """Login outcome.

    When the account has MFA enabled the password step returns
    ``mfa_required=True`` plus a short-lived ``mfa_token``; the client then
    calls ``/auth/mfa/verify`` to obtain the real access/refresh tokens.
    Otherwise the tokens are returned directly.
    """
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=1)
    company_name: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=12)
    phone: str = ""
    address: str = ""
    region: str = "us"
    is_msp: bool = False


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaActivateRequest(BaseModel):
    code: str


class MfaActivateResponse(BaseModel):
    backup_codes: list[str]


class MfaDisableRequest(BaseModel):
    code: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    full_name: str = ""
    role: Role = Role.viewer


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    notify_new_critical: Optional[bool] = None
    notify_scan_failed: Optional[bool] = None


class UserOut(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    phone: str = ""
    address: str = ""
    role: Role
    organization_id: str
    is_superadmin: bool = False
    mfa_enabled: bool = False
    notify_new_critical: bool = True
    notify_scan_failed: bool = True
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---- platform (superadmin) -----------------------------------------------
class PlatformOrgRow(BaseModel):
    id: str
    name: str
    type: str                # MSP | Direct
    plan: str
    region: str
    subscription_status: str
    customers: int
    firewalls: int
    users: int
    avg_score: float
    open_critical: int
    created_at: Optional[datetime] = None


class PlatformStats(BaseModel):
    organizations: int
    msp_count: int
    direct_count: int
    total_customers: int
    total_firewalls: int
    total_users: int
    plan_distribution: dict[str, int]
    region_distribution: dict[str, int]


class PlatformOverview(BaseModel):
    stats: PlatformStats
    organizations: list[PlatformOrgRow]


# ---- tenancy -------------------------------------------------------------
class OrganizationOut(BaseModel):
    id: str
    name: str
    is_msp: bool
    plan: PlanTier

    class Config:
        from_attributes = True


class CustomerCreate(BaseModel):
    name: str
    location: str = ""
    business_unit: str = ""
    contact_email: str = ""
    primary_contact: str = ""
    phone: str = ""
    country: str = ""
    timezone: str = ""
    notes: str = ""


class CustomerOut(BaseModel):
    id: str
    name: str
    organization_id: str
    location: str = ""
    business_unit: str = ""
    contact_email: str = ""
    primary_contact: str = ""
    phone: str = ""
    country: str = ""
    timezone: str = ""
    notes: str = ""
    device_count: int = 0

    class Config:
        from_attributes = True


# ---- devices -------------------------------------------------------------
class DeviceOut(BaseModel):
    id: str
    serial: str
    model: str
    firmware: str
    friendly_name: str
    latest_score: float
    latest_grade: str
    customer_id: str
    connection_method: str = "manual"
    analyze_mode: str = "manual"
    configured: bool = False
    last_connection_status: str = ""
    last_connection_at: Optional[datetime] = None
    last_connection_error: str = ""
    last_analysis_at: Optional[datetime] = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    created_at: Optional[datetime] = None
    hidden_severities: list[str] = []
    # License bundle info (populated from license_purchase relationship)
    license_bundle: str = ""
    license_expiry: Optional[datetime] = None
    license_days_remaining: Optional[int] = None
    # Decommissioning
    decommissioned: bool = False
    decommissioned_at: Optional[datetime] = None
    was_ever_configured: bool = False

    class Config:
        from_attributes = True


class DeviceRegisterRequest(BaseModel):
    customer_id: str
    friendly_name: str = Field(min_length=1, description="Device name")
    serial: str = Field(min_length=1, description="Device serial number")
    license_purchase_id: Optional[str] = Field(default=None, description="Specific license purchase to consume from")


class DeviceLicenseChange(BaseModel):
    """Reassign a device to a different license purchase."""
    license_purchase_id: str = Field(min_length=1, description="Target license purchase ID")


class DeviceConnectRequest(BaseModel):
    # Provide device_id to connect a pre-registered device, or customer_id to
    # register-and-connect a new firewall in one step. Exactly one is required.
    device_id: Optional[str] = Field(default=None, description="Pre-registered device ID")
    customer_id: Optional[str] = Field(default=None, description="Customer for a new API device")
    friendly_name: Optional[str] = Field(default=None, description="Name for a new API device")
    hostname: str
    port: int = Field(default=443, ge=1, le=65535)
    username: str
    password: str
    verify_tls: bool = Field(default=False, description="Verify the firewall TLS certificate")
    save_password: bool = Field(default=True, description="Store the password encrypted for future API pulls")


# ---- api connection logs --------------------------------------------------
class ApiConnectionLogOut(BaseModel):
    id: str
    timestamp: datetime
    trigger: str
    host: str
    port: int
    endpoint: str
    http_status: Optional[int] = None
    response_time_ms: Optional[int] = None
    success: bool
    error_message: str = ""
    connected_serial: str = ""
    registered_serial: str = ""
    result_summary: str = ""

    class Config:
        from_attributes = True


class ConnectStep(BaseModel):
    step: str
    status: str            # ok | failed | warn | skipped
    detail: str = ""


class DeviceConnectResponse(BaseModel):
    device_id: Optional[str] = None
    connection_status: str          # ok | failed
    message: str = ""
    version: dict[str, Any] = {}
    analysis_id: Optional[str] = None
    error_kind: Optional[str] = None   # see app.sonicos KIND_* on failure
    http_status: Optional[int] = None
    steps: list[ConnectStep] = []


# --- Device credentials ---------------------------------------------------
class DeviceCredentialOut(BaseModel):
    """Saved API credentials for a device. Password is never returned."""
    id: str
    device_id: str
    hostname: str
    port: int = 443
    username: str
    has_password: bool = False          # True if a password is stored
    last_test_status: str = ""          # ok | failed | ""
    last_test_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DeviceCredentialUpdate(BaseModel):
    """Update API credentials for a device. All fields optional;
    if password is omitted or empty, the existing password is kept.
    """
    hostname: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None


class CredentialTestResult(BaseModel):
    success: bool
    message: str = ""
    steps: list[ConnectStep] = []


# --- Configurable API flow (superadmin) ----------------------------------
class ApiFlowConfigOut(BaseModel):
    id: str
    name: str
    description: str = ""
    version_label: str = ""
    is_active: bool = False
    auth_type: str = "basic"
    verify_tls: bool = False
    timeout_seconds: int = 30
    api_base: str = "/api/sonicos"
    steps: list[dict[str, Any]] = []

    class Config:
        from_attributes = True


class ApiFlowConfigCreate(BaseModel):
    name: str = Field(min_length=1)
    description: str = ""
    version_label: str = ""
    auth_type: str = "basic"
    verify_tls: bool = False
    timeout_seconds: int = Field(default=30, ge=1, le=600)
    api_base: str = "/api/sonicos"
    steps: list[dict[str, Any]] = Field(default_factory=list)


class ApiFlowConfigUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    version_label: Optional[str] = None
    auth_type: Optional[str] = None
    verify_tls: Optional[bool] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=600)
    api_base: Optional[str] = None
    steps: Optional[list[dict[str, Any]]] = None


class ApiFlowTestRequest(BaseModel):
    config_id: Optional[str] = None                 # use a saved config…
    config: Optional[ApiFlowConfigCreate] = None    # …or an inline (unsaved) one
    hostname: str
    port: int = Field(default=443, ge=1, le=65535)
    username: str
    password: str
    verify_tls: Optional[bool] = None


class ApiFlowStepTrace(BaseModel):
    step: str
    method: str = ""
    url: str = ""
    request_headers: dict[str, Any] = {}
    status_code: Optional[int] = None
    response_excerpt: str = ""
    elapsed_ms: int = 0
    success: bool = False
    error: str = ""


class ApiFlowTestResult(BaseModel):
    success: bool
    error: str = ""
    tsr_bytes: int = 0
    traces: list[ApiFlowStepTrace] = []
    extracted: dict[str, Any] = {}


class TsrHistoryItem(BaseModel):
    """A single TSR upload with its analysis result (if available)."""
    id: str
    filename: str
    size_bytes: int
    uploaded_at: datetime
    uploaded_by: str = ""        # user UUID, "api-pull", "api-connect", or "api-scheduled"
    favorite: bool = False
    analysis_id: Optional[str] = None
    analysis_status: Optional[str] = None
    analysis_score: Optional[float] = None
    analysis_grade: Optional[str] = None

    class Config:
        from_attributes = True


class DeviceDetailOut(DeviceOut):
    """Device details with TSR upload history."""
    tsr_count: int = 0
    tsrs: list[TsrHistoryItem] = []


# ---- analyses ------------------------------------------------------------
class AnalysisSummary(BaseModel):
    id: str
    device_id: str
    tsr_id: str
    status: AnalysisStatus
    score: float
    grade: str
    finding_count: int
    critical_count: int
    high_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class AnalysisDetail(AnalysisSummary):
    result_json: dict[str, Any]


# ---- drift ---------------------------------------------------------------
class DriftEventOut(BaseModel):
    id: str
    device_id: str
    alert_count: int
    severity_counts: dict[str, int]
    alerts: list[dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True


# ---- alerts --------------------------------------------------------------
class AlertSubscriptionCreate(BaseModel):
    channel: AlertChannel = AlertChannel.email
    target: str
    on_new_critical: bool = True
    on_service_disabled: bool = True
    on_firmware_vuln: bool = True
    on_critical_drift: bool = True


class AlertSubscriptionOut(AlertSubscriptionCreate):
    id: str
    organization_id: str

    class Config:
        from_attributes = True


# ---- findings ------------------------------------------------------------
class FindingCommentOut(BaseModel):
    id: str
    author_email: str
    comment_type: CommentType
    body: str
    from_status: str
    to_status: str
    created_at: datetime

    class Config:
        from_attributes = True


class FindingCommentCreate(BaseModel):
    body: str = Field(min_length=1)


class FindingSummary(BaseModel):
    id: str
    device_id: str
    analysis_id: Optional[str] = None
    rule_id: str
    severity: str
    title: str
    category: str
    status: FindingStatus
    exploitability: str
    object_name: str
    object_type: str
    assignee_id: Optional[str] = None
    due_date: Optional[datetime] = None
    ticket_ref: str
    first_seen_at: datetime
    last_seen_at: datetime
    source: str = "parser"

    class Config:
        from_attributes = True


class FindingDetail(FindingSummary):
    description: str
    evidence: list[str]
    business_impact: str
    technical_impact: str
    remediation: str
    verification: list[str]
    compliance: dict[str, list[str]]
    object_detail: str
    justification: str
    accepted_risk_expiry: Optional[datetime] = None
    signed_off_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    ticket_system: str = ""
    ticket_url: str = ""
    ticket_status: str = ""
    comments: list[FindingCommentOut] = []


class FindingTransition(BaseModel):
    to_status: FindingStatus
    comment: str = Field(min_length=1)            # every transition needs a note
    justification: Optional[str] = None           # required for FP / accepted-risk
    accepted_risk_expiry: Optional[datetime] = None   # required for accepted-risk
    ticket_ref: Optional[str] = None


class ManualFindingUpdate(BaseModel):
    """Fields for updating a manual finding (all optional — only set what changes)."""
    severity: Optional[str] = Field(default=None, pattern="^(Critical|High|Medium|Low|Info)$")
    title: Optional[str] = Field(default=None, min_length=1, max_length=512)
    category: Optional[str] = Field(default=None, min_length=1, max_length=128)
    object_name: Optional[str] = Field(default=None, max_length=255)
    status: Optional[str] = Field(default=None, pattern="^(open|acknowledged|in_progress|fixed|false_positive|accepted_risk)$")
    description: Optional[str] = Field(default=None, max_length=4096)
    business_impact: Optional[str] = Field(default=None, max_length=2048)
    technical_impact: Optional[str] = Field(default=None, max_length=2048)
    remediation: Optional[str] = Field(default=None, max_length=4096)
    evidence: Optional[str] = Field(default=None, max_length=4096)


class ManualFindingCreate(BaseModel):
    """Fields for creating a manual finding on a device."""
    severity: str = Field(pattern="^(Critical|High|Medium|Low|Info)$")
    title: str = Field(min_length=1, max_length=512)
    category: str = Field(min_length=1, max_length=128)
    object_name: str = Field(default="", max_length=255)
    status: str = Field(pattern="^(open|acknowledged|in_progress|fixed|false_positive|accepted_risk)$")
    description: str = Field(default="", max_length=4096)
    business_impact: str = Field(default="", max_length=2048)
    technical_impact: str = Field(default="", max_length=2048)
    remediation: str = Field(default="", max_length=4096)
    evidence: str = Field(default="", max_length=4096)


class FindingAssign(BaseModel):
    assignee_id: Optional[str] = None
    due_date: Optional[datetime] = None
    comment: Optional[str] = None


class BulkTransition(BaseModel):
    finding_ids: list[str] = Field(min_length=1)
    to_status: FindingStatus
    comment: str = Field(min_length=1)
    justification: Optional[str] = None
    accepted_risk_expiry: Optional[datetime] = None


# ---- schedules -----------------------------------------------------------
class ScheduleIn(BaseModel):
    frequency: ScheduleFrequency = ScheduleFrequency.manual
    hour: int = Field(default=3, ge=0, le=23)
    minute: int = Field(default=0, ge=0, le=59)
    timezone: str = "UTC"
    day_of_week: Optional[int] = Field(default=None, ge=0, le=6)
    day_of_month: Optional[int] = Field(default=None, ge=1, le=31)
    enabled: bool = True
    blackout_windows: list[dict[str, Any]] = []


class ScheduleOut(ScheduleIn):
    id: str
    device_id: str
    organization_id: str
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---- audit log -----------------------------------------------------------
class AuditLogOut(BaseModel):
    id: str
    user_email: str
    action: str
    resource_type: str
    resource_id: str
    before: dict[str, Any]
    after: dict[str, Any]
    ip_address: str
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogPage(BaseModel):
    total: int
    items: list[AuditLogOut]


# ---- rules ---------------------------------------------------------------
class RuleVersionOut(BaseModel):
    version: int
    title: str
    severity: str
    condition: str
    remediation: str
    change_note: str
    edited_at: datetime

    class Config:
        from_attributes = True


class RuleOut(BaseModel):
    id: str
    organization_id: Optional[str] = None
    key: str
    title: str
    category: str
    severity: str
    description: str
    condition: str
    remediation: str
    compliance: dict[str, list[str]]
    references: list[str]
    source: RuleSource
    state: RuleState
    enabled: bool
    current_version: int
    api_support: str = "full"   # "full" | "none" — API-TSR evaluation support
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RuleDetail(RuleOut):
    versions: list[RuleVersionOut] = []


class RuleCreate(BaseModel):
    title: str = Field(min_length=1)
    category: str = "Custom"
    severity: str = "Medium"
    description: str = ""
    condition: str = Field(min_length=1)   # CEL expression
    remediation: str = ""
    compliance: dict[str, list[str]] = {}
    references: list[str] = []
    source: RuleSource = RuleSource.custom   # superadmins may set "system"
    key: str = ""                             # required when source=system


class RuleUpdate(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    condition: Optional[str] = None
    remediation: Optional[str] = None
    compliance: Optional[dict[str, list[str]]] = None
    references: Optional[list[str]] = None
    change_note: str = ""


class RuleStateChange(BaseModel):
    note: str = ""


class RuleTestRequest(BaseModel):
    analysis_id: Optional[str] = None       # source snapshot from a prior analysis
    snapshot: Optional[dict[str, Any]] = None
    condition: Optional[str] = None          # override (test an unsaved edit)


class RuleTestResponse(BaseModel):
    fired: Optional[bool] = None
    error: str = ""


# ---- CEL rule builder ----------------------------------------------------
class BuilderSnapshotRef(BaseModel):
    """Lightweight reference to a completed analysis for the CEL builder."""
    analysis_id: str
    device_model: str = ""
    device_serial: str = ""
    device_firmware: str = ""
    generated_at: Optional[datetime] = None


class BuilderTestRequest(BaseModel):
    """Test a hand-written CEL condition against a reference snapshot."""
    analysis_id: str = ""                         # optional: use stored analysis
    snapshot: Optional[dict[str, Any]] = None      # optional: pass snapshot directly
    condition: str = Field(min_length=1)


# ---- rule suppressions / overrides ---------------------------------------
class SuppressionCreate(BaseModel):
    rule_key: str
    device_id: Optional[str] = None
    action: SuppressionAction
    value: str = ""                          # required severity when overriding
    reason: str = ""
    expires_at: Optional[datetime] = None


class SuppressionOut(BaseModel):
    id: str
    rule_key: str
    device_id: Optional[str] = None
    action: SuppressionAction
    value: str
    reason: str
    expires_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ---- integrations --------------------------------------------------------
class IntegrationIn(BaseModel):
    type: IntegrationType = IntegrationType.slack
    name: str = ""
    enabled: bool = True
    webhook_url: str = ""                    # secret; stored encrypted
    config: dict[str, Any] = {}              # event toggles, etc.


class IntegrationOut(BaseModel):
    id: str
    type: IntegrationType
    name: str
    enabled: bool
    config: dict[str, Any]
    has_secret: bool = False
    last_status: str = ""
    last_delivery_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ---- API tokens ----------------------------------------------------------
class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1)
    scopes: list[str] = []
    expires_at: Optional[datetime] = None


class ApiTokenOut(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: list[str]
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ApiTokenCreated(ApiTokenOut):
    token: str                               # shown once at creation


# ---- SSO -----------------------------------------------------------------
class SSOConfigIn(BaseModel):
    enabled: bool = False
    protocol: SSOProtocol = SSOProtocol.oidc
    oidc_discovery_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""          # write-only; stored encrypted
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""
    saml_idp_x509_cert: str = ""
    groups_attribute: str = "groups"
    group_role_map: dict[str, str] = {}
    default_role: str = "viewer"


class SSOConfigOut(BaseModel):
    enabled: bool
    protocol: SSOProtocol
    oidc_discovery_url: str
    oidc_client_id: str
    has_client_secret: bool = False
    saml_idp_entity_id: str
    saml_idp_sso_url: str
    saml_idp_x509_cert: str
    groups_attribute: str
    group_role_map: dict[str, str]
    default_role: str


class SSOStatus(BaseModel):
    enabled: bool
    protocol: Optional[SSOProtocol] = None


# ---- organization / billing ----------------------------------------------
class OrganizationDetail(BaseModel):
    id: str
    name: str
    is_msp: bool
    plan: PlanTier
    subscription_status: str
    trial_ends_at: Optional[datetime] = None
    has_stripe_customer: bool = False
    region: str = "us"
    data_retention_days: Optional[int] = None
    brand_company_name: str = ""
    brand_logo_url: str = ""
    brand_primary_color: str = ""
    brand_contact: str = ""
    hidden_severities: list[str] = []

    class Config:
        from_attributes = True


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    region: Optional[str] = None
    data_retention_days: Optional[int] = None
    brand_company_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    brand_primary_color: Optional[str] = None
    brand_contact: Optional[str] = None


class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    business_unit: Optional[str] = None
    contact_email: Optional[str] = None
    notes: Optional[str] = None


class CheckoutRequest(BaseModel):
    plan: PlanTier


class CheckoutResponse(BaseModel):
    url: Optional[str] = None
    mode: str               # "stripe" | "local"
    message: str = ""


# ---- PSIRT ---------------------------------------------------------------
class PsirtRefreshOut(BaseModel):
    id: str
    ran_at: datetime
    source: str
    content_hash: str
    changed: bool
    advisory_count: int
    added: list[str]
    updated: list[str]
    affected_devices: int
    note: str

    class Config:
        from_attributes = True


# ---- drift comparison ----------------------------------------------------
class DriftCompareResponse(BaseModel):
    previous_analysis_id: str
    current_analysis_id: str
    new_findings: list[dict[str, Any]]
    resolved_findings: list[dict[str, Any]]
    config_changes: list[dict[str, Any]]
    severity_counts: dict[str, int]


# ---- dashboard -----------------------------------------------------------
class DashboardResponse(BaseModel):
    fleet_posture: dict[str, Any]
    findings_funnel: dict[str, Any]
    devices_needing_attention: list[dict[str, Any]]
    recent_activity: list[dict[str, Any]]
    compliance: dict[str, float]


# ---- fleet (MSP) ---------------------------------------------------------
class FleetDeviceRow(BaseModel):
    device_id: str
    customer_id: str = ""
    customer_name: str
    serial: str
    model: str
    firmware: str
    score: float
    grade: str
    critical_count: int
    high_count: int


class FleetSummary(BaseModel):
    device_count: int
    average_score: float
    grade_distribution: dict[str, int]
    devices_with_critical: int
    vulnerable_firmware_devices: int
    rows: list[FleetDeviceRow]


# ---- dynamic plans --------------------------------------------------------
class PlanFeature(BaseModel):
    key: str
    label: str
    enabled: bool


class PlanLimit(BaseModel):
    key: str
    label: str
    value: int


class PlanOut(BaseModel):
    id: str
    name: str
    description: str
    plan_type: str = "professional"
    is_active: bool
    is_visible: bool
    sort_order: int
    features: dict[str, bool]
    price_per_device: float = 0.0
    pricing_tiers: Optional[dict] = None
    yearly_discount_pct: int = 20
    is_testing: bool = False
    validity_minutes: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlanCreate(BaseModel):
    name: str = Field(min_length=1)
    description: str = ""
    plan_type: str = "professional"
    features: dict[str, bool] = {}
    price_per_device: float = 0.0
    pricing_tiers: dict = {}
    yearly_discount_pct: int = 20
    is_testing: bool = False
    validity_minutes: int = 0


class PlanUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    plan_type: Optional[str] = None
    is_active: Optional[bool] = None
    is_visible: Optional[bool] = None
    sort_order: Optional[int] = None
    features: Optional[dict[str, bool]] = None
    price_per_device: Optional[float] = None
    pricing_tiers: Optional[dict] = None
    yearly_discount_pct: Optional[int] = None
    is_testing: Optional[bool] = None
    validity_minutes: Optional[int] = None


class PlanAssignment(BaseModel):
    org_id: str


class CustomerPlanInfo(BaseModel):
    plan_name: str
    plan_type: str = "professional"
    features: dict[str, bool]
    price_per_device: float = 0.0
    pricing_tiers: Optional[dict] = None
    yearly_discount_pct: int = 20
    device_count: int = 0
    monthly_cost: float = 0.0
    yearly_total: float = 0.0
    usage: dict[str, int]
    license_allocations: dict = {}
    purchase_history: list = []
    subscription_term: str = "monthly"