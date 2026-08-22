// Types mirroring the FastAPI response models in app/schemas.py.

export interface Token {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  phone: string;
  address: string;
  role: string;
  organization_id: string;
  is_superadmin: boolean;
  mfa_enabled: boolean;
  notify_new_critical: boolean;
  notify_scan_failed: boolean;
  last_login_at: string | null;
}

export interface LoginResult {
  mfa_required: boolean;
  mfa_token: string | null;
  access_token: string | null;
  refresh_token: string | null;
  token_type: string;
}

// ---- finding workflow ----------------------------------------------------
export type FindingStatus =
  | "open"
  | "acknowledged"
  | "in_progress"
  | "fixed"
  | "false_positive"
  | "accepted_risk"
  | "suppressed";

export interface FindingRow {
  id: string;
  device_id: string;
  analysis_id: string;
  rule_id: string;
  severity: string;
  title: string;
  category: string;
  status: FindingStatus;
  exploitability: string;
  object_name: string;
  object_type: string;
  assignee_id: string | null;
  due_date: string | null;
  ticket_ref: string;
  first_seen_at: string;
  last_seen_at: string;
  source?: string;
}

export interface FindingComment {
  id: string;
  author_email: string;
  comment_type: string;
  body: string;
  from_status: string;
  to_status: string;
  created_at: string;
}

export interface FindingDetail extends FindingRow {
  description: string;
  evidence: string[];
  business_impact: string;
  technical_impact: string;
  remediation: string;
  verification: string[];
  compliance: Record<string, string[]>;
  object_detail: string;
  justification: string;
  accepted_risk_expiry: string | null;
  signed_off_by: string | null;
  resolved_at: string | null;
  ticket_system: string;
  ticket_url: string;
  ticket_status: string;
  comments: FindingComment[];
}

// ---- dashboard -----------------------------------------------------------
export interface DashboardData {
  fleet_posture: {
    device_count: number;
    scored_device_count: number;
    average_score: number;
    grade_distribution: Record<string, number>;
    trend_90d: { date: string; score: number }[];
  };
  findings_funnel: {
    critical_open: number;
    high_open: number;
    critical_delta_24h: number;
    high_delta_24h: number;
    total_open: number;
  };
  devices_needing_attention: {
    device_id: string;
    serial: string;
    model: string;
    friendly_name: string;
    grade: string;
    score: number;
    reasons: string[];
  }[];
  recent_activity: {
    action: string;
    resource_type: string;
    resource_id: string;
    user_email: string;
    created_at: string | null;
  }[];
  compliance: Record<string, number>;
}

export interface MfaEnroll {
  secret: string;
  otpauth_uri: string;
}

export interface FleetRow {
  device_id: string;
  customer_id: string;
  customer_name: string;
  serial: string;
  model: string;
  firmware: string;
  score: number;
  grade: string;
  critical_count: number;
  high_count: number;
}

export interface FleetSummary {
  device_count: number;
  average_score: number;
  grade_distribution: Record<string, number>;
  devices_with_critical: number;
  vulnerable_firmware_devices: number;
  rows: FleetRow[];
}

// ---- Phase 2: rules ------------------------------------------------------
export type RuleSource = "system" | "custom";
export type RuleState = "draft" | "submitted" | "approved";

export interface RuleVersion {
  version: number;
  title: string;
  severity: string;
  condition: string;
  remediation: string;
  change_note: string;
  edited_at: string;
}

export interface Rule {
  id: string;
  organization_id: string | null;
  key: string;
  title: string;
  category: string;
  severity: string;
  description: string;
  condition: string;
  remediation: string;
  compliance: Record<string, string[]>;
  references: string[];
  source: RuleSource;
  state: RuleState;
  enabled: boolean;
  /** "full" → evaluable on API-collected TSRs; "none" → GUI-TSR only (table data lost in API format). */
  api_support?: "full" | "none";
  current_version: number;
  created_at: string;
  updated_at: string;
  versions?: RuleVersion[];
}

export interface RuleTestResult {
  fired: boolean | null;
  error: string;
}

export interface BuilderSnapshotRef {
  analysis_id: string;
  device_model: string;
  device_serial: string;
  device_firmware: string;
  generated_at: string | null;
}

// ---- Product & Platform Config -------------------------------------------
export interface DeviceGeneration {
  id: string;
  name: string;
  sort_order: number;
  devices: { id: string; model: string }[];
  firmware_version: string;
}

export interface Suppression {
  id: string;
  rule_key: string;
  device_id: string | null;
  action: "disable" | "override_severity";
  value: string;
  reason: string;
  expires_at: string | null;
  created_at: string;
}

// ---- Phase 2: compliance -------------------------------------------------
export interface ComplianceMatrix {
  framework: string;
  devices: { device_id: string; serial: string; model: string; grade: string }[];
  controls: string[];
  cells: Record<string, { status: "pass" | "fail"; finding_ids: string[] }>;
}

// ---- Phase 2: integrations & tokens --------------------------------------
export interface Integration {
  id: string;
  type: string;
  name: string;
  enabled: boolean;
  config: Record<string, unknown>;
  has_secret: boolean;
  last_status: string;
  last_delivery_at: string | null;
  created_at: string;
}

export interface ApiToken {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  last_used_at: string | null;
  expires_at: string | null;
  revoked: boolean;
  created_at: string;
}

export interface ApiTokenCreated extends ApiToken {
  token: string;
}

// ---- Phase 2: drift comparison -------------------------------------------
export interface DriftCompare {
  previous_analysis_id: string;
  current_analysis_id: string;
  new_findings: Record<string, unknown>[];
  resolved_findings: Record<string, unknown>[];
  config_changes: Record<string, unknown>[];
  severity_counts: Record<string, number>;
}

export interface ConnectStep {
  step: string;
  status: "ok" | "failed" | "warn" | "skipped";
  detail: string;
}

// ---- Configurable API flow (superadmin) ----------------------------------
export interface ApiFlowStep {
  name: string;
  method: string;
  path: string;
  auth?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: string;
  success?: { status_codes?: number[]; json_not_false?: string; body_contains?: string };
  extract?: Record<string, { source: string; path?: string; pattern?: string; name?: string }>;
  is_tsr?: boolean;
  continue_on_error?: boolean;
}

export interface ApiFlowConfig {
  id: string;
  name: string;
  description: string;
  version_label: string;
  is_active: boolean;
  auth_type: string;
  verify_tls: boolean;
  timeout_seconds: number;
  api_base: string;
  steps: ApiFlowStep[];
}

export interface ApiFlowStepTrace {
  step: string;
  method: string;
  url: string;
  request_headers: Record<string, unknown>;
  status_code: number | null;
  response_excerpt: string;
  elapsed_ms: number;
  success: boolean;
  error: string;
}

export interface ApiFlowTestResult {
  success: boolean;
  error: string;
  tsr_bytes: number;
  traces: ApiFlowStepTrace[];
  extracted: Record<string, unknown>;
}

export interface DeviceConnectResult {
  device_id: string | null;
  connection_status: string;
  message: string;
  version: Record<string, unknown>;
  analysis_id: string | null;
  error_kind?: string | null;
  http_status?: number | null;
  steps?: ConnectStep[];
}

// ---- Phase 3: org / billing / SSO / customers / PSIRT --------------------
export interface OrganizationDetail {
  id: string;
  name: string;
  is_msp: boolean;
  plan: string;
  subscription_status: string;
  trial_ends_at: string | null;
  has_stripe_customer: boolean;
  region: string;
  data_retention_days: number | null;
  brand_company_name: string;
  brand_logo_url: string;
  brand_primary_color: string;
  brand_contact: string;
  hidden_severities: string[];
}

// ---- platform (superadmin) ----------------------------------------------
export interface PlatformOrgRow {
  id: string;
  name: string;
  type: string;
  plan: string;
  region: string;
  subscription_status: string;
  customers: number;
  firewalls: number;
  users: number;
  avg_score: number;
  open_critical: number;
  created_at: string | null;
}

export interface PlatformOverview {
  stats: {
    organizations: number;
    msp_count: number;
    direct_count: number;
    total_customers: number;
    total_firewalls: number;
    total_users: number;
    plan_distribution: Record<string, number>;
    region_distribution: Record<string, number>;
  };
  organizations: PlatformOrgRow[];
}

export interface TsrTestResult {
  filename: string;
  detected_format: "gui" | "api";
  requested_format: string;
  device: Record<string, unknown>;
  score: number;
  grade: string;
  severity_counts: Record<string, number>;
  finding_count: number;
  suppressed_rule_count: number;
  findings: {
    rule_id: string;
    severity: string;
    title: string;
    category: string;
    object_name: string;
  }[];
}

export interface Trends {
  score_progression: { device_id: string; serial: string; points: { month: string; score: number }[] }[];
  mttr_by_severity: Record<string, number>;
  recurrence: { total_findings: number; recurring_findings: number; rate: number };
  top_rules: { rule_id: string; title: string; count: number }[];
  category_evolution: { month: string; categories: Record<string, number> }[];
}

export interface ScoreTrendPoint {
  date: string;
  avg_score: number;
  device_count: number;
}

export interface SeverityBucket {
  count: number;
  pct: number;
}

export interface GradeBucket {
  count: number;
  pct: number;
}

export interface FirmwareBucket {
  firmware: string;
  count: number;
  pct: number;
}

export interface TopFinding {
  rule_id: string;
  title: string;
  count: number;
  severity?: string;
  devices?: number;
}

export interface DeviceHealth {
  configured: number;
  not_configured: number;
  expired_license: number;
}

export interface AnalysisActivity {
  automatic_scans: number;
  manual_pulls: number;
  manual_uploads: number;
  failed_pulls: number;
}

export interface ApiConnectionStatus {
  api_connected: number;
  api_failed: number;
  manual_devices: number;
}

export interface RecentlyChangedDevice {
  device_id: string;
  device_name: string;
  trend: "Improved" | "Dropped" | "No Change";
  old_score: number;
  new_score: number;
  changed_at: string;
}

export interface CustomerOverviewItem {
  customer_id: string;
  customer_name: string;
  device_count: number;
  avg_score: number;
  critical_count: number;
}

export interface OperationalSummary {
  device_health: DeviceHealth;
  analysis_activity: AnalysisActivity;
  api_status: ApiConnectionStatus;
  recently_changed: RecentlyChangedDevice[];
  customer_overview: CustomerOverviewItem[];
  is_msp: boolean;
}

export interface DashboardCharts {
  score_trend: ScoreTrendPoint[];
  severity_distribution: Record<string, SeverityBucket>;
  total_findings: number;
  grade_distribution: Record<string, GradeBucket>;
  total_graded_devices: number;
  firmware_distribution: FirmwareBucket[];
  total_firmware_devices: number;
  top_findings: TopFinding[];
  status_distribution: Record<string, SeverityBucket>;
  total_unique_findings: number;
  all_firmware_list: FirmwareBucket[];
  all_findings_list: TopFinding[];
}

export interface Row4Summary {
  firmware_health: { latest: number; behind: number; total: number };
  device_health: { healthy: number; warning: number; critical: number; total: number };
  recent_findings: {
    id: string; severity: string; title: string; device_name: string; first_seen_at: string | null;
  }[];
  recent_fixed: {
    id: string; severity: string; title: string; device_name: string; resolved_at: string | null;
  }[];
  recent_analyses: {
    id: string; device_name: string; model: string; score: number;
    score_delta: number | null; created_at: string | null;
  }[];
}

export interface RiskTrendPoint {
  date: string;
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
}

export interface RiskTrend {
  trend: RiskTrendPoint[];
  deltas: Record<string, number>;
}

export interface TrendPoint {
  date: string;
  value: number;
}

export interface DeviceStatusBreakdown {
  configured: number;
  not_configured: number;
  active: number;
  expired: number;
}

export interface ExecutiveSummary {
  overall_score: number;
  overall_grade: string;
  score_delta: number;
  score_trend: TrendPoint[];
  critical_count: number;
  critical_delta: number;
  critical_trend: TrendPoint[];
  high_count: number;
  high_delta: number;
  high_trend: TrendPoint[];
  total_devices: number;
  configured_devices: number;
  device_trend: TrendPoint[];
  protected_count: number;
  protected_percentage: number;
  protection_trend: TrendPoint[];
  active_devices: number;
  expired_devices: number;
}

export interface FirmwareComplianceGen {
  generation: string;
  recommended_firmware: string;
  latest_count: number;
  older_count: number;
  total: number;
}

export interface FirmwareCompliance {
  generations: FirmwareComplianceGen[];
}

export interface SSOConfig {
  enabled: boolean;
  protocol: "oidc" | "saml";
  oidc_discovery_url: string;
  oidc_client_id: string;
  has_client_secret: boolean;
  saml_idp_entity_id: string;
  saml_idp_sso_url: string;
  saml_idp_x509_cert: string;
  groups_attribute: string;
  group_role_map: Record<string, string>;
  default_role: string;
}

export interface CustomerDetail extends Customer {
  location: string;
  business_unit: string;
  contact_email: string;
  primary_contact: string;
  phone: string;
  country: string;
  timezone: string;
  notes: string;
  device_count: number;
}

export interface PsirtRefresh {
  id: string;
  ran_at: string;
  source: string;
  content_hash: string;
  changed: boolean;
  advisory_count: number;
  added: string[];
  updated: string[];
  affected_devices: number;
  note: string;
}

export interface AuditEntry {
  id: string;
  user_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  ip_address: string;
  created_at: string;
}

export interface Customer {
  id: string;
  name: string;
  organization_id: string;
}

export interface Device {
  id: string;
  serial: string;
  model: string;
  firmware: string;
  friendly_name: string;
  latest_score: number;
  latest_grade: string;
  customer_id: string;
  connection_method: string;
  analyze_mode: string;
  configured: boolean;
  last_connection_status: string;
  last_connection_at: string | null;
  last_connection_error: string;
  last_analysis_at: string | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string | null;
  hidden_severities: string[];
  license_bundle: string;
  license_expiry: string | null;
  license_days_remaining: number | null;
  decommissioned: boolean;
  decommissioned_at: string | null;
  was_ever_configured: boolean;
}

export interface DeviceRegisterRequest {
  customer_id: string;
  friendly_name: string;
  serial: string;
  license_purchase_id?: string;
}

export interface LicenseBundle {
  purchase_id?: string;
  tier?: string | null;
  label: string;
  remaining: number;
  start_date?: string | null;
  expiry_date?: string | null;
}

export interface FreeLicenseInfo {
  start_date: string | null;
  expiry_date: string | null;
  remaining: number;
  total: number;
  used: number;
  expired: boolean;
}

export interface LicenseBundlesResponse {
  bundles: LicenseBundle[];
  free: boolean;
  free_license?: FreeLicenseInfo;
}

export interface TsrHistoryItem {
  id: string;
  filename: string;
  size_bytes: number;
  uploaded_at: string;
  uploaded_by: string;
  favorite: boolean;
  analysis_id: string | null;
  analysis_status: string | null;
  analysis_score: number | null;
  analysis_grade: string | null;
}

export interface DeviceDetail extends Device {
  tsr_count: number;
  tsrs: TsrHistoryItem[];
}

export interface ApiConnectionLog {
  id: string;
  timestamp: string;
  trigger: string;
  host: string;
  port: number;
  endpoint: string;
  http_status: number | null;
  response_time_ms: number | null;
  success: boolean;
  error_message: string;
  connected_serial: string;
  registered_serial: string;
  result_summary: string;
}

export interface DeviceCredential {
  id: string;
  device_id: string;
  hostname: string;
  port: number;
  username: string;
  has_password: boolean;
  last_test_status: string;
  last_test_at: string | null;
}

export interface CredentialTestResult {
  success: boolean;
  message: string;
  steps: ConnectStep[];
}

export interface DeviceSchedule {
  id: string;
  device_id: string;
  frequency: string;       // hourly | daily | weekly | monthly
  hour: number;
  minute: number;
  timezone: string;
  day_of_week: number | null;
  day_of_month: number | null;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
}

export interface AnalysisSummary {
  id: string;
  device_id: string;
  tsr_id: string;
  status: "queued" | "running" | "complete" | "failed";
  score: number;
  grade: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  created_at: string;
}

export interface Finding {
  rule_id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  category: string;
  description: string;
  evidence: string[];
  business_impact: string;
  technical_impact: string;
  remediation: string;
  verification: string[];
  risk_reduction: string;
  references: string[];
  compliance: Record<string, string[]> | string[];
  exploitability: string;
  affected_count: number;
  object_name: string;
  object_type: string;
  object_detail: string;
}

export interface AttackPath {
  path_id: string;
  name: string;
  severity: string;
  narrative: string;
  stages: { stage: string; detail: string }[];
  contributing_rules: string[];
  recommended_priority: string;
}

export interface Advisory {
  advisory_id: string;
  title: string;
  cve: string[];
  cvss: number;
  severity: string;
  fixed_in: string;
  summary: string;
  url: string;
  upgrade_recommendation?: string;
}

export interface FirmwareIntel {
  firmware: string;
  generation: string;
  advisory_count: number;
  max_cvss: number;
  all_cves: string[];
  recommended_firmware: string;
  matched_advisories: Advisory[];
  eol: { series: string; status: string; note?: string };
  disclaimer: string;
}

export interface ScoreBlock {
  score: number;
  grade: string;
  grade_label: string;
  severity_counts: Record<string, number>;
  category_counts: Record<string, number>;
  total_findings: number;
}

export interface Analysis {
  generated_at: string;
  source_name: string;
  device: {
    model: string;
    firmware: string;
    serial: string;
    ha_mode: string;
    uptime: string;
  };
  score: ScoreBlock;
  exploitability: Record<string, number>;
  findings: Finding[];
  finding_count: number;
  firmware_intelligence: FirmwareIntel;
  attack_paths: AttackPath[];
}

// ---- dynamic plans --------------------------------------------------------
export interface PlanData {
  id: string;
  name: string;
  description: string;
  plan_type: string;
  is_active: boolean;
  is_visible: boolean;
  sort_order: number;
  features: Record<string, boolean>;
  price_per_device: number;
  pricing_tiers: Record<string, any>;
  yearly_discount_pct: number;
  is_testing: boolean;
  validity_minutes: number;
  created_at: string | null;
  updated_at: string | null;
}

export interface CustomerPlanInfo {
  plan_name: string;
  plan_type: string;
  features: Record<string, boolean>;
  price_per_device: number;
  pricing_tiers: Record<string, any>;
  yearly_discount_pct: number;
  device_count: number;
  monthly_cost: number;
  yearly_total: number;
  usage: Record<string, number>;
  license_allocations: Record<string, any>;
  purchase_history: LicensePurchase[];
  subscription_term: string;
}

export interface LicensePurchase {
  id: string;
  subscription_term: string;
  tier: string | null;
  tier_device_count: number;
  count: number;
  total_devices: number;
  purchased_at: string | null;
  expires_at: string | null;
}
