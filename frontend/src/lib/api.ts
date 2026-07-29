// API client for the FirewallGuard AI backend.
//
// Tokens are kept in memory and mirrored to sessionStorage so a page refresh
// during a working session keeps the user signed in. All calls attach the
// bearer token and transparently attempt a refresh on a 401.

import type {
  Analysis,
  AnalysisSummary,
  PlanData,
  CustomerPlanInfo,
  DeviceGeneration,
  ApiToken,
  ApiTokenCreated,
  AuditEntry,
  ComplianceMatrix,
  Customer,
  CustomerDetail,
  DashboardData,
  Device,
  DeviceConnectResult,
  DeviceDetail,
  DeviceRegisterRequest,
  DriftCompare,
  FleetSummary,
  LicenseBundlesResponse,
  OrganizationDetail,
  PlatformOverview,
  TsrTestResult,
  ApiFlowConfig,
  ApiFlowTestResult,
  PsirtRefresh,
  SSOConfig,
  Trends,
  ExecutiveSummary,
  DashboardCharts,
  RiskTrend,
  OperationalSummary,
  TsrHistoryItem,
  FindingDetail,
  FindingRow,
  FindingStatus,
  Integration,
  LoginResult,
  MfaEnroll,
  Rule,
  RuleTestResult,
  BuilderSnapshotRef,
  Suppression,
  Token,
  User,
} from "./types";

const BASE = "/api/v1";

let accessToken: string | null = sessionStorage.getItem("fgai_access");
let refreshToken: string | null = sessionStorage.getItem("fgai_refresh");

export function isAuthed(): boolean {
  return !!accessToken;
}

function setTokens(t: Token | null) {
  accessToken = t?.access_token ?? null;
  refreshToken = t?.refresh_token ?? null;
  if (t) {
    sessionStorage.setItem("fgai_access", t.access_token);
    sessionStorage.setItem("fgai_refresh", t.refresh_token);
  } else {
    sessionStorage.removeItem("fgai_access");
    sessionStorage.removeItem("fgai_refresh");
  }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function raw(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401 && retry && refreshToken) {
    const ok = await tryRefresh();
    if (ok) return raw(path, init, false);
  }
  return res;
}

async function json<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await raw(path, init);
  if (!res.ok) {
    let detail: string = res.statusText;
    try {
      const body = await res.json();
      const d = body.detail;
      if (Array.isArray(d)) {
        detail = d.map((e: any) => e.msg || JSON.stringify(e)).join("; ");
      } else if (typeof d === "string") {
        detail = d;
      } else if (d) {
        detail = String(d);
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

async function tryRefresh(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/auth/refresh?refresh_token=${encodeURIComponent(refreshToken!)}`, {
      method: "POST",
    });
    if (!res.ok) {
      setTokens(null);
      return false;
    }
    setTokens(await res.json());
    return true;
  } catch {
    setTokens(null);
    return false;
  }
}

export const api = {
  // Step 1: password. Returns either tokens (stored here) or an MFA challenge.
  async login(email: string, password: string): Promise<LoginResult> {
    const res = await json<LoginResult>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!res.mfa_required && res.access_token && res.refresh_token) {
      setTokens({ access_token: res.access_token, refresh_token: res.refresh_token,
        token_type: res.token_type });
    }
    return res;
  },

  // Public self-service sign-up: creates org + owner and logs in.
  async register(body: {
    full_name: string; company_name: string; email: string; password: string;
    phone?: string; address?: string; is_msp?: boolean; region?: string;
  }): Promise<User> {
    const t = await json<Token>("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    setTokens(t);
    return this.me();
  },

  // Step 2 (when MFA is enabled): validate a TOTP or backup code.
  async mfaVerify(mfaToken: string, code: string): Promise<User> {
    const t = await json<Token>("/auth/mfa/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mfa_token: mfaToken, code }),
    });
    setTokens(t);
    return this.me();
  },

  logout() {
    setTokens(null);
  },

  // Store tokens delivered by the SSO redirect (fragment carries access/refresh).
  applySsoTokens(access: string, refresh: string) {
    setTokens({ access_token: access, refresh_token: refresh, token_type: "bearer" });
  },

  me: () => json<User>("/auth/me"),

  updateProfile: (body: Partial<Pick<User, "full_name" | "phone" | "address" | "notify_new_critical" | "notify_scan_failed">>) =>
    json<User>("/auth/me", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),

  // ---- MFA enrollment ----
  mfaEnroll: () => json<MfaEnroll>("/auth/mfa/enroll", { method: "POST" }),
  mfaActivate: (code: string) =>
    json<{ backup_codes: string[] }>("/auth/mfa/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }),
  async mfaDisable(code: string): Promise<void> {
    await raw("/auth/mfa/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
  },

  // ---- dashboard & findings ----
  dashboard: () => json<DashboardData>("/dashboard"),
  fleet: () => json<FleetSummary>("/fleet"),

  listFindings: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    return json<FindingRow[]>(`/findings${qs ? `?${qs}` : ""}`);
  },
  // Snapshot-based findings for a specific analysis (preserves findings across scans).
  listAnalysisFindings: (analysisId: string, params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    return json<FindingRow[]>(`/analyses/${analysisId}/findings${qs ? `?${qs}` : ""}`);
  },
  getFinding: (id: string) => json<FindingDetail>(`/findings/${id}`),
  transitionFinding: (id: string, body: {
    to_status: FindingStatus; comment: string;
    justification?: string; accepted_risk_expiry?: string; ticket_ref?: string;
  }) =>
    json<FindingDetail>(`/findings/${id}/transition`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  commentFinding: (id: string, body: string) =>
    json<unknown>(`/findings/${id}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body }),
    }),
  bulkTransition: (body: {
    finding_ids: string[]; to_status: FindingStatus; comment: string;
    justification?: string; accepted_risk_expiry?: string;
  }) =>
    json<{ updated: string[]; skipped: string[] }>("/findings/bulk-transition", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),

  auditLog: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    return json<{ total: number; items: AuditEntry[] }>(`/audit-log${qs ? `?${qs}` : ""}`);
  },

  // ---- Device registration & connectivity ----
  registerDevice: (body: DeviceRegisterRequest) =>
    json<Device>("/devices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  fetchLicenseBundles: () =>
    json<LicenseBundlesResponse>("/organization/licenses"),
  connectDevice: (body: {
    device_id?: string; customer_id?: string; friendly_name?: string;
    hostname: string; port: number;
    username: string; password: string; verify_tls?: boolean; save_password?: boolean;
  }) =>
    json<DeviceConnectResult>("/devices/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  pullDevice: (deviceId: string) =>
    json<DeviceConnectResult>(`/devices/${deviceId}/pull`, { method: "POST" }),
  getDevice: (id: string) => json<Device>(`/devices/${id}`),
  getDeviceDetail: (id: string) => json<DeviceDetail>(`/devices/${id}/detail`),
  getConnectionLogs: (deviceId: string, limit = 50) =>
    json<import("./types").ApiConnectionLog[]>(`/devices/${deviceId}/connection-logs?limit=${limit}`),
  deleteTsr: (tsrId: string) =>
    raw(`/tsrs/${tsrId}`, { method: "DELETE" }).then(() => undefined),
  downloadTsr: (tsrId: string, filename: string) =>
    raw(`/tsrs/${tsrId}/download`).then((res) => {
      if (!res.ok) throw new ApiError(res.status, "Download failed");
      return res.blob().then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = filename; a.click();
        URL.revokeObjectURL(url);
      });
    }),
  toggleTsrFavorite: (tsrId: string, favorite: boolean) =>
    json<{ id: string; favorite: boolean }>(`/tsrs/${tsrId}/favorite`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ favorite }),
    }),

  // ---- Phase 2: rules ----
  listRules: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    return json<Rule[]>(`/rules${qs ? `?${qs}` : ""}`);
  },
  getRule: (id: string) => json<Rule>(`/rules/${id}`),
  createRule: (body: Partial<Rule>) =>
    json<Rule>("/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  updateRule: (id: string, body: Record<string, unknown>) =>
    json<Rule>(`/rules/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteRule: (id: string) =>
    raw(`/rules/${id}`, { method: "DELETE" }).then(() => undefined),
  ruleStateChange: (id: string, action: "submit" | "approve") =>
    json<Rule>(`/rules/${id}/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: "" }),
    }),
  testRule: (id: string, body: { analysis_id?: string; condition?: string; snapshot?: unknown }) =>
    json<RuleTestResult>(`/rules/${id}/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  // ---- CEL rule builder (superadmin) ----
  listBuilderSnapshots: () =>
    json<BuilderSnapshotRef[]>("/rules/builder/snapshots"),
  getBuilderSnapshot: (analysisId: string) =>
    json<Record<string, unknown>>(`/rules/builder/snapshot/${analysisId}`),
  getSavedBuilderSnapshot: () =>
    json<{ filename: string; snapshot: Record<string, unknown> }>("/rules/builder/snapshot/saved"),
  uploadBuilderTsr: async (file: File) => {
    const form = new FormData();
    form.append("file", file);
    // Use raw fetch with a timeout — file upload + parse can take 60+ seconds.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000);
    try {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      const res = await fetch(`${BASE}/rules/builder/upload`, {
        method: "POST", body: form, headers, signal: controller.signal,
      });
      if (!res.ok) {
        let detail = res.statusText;
        try { const body = await res.json(); detail = body.detail || detail; } catch { /* */ }
        throw new ApiError(res.status, detail);
      }
      return res.json() as Promise<{ filename: string; snapshot: Record<string, unknown>; meta: Record<string, unknown> }>;
    } finally {
      clearTimeout(timeout);
    }
  },
  testBuilderCondition: (analysisId: string, condition: string, snapshot?: Record<string, unknown>) =>
    json<RuleTestResult>("/rules/builder/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analysis_id: analysisId || "", condition, snapshot: snapshot || null }),
    }),
  listSuppressions: (ruleKey?: string) =>
    json<Suppression[]>(`/rule-suppressions${ruleKey ? `?rule_key=${encodeURIComponent(ruleKey)}` : ""}`),
  createSuppression: (body: {
    rule_key: string; device_id?: string | null;
    action: "disable" | "override_severity"; value?: string; reason?: string;
    expires_at?: string | null;
  }) =>
    json<Suppression>("/rule-suppressions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteSuppression: (id: string) =>
    raw(`/rule-suppressions/${id}`, { method: "DELETE" }).then(() => undefined),

  // ---- Phase 2: compliance ----
  complianceFrameworks: () => json<{ frameworks: string[] }>("/compliance/frameworks"),
  complianceMatrix: (framework: string) =>
    json<ComplianceMatrix>(`/compliance/matrix?framework=${encodeURIComponent(framework)}`),

  // ---- Phase 2: integrations ----
  listIntegrations: () => json<Integration[]>("/integrations"),
  saveIntegration: (body: {
    type: string; name?: string; enabled: boolean; webhook_url?: string;
    config?: Record<string, unknown>;
  }) =>
    json<Integration>("/integrations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  testIntegration: (id: string) =>
    json<{ status: string }>(`/integrations/${id}/test`, { method: "POST" }),
  deleteIntegration: (id: string) =>
    raw(`/integrations/${id}`, { method: "DELETE" }).then(() => undefined),

  // ---- Phase 2: API tokens ----
  listTokens: () => json<ApiToken[]>("/settings/api-tokens"),
  createToken: (body: { name: string; scopes: string[]; expires_at?: string | null }) =>
    json<ApiTokenCreated>("/settings/api-tokens", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  revokeToken: (id: string) =>
    raw(`/settings/api-tokens/${id}`, { method: "DELETE" }).then(() => undefined),

  // ---- Phase 2: drift comparison ----
  listDeviceAnalyses: (deviceId: string) =>
    json<AnalysisSummary[]>(`/devices/${deviceId}/analyses`),
  compareAnalyses: (deviceId: string, previous: string, current: string) =>
    json<DriftCompare>(`/devices/${deviceId}/compare?previous=${previous}&current=${current}`),
  async downloadComparisonReport(deviceId: string, previous: string, current: string): Promise<Blob> {
    const res = await raw(`/devices/${deviceId}/compare/report?previous=${encodeURIComponent(previous)}&current=${encodeURIComponent(current)}`);
    if (!res.ok) throw new ApiError(res.status, "Comparison report not available");
    return res.blob();
  },

  // ---- Phase 3: organization / billing ----
  getOrganization: () => json<OrganizationDetail>("/organization"),
  // Plans
  listPlans: () => json<PlanData[]>("/admin/plans"),
  createPlan: (body: Partial<PlanData>) =>
    json<PlanData>("/admin/plans", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  updatePlan: (id: string, body: Partial<PlanData>) =>
    json<PlanData>(`/admin/plans/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  clonePlan: (id: string) =>
    json<PlanData>(`/admin/plans/${id}/clone`, { method: "POST" }),
  deletePlan: (id: string) =>
    raw(`/admin/plans/${id}`, { method: "DELETE" }).then(() => undefined),
  assignPlan: (planId: string, orgId: string) =>
    json<{ status: string }>(`/admin/plans/${planId}/assign`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ org_id: orgId }),
    }),
  resetSubscription: (orgId: string) =>
    json<{ status: string; message: string }>(`/admin/organizations/${orgId}/reset-subscription`, { method: "POST" }),
  factoryReset: (orgId: string) =>
    json<{ status: string; message: string }>(`/admin/organizations/${orgId}/factory-reset`, { method: "POST" }),
  deleteOrganization: (orgId: string) =>
    json<{ deleted: boolean; organization_name: string; users: number; devices: number; findings: number }>(`/platform/organizations/${orgId}`, { method: "DELETE" }),
  listAdminFeatures: () => json<{ id: string; key: string; label: string; description: string; is_active: boolean }[]>("/admin/features"),
  createFeature: (body: { key: string; label: string; description?: string }) =>
    json<{ id: string }>("/admin/features", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  updateFeature: (id: string, body: Record<string, unknown>) =>
    json<{ id: string }>(`/admin/features/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  deleteFeature: (id: string) =>
    raw(`/admin/features/${id}`, { method: "DELETE" }).then(() => undefined),
  availablePlans: () => json<PlanData[]>("/plans/available"),
  currentPlan: () => json<CustomerPlanInfo>("/plans/current"),
  updateOrgPlan: (body: { plan_id?: string; device_count?: number; subscription_term?: string }) =>
    json<CustomerPlanInfo>("/organization/plan", {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  purchaseLicenses: (body: { count: number; tier?: string; subscription_term?: string }) =>
    json<CustomerPlanInfo>("/organization/purchase", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  startTrial: () => json<OrganizationDetail>("/billing/start-trial", { method: "POST" }),
  regions: () => json<{ regions: string[]; default: string }>("/regions"),
  updateOrganization: (body: Partial<OrganizationDetail>) =>
    json<OrganizationDetail>("/organization", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),

  // ---- Phase 4: analytics ----
  trends: () => json<Trends>("/analytics/trends"),
  executiveSummary: (rangeDays: number = 30, customerId?: string, deviceIds?: string, localToday?: string, tzOffset?: number) =>
    json<ExecutiveSummary>(`/analytics/executive-summary?range_days=${rangeDays}${customerId ? `&customer_id=${customerId}` : ""}${deviceIds ? `&device_ids=${deviceIds}` : ""}${localToday ? `&local_today=${localToday}` : ""}${tzOffset !== undefined ? `&tz_offset=${tzOffset}` : ""}`),
  dashboardCharts: (rangeDays: number = 30, customerId?: string, deviceIds?: string) =>
    json<DashboardCharts>(`/analytics/dashboard-charts?range_days=${rangeDays}&all_firmware=1&all_findings=1${customerId ? `&customer_id=${customerId}` : ""}${deviceIds ? `&device_ids=${deviceIds}` : ""}`),
  riskTrend: (rangeDays: number = 30, customerId?: string, deviceIds?: string, localToday?: string, tzOffset?: number) =>
    json<RiskTrend>(`/analytics/risk-trend?range_days=${rangeDays}${customerId ? `&customer_id=${customerId}` : ""}${deviceIds ? `&device_ids=${deviceIds}` : ""}${localToday ? `&local_today=${localToday}` : ""}${tzOffset !== undefined ? `&tz_offset=${tzOffset}` : ""}`),
  operationalSummary: (rangeDays: number = 30, customerId?: string, deviceIds?: string) =>
    json<OperationalSummary>(`/analytics/operational-summary?range_days=${rangeDays}${customerId ? `&customer_id=${customerId}` : ""}${deviceIds ? `&device_ids=${deviceIds}` : ""}`),
  firmwareCompliance: () =>
    json<import("./types").FirmwareCompliance>("/analytics/firmware-compliance"),

  // ---- platform operator (superadmin) ----
  platformOverview: () => json<PlatformOverview>("/platform/overview"),
  // Ad-hoc TSR analysis (superadmin tester). format: auto | gui | api.
  platformAnalyzeTsr: async (file: File, format: "auto" | "gui" | "api" = "auto") => {
    const form = new FormData();
    form.append("file", file);
    form.append("tsr_format", format);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000);
    try {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      const res = await fetch(`${BASE}/platform/analyze-tsr`, {
        method: "POST", body: form, headers, signal: controller.signal,
      });
      if (!res.ok) {
        let detail = res.statusText;
        try { const body = await res.json(); detail = body.detail || detail; } catch { /* */ }
        throw new ApiError(res.status, detail);
      }
      return res.json() as Promise<TsrTestResult>;
    } finally {
      clearTimeout(timeout);
    }
  },
  // ---- configurable API flow (superadmin) ----
  listApiConfigs: () => json<ApiFlowConfig[]>("/platform/api-configs"),
  createApiConfig: (body: Partial<ApiFlowConfig>) =>
    json<ApiFlowConfig>("/platform/api-configs", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  updateApiConfig: (id: string, body: Partial<ApiFlowConfig>) =>
    json<ApiFlowConfig>(`/platform/api-configs/${id}`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  activateApiConfig: (id: string) =>
    json<ApiFlowConfig>(`/platform/api-configs/${id}/activate`, { method: "POST" }),
  deleteApiConfig: (id: string) =>
    raw(`/platform/api-configs/${id}`, { method: "DELETE" }).then(() => undefined),
  testApiConfig: (body: {
    config_id?: string; config?: Partial<ApiFlowConfig>;
    hostname: string; port: number; username: string; password: string; verify_tls?: boolean;
  }) =>
    json<ApiFlowTestResult>("/platform/api-configs/test", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),

  // ---- product config (superadmin) ----
  listGenerations: () => json<DeviceGeneration[]>("/platform/generations"),
  listGenerationsPublic: () => json<DeviceGeneration[]>("/platform/generations/public"),
  createGeneration: (body: { name: string; sort_order?: number }) =>
    json<DeviceGeneration>("/platform/generations", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  updateGeneration: (id: string, body: { name?: string; sort_order?: number }) =>
    json<DeviceGeneration>(`/platform/generations/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  deleteGeneration: (id: string) =>
    raw(`/platform/generations/${id}`, { method: "DELETE" }).then(() => undefined),
  addDeviceToGeneration: (genId: string, model: string) =>
    json<{ id: string; generation_id: string; model: string }>(`/platform/generations/${genId}/devices`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ model }),
    }),
  removeDeviceFromGeneration: (genId: string, devId: string) =>
    raw(`/platform/generations/${genId}/devices/${devId}`, { method: "DELETE" }).then(() => undefined),
  setFirmwareRecommendation: (genId: string, version: string) =>
    json<{ generation_id: string; version: string }>(`/platform/generations/${genId}/firmware`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ version }),
    }),
  checkout: (plan: string) =>
    json<{ url: string | null; mode: string; message: string }>("/billing/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ plan }),
    }),

  // ---- Phase 3: SSO config ----
  getSsoConfig: () => json<SSOConfig>("/sso/config"),
  putSsoConfig: (body: Partial<SSOConfig> & { oidc_client_secret?: string }) =>
    json<SSOConfig>("/sso/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  ssoStatus: (orgId: string) =>
    json<{ enabled: boolean; protocol: string | null }>(`/sso/${orgId}/status`),

  // ---- Phase 3: customers (MSP) ----
  getCustomer: (id: string) => json<CustomerDetail>(`/customers/${id}`),
  updateCustomer: (id: string, body: Partial<CustomerDetail>) =>
    json<CustomerDetail>(`/customers/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteCustomer: (id: string) =>
    raw(`/customers/${id}`, { method: "DELETE" }).then(() => undefined),
  createCustomerFull: (body: Partial<CustomerDetail>) =>
    json<CustomerDetail>("/customers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),

  // ---- Phase 3: PSIRT ----
  psirtChangelog: () => json<PsirtRefresh[]>("/settings/psirt/changelog"),
  psirtRefresh: () => json<PsirtRefresh>("/settings/psirt/refresh", { method: "POST" }),

  listCustomers: () => json<Customer[]>("/customers"),

  createCustomer: (name: string) =>
    json<Customer>("/customers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    }),

  listDevices: (customerId?: string) =>
    json<Device[]>(`/devices${customerId ? `?customer_id=${customerId}` : ""}`),
  listDevicesDecommissioned: () =>
    json<Device[]>("/devices?decommissioned=true"),
  updateDevice: (id: string, body: { friendly_name?: string; connection_method?: string; analyze_mode?: string }) =>
    json<Device>(`/devices/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  deleteDevice: (id: string) =>
    raw(`/devices/${id}`, { method: "DELETE" }).then((res) => {
      if (res.status === 204) return undefined;
      return res.json() as Promise<Device>;  // decommissioned device
    }),
  deleteDevices: (ids: string[]) =>
    Promise.all(ids.map((id) => raw(`/devices/${id}`, { method: "DELETE" }))).then(() => undefined),
  recommissionDevice: (id: string) =>
    json<Device>(`/devices/${id}/recommission`, { method: "POST" }),
  changeDeviceLicense: (deviceId: string, licensePurchaseId: string) =>
    json<Device>(`/devices/${deviceId}/license`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ license_purchase_id: licensePurchaseId }),
    }),
  getDeviceCredentials: (deviceId: string) =>
    json<import("./types").DeviceCredential>(`/devices/${deviceId}/credentials`),
  updateDeviceCredentials: (deviceId: string, body: {
    hostname?: string; port?: number; username?: string; password?: string;
  }) =>
    json<import("./types").CredentialTestResult>(`/devices/${deviceId}/credentials`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  getDeviceSchedule: (deviceId: string) =>
    json<import("./types").DeviceSchedule>(`/devices/${deviceId}/schedule`).catch(() => null),
  upsertDeviceSchedule: (deviceId: string, body: {
    frequency: string; hour: number; minute: number; timezone?: string;
    day_of_week?: number | null; day_of_month?: number | null; enabled: boolean;
  }) =>
    json<import("./types").DeviceSchedule>(`/devices/${deviceId}/schedule`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  updateDeviceVisibility: (id: string, hidden_severities: string[]) =>
    json<Device>(`/devices/${id}/visibility`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden_severities }),
    }),
  updateOrgVisibility: (hidden_severities: string[]) =>
    json<OrganizationDetail>("/organization/visibility", {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden_severities }),
    }),

  listAnalyses: (deviceId: string) =>
    json<AnalysisSummary[]>(`/devices/${deviceId}/analyses`),

  getAnalysis: (id: string) =>
    json<AnalysisSummary & { result_json: Analysis }>(`/analyses/${id}`),

  async uploadTsr(customerId: string, deviceId: string, file: File): Promise<AnalysisSummary> {
    const form = new FormData();
    form.append("file", file);
    return json<AnalysisSummary>(`/customers/${customerId}/tsrs?device_id=${encodeURIComponent(deviceId)}`, {
      method: "POST",
      body: form,
    });
  },

  // Report downloads return binary; build an object URL the caller can use.
  async downloadReport(
    analysisId: string,
    kind: "executive" | "technical" | "csv" | "json" | "xlsx",
  ): Promise<Blob> {
    const path =
      kind === "csv" || kind === "json" || kind === "xlsx"
        ? `/analyses/${analysisId}/export/${kind}`
        : `/analyses/${analysisId}/report/${kind}`;
    const res = await raw(path);
    if (!res.ok) throw new ApiError(res.status, "Report not available");
    return res.blob();
  },
};
