import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import { useConfirm } from "./Modal";
import type { DeviceDetail, Customer, Analysis, DeviceCredential, CredentialTestResult, ConnectStep, DeviceSchedule, LicenseBundle, ApiConnectionLog } from "../lib/types";
import { UploadPanel } from "./UploadPanel";
import { navigate } from "../lib/router";
import { gradeColor, fmtDate } from "../lib/ui";

export function DeviceDetailView({ id, customers }: { id: string; customers: Customer[] }) {
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showUpload, setShowUpload] = useState(false);
  const confirm = useConfirm();

  // API credentials state
  const [creds, setCreds] = useState<DeviceCredential | null>(null);
  const [credsLoading, setCredsLoading] = useState(false);
  const [editingCreds, setEditingCreds] = useState(false);
  const [credForm, setCredForm] = useState({ hostname: "", port: 443, username: "", password: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [credTestResult, setCredTestResult] = useState<CredentialTestResult | null>(null);
  const [credSaving, setCredSaving] = useState(false);

  // Pull Now state
  const [pulling, setPulling] = useState(false);
  const [pullResult, setPullResult] = useState<CredentialTestResult | null>(null);

  // Schedule state for auto analyze mode
  const [sched, setSched] = useState<DeviceSchedule | null>(null);
  const [schedLoading, setSchedLoading] = useState(false);
  const [schedSaving, setSchedSaving] = useState(false);
  const [showScheduleEditor, setShowScheduleEditor] = useState(false);
  const [schedMsg, setSchedMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [schedForm, setSchedForm] = useState({
    frequency: "monthly", hour: 3, minute: 0, day_of_week: 0, day_of_month: 1, enabled: true,
  });

  // Change license state
  const [showLicenseChange, setShowLicenseChange] = useState(false);
  const [licenseBundles, setLicenseBundles] = useState<LicenseBundle[]>([]);
  const [licenseBundlesLoading, setLicenseBundlesLoading] = useState(false);
  const [selectedBundleId, setSelectedBundleId] = useState<string>("");
  const [licenseChanging, setLicenseChanging] = useState(false);
  const [licenseChangeMsg, setLicenseChangeMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // Connection logs state
  const [connLogs, setConnLogs] = useState<ApiConnectionLog[]>([]);
  const [connLogsLoading, setConnLogsLoading] = useState(false);
  const [showConnLogs, setShowConnLogs] = useState(false);

  const load = useCallback(() => {
    api.getDeviceDetail(id).then(setDevice).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load device"));
  }, [id]);
  useEffect(() => { load(); }, [load]);

  // Load credentials for API-configured devices
  useEffect(() => {
    if (!device || device.connection_method !== "api" || !device.configured) return;
    setCredsLoading(true);
    api.getDeviceCredentials(id).then((c) => {
      setCreds(c);
      setCredForm({ hostname: c.hostname, port: c.port, username: c.username, password: "" });
    }).catch(() => setCreds(null))
    .finally(() => setCredsLoading(false));
  }, [id, device?.connection_method, device?.configured]);

  // Load schedule when in auto mode
  useEffect(() => {
    if (!device || device.analyze_mode !== "auto") { setSched(null); return; }
    setSchedLoading(true);
    api.getDeviceSchedule(id).then((s) => {
      setSched(s);
      if (s) setSchedForm({ frequency: s.frequency, hour: s.hour, minute: s.minute, day_of_week: s.day_of_week ?? 0, day_of_month: s.day_of_month ?? 1, enabled: s.enabled });
    }).catch(() => setSched(null))
    .finally(() => setSchedLoading(false));
  }, [id, device?.analyze_mode]);

  async function saveSchedule() {
    if (!device) return;
    const freq = schedForm.frequency;
    setSchedSaving(true); setSchedMsg(null);
    try {
      const body: any = {
        frequency: freq, hour: freq === "hourly" ? 0 : schedForm.hour,
        minute: schedForm.minute, timezone: "UTC", enabled: true,
      };
      if (freq === "weekly") body.day_of_week = schedForm.day_of_week;
      if (freq === "monthly") body.day_of_month = schedForm.day_of_month;
      const result = await api.upsertDeviceSchedule(id, body);
      setSched(result);
      setSchedMsg({ ok: true, text: "Schedule saved successfully." });
      setShowScheduleEditor(false);
    } catch (e) {
      setSchedMsg({ ok: false, text: e instanceof Error ? e.message : "Failed to save schedule." });
    } finally {
      setSchedSaving(false);
    }
  }

  async function handleTestAndSaveCreds() {
    setCredSaving(true);
    setCredTestResult(null);
    try {
      const body: Record<string, unknown> = {
        hostname: credForm.hostname,
        port: credForm.port,
        username: credForm.username,
      };
      if (credForm.password) body.password = credForm.password;
      const result = await api.updateDeviceCredentials(id, body as any);
      setCredTestResult(result);
      if (result.success) {
        // Reload credentials to get updated info
        const c = await api.getDeviceCredentials(id);
        setCreds(c);
        setCredForm({ hostname: c.hostname, port: c.port, username: c.username, password: "" });
        setEditingCreds(false);
        load();
        if (showConnLogs) refreshConnectionLogs();
      }
    } catch (e) {
      setCredTestResult({ success: false, message: e instanceof Error ? e.message : "Test failed", steps: [] });
    } finally {
      setCredSaving(false);
    }
  }

  async function handleDeleteTsr(tsrId: string, filename: string) {
    if (!await confirm("Delete TSR", `Remove "${filename}"? This deletes the TSR, its analysis, and all associated findings.`)) return;
    try {
      await api.deleteTsr(tsrId);
      load();
    } catch (e) {
      alert(e instanceof Error ? e.message : "Delete failed");
    }
  }

  async function handleDeleteDevice() {
    const name = device?.friendly_name || device?.serial || "this device";
    const everConfigured = device?.was_ever_configured;
    const message = everConfigured
      ? `Decommission "${name}"? All TSR history, findings, and stored files will be permanently deleted. The license will remain consumed until it expires. The device can be recommissioned later from the Decommissioned Devices list.`
      : `Permanently delete "${name}"? This device was never configured, so its license will be released back to the pool.`;
    if (!await confirm(everConfigured ? "Decommission Device" : "Delete Device", message)) return;
    try {
      await api.deleteDevice(id);
      navigate("/devices");
    } catch (e) {
      alert(e instanceof Error ? e.message : "Delete failed");
    }
  }

  function handleUploadComplete(_analysisId: string, _analysis: Analysis) {
    setShowUpload(false);
    load();
  }

  async function openLicenseChange() {
    setShowLicenseChange(true);
    setLicenseChangeMsg(null);
    setSelectedBundleId("");
    setLicenseBundlesLoading(true);
    try {
      const res = await api.fetchLicenseBundles();
      // Filter to bundles with remaining capacity.
      setLicenseBundles(res.bundles.filter((b) => b.remaining > 0));
    } catch (e) {
      setLicenseChangeMsg({ ok: false, text: e instanceof Error ? e.message : "Failed to load licenses" });
    } finally {
      setLicenseBundlesLoading(false);
    }
  }

  async function loadConnectionLogs() {
    setShowConnLogs(!showConnLogs);
    if (!showConnLogs) {
      await refreshConnectionLogs();
    }
  }

  async function refreshConnectionLogs() {
    setConnLogsLoading(true);
    try {
      const logs = await api.getConnectionLogs(id);
      setConnLogs(logs);
    } catch { /* ignore */ }
    finally { setConnLogsLoading(false); }
  }

  async function confirmLicenseChange() {
    if (!selectedBundleId) return;
    setLicenseChanging(true);
    setLicenseChangeMsg(null);
    try {
      await api.changeDeviceLicense(id, selectedBundleId);
      setLicenseChangeMsg({ ok: true, text: "License reassigned successfully." });
      setShowLicenseChange(false);
      load();
    } catch (e) {
      setLicenseChangeMsg({ ok: false, text: e instanceof Error ? e.message : "License change failed" });
    } finally {
      setLicenseChanging(false);
    }
  }

  if (err) {
    return (
      <div className="card-glow p-8 text-center fade-in">
        <p className="text-sev-high text-[13px] font-mono">{err}</p>
        <button onClick={() => navigate("/devices")}
                className="mt-3 px-4 py-2 rounded-lg border border-base-500 text-[13px] text-ink-300 hover:text-ink-100">
          ← Back to Devices
        </button>
      </div>
    );
  }

  if (!device) {
    return (
      <div className="min-h-[300px] grid place-items-center">
        <span className="font-mono text-ink-500 text-sm animate-pulse">Loading…</span>
      </div>
    );
  }

  const isConfigured = device.configured;

  return (
    <div className="max-w-[1200px] fade-in space-y-5">
      {/* ── Back + header ─────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <button onClick={() => navigate("/devices")}
                  className="text-ink-500 hover:text-ink-100 text-[12px] font-mono mb-1 inline-block">
            ← Devices
          </button>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">
            {device.friendly_name || device.model || device.serial}
          </h1>
        </div>
        {isConfigured && (
          <div className="flex items-center gap-2">
            <button onClick={() => navigate(`/findings?device=${id}`)}
                    className="px-4 py-2 rounded-lg border border-accent/40 text-accent text-[13px] font-medium hover:bg-accent/10 transition-all">
              Go to Findings
            </button>
            {device.connection_method === "manual" && (
              <button onClick={() => setShowUpload(!showUpload)}
                      className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
                {showUpload ? "Cancel Upload" : "Upload New TSR"}
              </button>
            )}
            {device.connection_method === "api" && (
              <button onClick={async () => {
                 setPulling(true); setPullResult(null);
                try {
                  const res = await api.pullDevice(id);
                  setPullResult({ success: res.connection_status === "ok", message: res.message, steps: res.steps || [] });
                  if (res.connection_status === "ok") {
                    // Refresh device data and connection logs (pull runs synchronously now).
                    load();
                    if (showConnLogs) refreshConnectionLogs();
                  }
                } catch (e) {
                  setPullResult({ success: false, message: e instanceof Error ? e.message : "Pull failed", steps: [] });
                } finally {
                  setPulling(false);
                }
              }} disabled={pulling}
                      className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
                {pulling ? "Pulling…" : "Pull Now"}
              </button>
            )}
            <button onClick={openLicenseChange}
                    className="px-4 py-2 rounded-lg border border-base-500 text-ink-300 text-[13px] font-medium hover:text-accent hover:border-accent transition-all">
              Change License
            </button>
            <button onClick={handleDeleteDevice}
                    className="px-4 py-2 rounded-lg border border-sev-high/30 text-sev-high text-[13px] font-medium hover:bg-sev-high/10 transition-all">
              {device?.was_ever_configured ? "Decommission" : "Delete Device"}
            </button>
          </div>
        )}
        {!isConfigured && (
          <button onClick={() => navigate(`/devices`)}
                  className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all">
            Configure Device
          </button>
        )}
      </div>

      {/* ── Pull result ──────────────────────────────────────────── */}
      {pullResult && (
        <div className={`p-3 rounded-lg border ${pullResult.success ? "border-signal/30 bg-signal/5" : "border-sev-high/30 bg-sev-high/5"}`}>
          <p className={`font-mono text-[12px] font-medium ${pullResult.success ? "text-signal" : "text-sev-high"}`}>
            {pullResult.success ? "✓" : "✕"} {pullResult.message}
          </p>
          {pullResult.steps.length > 0 && (
            <ul className="mt-2 space-y-0.5">
              {pullResult.steps.map((s, i) => (
                <li key={i} className="flex items-start gap-2 text-[11px] font-mono"
                    style={{ color: s.status === "ok" ? "#39d98a" : s.status === "failed" ? "#ff4d4d" : s.status === "warn" ? "#f5c451" : "#7a879b" }}>
                  <span className="mt-0.5">{s.status === "ok" ? "✓" : s.status === "failed" ? "✕" : s.status === "warn" ? "!" : "·"}</span>
                  <span className="text-ink-400">{s.detail || s.step}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* ── Upload panel (toggle) ─────────────────────────────────── */}
      {showUpload && (
        <div className="card-glow p-5 fade-in">
          <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Upload New TSR</h3>
          <p className="font-mono text-[11px] text-ink-500 mb-3">
            Uploading a new TSR will re-analyze this device. Previous TSRs remain in the history below.
          </p>
          <UploadPanel customers={customers} deviceId={id} customerId={device?.customer_id}
                       onComplete={handleUploadComplete} />
        </div>
      )}

      {/* ── Device info card ──────────────────────────────────────── */}
      <div className="card-glow p-5">
        <h2 className="font-display font-semibold text-sm text-ink-100 mb-4">Device Information</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
          <InfoField label="Device Name" value={device.friendly_name || "—"} />
          <InfoField label="Serial Number" value={device.serial || "—"} mono />
          <InfoField label="Model" value={device.model || "—"} />
          <InfoField label="Firmware" value={device.firmware || "—"} mono />
          <InfoField label="Customer"
                     value={customers.find((c) => c.id === device.customer_id)?.name || "—"} />
          <InfoField label="Status"
                     value={isConfigured ? "Configured" : "Not Configured"}
                     color={isConfigured ? "#39d98a" : "#f5c451"} />
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-0.5">Retrieve Mode</div>
            {isConfigured ? (
              <select value={device.connection_method}
                      onChange={async (e) => {
                        const method = e.target.value;
                        try {
                          await api.updateDevice(id, { connection_method: method } as any);
                          load();
                        } catch { /* ignore */ }
                      }}
                      className="bg-base-900/80 border border-base-500 rounded-lg px-2 py-1 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                <option value="manual">Manual (Upload)</option>
                <option value="api">API</option>
              </select>
            ) : (
              <span className="text-[13px] text-ink-500">—</span>
            )}
          </div>
          <InfoField label="TSRs Uploaded" value={String(device.tsr_count)} />
          <InfoField label="Date Added" value={device.created_at ? fmtDate(device.created_at) : "—"} />
          <InfoField label="Last Analysis" value={device.last_analysis_at ? fmtDate(device.last_analysis_at) : "—"} />
          <InfoField label="Latest Score" value={isConfigured && device.latest_grade ? `${device.latest_score?.toFixed(0)}%` : "—"}
                     color={isConfigured ? gradeColor(device.latest_grade) : undefined} />
          <InfoField label="Latest Grade" value={isConfigured ? device.latest_grade || "—" : "—"}
                     color={isConfigured ? gradeColor(device.latest_grade) : undefined} />
          <InfoField label="License" value={device.license_bundle || "—"}
                     color={device.license_bundle === "Active" || device.license_bundle?.startsWith("Tier-") ? "#39d98a"
                       : device.license_bundle === "Active (Trial)" ? "#4a9eff"
                       : device.license_bundle === "Expired" || device.license_bundle === "Expired (Trial)" ? "#ff4d4d"
                       : undefined} />
          {device.license_expiry && (
            <InfoField label="License Expiry"
                       value={(() => {
                         const exp = new Date(device.license_expiry);
                         const now = new Date();
                         const diffMs = exp.getTime() - now.getTime();
                         if (diffMs <= 0) return "Expired";
                         const days = Math.floor(diffMs / 86400000);
                         if (days >= 30) return `${Math.floor(days / 30)} months`;
                         if (days >= 1) return `${days} days`;
                         const hrs = Math.floor(diffMs / 3600000);
                         return `${hrs} hours`;
                       })()}
                       color={new Date(device.license_expiry) <= new Date() ? "#ff4d4d" : "#39d98a"} />
          )}
        </div>
      </div>

      {/* ── Change License modal ────────────────────────────────────── */}
      {showLicenseChange && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setShowLicenseChange(false)} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={() => setShowLicenseChange(false)}>
            <div className="w-full max-w-[480px] bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
                 onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="font-display font-semibold text-ink-100 text-lg">Change License</h3>
                <button onClick={() => setShowLicenseChange(false)}
                        className="w-6 h-6 grid place-items-center rounded text-ink-500 hover:text-ink-100 transition-colors">×</button>
              </div>
              <p className="font-mono text-[12px] text-ink-500">
                Select a new license bundle for <span className="text-ink-300">{device.friendly_name || device.serial}</span>.
                The current license assignment will be released and replaced.
              </p>

              {licenseChangeMsg && (
                <div className={`p-3 rounded-lg border ${licenseChangeMsg.ok ? "border-signal/30 bg-signal/5" : "border-sev-high/30 bg-sev-high/5"}`}>
                  <p className={`font-mono text-[12px] ${licenseChangeMsg.ok ? "text-signal" : "text-sev-high"}`}>
                    {licenseChangeMsg.ok ? "✓" : "✕"} {licenseChangeMsg.text}
                  </p>
                </div>
              )}

              {licenseBundlesLoading ? (
                <div className="py-8 text-center">
                  <span className="font-mono text-ink-500 text-sm animate-pulse">Loading licenses…</span>
                </div>
              ) : licenseBundles.length === 0 ? (
                <div className="p-4 rounded-lg bg-base-800/50 border border-[#f5c45155] space-y-2">
                  <p className="text-[#f5c451] text-[13px] font-mono">No licenses available</p>
                  <p className="text-ink-500 text-[12px] font-mono">
                    All license bundles are either fully consumed or expired. Purchase additional licenses from Organization → Plan &amp; Billing.
                  </p>
                </div>
              ) : (
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">Available Bundles</span>
                  <select value={selectedBundleId}
                          onChange={(e) => setSelectedBundleId(e.target.value)}
                          className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                    <option value="">— Select a license bundle —</option>
                    {licenseBundles.map((b) => (
                      <option key={b.purchase_id} value={b.purchase_id || ""}>
                        {b.label}{b.expiry_date ? ` · expires ${new Date(b.expiry_date).toLocaleDateString()}` : ""}
                      </option>
                    ))}
                  </select>
                </label>
              )}

              <div className="flex items-center gap-3 pt-2 border-t border-base-500">
                <button onClick={confirmLicenseChange}
                        disabled={licenseChanging || !selectedBundleId}
                        className="px-5 py-2.5 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
                  {licenseChanging ? "Changing…" : "Confirm Change"}
                </button>
                <button onClick={() => setShowLicenseChange(false)}
                        className="px-4 py-2 rounded-lg border border-base-500 text-[13px] text-ink-300 hover:text-ink-100 transition-colors">
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── API Configuration (API-configured devices only) ────────── */}
      {device.connection_method === "api" && (
        <div className="card-glow p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display font-semibold text-sm text-ink-100">API Configuration</h2>
            {!editingCreds && (
              <div className="flex items-center gap-2">
                <button onClick={loadConnectionLogs}
                        className="px-3 py-1.5 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
                  {showConnLogs ? "Hide Logs" : "View Logs"}
                </button>
                <button onClick={() => { setEditingCreds(true); setCredTestResult(null); }}
                        className="px-3 py-1.5 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
                  Edit
                </button>
              </div>
            )}
          </div>

          {/* ── Analyze Mode ──────────────────────────────────────── */}
          {device.configured && (
            <div className="mb-4 p-3 rounded-lg border border-base-500/60 bg-base-900/30">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-display font-semibold text-[13px] text-ink-100">Analyze Mode</div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={async () => {
                    await api.updateDevice(id, { analyze_mode: "manual" } as any); load();
                  }}
                          className={`px-3 py-1.5 rounded-lg text-[12px] font-medium transition-colors ${
                            device.analyze_mode === "manual"
                              ? "bg-accent text-white"
                              : "border border-base-500 text-ink-300 hover:text-accent"
                          }`}>
                    Manual
                  </button>
                  <button onClick={async () => {
                    await api.updateDevice(id, { analyze_mode: "auto" } as any); load();
                  }}
                          className={`px-3 py-1.5 rounded-lg text-[12px] font-medium transition-colors ${
                            device.analyze_mode === "auto"
                              ? "bg-accent text-white"
                              : "border border-base-500 text-ink-300 hover:text-accent"
                          }`}>
                    Auto
                  </button>
                </div>
              </div>

              {/* Schedule configuration (auto mode) */}
              {device.analyze_mode === "auto" && (
                <div className="mt-3 pt-3 border-t border-base-500/40">
                  {schedLoading ? (
                    <p className="font-mono text-[11px] text-ink-500">Loading schedule…</p>
                  ) : !showScheduleEditor && sched ? (
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <span className="font-mono text-[12px] text-ink-300">
                        {formatScheduleSummary(sched)}
                      </span>
                      <button onClick={() => { setShowScheduleEditor(true); setSchedMsg(null); setSchedForm((f) => ({ ...f, enabled: true })); }}
                              className="px-3 py-1.5 rounded-lg border border-base-500 text-ink-300 text-[11px] hover:text-accent hover:border-accent transition-all">
                        Edit Schedule
                      </button>
                    </div>
                  ) : (
                    <ScheduleConfig
                      form={schedForm}
                      onChange={setSchedForm}
                      onSave={saveSchedule}
                      saving={schedSaving}
                      onCancel={sched ? () => { setShowScheduleEditor(false); setSchedMsg(null); } : undefined}
                    />
                  )}
                  {schedMsg && (
                    <p className={`mt-2 font-mono text-[11px] ${schedMsg.ok ? "text-signal" : "text-sev-high"}`}>
                      {schedMsg.ok ? "✓" : "✕"} {schedMsg.text}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          {credsLoading ? (
            <p className="font-mono text-[12px] text-ink-500">Loading…</p>
          ) : editingCreds ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Hostname / IP</span>
                  <input value={credForm.hostname} onChange={(e) => setCredForm((f) => ({ ...f, hostname: e.target.value }))}
                         className="mt-1 block w-full bg-base-900/80 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
                </label>
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Port</span>
                  <input type="number" value={credForm.port} onChange={(e) => setCredForm((f) => ({ ...f, port: Number(e.target.value) }))}
                         className="mt-1 block w-full bg-base-900/80 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
                </label>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Username</span>
                  <input value={credForm.username} onChange={(e) => setCredForm((f) => ({ ...f, username: e.target.value }))}
                         className="mt-1 block w-full bg-base-900/80 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
                </label>
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Password</span>
                  <div className="relative mt-1">
                    <input type={showPassword ? "text" : "password"} value={credForm.password}
                           onChange={(e) => setCredForm((f) => ({ ...f, password: e.target.value }))}
                           placeholder={creds?.has_password ? "Leave blank to keep current" : "Enter password"}
                           className="block w-full bg-base-900/80 border border-base-500 rounded-lg px-3 py-2 pr-16 text-[13px] text-ink-100 focus:outline-none focus:border-accent placeholder:text-ink-500/50" />
                    <button onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-2 top-1/2 -translate-y-1/2 font-mono text-[10px] text-ink-500 hover:text-accent transition-colors">
                      {showPassword ? "Hide" : "Show"}
                    </button>
                  </div>
                </label>
              </div>

              {/* Test result */}
              {credTestResult && (
                <div className={`p-3 rounded-lg border ${credTestResult.success ? "border-signal/30 bg-signal/5" : "border-sev-high/30 bg-sev-high/5"}`}>
                  <p className={`font-mono text-[12px] font-medium ${credTestResult.success ? "text-signal" : "text-sev-high"}`}>
                    {credTestResult.success ? "✓" : "✕"} {credTestResult.message}
                  </p>
                  {credTestResult.steps.length > 0 && (
                    <ul className="mt-2 space-y-0.5">
                      {credTestResult.steps.map((s, i) => (
                        <li key={i} className="flex items-start gap-2 text-[11px] font-mono"
                            style={{ color: s.status === "ok" ? "#39d98a" : s.status === "failed" ? "#ff4d4d" : "#7a879b" }}>
                          <span className="mt-0.5">{s.status === "ok" ? "✓" : s.status === "failed" ? "✕" : "·"}</span>
                          <span className="text-ink-400">{s.detail || s.step}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              <div className="flex items-center gap-3">
                <button onClick={handleTestAndSaveCreds}
                        disabled={credSaving || !credForm.hostname || !credForm.username || (!creds?.has_password && !credForm.password)}
                        className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
                  {credSaving ? "Testing…" : "Test & Connect"}
                </button>
                <button onClick={() => { setEditingCreds(false); setCredTestResult(null); }}
                        className="px-4 py-2 rounded-lg border border-base-500 text-[13px] text-ink-300 hover:text-ink-100 transition-colors">
                  Cancel
                </button>
              </div>
            </div>
          ) : creds === null ? (
            <p className="font-mono text-[12px] text-ink-500">No saved credentials. Click Edit to configure.</p>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
              <InfoField label="Hostname / IP" value={creds.hostname} mono />
              <InfoField label="Port" value={String(creds.port)} />
              <InfoField label="Username" value={creds.username} mono />
              <InfoField label="Password" value={creds.has_password ? "••••••••" : "—"} mono />
              {creds.last_test_status && (
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-0.5">Last Test</div>
                  <div className="flex items-center gap-1.5 text-[13px]">
                    <span className={`w-1.5 h-1.5 rounded-full ${creds.last_test_status === "ok" ? "bg-signal" : "bg-sev-high"}`} />
                    <span className={`font-mono text-[12px] ${creds.last_test_status === "ok" ? "text-signal" : "text-sev-high"}`}>
                      {creds.last_test_status === "ok" ? "OK" : "Failed"}
                    </span>
                    {creds.last_test_at && (
                      <span className="font-mono text-[10px] text-ink-500 ml-1">{fmtDate(creds.last_test_at)}</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Connection logs panel (collapsible, inside API Config) */}
          {showConnLogs && (
            <div className="mt-4 pt-4 border-t border-base-500/40">
              {connLogsLoading ? (
                <div className="py-4 text-center">
                  <span className="font-mono text-ink-500 text-sm animate-pulse">Loading…</span>
                </div>
              ) : connLogs.length === 0 ? (
                <div className="py-4 text-center">
                  <p className="text-ink-500 text-[13px] font-mono">No connection attempts recorded yet.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-[12px]">
                    <thead>
                      <tr className="text-left font-mono text-[9px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                        <th className="py-2 px-2">Time</th>
                        <th className="py-2 px-2">Trigger</th>
                        <th className="py-2 px-2 hidden sm:table-cell">Host</th>
                        <th className="py-2 px-2 hidden lg:table-cell">Endpoint</th>
                        <th className="py-2 px-2 hidden md:table-cell">Status</th>
                        <th className="py-2 px-2">Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {connLogs.map((l) => (
                        <tr key={l.id} className="table-row border-b border-base-500/30">
                          <td className="py-1.5 px-2 font-mono text-[10px] text-ink-400 whitespace-nowrap">
                            {fmtDate(l.timestamp)}
                          </td>
                          <td className="py-1.5 px-2">
                            <span className="badge text-[9px]" style={{
                              color: l.trigger === "test_connect" ? "#4f8cff" : l.trigger === "api_connect" ? "#39d98a" : "#c084fc",
                              borderColor: l.trigger === "test_connect" ? "#4f8cff55" : l.trigger === "api_connect" ? "#39d98a55" : "#c084fc55",
                              background: l.trigger === "test_connect" ? "#4f8cff14" : l.trigger === "api_connect" ? "#39d98a14" : "#c084fc14",
                            }}>
                              {l.trigger === "test_connect" ? "Test & Connect"
                                : l.trigger === "pull_now" ? "Pull Now"
                                : l.trigger === "scheduled_pull" ? "Scheduled"
                                : "API Connect"}
                            </span>
                          </td>
                          <td className="py-1.5 px-2 font-mono text-[10px] text-ink-300 hidden sm:table-cell">
                            {l.host}:{l.port}
                          </td>
                          <td className="py-1.5 px-2 font-mono text-[10px] text-ink-500 hidden lg:table-cell truncate max-w-[140px]" title={l.endpoint}>
                            {l.endpoint || "—"}
                          </td>
                          <td className="py-1.5 px-2 hidden md:table-cell">
                            {l.http_status ? (
                              <span className="font-mono text-[10px]" style={{ color: l.success ? "#39d98a" : "#ff4d4d" }}>
                                {l.http_status}{l.response_time_ms ? ` · ${(l.response_time_ms / 1000).toFixed(1)}s` : ""}
                              </span>
                            ) : "—"}
                          </td>
                          <td className="py-1.5 px-2">
                            <div className="flex items-center gap-1">
                              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${l.success ? "bg-signal" : "bg-sev-high"}`} />
                              <span className={`text-[10px] font-mono ${l.success ? "text-signal" : "text-sev-high"}`}
                                    title={l.error_message || l.result_summary}>
                                {l.success ? l.result_summary || "OK" : l.error_message || "Failed"}
                              </span>
                            </div>
                            {(l.connected_serial || l.registered_serial) && (
                              <div className="font-mono text-[9px] text-ink-500 mt-0.5">
                                {l.connected_serial && l.registered_serial && l.connected_serial !== l.registered_serial ? (
                                  <>Mismatch: reg {l.registered_serial} ≠ conn {l.connected_serial}</>
                                ) : l.connected_serial ? (
                                  <>Serial: {l.connected_serial}</>
                                ) : null}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── TSR history ───────────────────────────────────────────── */}
      <div className="card-glow">
        <div className="p-5 border-b border-base-500/40">
          <h2 className="font-display font-semibold text-sm text-ink-100">TSR History</h2>
          <p className="font-mono text-[10px] text-ink-500 mt-0.5">
            {device.tsr_count} upload{device.tsr_count !== 1 ? "s" : ""}
          </p>
        </div>
        {device.tsrs.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-ink-500 text-[13px] font-mono">No TSRs uploaded yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                  <th className="py-3 px-4">Filename</th>
                  <th className="py-3 px-4 hidden sm:table-cell">Uploaded</th>
                  <th className="py-3 px-4 hidden sm:table-cell">Mode</th>
                  <th className="py-3 px-4 hidden md:table-cell">Size</th>
                  <th className="py-3 px-4">Analysis</th>
                  <th className="py-3 px-4">Score</th>
                  <th className="py-3 px-4 w-10"></th>
                </tr>
              </thead>
              <tbody>
                {device.tsrs.map((tsr) => (
                  <tr key={tsr.id} className="table-row border-b border-base-500/40">
                    <td className="py-3 px-4 text-ink-100 font-medium max-w-[200px] truncate"
                        title={tsr.filename}>{tsr.filename}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden sm:table-cell">
                      {fmtDate(tsr.uploaded_at)}
                    </td>
                    <td className="py-3 px-4 hidden sm:table-cell">
                      {tsr.uploaded_by && tsr.uploaded_by.length === 36 && tsr.uploaded_by.includes("-") ? (
                        <span className="badge" style={{ color: "#4f8cff", borderColor: "#4f8cff55", background: "#4f8cff14" }}>Manual</span>
                      ) : tsr.uploaded_by === "api-connect" || tsr.uploaded_by === "api-pull" ? (
                        <span className="badge" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>API (Pull)</span>
                      ) : tsr.uploaded_by === "api-scheduled" ? (
                        <span className="badge" style={{ color: "#c084fc", borderColor: "#c084fc55", background: "#c084fc14" }}>API (Auto)</span>
                      ) : (
                        <span className="text-ink-500 text-[12px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden md:table-cell">
                      {tsr.size_bytes > 1024 * 1024
                        ? `${(tsr.size_bytes / (1024 * 1024)).toFixed(1)} MB`
                        : `${(tsr.size_bytes / 1024).toFixed(0)} KB`}
                    </td>
                    <td className="py-3 px-4">
                      {tsr.analysis_status ? (
                        <span className={`badge ${
                          tsr.analysis_status === "complete" ? ""
                          : tsr.analysis_status === "failed" ? "text-sev-high border-sev-high/30 bg-sev-high/10"
                          : "text-ink-300 border-base-500 bg-base-700/50"
                        }`}
                        style={tsr.analysis_status === "complete"
                          ? { color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }
                          : undefined}>
                          {tsr.analysis_status}
                        </span>
                      ) : (
                        <span className="text-ink-500 text-[12px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {tsr.analysis_score != null && tsr.analysis_grade ? (
                        <span className="font-display font-bold text-xs tabular-nums"
                              style={{ color: gradeColor(tsr.analysis_grade) }}>
                          {tsr.analysis_score.toFixed(0)}% {tsr.analysis_grade}
                        </span>
                      ) : (
                        <span className="text-ink-500 text-[12px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1">
                        <button onClick={async () => {
                          try {
                            await api.toggleTsrFavorite(tsr.id, !tsr.favorite);
                            load();
                          } catch (e) {
                            alert(e instanceof Error ? e.message : "Failed to update favorite");
                          }
                        }}
                                title={tsr.favorite ? "Unfavorite" : "Favorite (max 5)"}
                                className={`w-7 h-7 grid place-items-center rounded-lg border transition-colors text-sm leading-none ${
                                  tsr.favorite
                                    ? "border-[#f5c45155] text-[#f5c451] hover:bg-[#f5c45114]"
                                    : "border-base-500 text-ink-500 hover:text-[#f5c451] hover:border-[#f5c45155]"
                                }`}>
                          {tsr.favorite ? "★" : "☆"}
                        </button>
                        <button onClick={async () => {
                          try { await api.downloadTsr(tsr.id, tsr.filename); }
                          catch (e) { alert(e instanceof Error ? e.message : "Download failed"); }
                        }}
                                title="Download TSR"
                                className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-accent hover:border-accent/50 transition-colors text-sm leading-none">
                          ↓
                        </button>
                        <button onClick={() => handleDeleteTsr(tsr.id, tsr.filename)}
                                title="Delete TSR"
                                className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-sev-high hover:border-sev-high/50 transition-colors text-sm leading-none">
                          ×
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Schedule summary formatter ──────────────────────────────────────────
function formatScheduleSummary(s: { frequency: string; hour: number; minute: number;
  day_of_week: number | null; day_of_month: number | null; next_run_at?: string | null }) {
  const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const hh = String(s.hour).padStart(2, "0");
  const mm = String(s.minute).padStart(2, "0");
  const time = `${hh}:${mm}`;
  const freq = (s.frequency || "").toLowerCase();
  if (freq === "hourly") return `Every hour at minute ${s.minute} (UTC)`;
  if (freq === "daily") return `Every day at ${time} UTC`;
  if (freq === "weekly") return `Every ${DAYS[s.day_of_week ?? 0]} at ${time} UTC`;
  if (freq === "monthly") return `Every month on the ${s.day_of_month ?? 1}${nth(s.day_of_month ?? 1)} at ${time} UTC`;
  return `${hh}:${mm} UTC`;
}
function nth(n: number): string {
  if (n >= 11 && n <= 13) return "th";
  const d = n % 10;
  return d === 1 ? "st" : d === 2 ? "nd" : d === 3 ? "rd" : "th";
}

// ── Schedule configuration (auto mode) ──────────────────────────────────
function ScheduleConfig({ form, onChange, onSave, saving, onCancel }: {
  form: { frequency: string; hour: number; minute: number; day_of_week: number; day_of_month: number; enabled: boolean };
  onChange: (f: typeof form) => void;
  onSave: () => void;
  saving: boolean;
  onCancel?: () => void;
}) {
  const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const HOURS = Array.from({ length: 24 }, (_, i) => i);
  const MINUTES = Array.from({ length: 60 }, (_, i) => i);
  const frequency = form.frequency;

  return (
    <div className="flex flex-wrap items-end gap-3">
      <label className="block">
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Frequency</span>
        <select value={frequency} onChange={(e) => onChange({ ...form, frequency: e.target.value })}
                className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
          <option value="hourly">Hourly</option>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </label>
      {frequency === "monthly" && (
        <label className="block">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Day of month</span>
          <select value={form.day_of_month}
                  onChange={(e) => onChange({ ...form, day_of_month: Number(e.target.value) })}
                  className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
            {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
        </label>
      )}
      {frequency === "weekly" && (
        <label className="block">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Day of week</span>
          <select value={form.day_of_week}
                  onChange={(e) => onChange({ ...form, day_of_week: Number(e.target.value) })}
                  className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
            {DAYS.map((d, i) => (
              <option key={i} value={i}>{d}</option>
            ))}
          </select>
        </label>
      )}
      {frequency !== "hourly" && (
        <label className="block">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Hour (UTC)</span>
          <select value={form.hour} onChange={(e) => onChange({ ...form, hour: Number(e.target.value) })}
                  className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
            {HOURS.map((h) => (
              <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>
            ))}
          </select>
        </label>
      )}
      <label className="block">
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Minute</span>
        <select value={form.minute}
                onChange={(e) => onChange({ ...form, minute: Number(e.target.value) })}
                className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
          {frequency === "hourly"
            ? MINUTES.map((m) => (<option key={m} value={m}>:{String(m).padStart(2, "0")}</option>))
            : [0, 15, 30, 45].map((m) => (<option key={m} value={m}>:{String(m).padStart(2, "0")}</option>))}
        </select>
      </label>
      <button onClick={onSave} disabled={saving}
              className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
        {saving ? "Saving…" : "Save Schedule"}
      </button>
      {onCancel && (
        <button onClick={onCancel}
                className="px-4 py-2 rounded-lg border border-base-500 text-[13px] text-ink-300 hover:text-ink-100 transition-colors">
          Cancel
        </button>
      )}
    </div>
  );
}

// ── Info field helper ─────────────────────────────────────────────────
function InfoField({ label, value, mono, color }: {
  label: string; value: string; mono?: boolean; color?: string;
}) {
  return (
    <div>
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-0.5">{label}</div>
      <div className={`text-[13px] text-ink-100 ${mono ? "font-mono" : ""}`}
           style={color ? { color } : undefined}>
        {value}
      </div>
    </div>
  );
}
