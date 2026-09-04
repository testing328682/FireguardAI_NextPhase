import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { createPortal } from "react-dom";
import { usePrompt } from "./Modal";
import { api } from "../lib/api";
import type { FindingRow, FindingStatus, Customer, Device, AnalysisSummary, DriftCompare, ExecutiveSummary, RiskTrend, FindingGroup } from "../lib/types";
import { navigate } from "../lib/router";
import {
  SEVERITIES, sevColor, STATUS_LABEL, statusColor, fmtDate, ACTIVE_STATUSES, triggerDownload, gradeColor,
} from "../lib/ui";
import { SummaryCard, RiskTrendWidget, AnimatedValue, Delta, FindingsBySeverityWidget } from "./SecurityAnalytics";

const RANGES: { label: string; days: number }[] = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "1y", days: 365 },
];

interface Filters { severity: string[]; status: string[]; category: string[]; q: string; }
const EMPTY: Filters = { severity: [], status: [], category: [], q: "" };
const SAVED_KEY = "fgai_saved_views";
const PAGE_SIZES = [25, 50, 100];
interface SavedView { name: string; filters: Filters }

function hashParam(name: string): string {
  return new URLSearchParams(window.location.hash.split("?")[1] || "").get(name) || "";
}

// ── Findings Explorer (device-centric) ─────────────────────────────────
export function FindingsExplorer({ backRoute }: { backRoute?: string }) {
  const [isMsp, setIsMsp] = useState(false);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [customerId, setCustomerId] = useState<string>(hashParam("customer"));
  const [deviceId, setDeviceId] = useState<string>(hashParam("device"));
  const [searchQ, setSearchQ] = useState("");
  const [globalVisOpen, setGlobalVisOpen] = useState(false);
  const [quickFilter, setQuickFilter] = useState<{ severity?: string; status?: string } | null>(null);
  const prompt = usePrompt();

  useEffect(() => {
    api.getOrganization().then((o) => setIsMsp(o.is_msp)).catch(() => {});
    api.listCustomers().then(setCustomers).catch(() => {});
    api.listDevices().then(setDevices).catch(() => {});
  }, []);

  // Load all findings for aggregate stats (KPI strip)
  const [allRows, setAllRows] = useState<FindingRow[]>([]);
  // Load all findings — customer filtering done client-side for reliability
  // Load findings — reloads when deviceId or customerId changes
  useEffect(() => {
    const params: Record<string, string> = { limit: "500" };
    if (deviceId) params.device_id = deviceId;
    else if (customerId) params.customer_id = customerId;
    api.listFindings(params).then(setAllRows).catch(() => setAllRows([]));
  }, [deviceId, customerId]);

  const scopedDevices = useMemo(() => {
    let filtered = customerId
      ? devices.filter((d) => d.customer_id === customerId)
      : devices;
    filtered = filtered.filter((d) => d.configured);
    if (searchQ) {
      const q = searchQ.toLowerCase();
      filtered = filtered.filter((d) =>
        (d.friendly_name || "").toLowerCase().includes(q) ||
        (d.model || "").toLowerCase().includes(q) ||
        (d.serial || "").toLowerCase().includes(q)
      );
    }
    return filtered;
  }, [devices, customerId, searchQ]);

  // Load org visibility for global filter (declared early — used by stats)
  const [orgHidden, setOrgHidden] = useState<string[]>([]);

  const stats = useMemo(() => {
    // GROUPED counts: one logical finding per (device, rule). A rule affecting
    // N objects counts once for its severity/status (see buildRowGroups), so
    // this strip agrees with the account Dashboard and Security Analytics.
    const sev: Record<string, number> = {};
    const sevTotal: Record<string, number> = {};
    for (const s of SEVERITIES) { sev[s] = 0; sevTotal[s] = 0; }
    const hiddenSet = new Set(orgHidden);
    const groups = buildRowGroups(allRows.filter((r) => !hiddenSet.has(r.severity)));
    let resolved = 0, open = 0, inProgress = 0;
    for (const g of groups) {
      sevTotal[g.severity] = (sevTotal[g.severity] || 0) + 1;
      if (g.status === "fixed") { resolved++; }
      else {
        sev[g.severity] = (sev[g.severity] || 0) + 1;
        if (g.affectedFixed > 0) inProgress++; else open++;
      }
    }
    const selectedDevice = deviceId ? (devices.find((d) => d.id === deviceId) ?? null) : null;
    return { sev, sevTotal, resolved, open, inProgress, selectedDevice, total: groups.length };
  }, [allRows, deviceId, devices, orgHidden]);

  const customerName = (id: string) => customers.find((c) => c.id === id)?.name || id;

  useEffect(() => {
    api.getOrganization().then((o) => {
      const allowed = new Set(["Medium", "Low", "Info"]);
      setOrgHidden((o.hidden_severities || []).filter((s: string) => allowed.has(s)));
    }).catch(() => {});
  }, []);

  // ── Device-scoped KPI widgets (Security Analytics context only) ──────
  const [deviceSummary, setDeviceSummary] = useState<ExecutiveSummary | null>(null);
  const [deviceRiskTrend, setDeviceRiskTrend] = useState<RiskTrend | null>(null);
  const [deviceRangeDays, setDeviceRangeDays] = useState(30);
  const localToday = useCallback(() => {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${String(now.getDate()).padStart(2,"0")}`;
  }, []);
  const localTzOffset = useCallback(() => new Date().getTimezoneOffset(), []);
  const refreshDeviceData = useCallback(() => {
    if (!backRoute || !deviceId) return;
    const lt = localToday();
    const tzo = localTzOffset();
    api.executiveSummary(deviceRangeDays, undefined, deviceId, lt, tzo).then(setDeviceSummary).catch(() => setDeviceSummary(null));
    api.riskTrend(deviceRangeDays, undefined, deviceId, lt, tzo).then(setDeviceRiskTrend).catch(() => setDeviceRiskTrend(null));
  }, [backRoute, deviceId, deviceRangeDays, localToday, localTzOffset]);
  useEffect(() => {
    if (backRoute && deviceId) {
      refreshDeviceData();
    } else {
      setDeviceSummary(null);
      setDeviceRiskTrend(null);
    }
  }, [backRoute, deviceId, deviceRangeDays]);

  // If a device is selected, show device-specific findings view
  if (deviceId) {
    return (
      <DeviceFindingsView
        deviceId={deviceId}
        stats={stats}
        onBack={() => { if (backRoute) { navigate(backRoute); } else { setDeviceId(""); } }}
        findingDetailRoute="/security-analytics/finding"
        deviceSummary={backRoute ? deviceSummary : null}
        deviceRiskTrend={backRoute ? deviceRiskTrend : null}
        rangeDays={deviceRangeDays}
        setRangeDays={setDeviceRangeDays}
        onRefresh={refreshDeviceData}
        orgHidden={orgHidden}
      />
    );
  }

  // ── Device list (default view) ──────────────────────────────────
  return (
    <div className="max-w-[1440px] fade-in space-y-5">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Findings</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">
            {customerId
              ? `Customer: ${customerName(customerId)} · ${scopedDevices.length} device${scopedDevices.length !== 1 ? "s" : ""}`
              : `${scopedDevices.length} configured device${scopedDevices.length !== 1 ? "s" : ""}`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isMsp && (
            <label className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Customer</span>
              <select value={customerId} onChange={(e) => { setCustomerId(e.target.value); setDeviceId(""); }}
                      className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                <option value="">All customers</option>
                {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
            </label>
          )}
          <label className="flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Search</span>
            <input value={searchQ} onChange={(e) => setSearchQ(e.target.value)}
                   placeholder="name, model, serial…"
                   className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent w-44 placeholder:text-ink-500/50" />
          </label>
          <button onClick={() => setGlobalVisOpen(true)}
                  className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
            Filter
          </button>
        </div>
      </div>

      {/* ── Global visibility modal ─────────────────────────────────── */}
      {globalVisOpen && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setGlobalVisOpen(false)} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={() => setGlobalVisOpen(false)}>
            <div className="w-full max-w-[420px] bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
                 onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="font-display font-semibold text-ink-100">Global Findings Filter</h3>
                <button onClick={() => setGlobalVisOpen(false)}
                        className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors">×</button>
              </div>
              <p className="font-mono text-[11px] text-ink-500">
                Hidden severities apply to all devices unless overridden per device.
              </p>
              <div className="space-y-2">
                {(["Medium", "Low", "Info"] as const).map((sev) => {
                  const isHidden = orgHidden.includes(sev);
                  return (
                    <div key={sev} className="flex items-center justify-between py-1.5 px-3 rounded bg-base-800/50">
                      <span className="text-[13px] font-medium" style={{ color: sevColor[sev] }}>{sev}</span>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" checked={!isHidden}
                               onChange={() => {
                                 const next = orgHidden.includes(sev) ? orgHidden.filter((s) => s !== sev) : [...orgHidden, sev];
                                 setOrgHidden(next);
                                 api.updateOrgVisibility(next).catch(() => {});
                               }}
                               className="sr-only peer" />
                        <div className={`w-9 h-5 rounded-full peer border transition-colors ${isHidden ? "bg-base-600 border-base-500" : "bg-accent/30 border-accent"}`}>
                          <div className={`w-3.5 h-3.5 rounded-full bg-white mt-[2.5px] transition-transform ${isHidden ? "ml-1" : "ml-[18px]"}`} />
                        </div>
                      </label>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Quick findings modal (from KPI click) ────────────────────── */}
      {quickFilter && (
        <QuickFindingsModal
          filter={quickFilter}
          allRows={allRows}
          devices={scopedDevices}
          onClose={() => setQuickFilter(null)}
          onSelectDevice={(did) => { setDeviceId(did); setQuickFilter(null); }}
        />
      )}

      {/* ── KPI strip ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
        <KpiCard label="Devices" value={scopedDevices.length} color="#4f8cff"
                 sub="configured" icon={<IconServer />} />
        <KpiCard label="Critical" value={stats.sev.Critical || 0} color="#ff4d4d"
                 sub={`${(stats.sevTotal.Critical || 0) - (stats.sev.Critical || 0)}/${stats.sevTotal.Critical || 0} Fixed`}
                 alert={(stats.sev.Critical || 0) > 0} icon={<IconAlert />}
                 onClick={() => setQuickFilter(q => q?.severity === "Critical" ? null : { severity: "Critical" })} />
         <KpiCard label="High" value={stats.sev.High || 0} color="#ff8a3d"
                  sub={`${(stats.sevTotal.High || 0) - (stats.sev.High || 0)}/${stats.sevTotal.High || 0} Fixed`}
                  icon={<IconFlag />}
                  onClick={() => setQuickFilter(q => q?.severity === "High" ? null : { severity: "High" })} />
         <KpiCard label="Medium" value={stats.sev.Medium || 0} color="#f5c451"
                  sub={`${(stats.sevTotal.Medium || 0) - (stats.sev.Medium || 0)}/${stats.sevTotal.Medium || 0} Fixed`}
                  icon={<IconDot />}
                  onClick={() => setQuickFilter(q => q?.severity === "Medium" ? null : { severity: "Medium" })} />
         <KpiCard label="Low" value={stats.sev.Low || 0} color="#4a9eff"
                  sub={`${(stats.sevTotal.Low || 0) - (stats.sev.Low || 0)}/${stats.sevTotal.Low || 0} Fixed`}
                  icon={<IconDot />}
                  onClick={() => setQuickFilter(q => q?.severity === "Low" ? null : { severity: "Low" })} />
         <KpiCard label="In Progress" value={stats.inProgress} color="#9ad94a"
                  sub="active triage" icon={<IconClock />}
                  onClick={() => setQuickFilter(q => q?.status === "in_progress" ? null : { status: "in_progress" })} />
         <KpiCard label="Resolved" value={stats.resolved} color="#39d98a"
                  sub="fixed · dismissed" icon={<IconCheck />}
                  onClick={() => setQuickFilter(q => q?.status === "fixed" ? null : { status: "fixed" })} />
      </div>

      {/* ── Device list ─────────────────────────────────────────────── */}
      {scopedDevices.length === 0 ? (
        <div className="card-glow p-16 text-center fade-in">
          <div className="text-5xl mb-4 opacity-30">🔍</div>
          <h2 className="font-display font-semibold text-ink-100 text-lg mb-2">No configured devices</h2>
          <p className="text-ink-500 text-sm max-w-sm mx-auto font-mono">
            Register and configure a device to start viewing findings.
          </p>
        </div>
      ) : (
        <div className="card-glow">
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                  <th className="py-3 px-4">Device</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Customer</th>
                  <th className="py-3 px-4">Score</th>
                  <th className="py-3 px-4 hidden sm:table-cell">Critical</th>
                  <th className="py-3 px-4 hidden md:table-cell">High</th>
                  <th className="py-3 px-4 hidden md:table-cell">Medium</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Low</th>
                  <th className="py-3 px-4">Open</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Last Scan</th>
                </tr>
              </thead>
              <tbody>
                {scopedDevices.map((d) => (
                  <tr key={d.id}
                      onClick={() => setDeviceId(d.id)}
                      className="table-row border-b border-base-500/40 cursor-pointer hover:bg-base-700/30 transition-colors">
                    <td className="py-3 px-4">
                      <div className="text-ink-100 font-medium">{d.friendly_name || d.model || d.serial}</div>
                      <div className="font-mono text-[10px] text-ink-500 mt-0.5">
                        {d.model || d.serial} · {d.connection_method === "api" ? "API" : "TSR"}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px] text-ink-500 hidden lg:table-cell">
                      {customerName(d.customer_id)}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 min-w-[70px]">
                        <div className="h-1.5 flex-1 rounded-full bg-base-700 overflow-hidden max-w-[50px]">
                          <div className="h-full rounded-full" style={{
                            width: `${d.latest_score || 0}%`,
                            background: gradeColor(d.latest_grade),
                          }} />
                        </div>
                        <span className="font-display font-bold text-xs tabular-nums"
                              style={{ color: gradeColor(d.latest_grade) }}>
                          {d.latest_grade || "—"}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 hidden sm:table-cell">
                      <span className={`font-mono text-xs font-semibold ${d.critical_count > 0 ? "text-[#ff4d4d]" : "text-ink-500"}`}>
                        {d.critical_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 hidden md:table-cell">
                      <span className={`font-mono text-xs font-semibold ${d.high_count > 0 ? "text-[#ff8a3d]" : "text-ink-500"}`}>
                        {d.high_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 hidden md:table-cell">
                      <span className={`font-mono text-xs font-semibold ${d.medium_count > 0 ? "text-[#f5c451]" : "text-ink-500"}`}>
                        {d.medium_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 hidden lg:table-cell">
                      <span className={`font-mono text-xs font-semibold ${d.low_count > 0 ? "text-[#4a9eff]" : "text-ink-500"}`}>
                        {d.low_count}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`font-mono text-xs font-semibold ${
                        (d.critical_count + d.high_count + d.medium_count + d.low_count) > 0 ? "text-ink-100" : "text-ink-500"
                      }`}>
                        {d.critical_count + d.high_count + d.medium_count + d.low_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden lg:table-cell">
                      {d.last_analysis_at ? fmtDate(d.last_analysis_at) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// A logical finding for the list: one detection rule and every object it
// affects, derived client-side from the snapshot rows (which already carry
// live triage status). Mirrors the backend finding_groups semantics so the
// list, its counts, and the detail view all agree.
const _RESOLVED_STATES = new Set(["fixed", "false_positive", "accepted_risk"]);
interface RowGroup {
  ruleId: string; severity: string; title: string; category: string;
  status: FindingStatus; affectedTotal: number; affectedOpen: number;
  affectedFixed: number; repId: string; rep: FindingRow; openIds: string[];
  lastSeen: string; source?: string;
}
// `liveByKey` supplies the authoritative parent status per group (keyed by
// FindingGroup.group_id, i.e. "<device_id>::<rule_id>") from GET
// /finding-groups — the same source the backend Dashboard/Security Analytics
// use. Without it, a single-instance group's own status is already correct
// (see below); a multi-instance group falls back to "open" (never derived as
// fixed client-side) so it can never show "Fixed" ahead of the real,
// explicitly-set parent status.
function buildRowGroups(rows: FindingRow[], liveByKey?: Record<string, FindingGroup>): RowGroup[] {
  const buckets = new Map<string, FindingRow[]>();
  for (const r of rows) {
    // Key by device + rule so the same rule on two devices stays two findings.
    const k = `${r.device_id}::${r.rule_id || r.title}`;
    (buckets.get(k) ?? buckets.set(k, []).get(k)!).push(r);
  }
  const sevOrder = ["Critical", "High", "Medium", "Low", "Info"];
  const out: RowGroup[] = [];
  for (const [key, insts] of buckets) {
    const fixed = insts.filter((i) => _RESOLVED_STATES.has(i.status)).length;
    const open = insts.length - fixed;   // suppressed counts as open, not excluded
    // A single-instance group has no separate parent — its own status is
    // authoritative directly. A multi-instance group uses the real,
    // explicitly-set parent status (never auto-derived from its children).
    const status: FindingStatus = insts.length === 1
      ? insts[0].status
      : (liveByKey?.[key]?.status ?? "open");
    // Prefer an open instance with a real (persisted) id for the detail link.
    const real = (i: FindingRow) => !String(i.id).startsWith("snapshot-");
    const openReal = insts.find((i) => !_RESOLVED_STATES.has(i.status) && real(i));
    const anyReal = insts.find(real);
    const rep = openReal || anyReal || insts[0];
    const rep0 = insts[0];
    out.push({
      ruleId: rep0.rule_id, severity: rep0.severity, title: rep0.title, category: rep0.category,
      status, affectedTotal: insts.length, affectedOpen: open, affectedFixed: fixed,
      repId: rep.id, rep,
      openIds: insts.filter((i) => !_RESOLVED_STATES.has(i.status) && real(i)).map((i) => i.id),
      lastSeen: insts.reduce((m, i) => (i.last_seen_at > m ? i.last_seen_at : m), rep0.last_seen_at),
      source: rep0.source,
    });
  }
  out.sort((a, b) =>
    (sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity)) ||
    (b.affectedOpen - a.affectedOpen) || a.title.localeCompare(b.title));
  return out;
}

// ── Device-specific findings view ──────────────────────────────────────
function DeviceFindingsView({ deviceId, stats, onBack, findingDetailRoute, deviceSummary, deviceRiskTrend, rangeDays, setRangeDays, onRefresh, orgHidden: parentOrgHidden }: {
  deviceId: string;
  stats: { sev: Record<string, number>; resolved: number; open: number; inProgress: number; selectedDevice: Device | null; total: number };
  onBack: () => void;
  findingDetailRoute: string;
  deviceSummary: ExecutiveSummary | null;
  deviceRiskTrend: RiskTrend | null;
  rangeDays: number;
  setRangeDays: (d: number) => void;
  onRefresh: () => void;
  orgHidden: string[];
}) {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [allAnalysisRows, setAllAnalysisRows] = useState<FindingRow[]>([]);
  const [autoRefreshS, setAutoRefreshS] = useState(0);
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);
  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    if (autoRefreshRef.current) { clearInterval(autoRefreshRef.current); autoRefreshRef.current = null; }
    if (autoRefreshS > 0) {
      autoRefreshRef.current = setInterval(onRefresh, autoRefreshS * 1000);
    }
    return () => { if (autoRefreshRef.current) clearInterval(autoRefreshRef.current); };
  }, [autoRefreshS, onRefresh]);
  useEffect(() => {
    if (!exportOpen) return;
    const h = (e: MouseEvent) => { if (exportRef.current && !exportRef.current.contains(e.target as Node)) setExportOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [exportOpen]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [views, setViews] = useState<SavedView[]>(() => {
    try { return JSON.parse(localStorage.getItem(SAVED_KEY) || "[]"); } catch { return []; }
  });
  const prompt = usePrompt();

  const device = stats.selectedDevice;

  // TSR / analysis list for dropdown and comparison
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string>("");
  const [compareOpen, setCompareOpen] = useState(false);
  const [compareTsr1, setCompareTsr1] = useState<string>("");
  const [compareTsr2, setCompareTsr2] = useState<string>("");
  const [compareResult, setCompareResult] = useState<DriftCompare | null>(null);
  const [compareBusy, setCompareBusy] = useState(false);
  const [detailReport, setDetailReport] = useState(false); // full side-by-side
  const [detailFindings1, setDetailFindings1] = useState<FindingRow[]>([]);
  const [detailFindings2, setDetailFindings2] = useState<FindingRow[]>([]);
  const [visOpen, setVisOpen] = useState(false);
  const [addFindingOpen, setAddFindingOpen] = useState(false);
  const [newFinding, setNewFinding] = useState({ severity: "Medium", title: "", category: "", object_name: "", status: "open", description: "", business_impact: "", technical_impact: "", remediation: "", evidence: "" });
  const [editingFinding, setEditingFinding] = useState<FindingRow | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [newFindingBusy, setNewFindingBusy] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    api.listDeviceAnalyses(deviceId).then((a) => {
      setAnalyses(a);
      // Default to latest completed analysis
      const completed = a.filter((x) => x.status === "complete");
      if (completed.length > 0) setSelectedAnalysisId(completed[0].id);
    }).catch(() => setAnalyses([]));
  }, [deviceId]);

  // Load ALL findings for selected analysis (no filters) — KPIs use this
  const loadFindings = useCallback(async () => {
    if (!selectedAnalysisId) { setAllAnalysisRows([]); return; }
    setBusy(true); setErr(null);
    try {
      setAllAnalysisRows(await api.listAnalysisFindings(selectedAnalysisId, { limit: "500" }));
      setSelected(new Set());
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load findings");
    } finally { setBusy(false); }
  }, [selectedAnalysisId]);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  // Authoritative parent status per grouped finding (live, current — not tied
  // to the selected TSR snapshot), the same source the Dashboard and Security
  // Analytics read. Row groups below use this instead of re-deriving a status
  // client-side, so this list can never show "Fixed" ahead of a real,
  // explicitly-set parent status.
  const [liveGroups, setLiveGroups] = useState<FindingGroup[]>([]);
  const refreshLiveGroups = useCallback(() => {
    api.listFindingGroups({ device_id: deviceId }).then(setLiveGroups).catch(() => {});
  }, [deviceId]);
  useEffect(() => { refreshLiveGroups(); }, [refreshLiveGroups]);
  const liveByKey = useMemo(
    () => Object.fromEntries(liveGroups.map((g) => [g.group_id, g])),
    [liveGroups]);

  // Load org + device visibility settings
  const [orgHidden, setOrgHidden] = useState<string[]>([]);
  const [devHidden, setDevHidden] = useState<string[]>([]);
  const [inheritGlobal, setInheritGlobal] = useState(true);
  useEffect(() => {
    api.getOrganization().then((o) => {
      const allowed = new Set(["Medium", "Low", "Info"]);
      setOrgHidden((o.hidden_severities || []).filter((s: string) => allowed.has(s)));
    }).catch(() => {});
    if (deviceId) {
      api.getDevice(deviceId).then((d) => {
        const dh = d.hidden_severities || [];
        setDevHidden(dh);
        setInheritGlobal(dh.length === 0);
      }).catch(() => {});
    }
  }, [deviceId]);

  // Effective hidden severities: inherit flag controls source
  const effHidden = inheritGlobal ? orgHidden : devHidden;

  // ── Pagination ──────────────────────────────────────────────
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);

  // Reset to the first page whenever the filter set, data source or page size
  // changes. This covers every filter entry point (dropdowns, KPI cards, saved
  // views, reset, search) so pagination can never be left pointing past the end
  // of a freshly-filtered result set.
  useEffect(() => {
    setPage(0);
  }, [filters.severity, filters.status, filters.category, filters.q,
      selectedAnalysisId, orgHidden, devHidden, pageSize]);

  // Step 1: filter (OR within each type, AND across types)
  const filteredRows = useMemo(() => {
    let r = allAnalysisRows;
    if (filters.severity.length) r = r.filter((f) => filters.severity.includes(f.severity));
    if (filters.status.length) r = r.filter((f) => filters.status.includes(f.status));
    if (filters.category.length) r = r.filter((f) => filters.category.includes(f.category));
    if (filters.q) {
      const ql = filters.q.toLowerCase();
      r = r.filter((f) => f.title.toLowerCase().includes(ql) || (f.object_name || "").toLowerCase().includes(ql));
    }
    const hidden = effHidden;
    if (hidden.length > 0) r = r.filter((row) => !hidden.includes(row.severity));
    // Sort by severity: Critical → High → Medium → Low → Info
    const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    r = [...r].sort((a, b) => (sevOrder[(a.severity || "").toLowerCase()] ?? 9) - (sevOrder[(b.severity || "").toLowerCase()] ?? 9));
    return r;
  }, [allAnalysisRows, filters.severity, filters.status, filters.category, filters.q, orgHidden, devHidden]);

  // One row per logical finding (rule), with its affected-object instances.
  const filteredGroups = useMemo(() => buildRowGroups(filteredRows, liveByKey), [filteredRows, liveByKey]);
  const totalFiltered = filteredGroups.length;

  const filteredRiskTrend = useMemo(() => {
    if (!deviceRiskTrend || effHidden.length === 0) return deviceRiskTrend;
    return {
      ...deviceRiskTrend,
      trend: deviceRiskTrend.trend.map((p: any) => { const r = { ...p }; for (const s of effHidden) delete r[s]; return r; }),
      deltas: (() => { const d = { ...deviceRiskTrend.deltas }; for (const s of effHidden) delete d[s]; return d; })(),
    };
  }, [deviceRiskTrend, effHidden]);
  const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));

  // Clamp the active page so an out-of-range index (e.g. left over from a larger
  // result set) can never produce a stale or empty slice, even for the single
  // render before the reset effect above commits.
  const safePage = Math.min(page, totalPages - 1);

  // Step 2: paginate groups using the clamped page.
  const displayGroups = useMemo(() => {
    return filteredGroups.slice(safePage * pageSize, (safePage + 1) * pageSize);
  }, [filteredGroups, safePage, pageSize]);

  // KPI stats for the selected analysis — GROUPED: one logical finding per
  // rule. A rule affecting N objects counts once for its severity/status, so
  // these agree with the account-level Dashboard and Security Analytics.
  const analysisStats = useMemo(() => {
    const sev: Record<string, number> = {};
    const sevTotal: Record<string, number> = {};
    for (const s of SEVERITIES) { sev[s] = 0; sevTotal[s] = 0; }
    const hiddenSet = new Set(effHidden);
    const groups = buildRowGroups(allAnalysisRows.filter((r) => !hiddenSet.has(r.severity)), liveByKey);
    let open = 0, resolved = 0, inProgress = 0;
    for (const g of groups) {
      sevTotal[g.severity] = (sevTotal[g.severity] || 0) + 1;
      if (_RESOLVED_STATES.has(g.status)) { resolved++; }
      else {
        sev[g.severity] = (sev[g.severity] || 0) + 1;
        if (g.status === "open") open++; else inProgress++;
      }
    }
    const selAnalysis = selectedAnalysisId ? analyses.find((a) => a.id === selectedAnalysisId) : null;
    return { sev, sevTotal, resolved, open, inProgress, totalFindings: groups.length, score: selAnalysis?.score || 0, grade: selAnalysis?.grade || "" };
  }, [allAnalysisRows, selectedAnalysisId, analyses, orgHidden, devHidden, liveByKey]);

  // Findings by Severity widget — derived from the SAME population as the
  // summary strip above: the selected TSR's snapshot findings cross-referenced
  // with live triage status (analysisStats). Active-status counts per severity,
  // percentages against the active total, so the widget and the KPI strip can
  // never disagree (previously this widget read the live findings table via
  // dashboard-charts, which is a different population — e.g. 140 vs 252).
  const severityDist = useMemo(() => {
    const dist: Record<string, { count: number; pct: number }> = {};
    const total = SEVERITIES.reduce((s, sev) => s + (analysisStats.sev[sev] || 0), 0);
    for (const sev of SEVERITIES) {
      const count = analysisStats.sev[sev] || 0;
      dist[sev] = { count, pct: total > 0 ? Math.round((count / total) * 1000) / 10 : 0 };
    }
    return { dist, total };
  }, [analysisStats]);

  async function exportReport(kind: "technical" | "csv" | "xlsx") {
    if (!selectedAnalysisId) return;
    setExporting(true); setErr(null);
    try {
      const blob = await api.downloadReport(selectedAnalysisId, kind);
      triggerDownload(blob, `findings-${deviceId.slice(0, 8)}.${kind === "technical" ? "pdf" : kind}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Export failed");
    } finally { setExporting(false); }
  }

  const [exporting, setExporting] = useState(false);

  async function runCompare() {
    if (!compareTsr1 || !compareTsr2) return;
    setCompareBusy(true); setDetailReport(false);
    try {
      const res = await api.compareAnalyses(deviceId, compareTsr1, compareTsr2);
      setCompareResult(res);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Comparison failed");
    } finally { setCompareBusy(false); }
  }

  async function loadDetailedReport() {
    if (!compareTsr1 || !compareTsr2) return;
    setCompareBusy(true);
    try {
      const [f1, f2] = await Promise.all([
        api.listAnalysisFindings(compareTsr1, { limit: "1000" }),
        api.listAnalysisFindings(compareTsr2, { limit: "1000" }),
      ]);
      setDetailFindings1(f1);
      setDetailFindings2(f2);
      setDetailReport(true);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load detailed report");
    } finally { setCompareBusy(false); }
  }

  async function saveCurrentView() {
    const name = await prompt("Save View", "", "e.g. Critical WAN rules");
    if (!name) return;
    const next = [...views.filter((v) => v.name !== name), { name, filters }];
    setViews(next);
    localStorage.setItem(SAVED_KEY, JSON.stringify(next));
  }
  function deleteView(name: string) {
    const next = views.filter((v) => v.name !== name);
    setViews(next);
    localStorage.setItem(SAVED_KEY, JSON.stringify(next));
  }
  async function bulkApply(to_status: FindingStatus) {
    if (selected.size === 0) return;
    const comment = await prompt("Bulk Action", "", `Moving ${selected.size} finding(s) to ${STATUS_LABEL[to_status]} — add a comment`);
    if (!comment) return;
    try {
      await api.bulkTransition({ finding_ids: [...selected], to_status, comment });
      await loadFindings();
      refreshLiveGroups();
    }
    catch (e) { setErr(e instanceof Error ? e.message : "Bulk action failed"); }
  }

  const completedAnalyses = analyses.filter((a) => a.status === "complete");
  const canCompare = completedAnalyses.length >= 2;

  return (
    <div className="max-w-[1440px] fade-in space-y-5">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <button onClick={onBack}
                  className="text-ink-500 hover:text-ink-100 text-[12px] font-mono mb-1 inline-block">
            ← All Devices
          </button>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">
            {device?.friendly_name || device?.model || "Device"}
          </h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">
            {device?.serial} · {device?.model}{device?.firmware ? ` · ${device.firmware}` : ""}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {/* TSR / Analysis selector */}
          <label className="flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-widest text-ink-500">TSR</span>
            <select value={selectedAnalysisId} onChange={(e) => setSelectedAnalysisId(e.target.value)}
                    className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent max-w-[280px] truncate">
              {analyses.filter((a) => a.status === "complete").map((a) => (
                <option key={a.id} value={a.id}>
                  {fmtDate(a.created_at)} · {a.grade} · {a.finding_count} findings
                </option>
              ))}
              {completedAnalyses.length === 0 && <option value="">No completed analyses</option>}
            </select>
          </label>

          {/* SA dashboard controls — time range + refresh + auto-refresh */}
          {deviceSummary !== null && (
            <>
              <select value={rangeDays} onChange={(e) => setRangeDays(Number(e.target.value))}
                className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[11px] font-mono text-ink-400 focus:outline-none focus:border-accent">
                {RANGES.map((r) => (
                  <option key={r.days} value={r.days}>{r.label}</option>
                ))}
              </select>
              <button onClick={onRefresh}
                      className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all font-mono"
                      title="Refresh dashboard">
                ↻
              </button>

            </>
          )}

          {selectedAnalysisId && (
            <>
              <div ref={exportRef} className="relative">
                <button onClick={() => setExportOpen(!exportOpen)} disabled={exporting}
                        className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:border-accent hover:text-accent transition-all font-mono inline-flex items-center gap-1">
                  Export ▾
                </button>
                {exportOpen && (
                  <div className="absolute left-0 mt-1 w-28 bg-base-800 border border-base-500 rounded-lg shadow-xl py-1 z-50">
                    <button onClick={() => { exportReport("technical"); setExportOpen(false); }}
                            className="w-full text-left px-3 py-2 text-[12px] text-ink-300 hover:bg-base-700/60 hover:text-ink-100 font-mono">
                      PDF
                    </button>
                    <button onClick={() => { exportReport("csv"); setExportOpen(false); }}
                            className="w-full text-left px-3 py-2 text-[12px] text-ink-300 hover:bg-base-700/60 hover:text-ink-100 font-mono">
                      CSV
                    </button>
                  </div>
                )}
              </div>
            </>
          )}

          {canCompare && (
            <button onClick={() => { setCompareOpen(true); setCompareResult(null); setCompareTsr1(""); setCompareTsr2(""); }}
                    className="px-3 py-2 rounded-lg border border-accent/40 text-accent text-[12px] font-medium hover:bg-accent/10 transition-all">
              Compare
            </button>
          )}

          <button onClick={() => setVisOpen(true)}
                  className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
            Filter
          </button>

          <button onClick={() => navigate(`/devices/${deviceId}`)}
                  className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
            Details ↗
          </button>
        </div>
      </div>

      {/* ── Success toast ────────────────────────────────────────────── */}
      {successMsg && (
        <div className="fixed top-4 right-4 z-50 bg-[#39d98a]/15 border border-[#39d98a]/40 rounded-lg px-4 py-3 flex items-center gap-2 animate-pulse-once shadow-lg">
          <span className="text-[#39d98a] text-sm font-mono">{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-ink-400 hover:text-ink-200 ml-2">✕</button>
        </div>
      )}

      {/* ── SA top-row widgets (device-scoped) ────────────────────────── */}
      {deviceSummary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <SummaryCard
            title="Overall Security Score"
            icon={<IconShield />}
            primaryValue={
              deviceSummary.overall_grade
                ? <><AnimatedValue value={`${deviceSummary.overall_score}`} /><span className="text-ink-500 text-lg font-normal">/100</span></>
                : "No Data"
            }
            secondaryLines={[
              <><span style={{ color: gradeColor(deviceSummary.overall_grade) }}>Grade {deviceSummary.overall_grade}</span></>,
              <Delta value={deviceSummary.score_delta} sense="score" />,
            ]}
            sparklineData={deviceSummary.score_trend}
            sparklineColor={gradeColor(deviceSummary.overall_grade)}
            sparklineLabel="Security Score"
            tooltip="Security posture score for this device."
          />
          <SummaryCard
            title="Critical Findings"
            icon={<IconAlert />}
            primaryValue={<AnimatedValue value={String(deviceSummary.critical_count)} />}
            secondaryLines={[<Delta value={deviceSummary.critical_delta} sense="finding" />]}
            sparklineData={deviceSummary.critical_trend}
            sparklineColor="#ff4d4d"
            sparklineLabel="Critical Findings"
            tooltip="Critical findings for this device."
          />
          <SummaryCard
            title="High Findings"
            icon={<IconFlag />}
            primaryValue={<AnimatedValue value={String(deviceSummary.high_count)} />}
            secondaryLines={[<Delta value={deviceSummary.high_delta} sense="finding" />]}
            sparklineData={deviceSummary.high_trend}
            sparklineColor="#ff8a3d"
            sparklineLabel="High Findings"
            tooltip="High-severity findings for this device."
          />
          <RiskTrendWidget data={filteredRiskTrend} loading={!deviceRiskTrend} rangeDays={rangeDays} />
          <FindingsBySeverityWidget
            distribution={severityDist.dist}
            total={severityDist.total}
            onSeverityClick={() => {}}
            activeSeverity={null}
          />
        </div>
      )}

      {/* ── Visibility settings modal ───────────────────────────────── */}
      {visOpen && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setVisOpen(false)} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={() => setVisOpen(false)}>
            <div className="w-full max-w-[480px] bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
                 onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="font-display font-semibold text-ink-100">Findings Visibility</h3>
                <button onClick={() => setVisOpen(false)}
                        className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors">×</button>
              </div>
              <p className="font-mono text-[11px] text-ink-500">
                Toggle visibility for this device. Hidden severities are excluded from the findings list.
              </p>
              {/* Inherit toggle */}
              <label className="flex items-center gap-3 py-2 cursor-pointer">
                <input type="checkbox" checked={inheritGlobal}
                       onChange={(e) => {
                         if (e.target.checked) {
                           setInheritGlobal(true);
                           api.updateDeviceVisibility(deviceId, []).catch(() => {});
                         } else {
                           setInheritGlobal(false);
                           // Seed device filter with current effective hidden set
                           setDevHidden([...effHidden]);
                           api.updateDeviceVisibility(deviceId, [...effHidden]).catch(() => {});
                         }
                       }}
                       className="rounded accent-accent" />
                <span className="text-[13px] text-ink-300">Inherit from Global</span>
              </label>
              {/* Per-severity toggles */}
              <div className="space-y-2">
                {(["Medium", "Low", "Info"] as const).map((sev) => {
                  const isHidden = devHidden.includes(sev);
                  const disabled = inheritGlobal;
                  return (
                    <div key={sev} className="flex items-center justify-between py-1.5 px-3 rounded bg-base-800/50">
                      <span className="text-[13px] font-medium" style={{ color: disabled ? "#6b7689" : sevColor[sev] }}>{sev}</span>
                      <label className={`relative inline-flex items-center ${disabled ? "opacity-40 cursor-not-allowed" : "cursor-pointer"}`}>
                        <input type="checkbox" checked={!isHidden} disabled={disabled}
                               onChange={() => {
                                 const next = isHidden ? devHidden.filter((s) => s !== sev) : [...devHidden, sev];
                                 setDevHidden(next);
                                 api.updateDeviceVisibility(deviceId, next).catch(() => {});
                               }}
                               className="sr-only peer" />
                        <div className={`w-9 h-5 rounded-full peer border transition-colors ${isHidden ? "bg-base-600 border-base-500" : "bg-accent/30 border-accent"}`}>
                          <div className={`w-3.5 h-3.5 rounded-full bg-white mt-[2.5px] transition-transform ${isHidden ? "ml-1" : "ml-[18px]"}`} />
                        </div>
                      </label>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Add Finding modal ────────────────────────────────── */}
      {addFindingOpen && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setAddFindingOpen(false)} />
          <div className="fixed inset-0 z-40 grid place-items-center pointer-events-none">
            <div className="pointer-events-auto bg-base-800 border border-base-500 rounded-panel shadow-2xl w-full max-w-lg p-6 mx-4" onClick={(e) => e.stopPropagation()}>
              <h2 className="font-display text-lg font-semibold text-ink-100 mb-4">{editingFinding ? "Edit Manual Finding" : "Add Manual Finding"}</h2>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <label className="block">
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Severity</span>
                    <select value={newFinding.severity} onChange={(e) => setNewFinding((f) => ({ ...f, severity: e.target.value }))}
                            className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                      {["Critical", "High", "Medium", "Low", "Info"].map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </label>
                  <label className="block">
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Status</span>
                    <select value={newFinding.status} onChange={(e) => setNewFinding((f) => ({ ...f, status: e.target.value }))}
                            className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                      {[{ v: "open", l: "Open" }, { v: "in_progress", l: "In Progress" }, { v: "fixed", l: "Fixed" }, { v: "false_positive", l: "Dismissed" }].map((s) => <option key={s.v} value={s.v}>{s.l}</option>)}
                    </select>
                  </label>
                </div>
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Title</span>
                  <input type="text" value={newFinding.title} onChange={(e) => setNewFinding((f) => ({ ...f, title: e.target.value }))}
                         className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent"
                         placeholder="e.g. Weak encryption cipher detected" />
                </label>
                <div className="grid grid-cols-2 gap-4">
                  <label className="block">
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Category</span>
                    <select value={newFinding.category} onChange={(e) => setNewFinding((f) => ({ ...f, category: e.target.value }))}
                            className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                      <option value="">— Select —</option>
                      {["Access Control", "Administration", "Authentication", "Certificate", "Custom", "Encryption", "Exposure", "Firmware Compliance", "High Availability", "Licensing", "Logging", "NAT", "Object Hygiene", "Performance", "SSL VPN", "Security Services", "VPN"].map((c) => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </label>
                  <label className="block">
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Affected Object</span>
                    <input type="text" value={newFinding.object_name} onChange={(e) => setNewFinding((f) => ({ ...f, object_name: e.target.value }))}
                           className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent"
                           placeholder="e.g. WAN interface" />
                  </label>
                </div>
                <details className="group">
                  <summary className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500 cursor-pointer hover:text-ink-300">More Details (optional)</summary>
                  <div className="space-y-4 mt-3">
                    <label className="block">
                      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Description</span>
                      <textarea value={newFinding.description} onChange={(e) => setNewFinding((f) => ({ ...f, description: e.target.value }))} rows={2}
                                className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent resize-none"
                                placeholder="Describe the finding..." />
                    </label>
                    <div className="grid grid-cols-2 gap-4">
                      <label className="block">
                        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Business Impact</span>
                        <input type="text" value={newFinding.business_impact} onChange={(e) => setNewFinding((f) => ({ ...f, business_impact: e.target.value }))}
                               className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent"
                               placeholder="Business risk..." />
                      </label>
                      <label className="block">
                        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Technical Impact</span>
                        <input type="text" value={newFinding.technical_impact} onChange={(e) => setNewFinding((f) => ({ ...f, technical_impact: e.target.value }))}
                               className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent"
                               placeholder="Technical details..." />
                      </label>
                    </div>
                    <label className="block">
                      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Remediation</span>
                      <textarea value={newFinding.remediation} onChange={(e) => setNewFinding((f) => ({ ...f, remediation: e.target.value }))} rows={2}
                                className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent resize-none"
                                placeholder="How to fix..." />
                    </label>
                    <label className="block">
                      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Evidence</span>
                      <input type="text" value={newFinding.evidence} onChange={(e) => setNewFinding((f) => ({ ...f, evidence: e.target.value }))}
                             className="mt-1 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent"
                             placeholder="Supporting evidence..." />
                    </label>
                  </div>
                </details>
              </div>
              <div className="flex items-center justify-end gap-3 mt-6 pt-4 border-t border-base-500/40">
                <button onClick={() => { setAddFindingOpen(false); setEditingFinding(null); }}
                        className="px-4 py-2 rounded-lg border border-base-500 text-ink-400 text-[13px] hover:border-ink-400 transition-all">
                  Cancel
                </button>
                <button onClick={async () => {
                  if (!newFinding.title || !newFinding.category) return;
                  setNewFindingBusy(true);
                  try {
                    if (editingFinding) {
                      // Build update payload — only include changed fields
                      const updates: Record<string, unknown> = {};
                      for (const k of ["severity", "title", "category", "object_name", "status", "description", "business_impact", "technical_impact", "remediation", "evidence"]) {
                        const newVal = (newFinding as any)[k];
                        const oldVal = (editingFinding as any)[k] ?? "";
                        if (k === "status") { if (newVal !== editingFinding.status) updates[k] = newVal; }
                        else if (newVal !== oldVal && newVal !== "") updates[k] = newVal;
                        else if (oldVal === undefined && newVal !== "") updates[k] = newVal;
                      }
                      await api.updateManualFinding(editingFinding.id, updates);
                    } else {
                      await api.createManualFinding(deviceId, {
                        severity: newFinding.severity, title: newFinding.title,
                        category: newFinding.category, object_name: newFinding.object_name,
                        status: newFinding.status, description: newFinding.description,
                        business_impact: newFinding.business_impact, technical_impact: newFinding.technical_impact,
                        remediation: newFinding.remediation, evidence: newFinding.evidence,
                      });
                    }
                    setAddFindingOpen(false);
                    setEditingFinding(null);
                    setSuccessMsg(editingFinding ? "Finding updated successfully." : "Manual finding created successfully.");
                    setTimeout(() => setSuccessMsg(null), 3000);
                    if (selectedAnalysisId) {
                      api.listAnalysisFindings(selectedAnalysisId, { limit: "1000" })
                        .then(setAllAnalysisRows).catch(() => {});
                    }
                  } catch (e) {
                    setErr(e instanceof Error ? e.message : "Failed to save finding");
                  } finally { setNewFindingBusy(false); }
                }}
                        disabled={newFindingBusy || !newFinding.title || !newFinding.category}
                        className="px-5 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:bg-accent/80 transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                  {newFindingBusy ? "Saving..." : editingFinding ? "Save Changes" : "Add Finding"}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Delete confirmation dialog ───────────────────────────── */}
      {deleteConfirmId && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setDeleteConfirmId(null)} />
          <div className="fixed inset-0 z-40 grid place-items-center pointer-events-none">
            <div className="pointer-events-auto bg-base-800 border border-base-500 rounded-panel shadow-2xl w-full max-w-sm p-6 mx-4" onClick={(e) => e.stopPropagation()}>
              <h2 className="font-display text-lg font-semibold text-ink-100 mb-2">Delete Manual Finding</h2>
              <p className="text-[13px] text-ink-400 mb-6">Are you sure you want to permanently delete this manual finding? This action cannot be undone.</p>
              <div className="flex items-center justify-end gap-3">
                <button onClick={() => setDeleteConfirmId(null)}
                        className="px-4 py-2 rounded-lg border border-base-500 text-ink-400 text-[13px] hover:border-ink-400 transition-all">
                  Cancel
                </button>
                <button onClick={async () => {
                  if (!deleteConfirmId) return;
                  setDeleteBusy(true);
                  try {
                    await api.deleteManualFinding(deleteConfirmId);
                    setDeleteConfirmId(null);
                    setSuccessMsg("Manual finding deleted successfully.");
                    setTimeout(() => setSuccessMsg(null), 3000);
                    if (selectedAnalysisId) {
                      api.listAnalysisFindings(selectedAnalysisId, { limit: "1000" })
                        .then(setAllAnalysisRows).catch(() => {});
                    }
                  } catch (e) {
                    setErr(e instanceof Error ? e.message : "Failed to delete finding");
                  } finally { setDeleteBusy(false); }
                }}
                        disabled={deleteBusy}
                        className="px-5 py-2 rounded-lg bg-sev-critical text-white text-[13px] font-semibold hover:bg-sev-critical/80 transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                  {deleteBusy ? "Deleting..." : "Delete"}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Device posture summary ────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        <KpiCard label="Score" value={analysisStats.score} color={gradeColor(analysisStats.grade)}
                 sub={`Grade ${analysisStats.grade || "—"}`} icon={<IconShield />} />
        <KpiCard label="Critical" value={analysisStats.sev.Critical || 0} color="#ff4d4d"
                 sub={`${(analysisStats.sevTotal.Critical || 0) - (analysisStats.sev.Critical || 0)}/${analysisStats.sevTotal.Critical || 0} Fixed`}
                 alert={(analysisStats.sev.Critical || 0) > 0} icon={<IconAlert />}
                 onClick={() => setFilters((f) => ({ ...f, severity: toggleArray(f.severity, "Critical") }))} />
        <KpiCard label="High" value={analysisStats.sev.High || 0} color="#ff8a3d"
                 sub={`${(analysisStats.sevTotal.High || 0) - (analysisStats.sev.High || 0)}/${analysisStats.sevTotal.High || 0} Fixed`}
                 icon={<IconFlag />}
                 onClick={() => setFilters((f) => ({ ...f, severity: toggleArray(f.severity, "High") }))} />
        <KpiCard label="Medium" value={analysisStats.sev.Medium || 0} color="#f5c451"
                 sub={`${(analysisStats.sevTotal.Medium || 0) - (analysisStats.sev.Medium || 0)}/${analysisStats.sevTotal.Medium || 0} Fixed`}
                 icon={<IconDot />}
                 onClick={() => setFilters((f) => ({ ...f, severity: toggleArray(f.severity, "Medium") }))} />
        <KpiCard label="Low" value={analysisStats.sev.Low || 0} color="#4a9eff"
                 sub={`${(analysisStats.sevTotal.Low || 0) - (analysisStats.sev.Low || 0)}/${analysisStats.sevTotal.Low || 0} Fixed`}
                 icon={<IconDot />}
                 onClick={() => setFilters((f) => ({ ...f, severity: toggleArray(f.severity, "Low") }))} />
        <KpiCard label="Open" value={analysisStats.open} color="#ff8a3d"
                 sub={`${analysisStats.open}/${analysisStats.totalFindings} Open`}
                 icon={<IconDot />}
                 onClick={() => setFilters((f) => ({ ...f, status: toggleArray(f.status, "open") }))} />
        <KpiCard label="In Progress" value={analysisStats.inProgress} color="#4a9eff"
                 sub={`${analysisStats.inProgress}/${analysisStats.totalFindings} In Progress`}
                 icon={<IconClock />}
                 onClick={() => setFilters((f) => ({ ...f, status: toggleArray(f.status, "in_progress") }))} />
        <KpiCard label="Resolved" value={analysisStats.resolved} color="#39d98a"
                 sub={`${analysisStats.resolved}/${analysisStats.totalFindings} Fixed`}
                 icon={<IconCheck />}
                 onClick={() => setFilters((f) => ({ ...f, status: toggleArray(f.status, "fixed") }))} />
      </div>

      {/* ── Compare modal ──────────────────────────────────────────── */}
      {compareOpen && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setCompareOpen(false)} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={() => setCompareOpen(false)}>
            <div className="w-full max-w-[720px] max-h-[85vh] overflow-y-auto bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-5"
                 onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="font-display font-semibold text-ink-100 text-lg">Compare TSRs</h3>
                <button onClick={() => setCompareOpen(false)}
                        className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors text-lg leading-none">×</button>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">Baseline (older)</span>
                  <select value={compareTsr1} onChange={(e) => setCompareTsr1(e.target.value)}
                          className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                    <option value="">Select TSR…</option>
                    {completedAnalyses.map((a) => <option key={a.id} value={a.id}>{fmtDate(a.created_at)} · {a.grade}</option>)}
                  </select>
                </label>
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">Newer</span>
                  <select value={compareTsr2} onChange={(e) => setCompareTsr2(e.target.value)}
                          className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                    <option value="">Select TSR…</option>
                    {completedAnalyses.map((a) => <option key={a.id} value={a.id}>{fmtDate(a.created_at)} · {a.grade}</option>)}
                  </select>
                </label>
              </div>

              <div className="flex items-center gap-2">
                <button onClick={runCompare} disabled={!compareTsr1 || !compareTsr2 || compareBusy}
                        className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
                  {compareBusy && !detailReport ? "Comparing…" : "Compare"}
                </button>
                {compareResult && (
                  <button onClick={loadDetailedReport} disabled={compareBusy}
                          className={`px-4 py-2 rounded-lg border text-[13px] font-medium transition-all ${
                            detailReport ? "border-accent/40 text-accent bg-accent/10" : "border-base-500 text-ink-300 hover:border-accent hover:text-accent"
                          }`}>
                    {detailReport ? "Detailed Report" : "Detailed Report"}
                  </button>
                )}
              </div>

              {detailReport && (
                <FullComparisonTable findings1={detailFindings1} findings2={detailFindings2}
                                     label1={completedAnalyses.find((a) => a.id === compareTsr1)?.created_at || "Older TSR"}
                                     label2={completedAnalyses.find((a) => a.id === compareTsr2)?.created_at || "Newer TSR"}
                                     onDownloadPdf={async () => {
                                       try {
                                         const blob = await api.downloadComparisonReport(deviceId, compareTsr1, compareTsr2);
                                         const url = URL.createObjectURL(blob);
                                         const a = document.createElement("a");
                                         a.href = url; a.download = `comparison-${deviceId.slice(0, 8)}.pdf`;
                                         a.click(); URL.revokeObjectURL(url);
                                       } catch { /* */ }
                                     }}
                                     summary={compareResult ? {
                                       newCount: compareResult.new_findings.length,
                                       resolvedCount: compareResult.resolved_findings.length,
                                       changeCount: compareResult.config_changes.length,
                                       scoreDelta: (() => {
                                         const prev = completedAnalyses.find((a) => a.id === compareTsr1);
                                         const curr = completedAnalyses.find((a) => a.id === compareTsr2);
                                         if (prev && curr) return `${(curr.score - prev.score) >= 0 ? "+" : ""}${(curr.score - prev.score).toFixed(0)}%`;
                                         return "—";
                                       })(),
                                     } : undefined} />
              )}

              {!detailReport && compareResult && (
                <div className="space-y-4 border-t border-base-500 pt-4">
                  <h4 className="font-display font-semibold text-sm text-ink-100">Comparison Results</h4>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <CompareCard label="New Findings" value={compareResult.new_findings.length} color="#ff4d4d" />
                    <CompareCard label="Resolved" value={compareResult.resolved_findings.length} color="#39d98a" />
                    <CompareCard label="Config Changes" value={compareResult.config_changes.length} color="#4f8cff" />
                    <CompareCard label="Score Δ" value={""}
                                 color="#f5c451"
                                 detail={(() => {
                                   const prev = completedAnalyses.find((a) => a.id === compareTsr1);
                                   const curr = completedAnalyses.find((a) => a.id === compareTsr2);
                                   if (prev && curr) {
                                     const delta = curr.score - prev.score;
                                     return `${delta >= 0 ? "+" : ""}${delta.toFixed(0)}%`;
                                   }
                                   return "—";
                                 })()} />
                  </div>

                  {/* New findings detail */}
                  {compareResult.new_findings.length > 0 && (
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#ff4d4d] mb-2">
                        Added Findings ({compareResult.new_findings.length})
                      </div>
                      <div className="space-y-1 max-h-[200px] overflow-y-auto">
                        {compareResult.new_findings.map((f: Record<string, unknown>, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-[12px] py-1 px-2 rounded bg-base-800/50">
                            <span className="badge shrink-0" style={{
                              color: sevColor[String(f.severity || "Info")],
                              borderColor: `${sevColor[String(f.severity || "Info")]}55`,
                              background: `${sevColor[String(f.severity || "Info")]}14`,
                              fontSize: "9px",
                            }}>{String(f.severity || "Info")}</span>
                            <span className="text-ink-300 truncate">{String(f.title || "")}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Resolved findings detail */}
                  {compareResult.resolved_findings.length > 0 && (
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#39d98a] mb-2">
                        Resolved Findings ({compareResult.resolved_findings.length})
                      </div>
                      <div className="space-y-1 max-h-[200px] overflow-y-auto">
                        {compareResult.resolved_findings.map((f: Record<string, unknown>, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-[12px] py-1 px-2 rounded bg-base-800/50">
                            <span className="badge shrink-0" style={{
                              color: sevColor[String(f.severity || "Info")],
                              borderColor: `${sevColor[String(f.severity || "Info")]}55`,
                              background: `${sevColor[String(f.severity || "Info")]}14`,
                              fontSize: "9px",
                            }}>{String(f.severity || "Info")}</span>
                            <span className="text-ink-300 truncate">{String(f.title || "")}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Config changes detail */}
                  {compareResult.config_changes.length > 0 && (
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#4f8cff] mb-2">
                        Configuration Changes ({compareResult.config_changes.length})
                      </div>
                      <div className="space-y-1 max-h-[200px] overflow-y-auto">
                        {compareResult.config_changes.map((c: Record<string, unknown>, i: number) => (
                          <div key={i} className="text-[11px] py-1 px-2 rounded bg-base-800/50 font-mono text-ink-400">
                            {String(c.section || "")}: {String(c.message || c.description || "")}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Side-by-side table */}
                  <SideBySideTable newFindings={compareResult.new_findings} resolvedFindings={compareResult.resolved_findings} />

                  {compareResult.severity_counts && Object.keys(compareResult.severity_counts).length > 0 && (
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-2">New findings by severity</div>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(compareResult.severity_counts).map(([sev, n]) => (
                          <span key={sev} className="badge" style={{
                            color: sevColor[sev] || "#7a879b",
                            borderColor: `${sevColor[sev] || "#7a879b"}55`,
                            background: `${sevColor[sev] || "#7a879b"}14`,
                          }}>{sev}: {n}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* ── Findings table ────────────────────────────────────────── */}
      <div className="card-glow">
        <div className="px-5 py-3.5 border-b border-base-500/60 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-end gap-3">
              <MultiSelect label="Severity" values={filters.severity}
                    onChange={(vals) => { setFilters((f) => ({ ...f, severity: vals })); setPage(0); }}
                    options={SEVERITIES} />
              <MultiSelect label="Status" values={filters.status}
                    onChange={(vals) => { setFilters((f) => ({ ...f, status: vals })); setPage(0); }}
                    options={Object.keys(STATUS_LABEL)} labels={STATUS_LABEL} />
              <MultiSelect label="Category" values={filters.category}
                    onChange={(vals) => { setFilters((f) => ({ ...f, category: vals })); setPage(0); }}
                    options={allCategories(allAnalysisRows)} />
            <label className="block">
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Search</span>
              <input value={filters.q} onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
                     placeholder="title or object…"
                     className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent w-40 placeholder:text-ink-500/50" />
            </label>
            <button onClick={() => setFilters(EMPTY)}
                    className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
              Reset
            </button>
            <button onClick={saveCurrentView}
                    className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
              ☆ Save
            </button>
          </div>
          <button onClick={() => { setEditingFinding(null); setNewFinding({ severity: "Medium", title: "", category: "", object_name: "", status: "open", description: "", business_impact: "", technical_impact: "", remediation: "", evidence: "" }); setAddFindingOpen(true); }}
                  className="px-3 py-2 rounded-lg border border-accent/50 text-accent text-[12px] hover:bg-accent/10 hover:border-accent transition-all font-mono shrink-0">
            + Add Finding
          </button>
        </div>

        {views.length > 0 && (
          <div className="flex flex-wrap gap-2 px-5 py-2 border-b border-base-500/40">
            {views.map((v) => (
              <span key={v.name} className="badge flex items-center gap-1.5" style={{ color: "#6b7689", borderColor: "#6b768955", background: "#6b768914" }}>
                <button onClick={() => setFilters(v.filters)}
                        className="hover:text-accent transition-colors">{v.name}</button>
                <button onClick={(e) => { e.stopPropagation(); deleteView(v.name); }}
                        className="text-ink-500 hover:text-sev-high leading-none text-[14px]">×</button>
              </span>
            ))}
          </div>
        )}

        {selected.size > 0 && (
          <div className="flex items-center gap-3 px-5 py-2 border-b border-base-500/40 bg-accent/5">
            <span className="font-mono text-[12px] text-ink-300">{selected.size} selected</span>
            <div className="flex-1" />
            <button onClick={() => bulkApply("acknowledged")}
                    className="px-3 py-1.5 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:border-accent hover:text-accent transition-all">Acknowledge</button>
            <button onClick={() => bulkApply("in_progress")}
                    className="px-3 py-1.5 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:border-accent hover:text-accent transition-all">In Progress</button>
            <button onClick={() => bulkApply("fixed")}
                    className="px-3 py-1.5 rounded-lg bg-signal/10 border border-signal/30 text-signal text-[12px] font-semibold hover:bg-signal/20 transition-all">Mark Fixed</button>
          </div>
        )}

        {err && <div className="px-5 py-2"><p className="text-sev-high text-[13px] font-mono">{err}</p></div>}

        <div>
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                <th className="py-2.5 px-4 w-8"></th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Title</th>
                <th className="py-2.5 px-4 hidden lg:table-cell">Category</th>
                <th className="py-2.5 px-4 hidden md:table-cell">Affected</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 hidden lg:table-cell">Last Seen</th>
                <th className="py-2.5 px-4 w-16"></th>
              </tr>
            </thead>
            <tbody>
              {displayGroups.map((g, i) => {
                const groupChecked = g.openIds.length > 0 && g.openIds.every((id) => selected.has(id));
                return (
                <tr key={`${g.ruleId}-${i}`} onClick={() => navigate(`/${findingDetailRoute}/${g.repId}`.replace(/\/\//g, "/"))}
                    className="table-row border-b border-base-500/40 cursor-pointer">
                  <td className="py-2.5 px-4" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" checked={groupChecked} disabled={g.openIds.length === 0}
                           onChange={() => setSelected((s) => {
                             const n = new Set(s);
                             if (groupChecked) g.openIds.forEach((id) => n.delete(id));
                             else g.openIds.forEach((id) => n.add(id));
                             return n;
                           })}
                           className="rounded accent-accent" />
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="badge" style={{
                      color: sevColor[g.severity], borderColor: `${sevColor[g.severity]}55`, background: `${sevColor[g.severity]}14`,
                    }}>{g.severity}</span>
                  </td>
                  <td className="py-2.5 px-4 text-ink-100 max-w-[300px] truncate">{g.title}</td>
                  <td className="py-2.5 px-4 font-mono text-[10px] text-ink-500 hidden lg:table-cell">{g.category || "—"}</td>
                  <td className="py-2.5 px-4 font-mono text-[11px] text-ink-300 hidden md:table-cell">
                    {g.affectedTotal === 1
                      ? (g.rep.object_name || "1 affected")
                      : <>{g.affectedTotal} affected{g.affectedFixed > 0 ? <span className="text-ink-500"> · {g.affectedOpen} open</span> : null}</>}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="badge" style={{
                      color: statusColor[g.status], borderColor: `${statusColor[g.status]}55`, background: `${statusColor[g.status]}14`,
                    }}>{STATUS_LABEL[g.status]}</span>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[11px] text-ink-500 hidden lg:table-cell">{fmtDate(g.lastSeen)}</td>
                  <td className="py-2.5 px-4" onClick={(e) => e.stopPropagation()}>
                    {g.source === "manual" && g.affectedTotal === 1 && (
                      <div className="flex items-center gap-1">
                        <button onClick={() => { setEditingFinding(g.rep); setNewFinding({ severity: g.rep.severity, title: g.rep.title, category: g.rep.category, object_name: g.rep.object_name, status: g.rep.status, description: (g.rep as any).description || "", business_impact: "", technical_impact: "", remediation: "", evidence: "" }); setAddFindingOpen(true); }}
                                className="p-1.5 rounded hover:bg-accent/10 text-ink-400 hover:text-accent transition-all" title="Edit">
                          ✏️
                        </button>
                        <button onClick={() => { setDeleteConfirmId(g.rep.id); }}
                                className="p-1.5 rounded hover:bg-sev-critical/10 text-ink-400 hover:text-sev-critical transition-all" title="Delete">
                          🗑️
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
          {!busy && allAnalysisRows.length > 0 && totalFiltered === 0 && (
            <div className="py-12 text-center">
              <div className="text-4xl mb-3 opacity-30">🔍</div>
              <p className="text-ink-500 text-sm font-mono">No findings match your filters</p>
            </div>
          )}
          {!busy && allAnalysisRows.length === 0 && (
            <div className="py-12 text-center">
              <p className="text-ink-500 text-sm font-mono">No findings for this analysis</p>
            </div>
          )}
          {busy && <div className="py-8 text-center"><div className="skeleton h-6 w-40 mx-auto rounded" /></div>}
        </div>

        {/* ── Pagination ────────────────────────────────────── */}
        {totalFiltered > pageSize && (
          <div className="px-5 py-3 border-t border-base-500/40 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] text-ink-500">Show</span>
              <select value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))}
                      className="bg-base-800 border border-base-500 rounded px-2 py-1 text-[12px] text-ink-100 focus:outline-none focus:border-accent">
                {PAGE_SIZES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <span className="font-mono text-[10px] text-ink-500">per page</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-[10px] text-ink-500">
                {(safePage * pageSize) + 1}–{Math.min((safePage + 1) * pageSize, totalFiltered)} of {totalFiltered}
              </span>
              <div className="flex items-center gap-1">
                <PageBtn onClick={() => setPage(0)} disabled={safePage === 0} label="««" />
                <PageBtn onClick={() => setPage(Math.max(0, safePage - 1))} disabled={safePage === 0} label="«" />
                {pageNumbers(safePage, totalPages).map((n) =>
                  n === "..." ? (
                    <span key={`ellipsis-${n}`} className="px-2 text-ink-500 font-mono text-[11px]">…</span>
                  ) : (
                    <button key={n} onClick={() => setPage(n as number)}
                            className={`w-7 h-7 rounded text-[12px] font-mono transition-colors ${
                              safePage === n ? "bg-accent text-white" : "text-ink-300 hover:text-accent"
                            }`}>
                      {(n as number) + 1}
                    </button>
                  )
                )}
                <PageBtn onClick={() => setPage(Math.min(totalPages - 1, safePage + 1))} disabled={safePage >= totalPages - 1} label="»" />
                <PageBtn onClick={() => setPage(totalPages - 1)} disabled={safePage >= totalPages - 1} label="»»" />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Comparison result card ────────────────────────────────────────────
function CompareCard({ label, value, color, detail }: {
  label: string; value: number | string; color: string; detail?: string;
}) {
  return (
    <div className="card-glow p-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">{label}</div>
      <div className="font-display text-[28px] font-bold" style={{ color }}>
        {typeof value === "number" ? value.toLocaleString() : detail || value}
      </div>
    </div>
  );
}

// ── KPI card ──────────────────────────────────────────────────────────
function KpiCard({ label, value, color, sub, alert, icon, onClick }: {
  label: string; value: number; color: string; sub: string; alert?: boolean; icon: React.ReactNode;
  onClick?: () => void;
}) {
  return (
    <div onClick={onClick}
         className={`stat-card group ${alert ? "animate-pulse" : ""} ${onClick ? "cursor-pointer hover:brightness-110" : ""}`}
         style={{ borderColor: alert ? `${color}55` : undefined }}>
      <div className="flex items-start justify-between">
        <div className="space-y-0.5 min-w-0">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 truncate">{label}</div>
          <div className="font-display text-[26px] font-bold leading-none tabular-nums" style={{ color }}>
            {typeof value === "number" && label === "Score" ? `${value.toFixed(0)}%` : value.toLocaleString()}
          </div>
          <div className="font-mono text-[10px] text-ink-500">{sub}</div>
        </div>
        <div className="opacity-25 group-hover:opacity-50 transition-opacity shrink-0" style={{ color }}>{icon}</div>
      </div>
      <div className="absolute left-0 top-[12%] bottom-[12%] w-[3px] rounded-r-sm" style={{ background: color }} />
    </div>
  );
}

// ── Select ────────────────────────────────────────────────────────────
function Select({ label, value, onChange, options, labels = {} }: {
  label: string; value: string; onChange: (v: string) => void;
  options: readonly string[]; labels?: Record<string, string>;
}) {
  return (
    <label className="block">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
              className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent transition-all max-w-[220px] truncate">
        {options.map((o) => <option key={o} value={o}>{labels[o] ?? o}</option>)}
      </select>
    </label>
  );
}

// ── Inline icons ──────────────────────────────────────────────────────
function IconServer() { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>; }
function IconAlert()  { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>; }
function IconFlag()   { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>; }
function IconDot()    { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="8"/></svg>; }
function IconCheck()  { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>; }
function IconClock()  { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>; }
function IconShield() { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>; }

// ── Full comparison table (all findings from both TSRs) ─────────────────
function FullComparisonTable({ findings1, findings2, label1, label2, summary, onDownloadPdf }: {
  findings1: FindingRow[]; findings2: FindingRow[]; label1: string; label2: string;
  summary?: { newCount: number; resolvedCount: number; changeCount: number; scoreDelta: string };
  onDownloadPdf?: () => void;
}) {
  // Build a merged list keyed by fingerprint
  const allKeys = new Set<string>();
  const map1: Record<string, FindingRow> = {};
  const map2: Record<string, FindingRow> = {};
  for (const f of findings1) {
    const key = `${f.rule_id}::${f.object_type}::${f.object_name}`;
    allKeys.add(key); map1[key] = f;
  }
  for (const f of findings2) {
    const key = `${f.rule_id}::${f.object_type}::${f.object_name}`;
    allKeys.add(key); map2[key] = f;
  }
  const rows = [...allKeys].map((k) => {
    const f1 = map1[k]; const f2 = map2[k];
    const f = f1 || f2;
    return {
      severity: f?.severity || "Info", title: f?.title || "",
      category: f?.category || "", status1: f1?.status || "—", status2: f2?.status || "—",
      in1: !!f1, in2: !!f2,
    };
  }).sort((a, b) => {
    const o: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (o[(a.severity || "").toLowerCase()] ?? 9) - (o[(b.severity || "").toLowerCase()] ?? 9);
  });

  return (
    <div className="border-t border-base-500 pt-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="font-display font-semibold text-sm text-ink-100">Detailed Comparison — All Findings</h4>
        <div className="flex items-center gap-2">
          <button onClick={onDownloadPdf}
                  className="px-3 py-1 rounded border border-accent/30 text-accent text-[11px] hover:bg-accent/10 transition-all font-mono">
            Download PDF
          </button>
          <span className="font-mono text-[10px] text-ink-500">{rows.length} total</span>
        </div>
      </div>
      {summary && (
        <div className="grid grid-cols-4 gap-2">
          <MiniMetric label="New" value={summary.newCount} color="#ff4d4d" />
          <MiniMetric label="Resolved" value={summary.resolvedCount} color="#39d98a" />
          <MiniMetric label="Changes" value={summary.changeCount} color="#4f8cff" />
          <MiniMetric label="Score Δ" value={summary.scoreDelta} color="#f5c451" />
        </div>
      )}
      <div className="overflow-x-auto max-h-[400px]">
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left font-mono text-[10px] uppercase tracking-[0.1em] text-ink-500 bg-base-900 sticky top-0 z-10 [&>th]:bg-base-900">
              <th className="py-2 px-3">Sev</th>
              <th className="py-2 px-3">Finding</th>
              <th className="py-2 px-3">Category</th>
              <th className="py-2 px-3 text-center">{fmtDate(label1)}</th>
              <th className="py-2 px-3 text-center">{fmtDate(label2)}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-b border-base-500/30">
                <td className="py-1.5 px-3">
                  <span className="text-[10px] font-mono font-semibold" style={{ color: sevColor[r.severity] }}>{r.severity.slice(0, 4)}</span>
                </td>
                <td className="py-1.5 px-3 text-ink-300 max-w-[250px] truncate" title={r.title}>{r.title}</td>
                <td className="py-1.5 px-3 font-mono text-[10px] text-ink-500 max-w-[120px] truncate">{r.category}</td>
                <td className="py-1.5 px-3 text-center">
                  {r.in1 ? (
                    <span className={`text-[10px] font-semibold ${r.status1 === "open" ? "text-[#ff8a3d]" : r.status1 === "fixed" ? "text-[#39d98a]" : "text-ink-300"}`}>
                      {r.status1}
                    </span>
                  ) : <span className="text-ink-500">—</span>}
                </td>
                <td className="py-1.5 px-3 text-center">
                  {r.in2 ? (
                    <span className={`text-[10px] font-semibold ${r.status2 === "open" ? "text-[#ff8a3d]" : r.status2 === "fixed" ? "text-[#39d98a]" : "text-ink-300"}`}>
                      {r.status2}
                    </span>
                  ) : <span className="text-ink-500">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Mini metric for comparison summary ─────────────────────────────────
function MiniMetric({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div className="bg-base-800/50 rounded-lg px-3 py-2 text-center">
      <div className="font-mono text-[9px] uppercase tracking-[0.1em] text-ink-500">{label}</div>
      <div className="font-display text-[18px] font-bold" style={{ color }}>
        {typeof value === "number" ? value : value}
      </div>
    </div>
  );
}

// ── Quick findings modal ────────────────────────────────────────────────
function QuickFindingsModal({ filter, allRows, devices, onClose, onSelectDevice }: {
  filter: { severity?: string; status?: string };
  allRows: FindingRow[]; devices: Device[]; onClose: () => void; onSelectDevice: (did: string) => void;
}) {
  const label = filter.severity || filter.status || "";
  const activeSet = new Set(ACTIVE_STATUSES);
  const filtered = allRows.filter((r) => {
    if (filter.severity && (r.severity !== filter.severity || !activeSet.has(r.status))) return false;
    if (filter.status && r.status !== filter.status) return false;
    return true;
  });
  const devName = (did: string) => devices.find((d) => d.id === did)?.friendly_name || did.slice(0, 8);

  return (
    <>
      <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={onClose} />
      <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={onClose}>
        <div className="w-full max-w-[700px] max-h-[80vh] overflow-y-auto bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
             onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center justify-between">
            <h3 className="font-display font-semibold text-ink-100">
              {filter.severity ? `${filter.severity} Findings` : `${STATUS_LABEL[label] || label} Findings`}
            </h3>
            <button onClick={onClose}
                    className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors">×</button>
          </div>
          <p className="font-mono text-[11px] text-ink-500">{filtered.length} finding{filtered.length !== 1 ? "s" : ""} across {new Set(filtered.map((f) => f.device_id)).size} device{new Set(filtered.map((f) => f.device_id)).size !== 1 ? "s" : ""}</p>
          {filtered.length === 0 ? (
            <p className="text-ink-500 text-sm font-mono text-center py-8">No matching findings</p>
          ) : (
            <div className="space-y-1 max-h-[50vh] overflow-y-auto">
              {filtered.map((f) => (
                <div key={f.id} className="flex items-center gap-3 text-[12px] py-2 px-3 rounded bg-base-800/50 hover:bg-base-700/50 cursor-pointer transition-colors"
                     onClick={() => { onSelectDevice(f.device_id); }}>
                  <span className="badge shrink-0" style={{
                    color: sevColor[f.severity], borderColor: `${sevColor[f.severity]}55`, background: `${sevColor[f.severity]}14`, fontSize: "9px",
                  }}>{f.severity}</span>
                  <span className="text-ink-300 flex-1 truncate">{f.title}</span>
                  <span className="font-mono text-[10px] text-ink-500">{devName(f.device_id)}</span>
                  <span className="badge shrink-0" style={{
                    color: statusColor[f.status], borderColor: `${statusColor[f.status]}55`, background: `${statusColor[f.status]}14`, fontSize: "9px",
                  }}>{STATUS_LABEL[f.status] || f.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── Pagination helpers ──────────────────────────────────────────────
function pageNumbers(current: number, total: number): (number | "...")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i);
  const pages: (number | "...")[] = [0];
  if (current > 3) pages.push("...");
  const start = Math.max(1, current - 1);
  const end = Math.min(total - 2, current + 1);
  for (let i = start; i <= end; i++) pages.push(i);
  if (current < total - 4) pages.push("...");
  pages.push(total - 1);
  return pages;
}

function PageBtn({ onClick, disabled, label }: { onClick: () => void; disabled: boolean; label: string }) {
  return (
    <button onClick={onClick} disabled={disabled}
            className={`w-7 h-7 rounded text-[12px] font-mono transition-colors ${
              disabled ? "text-ink-600 cursor-not-allowed" : "text-ink-300 hover:text-accent"
            }`}>
      {label}
    </button>
  );
}

function toggleArray(arr: string[], val: string): string[] {
  return arr.includes(val) ? arr.filter((v) => v !== val) : [...arr, val];
}

// ── Multi-select dropdown ───────────────────────────────────────────
function MultiSelect({ label, values, onChange, options, labels = {} }: {
  label: string; values: string[]; onChange: (vals: string[]) => void;
  options: readonly string[]; labels?: Record<string, string>;
}) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ top: 0, left: 0 });

  // Compute dropdown position from button rect
  const updatePos = useCallback(() => {
    const rect = btnRef.current?.getBoundingClientRect();
    if (rect) setPos({ top: rect.bottom + 4, left: rect.left });
  }, []);

  // Close on outside click; reposition on scroll (unless scroll is inside dropdown)
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    const onMouseDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (dropdownRef.current?.contains(t)) return;
      if (btnRef.current?.contains(t)) return;
      close();
    };
    const onScroll = (e: Event) => {
      // Allow scrolling inside the dropdown itself
      if (e.target instanceof Node && dropdownRef.current?.contains(e.target)) return;
      updatePos();
    };
    updatePos(); // initial position
    document.addEventListener("mousedown", onMouseDown);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      document.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [open, updatePos]);

  const active = values.length > 0;
  const display = values.length === 0
    ? "All " + label.toLowerCase() + "s"
    : values.length === 1
      ? (labels[values[0]] || values[0])
      : `${values.length} selected`;

  // Cap height to fit within viewport (16px bottom margin)
  const maxH = Math.min(256, window.innerHeight - pos.top - 16);
  const dropdown = open ? (
    <div ref={dropdownRef}
         style={{
           position: "fixed",
           top: pos.top,
           left: pos.left,
           minWidth: btnRef.current?.offsetWidth ?? 200,
           maxHeight: maxH,
           zIndex: 9999,
         }}
         className="overflow-y-auto bg-base-800 border border-base-500 rounded-lg shadow-lg py-1">
      {options.map((opt) => {
        const checked = values.includes(opt);
        return (
          <label key={opt}
                 className="flex items-center gap-2 px-3 py-1.5 hover:bg-base-700/50 cursor-pointer text-[13px] text-ink-300"
                 onClick={() => onChange(toggleArray(values, opt))}>
            <span className={`w-4 h-4 flex items-center justify-center rounded border text-[10px] transition-colors ${
              checked ? "bg-accent border-accent text-white" : "border-base-500 bg-base-900"
            }`}>
              {checked ? "✓" : ""}
            </span>
            {labels[opt] || opt}
          </label>
        );
      })}
    </div>
  ) : null;

  return (
    <div className="relative">
      <label className="block">
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</span>
        <button ref={btnRef} onClick={() => setOpen(!open)}
                className={`mt-1 flex items-center gap-2 bg-base-800 border rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none transition-all min-w-[140px] ${
                  active ? "border-accent/50" : "border-base-500"
                }`}>
          <span className="flex-1 text-left truncate" style={active ? { color: "#4f8cff" } : {}}>
            {display}
          </span>
          <span className="text-ink-500 text-[10px]">{open ? "▲" : "▼"}</span>
        </button>
      </label>
      {dropdown && createPortal(dropdown, document.body)}
    </div>
  );
}

function allCategories(rows: FindingRow[]): string[] {
  const cats = new Set<string>();
  for (const r of rows) if (r.category) cats.add(r.category);
  return [...cats].sort();
}
// ── Side-by-side comparison table (added to compareResult section) ─────
function SideBySideTable({ newFindings, resolvedFindings }: {
  newFindings: Record<string, unknown>[]; resolvedFindings: Record<string, unknown>[];
}) {
  const allKeys = new Set<string>();
  const byKey: Record<string, { severity: string; title: string; inOld: boolean; inNew: boolean }> = {};
  for (const f of newFindings) {
    const key = `${f.rule_id || ""}::${f.object_type || ""}::${f.object_name || ""}`;
    allKeys.add(key);
    byKey[key] = { severity: String(f.severity || "Info"), title: String(f.title || ""), inOld: false, inNew: true };
  }
  for (const f of resolvedFindings) {
    const key = `${f.rule_id || ""}::${f.object_type || ""}::${f.object_name || ""}`;
    allKeys.add(key);
    const existing = byKey[key];
    if (existing) {
      existing.inOld = true;
    } else {
      byKey[key] = { severity: String(f.severity || "Info"), title: String(f.title || ""), inOld: true, inNew: false };
    }
  }
  const rows = [...allKeys].map((k) => byKey[k]).sort((a, b) => {
    const o: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (o[(a.severity || "").toLowerCase()] ?? 9) - (o[(b.severity || "").toLowerCase()] ?? 9);
  });

  if (rows.length === 0) return null;
  return (
    <div>
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-2">Side-by-Side Comparison</div>
      <div className="overflow-x-auto max-h-[300px]">
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left font-mono text-[10px] uppercase tracking-[0.1em] text-ink-500 bg-base-800/50">
              <th className="py-2 px-3">Severity</th>
              <th className="py-2 px-3">Finding</th>
              <th className="py-2 px-3 text-center">Older TSR</th>
              <th className="py-2 px-3 text-center">New TSR</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-b border-base-500/30">
                <td className="py-1.5 px-3">
                  <span className="text-[10px] font-mono" style={{ color: sevColor[r.severity] || "#7a879b" }}>{r.severity}</span>
                </td>
                <td className="py-1.5 px-3 text-ink-300 truncate max-w-[200px]">{r.title}</td>
                <td className="py-1.5 px-3 text-center">
                  {r.inOld ? <span className="text-[#39d98a] font-bold">Yes</span> : <span className="text-ink-500">—</span>}
                </td>
                <td className="py-1.5 px-3 text-center">
                  {r.inNew ? <span className="text-[#39d98a] font-bold">Yes</span> : <span className="text-ink-500">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export { ACTIVE_STATUSES };