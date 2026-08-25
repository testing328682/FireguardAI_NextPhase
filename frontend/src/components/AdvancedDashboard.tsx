/**
 * Advanced Dashboard — Row 1: KPI Cards (simplified).
 *
 * Four clean KPI cards without sparklines — large metric, contextual sub-text,
 * trend indicator at the bottom.  All cards share identical visual hierarchy.
 */
import { useEffect, useState, useCallback, useRef, useMemo } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell,
} from "recharts";
import { api } from "../lib/api";
import { navigate } from "../lib/router";
import type { Customer, ExecutiveSummary, RiskTrend, Device, OrganizationDetail, CustomerPlanInfo, FreeLicenseInfo, LicenseBundle, TrendPoint, DashboardCharts, Row4Summary } from "../lib/types";
import { gradeColor } from "../lib/ui";

// ── Time ranges ───────────────────────────────────────────────────────────
interface Range { label: string; days: number }
const RANGES: Range[] = [
  { label: "Today", days: 1 },
  { label: "Last 7 Days", days: 7 },
  { label: "Last 30 Days", days: 30 },
  { label: "Last 90 Days", days: 90 },
  { label: "Last 365 Days", days: 365 },
];
const CUSTOM_RANGE: Range = { label: "Custom Range", days: -1 };

// Severity colors — matches the Security Analytics design language
const SEV_COLORS: Record<string, string> = {
  Critical: "#ff4d4d",
  High: "#ff8a3d",
  Medium: "#f5c451",
  Low: "#4a9eff",
  Info: "#7a879b",
};

const DONUT_TOOLTIP = {
  contentStyle: {
    backgroundColor: "#ffffff",
    color: "#1e293b",
    border: "1px solid #e2e8f0",
    fontSize: 11,
    borderRadius: 6,
    boxShadow: "0 2px 8px rgba(0, 0, 0, 0.12)",
    padding: "6px 8px",
  },
  itemStyle: { color: "#1e293b" },
  wrapperStyle: { zIndex: 9999 },
};


function localToday() { const n=new Date(); return `${n.getFullYear()}-${String(n.getMonth()+1).padStart(2,"0")}-${String(n.getDate()).padStart(2,"0")}`; }
function localTzOffset() { return new Date().getTimezoneOffset(); }
function fmtTime(d:Date){return d.toLocaleDateString("en-US",{month:"short",day:"numeric"})+", "+d.toLocaleTimeString("en-US",{hour:"numeric",minute:"2-digit",hour12:true});}

// Relative time ("10m ago", "2h ago", "Yesterday", "3d ago")
function fmtRelative(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso);
  const now = new Date();
  const mins = Math.max(0, Math.floor((now.getTime() - then.getTime()) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days === 1) return "Yesterday";
  return `${days}d ago`;
}

// ── Icons ─────────────────────────────────────────────────────────────────
const ICON = {
  org: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>,
  calendar: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>,
  refresh: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>,
  customize: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>,
  search: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  chevron: <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>,
  shield: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  server: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>,
  alert: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  warning: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
};
const btnBase = "inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border text-[12px] font-mono transition-all";

// ── Toolbar components ────────────────────────────────────────────────────

function CustomerFilter({ customers, value, onChange }: { customers: Customer[]; value: string; onChange: (id:string)=>void }) {
  const [o,setO]=useState(false); const [q,setQ]=useState(""); const r=useRef<HTMLDivElement>(null);
  useEffect(()=>{if(!o)return;const h=(e:MouseEvent)=>{if(r.current&&!r.current.contains(e.target as Node))setO(false)};document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h)},[o]);
  const f=customers.filter(c=>c.name.toLowerCase().includes(q.toLowerCase()));
  const s=value===""?"All Customers":(customers.find(c=>c.id===value)?.name||"All Customers");
  return <div ref={r} className="relative">
    <button onClick={()=>setO(!o)} className={`${btnBase} border-base-500 text-ink-300 hover:border-accent hover:text-accent min-w-[180px] justify-between`}><span className="flex items-center gap-1.5"><span className="text-ink-500">{ICON.org}</span><span className="truncate max-w-[160px]">{s}</span></span>{ICON.chevron}</button>
    {o&&<div className="absolute left-0 top-full mt-1 w-64 bg-base-800 border border-base-500 rounded-xl shadow-xl z-50 overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-base-500/40">{ICON.search}<input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search customers…" className="flex-1 bg-transparent text-[12px] text-ink-200 placeholder:text-ink-600 focus:outline-none font-mono"/></div>
      <div className="max-h-56 overflow-y-auto">
        <button onClick={()=>{onChange("");setO(false)}} className={`w-full text-left px-3 py-2 text-[12px] font-mono hover:bg-accent/10 transition-colors ${value===""?"text-accent":"text-ink-300"}`}>All Customers</button>
        {f.map(c=><button key={c.id} onClick={()=>{onChange(c.id);setO(false)}} className={`w-full text-left px-3 py-2 text-[12px] font-mono hover:bg-accent/10 transition-colors ${value===c.id?"text-accent":"text-ink-300"}`}>{c.name}</button>)}
        {f.length===0&&<p className="px-3 py-4 text-[12px] text-ink-600 text-center font-mono">No customers match</p>}
      </div>
    </div>}
  </div>;
}
function TimeRangeFilter({ value, onChange }: { value: Range; onChange: (r:Range)=>void }) {
  return <div className={`${btnBase} border-base-500 text-ink-300 gap-2 cursor-pointer`}>
    <span className="text-ink-500">{ICON.calendar}</span>
    <select value={value.days} onChange={e=>{const v=Number(e.target.value);const f=[...RANGES,CUSTOM_RANGE].find(r=>r.days===v);if(f)onChange(f)}} className="bg-transparent border-none text-[12px] font-mono text-ink-300 focus:outline-none cursor-pointer">
      {RANGES.map(r=><option key={r.days} value={r.days}>{r.label}</option>)}
      <option value={CUSTOM_RANGE.days}>Custom Range</option>
    </select>{ICON.chevron}
  </div>;
}
function LastUpdated({ date }: { date: Date|null }) {
  if(!date)return null;
  return <span className="text-[11px] text-ink-600 font-mono">Last Updated<br/><span className="text-ink-500">{fmtTime(date)}</span></span>;
}
function RefreshButton({ onClick }: { onClick: ()=>void }) {
  return <button onClick={onClick} className={`${btnBase} border-base-500 text-ink-400 hover:text-accent hover:border-accent`}>{ICON.refresh}<span>Refresh</span></button>;
}
function CustomizeButton() {
  const [s,setS]=useState(false);
  return <div className="relative"><button onClick={()=>setS(!s)} className={`${btnBase} border-base-500 text-ink-400 hover:text-accent hover:border-accent`}>{ICON.customize}<span>Customize</span></button>{s&&<><div className="fixed inset-0 z-30" onClick={()=>setS(false)}/><div className="absolute right-0 top-full mt-2 bg-base-800 border border-base-500 rounded-xl shadow-xl z-40 px-5 py-4 w-56"><p className="text-[13px] text-ink-300 font-mono text-center">Coming Soon</p></div></>}</div>;
}

// ── Animated number counter ───────────────────────────────────────────────

function AnimatedNumber({ target, duration = 800 }: { target: number; duration?: number }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (target <= 0) { setVal(0); return; }
    const start = performance.now();
    const tick = (now: number) => {
      const elapsed = now - start, progress = Math.min(elapsed / duration, 1);
      setVal(Math.round(target * progress));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, duration]);
  return <span className="tabular-nums">{val}</span>;
}

// ── KPI Card ──────────────────────────────────────────────────────────────

function KpiCard({ icon, color, title, value, sub, trend, trendSense, onClick }: {
  icon: React.ReactNode; color: string; title: string;
  value: React.ReactNode; sub?: React.ReactNode;
  trend?: { value: number; label: string };
  trendSense?: "positive" | "negative" | "neutral";
  onClick?: () => void;
}) {
  const trendClr = trendSense === "positive" ? "#39d98a" : trendSense === "negative" ? "#ff4d4d" : "#7a879b";
  const arrow = trend && trend.value > 0 ? "↑" : trend && trend.value < 0 ? "↓" : "→";
  return (
    <div onClick={onClick} className={`relative bg-base-800/70 border border-base-500/30 rounded-2xl p-6 flex flex-col justify-center gap-3 transition-all duration-300 hover:border-base-500/60 hover:shadow-lg hover:shadow-black/20 hover:-translate-y-0.5 ${onClick?"cursor-pointer":""}`}>
      {/* Icon + title */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span className="flex items-center justify-center w-9 h-9 rounded-full shrink-0" style={{ background: `${color}18`, color }}>{icon}</span>
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">{title}</span>
        </div>
        <span className="text-ink-700 text-xs cursor-help" title={`${title} — more info`}>ⓘ</span>
      </div>

      {/* Large value */}
      <div className="flex items-baseline gap-1.5">
        <span className="font-display text-[36px] font-bold leading-none tabular-nums text-ink-100">{value}</span>
        {sub && <span className="text-ink-500 text-[13px]">{sub}</span>}
      </div>

      {/* Trend */}
      {trend && (
        <div className="flex items-center gap-1 font-mono text-[11px]" style={{ color: trendClr }}>
          <span className="text-xs">{arrow} {Math.abs(trend.value).toFixed(1)}</span>
          <span className="text-ink-600">{trend.label}</span>
        </div>
      )}
    </div>
  );
}

// ── License Summary Card ──────────────────────────────────────────────────

function daysBetween(a: Date, b: Date) { return Math.ceil((a.getTime() - b.getTime()) / 86400000); }

function LicenseSummaryCard({ org, planInfo, freeLicense, licenseBundles, activeDevices, expiredDevices }: {
  org: OrganizationDetail | null;
  planInfo: CustomerPlanInfo | null;
  freeLicense: FreeLicenseInfo | null;
  licenseBundles: LicenseBundle[];
  activeDevices: number;
  expiredDevices: number;
}) {
  const now = new Date();
  const isFree = !!freeLicense; // backend returns free_license only on free plan

  // ── Active license capacity (only non-expired purchases) ──────────────
  const purchases = planInfo?.purchase_history || [];
  const activeCapacity = purchases
    .filter((p) => p.expires_at && new Date(p.expires_at) > now)
    .reduce((s, p) => s + (p.total_devices || 0), 0);

  // Free plan: capacity comes from the free license (0 once expired)
  const totalActive = isFree
    ? (freeLicense?.expired ? 0 : freeLicense?.total || 0)
    : activeCapacity;

  // Available licenses: backend already zeroes remaining on expired bundles
  const available = isFree
    ? (freeLicense?.expired ? 0 : freeLicense?.remaining || 0)
    : licenseBundles.reduce((s, b) => s + (b.remaining || 0), 0);

  const usedLicenses = isFree
    ? (freeLicense?.used || 0)
    : (planInfo?.usage?.firewalls ?? 0);

  // ── Status: reflects actual license state ─────────────────────────────
  const status: { label: string; color: string } = (() => {
    switch (org?.subscription_status) {
      case "past_due": return { label: "Past Due", color: "#ff4d4d" };
      case "canceled": return { label: "Canceled", color: "#7a879b" };
      case "trialing": return { label: "Trial", color: "#4f8cff" };
    }
    if (isFree) {
      return freeLicense?.expired
        ? { label: "Expired", color: "#ff4d4d" }
        : { label: "Trial", color: "#4f8cff" };
    }
    return activeCapacity > 0
      ? { label: "Active", color: "#39d98a" }
      : { label: "Expired", color: "#ff4d4d" };
  })();

  // ── Plan name ──────────────────────────────────────────────────────────
  const planNameMap: Record<string, string> = {
    free: "Free Trial", professional: "Professional Plan", msp: "MSP Plan",
  };
  const planName = planInfo?.plan_name || planNameMap[org?.plan || ""] || "No Plan";

  // ── Renewal / expiry line ──────────────────────────────────────────────
  const expiryLine = (() => {
    // Trial ends
    if (org?.subscription_status === "trialing" && org.trial_ends_at) {
      const d = daysBetween(new Date(org.trial_ends_at), now);
      if (d <= 0) return "Trial expired";
      return `Trial ends in ${d} day${d === 1 ? "" : "s"}`;
    }
    // Free license expiry
    if (freeLicense?.expiry_date) {
      const d = daysBetween(new Date(freeLicense.expiry_date), now);
      if (freeLicense.expired) return `Expired ${Math.abs(d)} day${Math.abs(d) === 1 ? "" : "s"} ago`;
      return `Expires ${new Date(freeLicense.expiry_date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}`;
    }
    // Purchases — earliest future expiry = renewal date
    const purchases = planInfo?.purchase_history || [];
    const future = purchases
      .map((p) => (p.expires_at ? new Date(p.expires_at) : null))
      .filter((d): d is Date => d !== null && d > now)
      .sort((a, b) => a.getTime() - b.getTime());
    if (future.length > 0) {
      return `Renews ${future[0].toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}`;
    }
    const past = purchases
      .map((p) => (p.expires_at ? new Date(p.expires_at) : null))
      .filter((d): d is Date => d !== null && d <= now)
      .sort((a, b) => b.getTime() - a.getTime());
    if (past.length > 0) {
      const d = daysBetween(now, past[0]);
      return `Expired ${d} day${d === 1 ? "" : "s"} ago`;
    }
    return "Active subscription";
  })();

  // ── License usage: only active capacity counts ─────────────────────────
  const usagePct = totalActive > 0 ? Math.min(100, Math.round((usedLicenses / totalActive) * 100)) : 0;

  // ── Expiring soon (≤30 days) ───────────────────────────────────────────
  const expiringSoon = (planInfo?.purchase_history || [])
    .map((p) => (p.expires_at ? new Date(p.expires_at) : null))
    .filter((d): d is Date => d !== null && d > now && daysBetween(d, now) <= 30).length
    + (freeLicense && freeLicense.expiry_date && !freeLicense.expired
        && daysBetween(new Date(freeLicense.expiry_date), now) <= 30 ? 1 : 0);

  const stats: { label: string; value: number; dot: string }[] = [
    { label: "Active Devices", value: activeDevices, dot: "#39d98a" },
    { label: "Expired Devices", value: expiredDevices, dot: "#ff4d4d" },
    { label: "Available Licenses", value: available, dot: "#4f8cff" },
    { label: "Expiring Soon", value: expiringSoon, dot: "#ff8a3d" },
  ];

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-2xl p-6 flex flex-col gap-4 transition-all duration-300 hover:border-base-500/60 hover:shadow-lg hover:shadow-black/20 hover:-translate-y-0.5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-9 h-9 rounded-full shrink-0" style={{ background: "#4f8cff18", color: "#4f8cff" }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
          </span>
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">License Summary</span>
          <span className="text-ink-700 text-xs cursor-help" title="Subscription and license health">ⓘ</span>
        </div>
        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold" style={{ background: `${status.color}18`, color: status.color }}>
          {status.label}
        </span>
      </div>

      {/* Plan info */}
      <div>
        <div className="text-ink-600 text-[10px] font-mono uppercase tracking-[0.12em]">Current Plan</div>
        <div className="font-display text-[18px] font-semibold text-ink-100">{planName}</div>
        <div className="font-mono text-[11px] text-ink-500 mt-0.5">{expiryLine}</div>
      </div>

      {/* License usage */}
      <div>
        <div className="flex items-baseline justify-between mb-1.5">
          <span className="font-mono text-[11px] text-ink-500">License Usage</span>
          {totalActive > 0 ? (
            <span className="font-mono text-[12px] text-ink-200 tabular-nums">
              {usedLicenses} / {totalActive} Devices Used
            </span>
          ) : (
            <span className="font-mono text-[11px] text-sev-critical">No active license capacity</span>
          )}
        </div>
        <div className="h-2 bg-base-700 rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all duration-700"
               style={{ width: totalActive > 0 ? `${usagePct}%` : "0%", background: usagePct >= 90 ? "#ff4d4d" : "#4f8cff" }} />
        </div>
      </div>

      {/* License stats */}
      <div className="space-y-1.5">
        {stats.map((s) => (
          <div key={s.label} className="flex items-center justify-between">
            <span className="flex items-center gap-2 font-mono text-[11px] text-ink-500">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.dot }} />
              {s.label}
            </span>
            <span className="font-mono text-[13px] font-semibold tabular-nums" style={{ color: s.dot }}>{s.value}</span>
          </div>
        ))}
      </div>

      {/* Quick action */}
      <button onClick={() => navigate("/settings/organization")}
              className="mt-auto self-start inline-flex items-center gap-1 font-mono text-[11px] text-accent hover:text-ink-100 hover:gap-2 transition-all">
        View License Details <span>→</span>
      </button>
    </div>
  );
}

// ── Row 2 Widget 1: Security Score Trend ─────────────────────────────────

function SecurityScoreTrend({ customerId }: { customerId: string }) {
  const [wRange, setWRange] = useState(30);
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const [currentScore, setCurrentScore] = useState(0);
  const [wLoading, setWLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setWLoading(true);
    api.executiveSummary(wRange, customerId || undefined, undefined, localToday(), localTzOffset())
      .then((s) => {
        if (!cancelled) {
          setTrend(s.score_trend || []);
          setCurrentScore(s.overall_score || 0);
        }
      })
      .catch(() => { if (!cancelled) { setTrend([]); setCurrentScore(0); } })
      .finally(() => { if (!cancelled) setWLoading(false); });
    return () => { cancelled = true; };
  }, [wRange, customerId]);

  // Trim leading zero-value days (backend fills days before the first
  // analysis with 0.0) so the chart starts at the earliest available record
  // instead of reserving empty space for missing dates.  If no historical
  // record exists at all but a current Security Score does, use the current
  // score as a single valid data point (today) instead of an empty chart.
  const data = useMemo(() => {
    let first = 0;
    while (first < trend.length && trend[first].value <= 0) first++;
    const trimmed = first >= trend.length ? [] : trend.slice(first);
    if (trimmed.length === 0 && currentScore > 0) {
      return [{ date: localToday(), value: currentScore }];
    }
    return trimmed;
  }, [trend, currentScore]);

  // Evenly distributed date ticks (first, last, and spaced middles)
  const ticks = useMemo(() => {
    const n = data.length;
    if (n === 0) return [];
    if (n <= 2) return data.map((d) => d.date);
    const indices = new Set<number>([0, n - 1]);
    const step = Math.max(1, Math.floor(n / 6));
    for (let i = step; i < n - 1; i += step) indices.add(i);
    return [...indices].sort((a, b) => a - b).map((i) => data[i].date);
  }, [data]);

  const fmtShort = (d: string) => new Date(d + "T00:00:00").toLocaleDateString("en-US", { month: "short", day: "numeric" });

  // Marker per point; latest point gets a soft halo highlight
  const renderDot = (props: any) => {
    const { cx, cy, index } = props;
    if (cx == null || cy == null) return <g />;
    const isLast = index === data.length - 1;
    return (
      <g>
        {isLast && <circle cx={cx} cy={cy} r={7} fill="#3b82f6" opacity={0.18} />}
        <circle cx={cx} cy={cy} r={isLast ? 4 : 3} fill="#3b82f6" stroke="#0b1020" strokeWidth={1.5} />
      </g>
    );
  };

  const tooltipContent = ({ active, payload }: any) => {
    if (!active || !payload?.length) return null;
    const p = payload[0].payload;
    return (
      <div className="bg-base-900 border border-base-500 rounded-lg shadow-lg px-3 py-2">
        <div className="text-[16px] font-bold text-ink-100 tabular-nums">{p.value}</div>
        <div className="text-[11px] text-ink-500">{fmtShort(p.date)}</div>
      </div>
    );
  };

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 shadow-sm h-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Security Score Trend</span>
          <span className="text-ink-700 text-xs cursor-help" title="How your security score changed over time">ⓘ</span>
        </div>
        <select value={wRange} onChange={(e) => setWRange(Number(e.target.value))}
                className="bg-base-800 border border-base-500 rounded-md px-2 py-1 text-[11px] text-ink-300 focus:outline-none focus:border-accent cursor-pointer">
          <option value={7}>Last 7 Days</option>
          <option value={30}>Last 30 Days</option>
          <option value={90}>Last 90 Days</option>
          <option value={365}>Last 365 Days</option>
        </select>
      </div>

      {/* Chart */}
      <div className="h-[120px] mt-auto">
        {wLoading ? (
          <div className="h-full flex items-center justify-center"><div className="animate-pulse h-full w-full bg-base-700/30 rounded-lg" /></div>
        ) : data.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center gap-1">
            <span className="text-2xl opacity-20">📈</span>
            <p className="text-ink-500 text-[12px]">No historical security score data available.</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={120}>
            <AreaChart data={data} margin={{ top: 10, right: 12, bottom: 0, left: -14 }}>
              <defs>
                <linearGradient id="scoreAreaFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.16} />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.01} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#7a879b1a" vertical={false} />
              <XAxis dataKey="date" ticks={ticks}
                     tickFormatter={fmtShort}
                     tick={{ fontSize: 10, fill: "#7a879b" }}
                     axisLine={{ stroke: "#7a879b33" }} tickLine={false} height={22} />
              <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]}
                     tick={{ fontSize: 10, fill: "#7a879b" }}
                     axisLine={false} tickLine={false} width={34} />
              <Tooltip content={tooltipContent} />
              <Area type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2.5}
                    fill="url(#scoreAreaFill)" strokeLinecap="round" strokeLinejoin="round"
                    dot={renderDot}
                    activeDot={{ r: 5, fill: "#3b82f6", stroke: "#0b1020", strokeWidth: 2 }}
                    isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

// ── Row 2 Widget 2: Security Grade Gauge ─────────────────────────────────

function SecurityGrade({ score, grade }: { score: number; grade: string }) {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    const start = performance.now();
    const duration = 1300;
    const tick = (now: number) => {
      const p = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3); // ease-out cubic
      setAnimated(score * eased);
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [score]);

  const gColor = gradeColor(grade || "F");

  // ── 240° radial gauge geometry (y-down screen coordinates) ──────────
  // Start at bottom-left (~210° compass) sweeping clockwise through the
  // top to bottom-right (~330° compass), leaving a ~120° gap at the bottom.
  const cx = 100, cy = 105, R = 80;
  const pt = (deg: number) => {
    const r = (deg * Math.PI) / 180;
    return { x: cx + R * Math.cos(r), y: cy + R * Math.sin(r) };
  };
  const startPt = pt(150);              // bottom-left tip
  const endPt = pt(30);                 // bottom-right tip (100%)
  const pct = Math.max(0, Math.min(100, animated));
  const scorePt = pt(150 + (pct / 100) * 240); // active arc endpoint
  const largeActive = pct > 75 ? 1 : 0;   // active sweep >180° when pct>75
  const largeInactive = pct < 25 ? 1 : 0; // inactive sweep >180° when pct<25

  // Contextual message from score
  const message = (() => {
    if (score >= 90) return { head: "Excellent", body: "Your security posture is excellent. Keep up the great work!" };
    if (score >= 80) return { head: "Good", body: "Your firewall is well protected with only minor improvements recommended." };
    if (score >= 70) return { head: "Fair", body: "Several improvements are recommended to strengthen your security posture." };
    if (score >= 55) return { head: "Poor", body: "Immediate attention is recommended to reduce security risk." };
    return { head: "Critical", body: "Your firewall requires urgent remediation." };
  })();

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 transition-all duration-300 hover:border-base-500/60 hover:shadow-lg hover:shadow-black/20 hover:-translate-y-0.5 h-full">
      {/* Header — sentence case */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-7 h-7 rounded-full shrink-0" style={{ background: `${gColor}18`, color: gColor }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2a10 10 0 1 0 10 10"/><polyline points="12 6 12 12 16 14"/></svg>
          </span>
          <span className="text-[12px] font-medium text-ink-400">Security Grade</span>
          <span className="text-ink-700 text-xs cursor-help" title="Current security posture rating">ⓘ</span>
        </div>
      </div>

      {/* 240° donut gauge */}
      <div className="flex-1 flex flex-col items-center justify-start">
        <svg viewBox="0 16 200 149" className="w-full max-w-[165px]">
          <defs>
            <linearGradient id="gaugeArcGrad" gradientUnits="userSpaceOnUse" x1={startPt.x} y1="0" x2={endPt.x} y2="0">
              <stop offset="0%" stopColor="#ff4d4d" />
              <stop offset="30%" stopColor="#f5c451" />
              <stop offset="70%" stopColor="#9ad94a" />
              <stop offset="100%" stopColor="#39d98a" />
            </linearGradient>
          </defs>

            {/* Inactive grey arc — from score point to 100% */}
            <path d={`M ${scorePt.x} ${scorePt.y} A ${R} ${R} 0 ${largeInactive} 1 ${endPt.x} ${endPt.y}`}
                  fill="none" stroke="#2d3748" strokeWidth="16" strokeLinecap="round" />
            {/* Active gradient arc — from 0 to the score point */}
            <path d={`M ${startPt.x} ${startPt.y} A ${R} ${R} 0 ${largeActive} 1 ${scorePt.x} ${scorePt.y}`}
                  fill="none" stroke="url(#gaugeArcGrad)" strokeWidth="16" strokeLinecap="round" />

          {/* Inner text — centered in the hollow */}
          <text x="100" y="98" textAnchor="middle" fill={gColor} fontSize="44" fontWeight="700" fontFamily="ui-monospace, monospace">
            {grade || "—"}
          </text>
          <text x="100" y="122" textAnchor="middle" fill="#e8ecf3" fontSize="20" fontWeight="600" fontFamily="ui-monospace, monospace">
            {Math.round(animated)}/100
          </text>
          <text x="100" y="142" textAnchor="middle" fill={gColor} fontSize="15" fontWeight="600" fontFamily="ui-monospace, monospace">
            {message.head}
          </text>

          {/* 0 / 100 labels directly below the arc tips */}
          <text x={startPt.x} y="161" textAnchor="middle" fill="#7a879b" fontSize="8" fontFamily="ui-monospace, monospace">0</text>
          <text x={endPt.x} y="161" textAnchor="middle" fill="#7a879b" fontSize="8" fontFamily="ui-monospace, monospace">100</text>
        </svg>
      </div>
    </div>
  );
}

// ── Row 3 Widget 1: Findings by Severity (donut + legend) ────────────────

function FindingsBySeverityCard({ charts }: { charts: DashboardCharts | null }) {
  const dist = charts?.severity_distribution || {};
  const total = charts?.total_findings || 0;
  const segments = Object.entries(dist)
    .filter(([sev, b]) => b.count > 0)
    .map(([sev, b]) => ({ name: sev, value: b.count, color: SEV_COLORS[sev] || "#7a879b" }));
  const totalForPct = segments.reduce((s, x) => s + x.value, 0) || 1;

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Findings by Severity</span>
          <span className="text-ink-700 text-xs cursor-help" title="Active findings by severity">ⓘ</span>
        </div>
      </div>

      {segments.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">🍩</span>
          <p className="text-ink-500 text-[12px]">No findings available.</p>
        </div>
      ) : (
        <div className="flex-1 flex items-center gap-3 min-h-0">
          {/* Donut — left half */}
          <div className="relative w-[110px] h-[110px] shrink-0 mx-auto">
            <PieChart width={110} height={110} style={{ position: "relative", zIndex: 10 }}>
              <Pie data={segments} dataKey="value" nameKey="name" cx="50%" cy="50%"
                   innerRadius={36} outerRadius={52} paddingAngle={2} strokeWidth={0}
                   isAnimationActive={false}>
                {segments.map((s, i) => <Cell key={i} fill={s.color} />)}
              </Pie>
               <Tooltip {...DONUT_TOOLTIP} />
            </PieChart>
            <div className="absolute inset-0 z-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="font-display text-[20px] font-bold leading-none tabular-nums text-ink-100">{total}</span>
              <span className="text-ink-600 text-[9px] mt-0.5">Total</span>
            </div>
          </div>

          {/* Legend — right side */}
          <div className="flex-1 space-y-1.5 min-w-0">
            {segments.map((s) => (
              <div key={s.name} className="flex items-center gap-1.5 text-[10px]">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
                <span className="text-ink-400 truncate">{s.name}</span>
                <span className="ml-auto text-ink-300 tabular-nums shrink-0">
                  {s.value} ({Math.round((s.value / totalForPct) * 100)}%)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <button onClick={() => navigate("/security-analytics")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View all findings →
      </button>
    </div>
  );
}

// ── Row 3 Widget 2: Open vs Fixed (donut + legend) ───────────────────────

function OpenVsFixedCard({ charts }: { charts: DashboardCharts | null }) {
  const dist = charts?.status_distribution || {};
  const rows = [
    { key: "open", label: "Open", color: "#ff4d4d", count: dist.open?.count || 0 },
    { key: "in_progress", label: "In Progress", color: "#ff8a3d", count: dist.in_progress?.count || 0 },
    { key: "fixed", label: "Fixed", color: "#39d98a", count: dist.fixed?.count || 0 },
  ];
  const segments = rows.filter((r) => r.count > 0);
  const total = rows.reduce((s, r) => s + r.count, 0) || 1;

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Open vs Fixed</span>
          <span className="text-ink-700 text-xs cursor-help" title="Finding status distribution">ⓘ</span>
        </div>
      </div>

      {segments.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">🍩</span>
          <p className="text-ink-500 text-[12px]">No findings available.</p>
        </div>
      ) : (
        <div className="flex-1 flex items-center gap-3 min-h-0">
          <div className="relative w-[110px] h-[110px] shrink-0 mx-auto">
            <PieChart width={110} height={110} style={{ position: "relative", zIndex: 10 }}>
              <Pie data={segments} dataKey="count" nameKey="label" cx="50%" cy="50%"
                   innerRadius={36} outerRadius={52} paddingAngle={2} strokeWidth={0}
                   isAnimationActive={false}>
                {segments.map((s, i) => <Cell key={i} fill={s.color} />)}
              </Pie>
               <Tooltip {...DONUT_TOOLTIP} />
            </PieChart>
            <div className="absolute inset-0 z-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="font-display text-[20px] font-bold leading-none tabular-nums text-ink-100">{total}</span>
              <span className="text-ink-600 text-[9px] mt-0.5">Total</span>
            </div>
          </div>

          <div className="flex-1 space-y-1.5 min-w-0">
            {rows.map((r) => (
              <div key={r.key} className="flex items-center gap-1.5 text-[10px]">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: r.color }} />
                <span className="text-ink-400 truncate">{r.label}</span>
                <span className="ml-auto text-ink-300 tabular-nums shrink-0">
                  {r.count} ({Math.round((r.count / total) * 100)}%)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <button onClick={() => navigate("/security-analytics")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View details →
      </button>
    </div>
  );
}

// ── Row 3 Widget 3: Risk Trend (stacked area) ────────────────────────────

function RiskTrendStackedCard({ trend, hidden }: { trend: RiskTrend | null; hidden: string[] }) {
  const [wRange, setWRange] = useState(30);
  const [data, setData] = useState<RiskTrend | null>(null);
  const [wLoading, setWLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setWLoading(true);
    api.riskTrend(wRange, undefined, undefined, localToday(), localTzOffset())
      .then((t) => { if (!cancelled) setData(t); })
      .catch(() => { if (!cancelled) setData(null); })
      .finally(() => { if (!cancelled) setWLoading(false); });
    return () => { cancelled = true; };
  }, [wRange]);

  const t = data || trend;
  const hiddenSet = new Set(hidden);
  const visible = ["Critical", "High", "Medium", "Low"].filter((s) => !hiddenSet.has(s));

  const rows = useMemo(() => {
    if (!t?.trend?.length) return [];
    return t.trend.map((p) => {
      const row: Record<string, string | number> = { date: p.date };
      for (const s of visible) row[s] = (p as any)[s] || 0;
      return row;
    });
  }, [t, visible.join(",")]);

  const maxY = useMemo(() => {
    let m = 0;
    for (const r of rows) {
      const sum = visible.reduce((a, s) => a + (Number(r[s]) || 0), 0);
      if (sum > m) m = sum;
    }
    return m > 0 ? Math.ceil((m * 1.15) / 50) * 50 : 100;
  }, [rows, visible.join(",")]);

  // Adaptive date ticks
  const ticks = useMemo(() => {
    const n = rows.length;
    if (n <= 2) return rows.map((r) => r.date as string);
    const indices = new Set<number>([0, n - 1]);
    const step = Math.max(1, Math.floor(n / 6));
    for (let i = step; i < n - 1; i += step) indices.add(i);
    return [...indices].sort((a, b) => a - b).map((i) => rows[i].date as string);
  }, [rows]);

  const fmtShort = (d: string) => new Date(d + "T00:00:00").toLocaleDateString("en-US", { month: "short", day: "numeric" });

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="text-[13px] font-semibold text-ink-100">Risk Trend</span>
          <span className="text-ink-600 text-[10px] truncate">Findings by Severity</span>
          <span className="text-ink-700 text-xs cursor-help shrink-0" title="Historical findings by severity">ⓘ</span>
        </div>
        <select value={wRange} onChange={(e) => setWRange(Number(e.target.value))}
                className="bg-base-800 border border-base-500 rounded-md px-2 py-1 text-[11px] text-ink-300 focus:outline-none focus:border-accent cursor-pointer shrink-0">
          <option value={7}>Last 7 Days</option>
          <option value={30}>Last 30 Days</option>
          <option value={90}>Last 90 Days</option>
          <option value={365}>Last 365 Days</option>
        </select>
      </div>

      {/* Horizontal legend */}
      <div className="flex items-center gap-3">
        {visible.map((s) => (
          <span key={s} className="flex items-center gap-1 text-[9px] text-ink-400">
            <span className="w-2 h-2 rounded-full shrink-0" style={{ background: SEV_COLORS[s] }} />
            {s}
          </span>
        ))}
      </div>

      <div className="h-[170px]">
        {wLoading ? (
          <div className="h-full flex items-center justify-center"><div className="animate-pulse h-full w-full bg-base-700/30 rounded-lg" /></div>
        ) : rows.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center gap-1 text-center">
            <span className="text-2xl opacity-20">📈</span>
            <p className="text-ink-500 text-[12px]">No historical findings data available.</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={170}>
            <AreaChart data={rows} margin={{ top: 6, right: 8, bottom: 0, left: -16 }}>
              <defs>
                {visible.map((s) => (
                  <linearGradient key={s} id={`stack-${s}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={SEV_COLORS[s]} stopOpacity={0.35} />
                    <stop offset="100%" stopColor={SEV_COLORS[s]} stopOpacity={0.05} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#7a879b1a" vertical={false} />
              <XAxis dataKey="date" ticks={ticks} tickFormatter={fmtShort}
                     tick={{ fontSize: 9, fill: "#7a879b" }}
                     axisLine={{ stroke: "#7a879b33" }} tickLine={false} height={18} />
              <YAxis domain={[0, maxY]} tick={{ fontSize: 9, fill: "#7a879b" }}
                     axisLine={false} tickLine={false} width={38} />
               <Tooltip {...DONUT_TOOLTIP}
                        labelFormatter={(d: string) => new Date(d + "T00:00:00").toLocaleDateString("en-US", { month: "long", day: "numeric" })} />
              {/* Stack order bottom→top: Low, Medium, High, Critical */}
              {["Low", "Medium", "High", "Critical"].filter((s) => hiddenSet.has(s) === false).map((s) => (
                <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={SEV_COLORS[s]}
                      strokeWidth={1.5} fill={`url(#stack-${s})`} isAnimationActive={false} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

// ── Row 3 Widget 4: Top Risks (ranked list) ──────────────────────────────

function TopRisksCard({ charts }: { charts: DashboardCharts | null }) {
  const risks = charts?.top_findings || [];
  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Top Risks</span>
          <span className="text-ink-700 text-xs cursor-help" title="Most frequent findings across devices">ⓘ</span>
        </div>
      </div>

      {risks.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">🛡️</span>
          <p className="text-ink-500 text-[12px]">No risks identified.</p>
        </div>
      ) : (
        <div className="flex-1 flex flex-col justify-center gap-2.5 min-h-0">
          {risks.slice(0, 5).map((r, i) => {
            const sev = r.severity || "Info";
            const color = SEV_COLORS[sev] || "#7a879b";
            return (
              <div key={r.rule_id || i} className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-md flex items-center justify-center shrink-0" style={{ background: `${color}18` }}>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] text-ink-200 truncate leading-tight">{r.title}</div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[13px] font-semibold tabular-nums" style={{ color }}>{r.devices ?? r.count}</div>
                  <div className="text-ink-600 text-[8px] leading-tight">Devices</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <button onClick={() => navigate("/security-analytics")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View all risks →
      </button>
    </div>
  );
}

// ── Row 4 Widget 1: Firmware Health ──────────────────────────────────────

function FirmwareHealthCard({ data }: { data: Row4Summary | null }) {
  const fh = data?.firmware_health;
  const latest = fh?.latest || 0;
  const behind = fh?.behind || 0;
  const total = fh?.total ?? latest + behind;
  const segments = [
    { name: "Latest", value: latest, color: "#39d98a" },
    { name: "Older", value: behind, color: "#ff8a3d" },
  ].filter((s) => s.value > 0);
  const totalForPct = total || 1;

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Firmware Health</span>
          <span className="text-ink-700 text-xs cursor-help" title="Firmware vs recommended version per generation">ⓘ</span>
        </div>
      </div>

      {segments.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">🍩</span>
          <p className="text-ink-500 text-[12px]">No firmware data available.</p>
        </div>
      ) : (
        <div className="flex-1 flex items-center gap-3 min-h-0">
          <div className="relative w-[100px] h-[100px] shrink-0 mx-auto">
            <PieChart width={100} height={100} style={{ position: "relative", zIndex: 10 }}>
              <Pie data={segments} dataKey="value" nameKey="name" cx="50%" cy="50%"
                   innerRadius={33} outerRadius={48} paddingAngle={2} strokeWidth={0}
                   isAnimationActive={false}>
                {segments.map((s, i) => <Cell key={i} fill={s.color} />)}
              </Pie>
               <Tooltip {...DONUT_TOOLTIP} />
            </PieChart>
            <div className="absolute inset-0 z-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-[16px] font-bold text-ink-100 tabular-nums">{total}</span>
              <span className="text-[9px] text-ink-500">Total</span>
            </div>
          </div>
          <div className="flex-1 space-y-1.5 min-w-0">
            {segments.map((s) => (
              <div key={s.name} className="flex items-center gap-1.5 text-[10px]">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
                <span className="text-ink-400 truncate">{s.name}</span>
                <span className="ml-auto text-ink-300 tabular-nums shrink-0">
                  {s.value} ({Math.round((s.value / totalForPct) * 100)}%)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <button onClick={() => navigate("/security-analytics")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View firmware report →
      </button>
    </div>
  );
}

// ── Row 4 Widget 2: Device Health ────────────────────────────────────────

function DeviceHealthCard({ data }: { data: Row4Summary | null }) {
  const dh = data?.device_health;
  const healthy = dh?.healthy || 0;
  const warning = dh?.warning || 0;
  const critical = dh?.critical || 0;
  const total = dh?.total ?? healthy + warning + critical;
  const segments = [
    { name: "Healthy", value: healthy, color: "#39d98a" },
    { name: "Warning", value: warning, color: "#ff8a3d" },
    { name: "Critical", value: critical, color: "#ff4d4d" },
  ].filter((s) => s.value > 0);
  const totalForPct = total || 1;

  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Device Health</span>
          <span className="text-ink-700 text-xs cursor-help" title="Device health based on security grade">ⓘ</span>
        </div>
      </div>

      {segments.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">🍩</span>
          <p className="text-ink-500 text-[12px]">No device health data available.</p>
        </div>
      ) : (
        <div className="flex-1 flex items-center gap-3 min-h-0">
          <div className="relative w-[100px] h-[100px] shrink-0 mx-auto">
            <PieChart width={100} height={100} style={{ position: "relative", zIndex: 10 }}>
              <Pie data={segments} dataKey="value" nameKey="name" cx="50%" cy="50%"
                   innerRadius={33} outerRadius={48} paddingAngle={2} strokeWidth={0}
                   isAnimationActive={false}>
                {segments.map((s, i) => <Cell key={i} fill={s.color} />)}
              </Pie>
               <Tooltip {...DONUT_TOOLTIP} />
            </PieChart>
            <div className="absolute inset-0 z-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-[16px] font-bold text-ink-100 tabular-nums">{total}</span>
              <span className="text-[9px] text-ink-500">Total</span>
            </div>
          </div>
          <div className="flex-1 space-y-1.5 min-w-0">
            {segments.map((s) => (
              <div key={s.name} className="flex items-center gap-1.5 text-[10px]">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
                <span className="text-ink-400 truncate">{s.name}</span>
                <span className="ml-auto text-ink-300 tabular-nums shrink-0">
                  {s.value} ({Math.round((s.value / totalForPct) * 100)}%)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <button onClick={() => navigate("/devices")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View all devices →
      </button>
    </div>
  );
}

// ── Row 4 Widget 3: Recently Detected Findings ───────────────────────────

function RecentlyDetectedCard({ data }: { data: Row4Summary | null }) {
  const items = data?.recent_findings || [];
  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Recently Detected Findings</span>
          <span className="text-ink-700 text-xs cursor-help" title="Most recently detected findings">ⓘ</span>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">🔍</span>
          <p className="text-ink-500 text-[12px]">No recent findings.</p>
        </div>
      ) : (
        <div className="flex-1 flex flex-col justify-center gap-2 min-h-0">
          {items.slice(0, 3).map((f) => {
            const color = SEV_COLORS[f.severity] || "#7a879b";
            return (
              <div key={f.id} className="flex items-start gap-2 border-b border-base-500/20 last:border-0 pb-2 last:pb-0">
                <span className="mt-0.5 px-1.5 py-0.5 rounded text-[8px] font-bold shrink-0" style={{ background: `${color}18`, color }}>
                  {f.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] text-ink-200 leading-tight line-clamp-2">{f.title}</div>
                  <div className="text-[9px] text-ink-600 mt-0.5 truncate">{f.device_name}</div>
                </div>
                <span className="text-[9px] text-ink-600 shrink-0 tabular-nums">{fmtRelative(f.first_seen_at)}</span>
              </div>
            );
          })}
        </div>
      )}

      <button onClick={() => navigate("/security-analytics")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View all findings →
      </button>
    </div>
  );
}

// ── Row 4 Widget 4: Recently Fixed ───────────────────────────────────────

function RecentlyFixedCard({ data }: { data: Row4Summary | null }) {
  const items = data?.recent_fixed || [];
  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Recently Fixed</span>
          <span className="text-ink-700 text-xs cursor-help" title="Most recently resolved findings">ⓘ</span>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">✅</span>
          <p className="text-ink-500 text-[12px]">No recently fixed findings.</p>
        </div>
      ) : (
        <div className="flex-1 flex flex-col justify-center gap-2 min-h-0">
          {items.slice(0, 3).map((f) => {
            const color = SEV_COLORS[f.severity] || "#7a879b";
            return (
              <div key={f.id} className="flex items-start gap-2 border-b border-base-500/20 last:border-0 pb-2 last:pb-0">
                <span className="mt-0.5 px-1.5 py-0.5 rounded text-[8px] font-bold shrink-0" style={{ background: `${color}18`, color }}>
                  {f.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] text-ink-200 leading-tight line-clamp-2">{f.title}</div>
                  <div className="text-[9px] text-ink-600 mt-0.5 truncate">{f.device_name}</div>
                  <span className="inline-block mt-0.5 px-1 py-px rounded text-[8px] font-semibold bg-[#39d98a]15 text-[#39d98a]">Fixed</span>
                </div>
                <span className="text-[9px] text-ink-600 shrink-0 tabular-nums">{fmtRelative(f.resolved_at)}</span>
              </div>
            );
          })}
        </div>
      )}

      <button onClick={() => navigate("/security-analytics")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View all resolved findings →
      </button>
    </div>
  );
}

// ── Row 4 Widget 5: Recent Analyses ──────────────────────────────────────

function RecentAnalysesCard({ data }: { data: Row4Summary | null }) {
  const items = data?.recent_analyses || [];
  return (
    <div className="relative bg-base-800/70 border border-base-500/30 rounded-xl p-4 flex flex-col gap-2.5 h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[13px] font-semibold text-ink-100">Recent Analyses</span>
          <span className="text-ink-700 text-xs cursor-help" title="Recently completed analyses">ⓘ</span>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-1 text-center">
          <span className="text-2xl opacity-20">📋</span>
          <p className="text-ink-500 text-[12px]">No recent analyses.</p>
        </div>
      ) : (
        <div className="flex-1 flex flex-col justify-center gap-2 min-h-0">
          {items.slice(0, 3).map((a) => {
            const delta = a.score_delta;
            const deltaColor = delta == null || delta === 0 ? "#7a879b" : delta > 0 ? "#39d98a" : "#ff4d4d";
            const arrow = delta == null || delta === 0 ? "→" : delta > 0 ? "↑" : "↓";
            return (
              <div key={a.id} className="flex items-start gap-2 border-b border-base-500/20 last:border-0 pb-2 last:pb-0">
                <span className="mt-0.5 w-5 h-5 rounded-md flex items-center justify-center shrink-0 bg-accent/10">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#4f8cff" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="#4f8cff"/><circle cx="6" cy="18" r="1" fill="#4f8cff"/></svg>
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] text-ink-200 leading-tight truncate">{a.device_name}</div>
                  <div className="text-[9px] text-ink-600 truncate">{a.model || "Firewall"}</div>
                  <span className="inline-block mt-0.5 px-1 py-px rounded text-[8px] font-semibold bg-[#39d98a]15 text-[#39d98a]">Completed</span>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[9px] text-ink-600 tabular-nums">{fmtRelative(a.created_at)}</div>
                  <div className="text-[10px] font-semibold tabular-nums mt-0.5" style={{ color: deltaColor }}>
                    Score {delta != null && delta !== 0 ? `${delta > 0 ? "+" : ""}${delta} ${arrow}` : `${a.score} ${arrow}`}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <button onClick={() => navigate("/devices")}
              className="self-start text-[11px] text-accent hover:text-ink-100 transition-colors">
        View all analyses →
      </button>
    </div>
  );
}

// ── Main Dashboard ────────────────────────────────────────────────────────

export function AdvancedDashboard() {
  const [isMsp, setIsMsp] = useState(false);
  const [org, setOrg] = useState<OrganizationDetail | null>(null);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [customerId, setCustomerId] = useState("");
  const [range, setRange] = useState<Range>(RANGES[2]);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [loading, setLoading] = useState(true);

  const [summary, setSummary] = useState<ExecutiveSummary | null>(null);
  const [riskTrend, setRiskTrend] = useState<RiskTrend | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [charts, setCharts] = useState<DashboardCharts | null>(null);
  const [row4, setRow4] = useState<Row4Summary | null>(null);
  const [planInfo, setPlanInfo] = useState<CustomerPlanInfo | null>(null);
  const [freeLicense, setFreeLicense] = useState<FreeLicenseInfo | null>(null);
  const [licenseBundles, setLicenseBundles] = useState<LicenseBundle[]>([]);
  const [hiddenSeverities, setHiddenSeverities] = useState<string[]>([]);

  useEffect(() => {
    api.getOrganization().then(o => {
      setOrg(o); setIsMsp(!!o.is_msp);
      const allowed = new Set(["Medium", "Low", "Info"]);
      setHiddenSeverities((o.hidden_severities || []).filter((s: string) => allowed.has(s)));
    }).catch(()=>{});
    api.listCustomers().then(setCustomers).catch(()=>{});
    api.currentPlan().then(setPlanInfo).catch(()=>{});
    api.fetchLicenseBundles().then(r => { setFreeLicense(r.free_license ?? null); setLicenseBundles(r.bundles ?? []); }).catch(()=>{});
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    const lt = localToday(), tzo = localTzOffset();
    try {
      const [s, rt, d, c, r4] = await Promise.all([
        api.executiveSummary(range.days, customerId||undefined, undefined, lt, tzo),
        api.riskTrend(range.days, customerId||undefined, undefined, lt, tzo),
        api.listDevices().catch(() => [] as Device[]),
        api.dashboardCharts(range.days, customerId||undefined, undefined, lt, tzo, hiddenSeverities).catch(() => null),
        api.row4Summary(customerId||undefined, hiddenSeverities).catch(() => null),
      ]);
      setSummary(s); setRiskTrend(rt); setDevices(d); setCharts(c); setRow4(r4);
      setLastUpdated(new Date());
    } catch { /* graceful */ }
    setLoading(false);
  }, [customerId, range, hiddenSeverities]);

  useEffect(() => { refresh(); }, [refresh]);

  // ── Derived metrics ──────────────────────────────────────────────────
  const openFindings = useMemo(() => {
    if (!riskTrend?.trend?.length) return 0;
    const last = riskTrend.trend[riskTrend.trend.length - 1];
    return (last.Critical||0)+(last.High||0)+(last.Medium||0)+(last.Low||0);
  }, [riskTrend]);
  const openDelta = useMemo(() => {
    if (!riskTrend?.deltas) return 0;
    return (riskTrend.deltas.Critical||0)+(riskTrend.deltas.High||0)+(riskTrend.deltas.Medium||0)+(riskTrend.deltas.Low||0);
  }, [riskTrend]);

  const deviceTrend = useMemo(() => {
    if (!summary) return 0;
    return (summary as any).device_trend || 0;
  }, [summary]);

  return (
    <div className="max-w-[1440px] fade-in space-y-5 pb-8">
      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4 py-3">
        <div className="flex flex-wrap items-center gap-3">
          {isMsp && <CustomerFilter customers={customers} value={customerId} onChange={setCustomerId} />}
          <TimeRangeFilter value={range} onChange={setRange} />
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <LastUpdated date={lastUpdated} />
          <RefreshButton onClick={refresh} />
          <CustomizeButton />
        </div>
      </div>

      {/* ── Rows 1+2 + License Summary ──────────────────────────────────── */}
      <div className="flex flex-col xl:flex-row gap-4 items-start">
        <div className="flex-1 min-w-0 space-y-4">
        {/* Row 1 — KPI cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {loading && ([1,2,3,4].map(i => <div key={i} className="bg-base-800/40 border border-base-500/20 rounded-2xl p-6 animate-pulse"><div className="flex items-center gap-2.5 mb-4"><div className="w-9 h-9 rounded-full bg-base-700/50"/><div className="h-3 w-24 bg-base-700/50 rounded"/></div><div className="h-9 w-20 bg-base-700/50 rounded mb-3"/><div className="h-3 w-28 bg-base-700/50 rounded"/></div>))}
          {!loading && summary && (
            <>
              <KpiCard
                icon={ICON.shield} color="#4f8cff" title="Security Score"
                value={<><AnimatedNumber target={summary.overall_score} /> <span className="text-ink-600 text-lg font-normal">/ 100</span></>}
                sub={<span className="px-2 py-0.5 rounded-full text-[10px] font-bold ml-2" style={{background:`${gradeColor(summary.overall_grade)}18`,color:gradeColor(summary.overall_grade)}}>Grade {summary.overall_grade}</span>}
                trend={{value:summary.score_delta,label:"since last 30 days"}}
                trendSense={summary.score_delta > 0 ? "positive" : summary.score_delta < 0 ? "negative" : "neutral"}
              />
              <KpiCard
                icon={ICON.server} color="#a855f7" title="Devices"
                value={<AnimatedNumber target={summary.total_devices} />}
                sub={<span className="text-ink-600 font-mono text-[11px]">Total Devices</span>}
                trend={{value:deviceTrend,label:deviceTrend>0?"devices added this month":deviceTrend<0?"devices removed this month":"changes this month"}}
                trendSense={deviceTrend > 0 ? "positive" : deviceTrend < 0 ? "negative" : "neutral"}
              />
              <KpiCard
                icon={ICON.alert} color="#ff4d4d" title="Critical Findings"
                value={<AnimatedNumber target={summary.critical_count} />}
                sub={<span className="text-ink-600 font-mono text-[11px]">active</span>}
                trend={{value:summary.critical_delta,label:"since last 30 days"}}
                trendSense={summary.critical_delta < 0 ? "positive" : summary.critical_delta > 0 ? "negative" : "neutral"}
              />
              <KpiCard
                icon={ICON.warning} color="#ff8a3d" title="Open Findings"
                value={<AnimatedNumber target={openFindings} />}
                sub={<span className="text-ink-600 font-mono text-[11px]">unresolved</span>}
                trend={{value:openDelta,label:"since last 30 days"}}
                trendSense={openDelta < 0 ? "positive" : openDelta > 0 ? "negative" : "neutral"}
              />
            </>
          )}
          {!loading && !summary && (
            <div className="col-span-full flex flex-col items-center justify-center py-16 text-center gap-3">
              <span className="text-4xl opacity-20">📊</span>
              <p className="text-ink-500 text-sm font-mono">No data available</p>
              <p className="text-ink-600 text-[12px]">Run your first analysis to populate the dashboard.</p>
            </div>
          )}
        </div>

        {/* Row 2 — Security Score Trend (60%) + Security Grade (40%) */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          <div className="lg:col-span-3">
            <SecurityScoreTrend customerId={customerId} />
          </div>
          <div className="lg:col-span-2">
            <SecurityGrade score={summary?.overall_score ?? 0} grade={summary?.overall_grade || ""} />
          </div>
        </div>
        </div>

        {/* License Summary — taller card on the right */}
        <div className="xl:w-[300px] shrink-0">
          {loading ? (
            <div className="bg-base-800/40 border border-base-500/20 rounded-2xl p-6 animate-pulse h-full"><div className="flex items-center gap-2.5 mb-4"><div className="w-9 h-9 rounded-full bg-base-700/50"/><div className="h-3 w-28 bg-base-700/50 rounded"/></div><div className="h-5 w-32 bg-base-700/50 rounded mb-3"/><div className="h-3 w-40 bg-base-700/50 rounded mb-4"/><div className="h-2 w-full bg-base-700/50 rounded mb-4"/><div className="grid grid-cols-2 gap-3"><div className="h-8 bg-base-700/50 rounded"/><div className="h-8 bg-base-700/50 rounded"/><div className="h-8 bg-base-700/50 rounded"/><div className="h-8 bg-base-700/50 rounded"/></div></div>
          ) : (
            <LicenseSummaryCard
              org={org} planInfo={planInfo} freeLicense={freeLicense} licenseBundles={licenseBundles}
              activeDevices={summary?.active_devices ?? 0}
              expiredDevices={summary?.expired_devices ?? 0}
            />
          )}
        </div>
      </div>

      {/* Row 3 — Findings by Severity (20%) | Open vs Fixed (20%) | Risk Trend (40%) | Top Risks (20%) */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
        <div className="md:col-span-1">
          <FindingsBySeverityCard charts={charts} />
        </div>
        <div className="md:col-span-1">
          <OpenVsFixedCard charts={charts} />
        </div>
        <div className="md:col-span-2 xl:col-span-2">
          <RiskTrendStackedCard trend={riskTrend} hidden={hiddenSeverities} />
        </div>
        <div className="md:col-span-1">
          <TopRisksCard charts={charts} />
        </div>
      </div>

      {/* Row 4 — Firmware Health | Device Health | Recently Detected | Recently Fixed | Recent Analyses (full width) */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-[19fr_19fr_19fr_19fr_24fr] gap-4">
         <div className="md:col-span-1">
           <FirmwareHealthCard data={row4} />
         </div>
         <div className="md:col-span-1">
           <DeviceHealthCard data={row4} />
         </div>
         <div className="md:col-span-1">
           <RecentlyDetectedCard data={row4} />
         </div>
         <div className="md:col-span-1">
           <RecentlyFixedCard data={row4} />
         </div>
         <div className="md:col-span-2 xl:col-span-1">
           <RecentAnalysesCard data={row4} />
         </div>
       </div>
    </div>
  );
}
