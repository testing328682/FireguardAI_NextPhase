import { useEffect, useState, useMemo, useCallback, useRef } from "react";
import {
  ResponsiveContainer, AreaChart, Area,
  LineChart as ReLineChart, Line,
  PieChart, Pie, Cell,
  CartesianGrid, XAxis, YAxis,
  Tooltip as ReTooltip,
} from "recharts";
import { api } from "../lib/api";
import type {
  ExecutiveSummary, TrendPoint, Device, Customer,
  DashboardCharts, ScoreTrendPoint, FirmwareBucket, TopFinding,
  OperationalSummary, DeviceHealth, AnalysisActivity, ApiConnectionStatus,
  RecentlyChangedDevice, CustomerOverviewItem, RiskTrend, RiskTrendPoint,
} from "../lib/types";
import { navigate } from "../lib/router";
import { gradeColor, sevColor, SEVERITIES, fmtDate } from "../lib/ui";

// ── Time range options ─────────────────────────────────────────────────
const RANGES: { label: string; days: number }[] = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "1y", days: 365 },
];

// ── Inline SVG icons (20×20 – 25% larger) ──────────────────────────────
const ICON_SIZE = 20;
export function IconShield() {
  return (
    <svg width={ICON_SIZE} height={ICON_SIZE} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
export function IconAlert() {
  return (
    <svg width={ICON_SIZE} height={ICON_SIZE} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}
export function IconFlag() {
  return (
    <svg width={ICON_SIZE} height={ICON_SIZE} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" />
      <line x1="4" y1="22" x2="4" y2="15" />
    </svg>
  );
}
function IconServer() {
  return (
    <svg width={ICON_SIZE} height={ICON_SIZE} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  );
}
function IconCheck() {
  return (
    <svg width={ICON_SIZE} height={ICON_SIZE} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}
function IconFirmware() {
  return (
    <svg width={ICON_SIZE} height={ICON_SIZE} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <line x1="9" y1="9" x2="15" y2="9" />
      <line x1="9" y1="13" x2="13" y2="13" />
      <line x1="9" y1="17" x2="11" y2="17" />
    </svg>
  );
}

// ── Smooth number animation ────────────────────────────────────────────
function useAnimatedNumber(target: number, duration = 500): number {
  const [current, setCurrent] = useState(target);
  const rafRef = useRef<number>(0);
  const startRef = useRef<{ startVal: number; startTime: number } | null>(null);

  useEffect(() => {
    const startVal = current;
    const startTime = performance.now();
    startRef.current = { startVal, startTime };

    function tick(now: number) {
      const info = startRef.current;
      if (!info) return;
      const elapsed = now - info.startTime;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCurrent(info.startVal + (target - info.startVal) * eased);
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    }
    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);

  // Reset current when identity changes (e.g. different metric), not just value.
  // We intentionally do NOT include `current` in deps above to avoid loops;
  // the ref pattern ensures clean transitions.
  return Math.round(current * 10) / 10;
}

/** Renders a numeric value with animation. Pass a string containing a number. */
export function AnimatedValue({ value }: { value: string }) {
  // Extract the first number from the string to animate
  const num = parseFloat(value);
  if (isNaN(num)) return <>{value}</>;
  const animated = useAnimatedNumber(num, 500);
  // Reconstruct the string with the animated number
  const display = value.replace(String(num), String(animated));
  return <>{display}</>;
}

// ── Date formatters (no Date object — avoids timezone shifts) ─────────
const MONTHS_SHORT = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const MONTHS_LONG = ["January","February","March","April","May","June","July","August","September","October","November","December"];
const fmtShort = (d: string) => { const [y, m, day] = d.split("-"); return `${MONTHS_SHORT[+m-1]} ${+day}`; };
const fmtLong = (d: string) => { const [y, m, day] = d.split("-"); return `${MONTHS_LONG[+m-1]} ${+day}, ${y}`; };

// ── Devices KPI widget ─────────────────────────────────────────────────
function DevicesWidget({ configured, notConfigured, active, expired, total, onFilter, activeFilter }: {
  configured: number; notConfigured: number; active: number; expired: number; total: number;
  onFilter: (kind: string | null) => void;
  activeFilter: string | null;
}) {
  const BAR_COLOR = "#4f8cff";

  function barPct(value: number) {
    return total > 0 ? Math.round((value / total) * 100) : 0;
  }

  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col"
         title="Device inventory breakdown">
      {/* Header */}
      <div className="flex items-center gap-2 mb-1.5">
        <span style={{ color: "#4f8cff" }}><IconServer /></span>
        <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500 flex-1">Devices</span>
        <span className="text-ink-600 text-[11px] cursor-help leading-none" title="Device inventory breakdown">ⓘ</span>
      </div>

      {/* Total count */}
      <div className="font-display text-[26px] font-bold text-ink-100 leading-tight mb-2">{total}</div>

      {/* Configuration Status section */}
      <div className="space-y-1.5">
        {/* Configured */}
        <div className="space-y-0.5">
          <div className="flex items-center justify-between font-mono text-[10px]">
            <span className="text-ink-400">Configured</span>
            <span className="text-ink-200 tabular-nums">{configured} / {total}</span>
          </div>
          <div className="h-2 w-full rounded-full bg-base-700 overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500"
                 style={{ width: `${barPct(configured)}%`, background: BAR_COLOR }} />
          </div>
        </div>
        {/* Not Configured */}
        <div className="space-y-0.5">
          <div className="flex items-center justify-between font-mono text-[10px]">
            <span className="text-ink-500">Not Configured</span>
            <span className="text-ink-500 tabular-nums">{notConfigured} / {total}</span>
          </div>
          <div className="h-2 w-full rounded-full bg-base-700 overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500"
                 style={{ width: `${barPct(notConfigured)}%`, background: "#7a879b" }} />
          </div>
        </div>
      </div>

      {/* Divider */}
      <div className="border-t border-base-500/30 my-2.5" />

      {/* License Status section */}
      <div className="space-y-1.5">
        {/* Active */}
        <div className="space-y-0.5">
          <div className="flex items-center justify-between font-mono text-[10px]">
            <span className="text-ink-400">Active</span>
            <span className="text-ink-200 tabular-nums">{active} / {total}</span>
          </div>
          <div className="h-2 w-full rounded-full bg-base-700 overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500"
                 style={{ width: `${barPct(active)}%`, background: "#39d98a" }} />
          </div>
        </div>
        {/* Expired */}
        <div className="space-y-0.5">
          <div className="flex items-center justify-between font-mono text-[10px]">
            <span className="text-ink-500">Expired</span>
            <span className="text-ink-500 tabular-nums">{expired} / {total}</span>
          </div>
          <div className="h-2 w-full rounded-full bg-base-700 overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500"
                 style={{ width: `${barPct(expired)}%`, background: "#ff4d4d" }} />
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Gradient Sparkline ─────────────────────────────────────────────────
const GRADIENT_ID_PREFIX = "spark-grad-";
let _gid = 0;
function nextGid() { return `${GRADIENT_ID_PREFIX}${_gid++}`; }

function Sparkline({ data, color, height = 64, label = "Value" }: { data: TrendPoint[]; color: string; height?: number; label?: string }) {
  const gradientId = useRef(nextGid()).current;

  if (!data || data.length < 2) {
    return (
      <div className="flex items-center" style={{ height }}>
        <div className="w-full h-px rounded-full" style={{ background: color, opacity: 0.18 }} />
      </div>
    );
  }

  // Build tick indices: always include first and last, evenly spaced between
  const n = data.length;
  const dense = n <= 8;
  const tickIndices: number[] = dense
    ? data.map((_, i) => i)
    : (() => {
        const step = Math.max(1, Math.floor(n / 5));
        const indices = new Set<number>([0, n - 1]);
        for (let i = step; i < n - 1; i += step) indices.add(i);
        return [...indices].sort((a, b) => a - b);
      })();

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 30, left: 30, bottom: 0 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.25} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <XAxis dataKey="date" tickFormatter={fmtShort} ticks={tickIndices.map((i) => data[i].date)}
               tick={{ fontSize: 7, fill: "#4a5568" }} axisLine={false} tickLine={false} height={14} />
        <ReTooltip
          contentStyle={{ background: "#0f1521", border: "1px solid #2a3447", fontSize: 11, borderRadius: 6 }}
          labelFormatter={fmtLong}
          formatter={(v: number) => [`${v}`, label]} />
        <Area
          type="monotone"
          dataKey="value"
          stroke={color}
          strokeWidth={1.5}
          fill={`url(#${gradientId})`}
          dot={dense ? { r: 4, strokeWidth: 1.5, stroke: "#e2e8f0", fill: color } : false}
          activeDot={{ r: 6, strokeWidth: 2, stroke: "#e2e8f0", fill: color }}
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ── Delta indicator (context-aware coloring) ───────────────────────────
type DeltaSense = "score" | "finding" | "neutral";

function deltaColor(value: number, sense: DeltaSense): string {
  if (value === 0) return "#7a879b";
  const up = value > 0;
  if (sense === "score") return up ? "#39d98a" : "#ff4d4d";     // score ↑ = good (green)
  if (sense === "finding") return up ? "#ff4d4d" : "#39d98a";   // findings ↑ = bad (red)
  return "#7a879b";                                               // neutral
}

export function Delta({ value, sense }: { value: number; sense: DeltaSense }) {
  if (value === 0) return <span className="text-ink-500">—</span>;
  const up = value > 0;
  const arrow = up ? "↑" : "↓";
  const color = deltaColor(value, sense);
  return (
    <span style={{ color }}>
      {arrow} {Math.abs(value)}
    </span>
  );
}

// ── Skeleton card ──────────────────────────────────────────────────────
function SkeletonCard() {
  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-5 animate-pulse">
      <div className="flex items-center gap-2.5 mb-3">
        <div className="w-5 h-5 rounded bg-base-600" />
        <div className="h-3 w-24 bg-base-600 rounded" />
      </div>
      <div className="h-8 w-28 bg-base-600 rounded mb-3" />
      <div className="h-3.5 w-16 bg-base-600 rounded mb-4" />
      <div className="h-12 w-full bg-base-700 rounded" />
    </div>
  );
}

// ── Executive Summary Card ─────────────────────────────────────────────
interface SummaryCardProps {
  title: string;
  icon: React.ReactNode;
  primaryValue: React.ReactNode;
  secondaryLines: React.ReactNode[];
  sparklineData: TrendPoint[];
  sparklineColor: string;
  sparklineLabel?: string;
  tooltip: string;
  onClick?: () => void;
}

export function SummaryCard({
  title, icon, primaryValue, secondaryLines,
  sparklineData, sparklineColor, sparklineLabel, tooltip, onClick,
}: SummaryCardProps) {
  return (
    <div
      onClick={onClick}
      className={`bg-base-800 border border-base-500 rounded-panel p-4 transition-all hover:border-base-400 flex flex-col ${onClick ? "cursor-pointer" : ""}`}
      title={tooltip}
    >
      {/* Top row: icon + title + info */}
      <div className="flex items-center gap-2 mb-2">
        <span style={{ color: sparklineColor }}>{icon}</span>
        <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500 flex-1">{title}</span>
        <span className="text-ink-600 text-[11px] cursor-help leading-none" title={tooltip}>ⓘ</span>
      </div>

      {/* Two-column header: primary value (left) | secondary info (right) */}
      <div className="flex items-start justify-between mb-3">
        <div className="font-display text-[26px] font-bold text-ink-100 leading-tight">
          {primaryValue}
        </div>
        <div className="text-right space-y-0.5 shrink-0 ml-3">
          {secondaryLines.map((line, i) => (
            <div key={i} className="font-mono text-[11px] text-ink-400 leading-relaxed">
              {line}
            </div>
          ))}
        </div>
      </div>

      {/* Sparkline — fills remaining space */}
      <div className="flex-1 min-h-0">
        <Sparkline data={sparklineData} color={sparklineColor} label={sparklineLabel || "Value"} height={100} />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 2 — Chart Widget Components
// ═══════════════════════════════════════════════════════════════════════

function WidgetHeader({ title, tooltip }: { title: string; tooltip: string }) {
  return (
    <div className="flex items-center gap-2 mb-1.5">
      <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500 flex-1">{title}</span>
      <span className="text-ink-600 text-[11px] cursor-help leading-none" title={tooltip}>ⓘ</span>
    </div>
  );
}

// ── Widget 1: Risk Trend ──────────────────────────────────────────────
const RISK_COLORS: Record<string, string> = {
  Critical: "#ff4d4d", High: "#ff8a3d", Medium: "#f5c451", Low: "#4a9eff",
};
const RISK_ORDER = ["Critical", "High", "Medium", "Low"];

export function RiskTrendWidget({ data, loading, rangeDays }: { data: RiskTrend | null; loading: boolean; rangeDays: number }) {
  const pointCount = data?.trend?.length || 0;
  const dense = pointCount <= 8;
  const tickIndices: number[] = !data?.trend ? [] : dense
    ? data.trend.map((_, i) => i)
    : (() => {
        const n = pointCount;
        const step = Math.max(1, Math.floor(n / 5));
        const indices = new Set<number>([0, n - 1]);
        for (let i = step; i < n - 1; i += step) indices.add(i);
        return [...indices].sort((a, b) => a - b);
      })();

  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title={`Risk Trend (${rangeDays}d)`} tooltip="Finding counts over time by severity." />
      {!data || pointCount === 0 ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px] h-20 text-center px-2">
          No trend data available for the selected period.
        </div>
      ) : (
        <div className="flex-1 flex flex-col min-h-0">
          {/* Chart — full width */}
          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <ReLineChart data={data.trend} margin={{ top: 2, right: 14, left: 4, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a3447" />
                <XAxis dataKey="date" tickFormatter={fmtShort} ticks={tickIndices.map((i) => data!.trend[i].date)}
                       tick={{ fontSize: 8, fill: "#6b7689" }} axisLine={{ stroke: "#2a3447" }} tickLine={false} />
                <YAxis tick={{ fontSize: 8, fill: "#6b7689" }} axisLine={false} tickLine={false} width={32} />
                <ReTooltip
                  contentStyle={{ background: "#0f1521", border: "1px solid #2a3447", fontSize: 11, borderRadius: 8 }}
                  labelFormatter={fmtLong}
                  formatter={(v: number, name: string) => [`${v}`, name]} />
                {RISK_ORDER.map((s) => (
                  <Line key={s} type="monotone" dataKey={s} stroke={RISK_COLORS[s]} strokeWidth={1.2}
                        dot={dense ? { r: 4, strokeWidth: 1.5, stroke: "#e2e8f0", fill: RISK_COLORS[s] } : false}
                        activeDot={{ r: 6, strokeWidth: 2, stroke: "#e2e8f0", fill: RISK_COLORS[s] }} />
                ))}
              </ReLineChart>
            </ResponsiveContainer>
          </div>
          {/* Summary footer — centered two-column grid */}
          {data.deltas && (
            <div className="flex justify-center pt-0.5">
              <div className="grid grid-cols-2 gap-x-6 gap-y-0.5">
                {RISK_ORDER.map((s) => {
                  const v = data.deltas[s] || 0;
                  const arrow = v > 0 ? "↑" : v < 0 ? "↓" : "—";
                  const color = v > 0 ? "#ff4d4d" : v < 0 ? "#39d98a" : "#7a879b";
                  return (
                    <div key={s} className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono" style={{ color: RISK_COLORS[s] }}>{s}</span>
                      <span className="font-mono text-[10px] font-semibold tabular-nums" style={{ color }}>{arrow}{Math.abs(v)}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Widget 2: Findings by Severity (Doughnut) ─────────────────────────
export function FindingsBySeverityWidget({
  distribution, total, onSeverityClick, activeSeverity,
}: {
  distribution: Record<string, { count: number; pct: number }>;
  total: number;
  onSeverityClick: (sev: string) => void;
  activeSeverity: string | null;
}) {
  const sevs = ["Critical", "High", "Medium", "Low", "Info"];
  const pieData = sevs.map((s) => ({ name: s, value: distribution[s]?.count || 0 })).filter((d) => d.value > 0);

  // Row 1: Critical, High, Medium; Row 2: Low, Info (centered)
  const row1 = ["Critical", "High", "Medium"];
  const row2 = ["Low", "Info"];

  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Findings by Severity" tooltip="Breakdown of active findings by severity." />
      {total === 0 ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px] h-20">No findings</div>
      ) : (
        <div className="flex-1 flex flex-col min-h-0">
          {/* Donut — centered, ~70-75% height */}
          <div className="flex-1 flex items-center justify-center" style={{ maxHeight: "72%" }}>
            <div className="relative" style={{ width: 144, height: 144 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={48} outerRadius={68}
                       dataKey="value" paddingAngle={1} stroke="none"
                       onClick={(e) => onSeverityClick(e.name)}>
                    {pieData.map((d) => (
                      <Cell key={d.name} fill={sevColor[d.name] || "#7a879b"}
                            opacity={activeSeverity && activeSeverity !== d.name ? 0.35 : 1}
                            style={{ cursor: "pointer" }} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="font-display text-xl font-bold text-ink-100 leading-none">{total}</span>
                <span className="font-mono text-[9px] text-ink-500 leading-none mt-0.5">Total Findings</span>
              </div>
            </div>
          </div>

          {/* Legend below — two-column layout */}
          <div className="mt-2 pt-2 border-t border-base-500/30 -mx-1">
            <div className="grid grid-cols-2 gap-x-5 gap-y-0.5">
              {/* Left column: Critical / High / Medium — table-aligned */}
              <div className="space-y-0.5">
                {row1.map((s) => (
                  <button key={s} onClick={() => onSeverityClick(s)}
                          className={`flex items-center text-left text-[10px] font-mono transition-opacity whitespace-nowrap ${activeSeverity && activeSeverity !== s ? "opacity-35" : "opacity-100"}`}>
                    <span className="w-1.5 h-1.5 rounded-full shrink-0 mr-1" style={{ background: sevColor[s] || "#7a879b" }} />
                    <span className="text-ink-300 w-[3.75rem] shrink-0">{s}</span>
                    <span className="text-ink-400 tabular-nums">{distribution[s]?.count || 0}</span>
                    <span className="text-ink-600 text-[8px] tabular-nums ml-0.5">({distribution[s]?.pct || 0}%)</span>
                  </button>
                ))}
              </div>
              {/* Right column: Low / Info — same table layout as left */}
              <div className="space-y-0.5">
                {row2.map((s) => (
                  <button key={s} onClick={() => onSeverityClick(s)}
                          className={`flex items-center text-left text-[10px] font-mono transition-opacity whitespace-nowrap ${activeSeverity && activeSeverity !== s ? "opacity-35" : "opacity-100"}`}>
                    <span className="w-1.5 h-1.5 rounded-full shrink-0 mr-1" style={{ background: sevColor[s] || "#7a879b" }} />
                    <span className="text-ink-300 w-[2rem] shrink-0">{s}</span>
                    <span className="text-ink-400 tabular-nums">{distribution[s]?.count || 0}</span>
                    <span className="text-ink-600 text-[8px] tabular-nums ml-0.5">({distribution[s]?.pct || 0}%)</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Widget 3: Grade Distribution (Doughnut) ───────────────────────────
const GRADE_COLORS: Record<string, string> = {
  A: "#39d98a", B: "#9ad94a", C: "#f5c451", D: "#ff8a3d", F: "#ff4d4d",
};

function GradeDistributionWidget({
  distribution, totalDevices, onGradeClick, activeGrade,
}: {
  distribution: Record<string, { count: number; pct: number }>;
  totalDevices: number;
  onGradeClick: (g: string) => void;
  activeGrade: string | null;
}) {
  const grades = ["A", "B", "C", "D", "F"];
  const pieData = grades.map((g) => ({ name: g, value: distribution[g]?.count || 0 })).filter((d) => d.value > 0);
  const col1 = ["A", "B", "C"];
  const col2 = ["D", "F"];

  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Grade Distribution" tooltip="Configured devices across security grades." />
      {totalDevices === 0 ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px] h-20">No devices</div>
      ) : (
        <div className="flex-1 flex flex-col min-h-0">
          {/* Donut — centered */}
          <div className="flex-1 flex items-center justify-center" style={{ maxHeight: "72%" }}>
            <div className="relative" style={{ width: 144, height: 144 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={48} outerRadius={68}
                       dataKey="value" paddingAngle={1} stroke="none"
                       onClick={(e) => onGradeClick(e.name)}>
                    {pieData.map((d) => (
                      <Cell key={d.name} fill={GRADE_COLORS[d.name] || "#7a879b"}
                            opacity={activeGrade && activeGrade !== d.name ? 0.35 : 1}
                            style={{ cursor: "pointer" }} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="font-display text-xl font-bold text-ink-100 leading-none">{totalDevices}</span>
                <span className="font-mono text-[9px] text-ink-500 leading-none mt-0.5">Devices</span>
              </div>
            </div>
          </div>

          {/* Legend below — two-column layout */}
          <div className="mt-2 pt-2 border-t border-base-500/30">
            <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
              <div className="space-y-0.5">
                {col1.map((g) => (
                  <button key={g} onClick={() => onGradeClick(g)}
                          className={`flex items-center gap-1 text-[10px] font-mono transition-opacity ${activeGrade && activeGrade !== g ? "opacity-35" : "opacity-100"}`}>
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: GRADE_COLORS[g] || "#7a879b" }} />
                    <span className="text-ink-300 w-4">{g}</span>
                    <span className="text-ink-400 tabular-nums ml-1">{distribution[g]?.count || 0} ({distribution[g]?.pct || 0}%)</span>
                  </button>
                ))}
              </div>
              <div className="space-y-0.5">
                {col2.map((g) => (
                  <button key={g} onClick={() => onGradeClick(g)}
                          className={`flex items-center gap-1 text-[10px] font-mono transition-opacity ${activeGrade && activeGrade !== g ? "opacity-35" : "opacity-100"}`}>
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: GRADE_COLORS[g] || "#7a879b" }} />
                    <span className="text-ink-300 w-4">{g}</span>
                    <span className="text-ink-400 tabular-nums ml-1">{distribution[g]?.count || 0} ({distribution[g]?.pct || 0}%)</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Detail List Modal (View All) ──────────────────────────────────────
function DetailListModal({ title, items, onClose, onSelect, totalLabel }: {
  title: string;
  items: { key: string; label: string; count: number }[];
  onClose: () => void;
  onSelect: (key: string) => void;
  totalLabel: string;
}) {
  const [q, setQ] = useState("");
  const filtered = q ? items.filter((i) => i.label.toLowerCase().includes(q.toLowerCase())) : items;
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);
  return (
    <>
      <div className="fixed inset-0 z-30 bg-black/60 fade-in" onClick={onClose} />
      <div className="fixed inset-0 z-40 flex items-center justify-center p-4 fade-in" onClick={onClose}>
        <div className="w-full max-w-[640px] max-h-[80vh] bg-base-800 border border-base-500 rounded-xl shadow-2xl flex flex-col overflow-hidden"
             onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center justify-between px-5 py-4 border-b border-base-500/40">
            <h2 className="font-display font-semibold text-ink-100">{title}</h2>
            <button onClick={onClose} className="w-8 h-8 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors">×</button>
          </div>
          <div className="px-5 py-3 border-b border-base-500/30">
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search…"
                   className="w-full bg-base-700 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent placeholder:text-ink-500/50" />
          </div>
          <div className="flex-1 overflow-y-auto px-5 py-2">
            {filtered.length === 0 ? (
              <p className="text-ink-500 text-sm py-8 text-center">No matches found.</p>
            ) : (
              <div className="space-y-0.5">
                {filtered.map((item) => (
                  <button key={item.key} onClick={() => onSelect(item.key)}
                          className="w-full flex items-center justify-between py-2 px-2 rounded hover:bg-base-700/40 text-left transition-colors">
                    <span className="text-[13px] text-ink-200 truncate flex-1 mr-4">{item.label}</span>
                    <span className="text-[12px] font-mono text-ink-400 tabular-nums shrink-0">{item.count}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="px-5 py-2 border-t border-base-500/40 font-mono text-[10px] text-ink-500">
            {totalLabel} · {filtered.length} shown
          </div>
        </div>
      </div>
    </>
  );
}

// ── Widget 4: Firmware Distribution (Horizontal Bar) ──────────────────
function FirmwareDistributionWidget({
  data, totalDevices, onFirmwareClick, activeFirmware,
}: {
  data: FirmwareBucket[];
  totalDevices: number;
  onFirmwareClick: (fw: string) => void;
  activeFirmware: string | null;
}) {
  const top5 = data.slice(0, 5);
  const [fwModal, setFwModal] = useState(false);

  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Firmware Distribution" tooltip="Firmware versions across configured devices." />
      {top5.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px] h-20">No firmware data</div>
      ) : (
        <div className="flex-1 space-y-1.5">
          {top5.map((fw) => (
            <button key={fw.firmware} onClick={() => onFirmwareClick(fw.firmware)}
                    className={`w-full text-left transition-opacity ${activeFirmware && activeFirmware !== fw.firmware ? "opacity-35" : "opacity-100"}`}>
              <div className="flex items-center justify-between mb-0.5">
                <span className="font-mono text-[10px] text-ink-300 truncate max-w-[100px]">{fw.firmware}</span>
                <span className="font-mono text-[10px] text-ink-400 tabular-nums">{fw.count}</span>
              </div>
              <div className="h-1.5 rounded-full bg-base-700 overflow-hidden">
                <div className="h-full rounded-full" style={{
                  width: `${(fw.count / Math.max(top5[0]?.count || 1, 1)) * 100}%`,
                  background: "#4f8cff",
                }} />
              </div>
            </button>
          ))}
          <div className="pt-1.5 border-t border-base-500 mt-2 flex items-center justify-between">
            <span className="font-mono text-[9px] text-ink-500">{totalDevices} devices</span>
            {data.length > 5 && (
              <button onClick={() => setFwModal(true)} className="font-mono text-[9px] text-accent hover:underline">
                View All
              </button>
            )}
          </div>
        </div>
      )}
      {fwModal && (
        <DetailListModal
          title="All Firmware Versions"
          items={data.map((fw) => ({ key: fw.firmware, label: fw.firmware, count: fw.count }))}
          onClose={() => setFwModal(false)}
          onSelect={(fw) => { onFirmwareClick(fw); setFwModal(false); }}
          totalLabel={`${data.length} versions`}
        />
      )}
    </div>
  );
}

// ── Widget: Firmware Compliance ──────────────────────────────────────
function FirmwareComplianceWidget({ data, onOlderClick, activeFilter }: {
  data: import("../lib/types").FirmwareCompliance | null;
  onOlderClick: (generation: string) => void;
  activeFilter: string | null;
}) {
  const BAR_COLOR = "#4f8cff";
  const LATEST_COLOR = "#39d98a";

  if (!data || !Array.isArray(data.generations) || data.generations.length === 0) {
    return (
      <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
        <WidgetHeader title="Firmware Compliance" tooltip="Firmware compliance status across SonicWall generations." />
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px] h-20">No data</div>
      </div>
    );
  }

  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Firmware Compliance" tooltip="Firmware compliance status across SonicWall generations." />
      <div className="flex-1 flex flex-col justify-center min-h-0">
        {data.generations.map((gen, i) => {
          const pctLatest = gen.total > 0 ? Math.round((gen.latest_count / gen.total) * 100) : 0;
          return (
            <div key={gen.generation}>
              {i > 0 && <div className="border-t border-base-500/30 py-2.5" />}
              <div className="space-y-0.5">
              {/* Gen name + recommended fw — single row */}
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold text-ink-200 leading-tight">{gen.generation}</span>
                <span className="font-mono text-[9px] text-ink-500 leading-tight truncate max-w-[60%] text-right">
                  Recommended: {gen.recommended_firmware}
                </span>
              </div>

              {/* Progress bar */}
              <div className="h-2 w-full rounded-full bg-base-700 overflow-hidden mt-1">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${pctLatest}%`, background: BAR_COLOR }}
                />
              </div>

              {/* Compliance summary */}
              <div className="font-mono text-[10px] text-ink-400 tabular-nums mt-0.5">
                {gen.latest_count} / {gen.total} compliant
              </div>

              {/* Latest / Older counts */}
              <div className="grid grid-cols-2 gap-x-4 font-mono text-[10px] tabular-nums mt-0.5">
                <div className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: LATEST_COLOR }} />
                  <span className="text-ink-500">Latest</span>
                  <span className="text-ink-200 font-medium ml-1">{gen.latest_count}</span>
                </div>
                {gen.older_count > 0 ? (
                  <button
                    onClick={() => onOlderClick(activeFilter === gen.generation ? "" : gen.generation)}
                    className={`flex items-center gap-1 rounded transition-colors -mx-0.5 px-0.5 cursor-pointer
                      ${activeFilter === gen.generation ? "bg-[#ff4d4d]/15" : "hover:bg-base-700/40"}`}
                  >
                    <span className="w-1.5 h-1.5 rounded-full shrink-0"
                          style={{ background: "#ff4d4d" }} />
                    <span className="text-[#ff4d4d]">Older</span>
                    <span className="text-[#ff4d4d] font-medium ml-1">{gen.older_count}</span>
                  </button>
                ) : (
                  <div className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "#7a879b" }} />
                    <span className="text-ink-500">Older</span>
                    <span className="text-ink-200 font-medium ml-1">{gen.older_count}</span>
                  </div>
                )}
              </div>
            </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Widget 5: Most Common Findings (Top 5 Table) ──────────────────────
function MostCommonFindingsWidget({
  findings, totalUnique, onFindingClick, activeFinding,
}: {
  findings: TopFinding[];
  totalUnique: number;
  onFindingClick: (ruleId: string) => void;
  activeFinding: string | null;
}) {
  const [findModal, setFindModal] = useState(false);
  const top5 = findings.slice(0, 5);
  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Most Common Findings" tooltip="Top findings across the fleet." />
      {top5.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px] h-20">No findings</div>
      ) : (
        <div className="flex-1 space-y-1">
          {top5.map((f, i) => (
            <button key={f.rule_id} onClick={() => onFindingClick(f.rule_id)}
                    className={`w-full flex items-center gap-2 text-left py-1 px-1.5 rounded transition-all hover:bg-base-700/40 ${activeFinding === f.rule_id ? "bg-accent/10 ring-1 ring-accent/30" : ""} ${activeFinding && activeFinding !== f.rule_id ? "opacity-40" : ""}`}>
              <span className="font-mono text-[10px] text-ink-500 w-4 shrink-0 tabular-nums text-right">{i + 1}</span>
              <span className="text-[11px] text-ink-200 flex-1 truncate">{f.title}</span>
              <span className="font-mono text-[10px] text-ink-400 tabular-nums shrink-0">{f.count}</span>
            </button>
          ))}
          <div className="pt-1.5 border-t border-base-500 mt-2 flex items-center justify-between">
            <span className="font-mono text-[9px] text-ink-500">{totalUnique} unique findings</span>
            {findings.length > 5 && (
              <button onClick={() => setFindModal(true)} className="font-mono text-[9px] text-accent hover:underline">
                View All
              </button>
            )}
          </div>
        </div>
      )}
      {findModal && (
        <DetailListModal
          title="All Findings"
          items={findings.map((f) => ({ key: f.rule_id, label: f.title, count: f.count }))}
          onClose={() => setFindModal(false)}
          onSelect={(ruleId) => { onFindingClick(ruleId); setFindModal(false); }}
          totalLabel={`${totalUnique} unique findings`}
        />
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 3 — Operational Intelligence Widget Components
// ═══════════════════════════════════════════════════════════════════════

function MetricRow({ label, value, color, onClick }: { label: string; value: number; color: string; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      className={`w-full flex items-center justify-between py-1.5 ${onClick ? "hover:bg-base-700/30 rounded px-1.5 -mx-1.5 cursor-pointer" : ""}`}
    >
      <div className="flex items-center gap-1.5">
        <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
        <span className="text-[11px] text-ink-300 font-mono">{label}</span>
      </div>
      <span className="text-[11px] text-ink-100 font-mono font-semibold tabular-nums">{value}</span>
    </button>
  );
}

// ── Widget 6: Device Health ───────────────────────────────────────────
function DeviceHealthWidget({ data, onFilter }: { data: DeviceHealth; onFilter?: (kind: string) => void }) {
  const items = [
    { label: "Configured", value: data.configured, color: "#39d98a", kind: "configured" },
    { label: "Not Configured", value: data.not_configured, color: "#ff8a3d", kind: "not_configured" },
    { label: "Expired License", value: data.expired_license, color: "#ff4d4d", kind: "expired" },
  ];
  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Device Health" tooltip="Operational state of managed devices." />
      {items.every(i => i.value === 0) ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px]">No devices available.</div>
      ) : (
        <div className="flex-1 space-y-0.5">
          {items.map((it) => (
            <MetricRow key={it.kind} label={it.label} value={it.value} color={it.color} onClick={() => onFilter?.(it.kind)} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Widget 7: Analysis Activity ───────────────────────────────────────
function AnalysisActivityWidget({ data }: { data: AnalysisActivity }) {
  const items = [
    { label: "Automatic Scans", value: data.automatic_scans, color: "#4f8cff" },
    { label: "Manual Pulls (API)", value: data.manual_pulls, color: "#39d98a" },
    { label: "Manual Uploads", value: data.manual_uploads, color: "#9ad94a" },
    { label: "Failed Pulls", value: data.failed_pulls, color: "#ff4d4d" },
  ];
  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Analysis Activity" tooltip="Analysis operations during the selected period." />
      {items.every(i => i.value === 0) ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px]">No analyses during this period.</div>
      ) : (
        <div className="flex-1 space-y-0.5">
          {items.map((it) => (
            <MetricRow key={it.label} label={it.label} value={it.value} color={it.color} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Widget 8: API Connection Status ───────────────────────────────────
function ApiStatusWidget({ data, onFilter }: { data: ApiConnectionStatus; onFilter?: (kind: string) => void }) {
  const items = [
    { label: "API Connected", value: data.api_connected, color: "#39d98a", kind: "api_connected" },
    { label: "API Failed", value: data.api_failed, color: "#ff4d4d", kind: "api_failed" },
    { label: "Manual Devices", value: data.manual_devices, color: "#7a879b", kind: "manual" },
  ];
  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="API Connection Status" tooltip="Connectivity status of API-managed devices." />
      {items.every(i => i.value === 0) ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px]">No API configured devices.</div>
      ) : (
        <div className="flex-1 space-y-0.5">
          {items.map((it) => (
            <MetricRow key={it.kind} label={it.label} value={it.value} color={it.color} onClick={() => onFilter?.(it.kind)} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Widget 9: Recently Changed Devices ────────────────────────────────
function timeAgo(iso: string): string {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function RecentlyChangedWidget({ data, onDeviceClick }: { data: RecentlyChangedDevice[]; onDeviceClick: (id: string) => void }) {
  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Recently Changed Devices" tooltip="Devices whose score changed between the last two analyses." />
      {data.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px]">No score changes detected.</div>
      ) : (
        <div className="flex-1 space-y-1">
          {data.map((d) => {
            const trendColor = d.trend === "Improved" ? "#39d98a" : d.trend === "Dropped" ? "#ff4d4d" : "#7a879b";
            return (
              <button key={d.device_id} onClick={() => onDeviceClick(d.device_id)}
                      className="w-full flex items-center gap-2 py-1 hover:bg-base-700/30 rounded px-1 -mx-1 text-left">
                <span className="text-[11px] text-ink-200 flex-1 truncate">{d.device_name}</span>
                <span className="text-[10px] font-mono" style={{ color: trendColor }}>{d.trend}</span>
                <span className="text-[10px] font-mono text-ink-500 tabular-nums w-14 text-right shrink-0">
                  {d.old_score.toFixed(0)}→{d.new_score.toFixed(0)}
                </span>
                <span className="text-[9px] text-ink-500 w-12 text-right shrink-0">{timeAgo(d.changed_at)}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Widget 10: Customer Overview (MSP only) ───────────────────────────
function CustomerOverviewWidget({ data, onCustomerClick }: { data: CustomerOverviewItem[]; onCustomerClick: (id: string) => void }) {
  return (
    <div className="bg-base-800 border border-base-500 rounded-panel p-4 flex flex-col">
      <WidgetHeader title="Customer Overview" tooltip="Per-customer device counts and security posture." />
      {data.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-ink-500 text-[11px]">No customer data available.</div>
      ) : (
        <div className="flex-1 space-y-0.5">
          {/* Header */}
          <div className="flex items-center gap-1.5 text-[9px] font-mono text-ink-500 uppercase tracking-wider px-1 pb-1 border-b border-base-500/40">
            <span className="flex-1">Customer</span>
            <span className="w-8 text-right">Dev</span>
            <span className="w-10 text-right">Score</span>
            <span className="w-6 text-right" title="Critical findings">Crit</span>
          </div>
          {data.map((c) => (
            <button key={c.customer_id} onClick={() => onCustomerClick(c.customer_id)}
                    className="w-full flex items-center gap-1.5 py-1 hover:bg-base-700/30 rounded px-1 text-left">
              <span className="text-[10px] text-ink-200 flex-1 truncate font-mono">{c.customer_name}</span>
              <span className="text-[10px] text-ink-300 tabular-nums w-8 text-right">{c.device_count}</span>
              <span className="text-[10px] font-mono font-semibold tabular-nums w-10 text-right"
                    style={{ color: gradeColor(gradeFromScore(c.avg_score)) }}>
                {c.avg_score}
              </span>
              <span className="text-[10px] font-mono tabular-nums w-6 text-right"
                    style={{ color: c.critical_count > 0 ? "#ff4d4d" : "#7a879b" }}>
                {c.critical_count}
              </span>
            </button>
          ))}
          {/* Footer totals */}
          <div className="flex items-center gap-1.5 text-[9px] font-mono text-ink-200 pt-1.5 border-t border-base-500/40 px-1 font-bold">
            <span className="flex-1">Total: {data.length} customers</span>
            <span className="w-8 text-right tabular-nums">{data.reduce((s, c) => s + c.device_count, 0)}</span>
            <span className="w-10 text-right tabular-nums">{Math.round(data.reduce((s, c) => s + c.avg_score, 0) / Math.max(data.length, 1))}</span>
            <span className="w-6 text-right tabular-nums">{data.reduce((s, c) => s + c.critical_count, 0)}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function gradeFromScore(s: number): string {
  if (s >= 90) return "A";
  if (s >= 80) return "B";
  if (s >= 70) return "C";
  if (s >= 60) return "D";
  return "F";
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 4 — Advanced Device Inventory Table
// ═══════════════════════════════════════════════════════════════════════

type SortKey = "name" | "customer" | "model" | "serial" | "firmware" | "score" | "grade" | "critical" | "high" | "medium" | "low" | "last_analysis" | "created";

const PAGE_SIZES_4 = [25, 50, 100];

function scoreColor(s: number): string {
  if (s >= 80) return "#39d98a";
  if (s >= 60) return "#f5c451";
  if (s >= 40) return "#ff8a3d";
  return "#ff4d4d";
}

function gradeBadgeColor(g: string): string {
  switch (g) {
    case "A": return "#39d98a";
    case "B": return "#9ad94a";
    case "C": return "#f5c451";
    case "D": return "#ff8a3d";
    default: return "#ff4d4d";
  }
}

function DeviceTable({ devices, customers, isMsp, customerName, searchQ, setSearchQ, clearFilters }: {
  devices: Device[];
  customers: Customer[];
  isMsp: boolean;
  customerName: (id: string) => string;
  searchQ: string;
  setSearchQ: (q: string) => void;
  clearFilters: () => void;
}) {
  const [sortBy, setSortBy] = useState<SortKey>("created");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Reset page when devices change (filter/search)
  useEffect(() => { setPage(1); }, [devices]);

  // Sort
  const sorted = useMemo(() => {
    const arr = [...devices];
    const dir = sortDir === "asc" ? 1 : -1;
    arr.sort((a, b) => {
      let va: any, vb: any;
      switch (sortBy) {
        case "name": va = (a.friendly_name || a.model || a.serial || "").toLowerCase(); vb = (b.friendly_name || b.model || b.serial || "").toLowerCase(); break;
        case "customer": va = (customerName(a.customer_id) || "").toLowerCase(); vb = (customerName(b.customer_id) || "").toLowerCase(); break;
        case "model": va = (a.model || "").toLowerCase(); vb = (b.model || "").toLowerCase(); break;
        case "serial": va = (a.serial || "").toLowerCase(); vb = (b.serial || "").toLowerCase(); break;
        case "firmware": va = (a.firmware || "").toLowerCase(); vb = (b.firmware || "").toLowerCase(); break;
        case "score": va = a.latest_score || 0; vb = b.latest_score || 0; break;
        case "grade": va = a.latest_grade || "F"; vb = b.latest_grade || "F"; break;
        case "critical": va = a.critical_count || 0; vb = b.critical_count || 0; break;
        case "high": va = a.high_count || 0; vb = b.high_count || 0; break;
        case "medium": va = a.medium_count || 0; vb = b.medium_count || 0; break;
        case "low": va = a.low_count || 0; vb = b.low_count || 0; break;
        case "last_analysis": va = a.last_analysis_at || ""; vb = b.last_analysis_at || ""; break;
        case "created": va = a.created_at || ""; vb = b.created_at || ""; break;
        default: return 0;
      }
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return 0;
    });
    return arr;
  }, [devices, sortBy, sortDir, customerName]);

  // Paginate
  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const paginated = sorted.slice((safePage - 1) * pageSize, safePage * pageSize);

  function toggleSort(key: SortKey) {
    if (sortBy === key) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortBy(key);
      setSortDir("asc");
    }
  }

  function SortHeader({ sk, label, className = "", center }: { sk: SortKey; label: string; className?: string; center?: boolean }) {
    const active = sortBy === sk;
    return (
      <th className={`py-3 px-3 cursor-pointer select-none hover:text-ink-300 transition-colors ${center ? "text-center" : ""} ${className}`}
          onClick={() => toggleSort(sk)}>
        <span className="inline-flex items-center gap-1">
          {label}
          {active && <span className="text-[8px]">{sortDir === "asc" ? "▲" : "▼"}</span>}
        </span>
      </th>
    );
  }

  return (
    <div className="card-glow">
      {/* Pagination + Search */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-base-500/40 gap-4">
        {/* Left: Search */}
        <label className="flex items-center gap-2 shrink-0">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Search</span>
          <input value={searchQ} onChange={(e) => setSearchQ(e.target.value)}
                 placeholder="name, model, serial…"
                 className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent w-40 placeholder:text-ink-500/50" />
        </label>
        {/* Center: device count */}
        <span className="font-mono text-[10px] text-ink-500 text-center">
          {sorted.length} device{sorted.length !== 1 ? "s" : ""}
        </span>
        {/* Right: pagination */}
        <div className="flex items-center gap-1 shrink-0">
          <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page <= 1}
                  className="px-2 py-1 rounded text-[10px] font-mono text-ink-400 hover:text-ink-200 disabled:opacity-30 disabled:cursor-default">
            Prev
          </button>
          <span className="font-mono text-[10px] text-ink-400 px-2 tabular-nums">
            {safePage} / {totalPages}
          </span>
          <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page >= totalPages}
                  className="px-2 py-1 rounded text-[10px] font-mono text-ink-400 hover:text-ink-200 disabled:opacity-30 disabled:cursor-default">
            Next
          </button>
          <select value={pageSize} onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
                  className="bg-base-800 border border-base-500 rounded px-2 py-1 text-[10px] font-mono text-ink-400 focus:outline-none focus:border-accent ml-2">
            {PAGE_SIZES_4.map((s) => <option key={s} value={s}>{s} / page</option>)}
          </select>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left font-mono text-[10px] uppercase tracking-[0.1em] text-ink-500 bg-base-800/50 border-b border-base-500/40">
              <SortHeader sk="name" label="Device Name" />
              {isMsp && <SortHeader sk="customer" label="Customer" className="hidden lg:table-cell" />}
              <SortHeader sk="model" label="Model" className="hidden md:table-cell" />
              <SortHeader sk="serial" label="Serial Number" className="hidden lg:table-cell" />
              <SortHeader sk="firmware" label="Firmware" className="hidden xl:table-cell" />
              <SortHeader sk="score" label="Score" center />
              <SortHeader sk="grade" label="Grade" center />
              <SortHeader sk="critical" label="Critical" className="hidden sm:table-cell" center />
              <SortHeader sk="high" label="High" className="hidden md:table-cell" center />
              <SortHeader sk="medium" label="Medium" className="hidden lg:table-cell" center />
              <SortHeader sk="low" label="Low" className="hidden xl:table-cell" center />
              <SortHeader sk="last_analysis" label="Last Analysis" className="hidden lg:table-cell" center />
            </tr>
          </thead>
          <tbody>
            {paginated.length === 0 ? (
              <tr>
                <td colSpan={isMsp ? 13 : 12} className="py-16 text-center">
                  <p className="text-ink-400 text-sm mb-3">No devices found</p>
                  <p className="text-ink-500 text-[11px] font-mono mb-4">Try adjusting your search or filters.</p>
                  <button onClick={clearFilters}
                          className="px-4 py-2 rounded-lg border border-accent text-accent text-[12px] hover:bg-accent/10 transition-all">
                    Clear Filters
                  </button>
                </td>
              </tr>
            ) : (
              paginated.map((d: Device) => {
              const isApi = d.connection_method === "api";
              const badgeColor = isApi ? "#39d98a" : "#4f8cff";
              const badgeLabel = isApi ? "API" : "Manual";
              return (
                <tr key={d.id}
                    onClick={() => navigate(`/security-analytics/device-findings?device=${d.id}`)}
                    className="border-b border-base-500/30 cursor-pointer hover:bg-base-700/20 transition-colors">
                  {/* Device Name */}
                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-2">
                      <span className="text-ink-100 font-medium text-[13px] truncate max-w-[160px]">
                        {d.friendly_name || d.model || d.serial}
                      </span>
                      <span className="shrink-0 font-mono text-[9px] px-1.5 py-0.5 rounded-full font-semibold"
                            style={{ color: badgeColor, background: `${badgeColor}18`, border: `1px solid ${badgeColor}44` }}>
                        {badgeLabel}
                      </span>
                    </div>
                  </td>
                  {/* Customer */}
                  {isMsp && (
                    <td className="py-2.5 px-3 font-mono text-[10px] text-ink-500 hidden lg:table-cell">
                      {customerName(d.customer_id)}
                    </td>
                  )}
                  {/* Model */}
                  <td className="py-2.5 px-3 font-mono text-[11px] text-ink-300 hidden md:table-cell">{d.model || "—"}</td>
                  {/* Serial */}
                  <td className="py-2.5 px-3 font-mono text-[10px] text-ink-500 hidden lg:table-cell truncate max-w-[130px]"
                      title={d.serial}>{d.serial}</td>
                  {/* Firmware */}
                  <td className="py-2.5 px-3 font-mono text-[10px] text-ink-400 hidden xl:table-cell">{d.firmware || "—"}</td>
                  {/* Score */}
                  <td className="py-2.5 px-3 text-center">
                    <span className="font-mono text-[11px] font-bold tabular-nums"
                          style={{ color: scoreColor(d.latest_score || 0) }}>
                      {d.latest_score?.toFixed(0) || "—"}
                    </span>
                  </td>
                  {/* Grade */}
                  <td className="py-2.5 px-3 text-center">
                    <span className="inline-flex items-center justify-center w-7 h-7 rounded-full font-mono text-[10px] font-bold"
                          style={{ color: gradeBadgeColor(d.latest_grade), background: `${gradeBadgeColor(d.latest_grade)}15` }}>
                      {d.latest_grade || "—"}
                    </span>
                  </td>
                  {/* Severity counts */}
                  <td className="py-2.5 px-3 text-center hidden sm:table-cell">
                    <span className={`font-mono text-[10px] tabular-nums ${d.critical_count > 0 ? "text-sev-critical font-semibold" : "text-ink-600"}`}>
                      {d.critical_count || 0}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-center hidden md:table-cell">
                    <span className={`font-mono text-[10px] tabular-nums ${d.high_count > 0 ? "text-sev-high font-semibold" : "text-ink-600"}`}>
                      {d.high_count || 0}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-center hidden lg:table-cell">
                    <span className="font-mono text-[10px] tabular-nums text-ink-500">{d.medium_count || 0}</span>
                  </td>
                  <td className="py-2.5 px-3 text-center hidden xl:table-cell">
                    <span className="font-mono text-[10px] tabular-nums text-ink-500">{d.low_count || 0}</span>
                  </td>
                  {/* Last Analysis */}
                  <td className="py-2.5 px-3 text-center hidden lg:table-cell">
                    <span className="font-mono text-[10px] text-ink-500"
                          title={d.last_analysis_at ? fmtDate(d.last_analysis_at) : "Never"}>
                      {d.last_analysis_at ? timeAgo(d.last_analysis_at) : "—"}
                    </span>
                  </td>
                </tr>
              );
            })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Main Security Analytics Page ───────────────────────────────────────
export function SecurityAnalytics({ onSubtitle }: { onSubtitle?: (s: string | null) => void }) {
  const [summary, setSummary] = useState<ExecutiveSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rangeDays, setRangeDays] = useState(30);

  // Filters (mirrors FindingsExplorer pattern — unchanged)
  const [isMsp, setIsMsp] = useState(false);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [customerId, setCustomerId] = useState<string>("");
  const [searchQ, setSearchQ] = useState("");
  const [orgHidden, setOrgHidden] = useState<string[]>([]);
  const [globalVisOpen, setGlobalVisOpen] = useState(false);
  const [gradeFilter, setGradeFilter] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [firmwareFilter, setFirmwareFilter] = useState<string | null>(null);
  const [findingFilter, setFindingFilter] = useState<string | null>(null);
  const [deviceStatusFilter, setDeviceStatusFilter] = useState<string | null>(null);
  const [firmwareComplianceFilter, setFirmwareComplianceFilter] = useState<string | null>(null);
  const [generationsData, setGenerationsData] = useState<import("../lib/types").DeviceGeneration[]>([]);

  // Charts data
  const [charts, setCharts] = useState<DashboardCharts | null>(null);
  const [chartsLoading, setChartsLoading] = useState(true);
  const [riskTrend, setRiskTrend] = useState<RiskTrend | null>(null);

  // Operational data (Phase 3)
  const [ops, setOps] = useState<OperationalSummary | null>(null);
  const [opsLoading, setOpsLoading] = useState(true);

  // Firmware compliance data
  const [fwCompliance, setFwCompliance] = useState<import("../lib/types").FirmwareCompliance | null>(null);

  useEffect(() => {
    api.getOrganization().then((o) => {
      setIsMsp(o.is_msp);
      // Only Medium/Low/Info are configurable; ignore any stale Critical/High entries.
      const allowed = new Set(["Medium", "Low", "Info"]);
      setOrgHidden((o.hidden_severities || []).filter((s: string) => allowed.has(s)));
    }).catch(() => {});
    api.listCustomers().then(setCustomers).catch(() => {});
    api.listDevices().then(setDevices).catch(() => {});
    api.listGenerationsPublic().then(setGenerationsData).catch(() => {});
  }, []);

  const scopedDevices = useMemo(() => {
    let filtered = customerId
      ? devices.filter((d) => d.customer_id === customerId)
      : devices;
    filtered = filtered.filter((d) => !d.decommissioned);
    // Only show configured devices in Security Analytics — unconfigured
    // devices have no analyses, findings, scores or trends to display.
    filtered = filtered.filter((d) => d.configured);
    if (searchQ) {
      const q = searchQ.toLowerCase();
      filtered = filtered.filter((d) =>
        (d.friendly_name || "").toLowerCase().includes(q) ||
        (d.model || "").toLowerCase().includes(q) ||
        (d.serial || "").toLowerCase().includes(q)
      );
    }
    if (gradeFilter) {
      filtered = filtered.filter((d) => (d.latest_grade || "F") === gradeFilter);
    }
    if (firmwareFilter) {
      filtered = filtered.filter((d) => (d.firmware || "").toLowerCase().includes(firmwareFilter.toLowerCase()));
    }
    if (severityFilter) {
      const sevKey = severityFilter.toLowerCase();
      filtered = filtered.filter((d) => {
        if (sevKey === "critical") return (d.critical_count || 0) > 0;
        if (sevKey === "high") return (d.high_count || 0) > 0;
        if (sevKey === "medium") return (d.medium_count || 0) > 0;
        if (sevKey === "low") return (d.low_count || 0) > 0;
        return true;
      });
    }
    if (deviceStatusFilter === "Configured") {
      filtered = filtered.filter((d) => d.configured === true);
    } else if (deviceStatusFilter === "Not Configured") {
      filtered = filtered.filter((d) => d.configured === false);
    } else if (deviceStatusFilter === "Active") {
      filtered = filtered.filter((d) => {
        const bundle = (d.license_bundle || "").toLowerCase();
        return !bundle.startsWith("expired") && bundle.length > 0;
      });
    } else if (deviceStatusFilter === "Expired") {
      filtered = filtered.filter((d) => {
        const bundle = (d.license_bundle || "").toLowerCase();
        return bundle.startsWith("expired") || d.license_days_remaining === 0;
      });
    }
    if (firmwareComplianceFilter) {
      const gen = generationsData.find((g) => g.name === firmwareComplianceFilter);
      if (gen) {
        // gen.devices from the public API is string[] (model names), not objects.
        const genModels = new Set(gen.devices.map((m: any) => String(m?.model ?? m ?? "").trim()));
        const recFw = (gen.firmware_version || "").trim();
        filtered = filtered.filter((d) =>
          genModels.has((d.model || "").trim()) && (d.firmware || "").trim() !== recFw
        );
      }
    }
    return filtered;
  }, [devices, customerId, searchQ, gradeFilter, firmwareFilter, severityFilter, deviceStatusFilter, firmwareComplianceFilter, generationsData]);

  const customerName = (id: string) => customers.find((c) => c.id === id)?.name || id;

  // Filtered device IDs for cross-filtering API calls
  const filteredDeviceIds = useMemo(() => {
    const hasExtraFilters = gradeFilter || firmwareFilter || severityFilter;
    if (!hasExtraFilters) return undefined;
    return scopedDevices.map((d) => d.id).join(",") || undefined;
  }, [scopedDevices, gradeFilter, firmwareFilter, severityFilter]);

  // Last updated timestamp
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<number>(0); // seconds, 0 = off

  // Browser's local date as ISO string (e.g. "2026-07-09")
  const localToday = useCallback(() => {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${String(now.getDate()).padStart(2,"0")}`;
  }, []);

  // Browser's timezone offset in minutes (JS Date.getTimezoneOffset(): UTC = local + offset).
  // Sent to the backend so day boundaries for trend history match the user's local calendar.
  const localTzOffset = useCallback(() => new Date().getTimezoneOffset(), []);

  // Generate a single shared timeline and align all trends to it
  const alignTrends = useCallback((...trends: TrendPoint[][]): TrendPoint[][] => {
    // Collect all dates across all trends
    const allDates = new Set<string>();
    trends.forEach((t) => t.forEach((p) => allDates.add(p.date)));
    if (allDates.size === 0) return trends.map(() => []);
    const sorted = [...allDates].sort();
    const first = sorted[0];
    const last = sorted[sorted.length - 1];
    // Determine end: use browser's local date if it's beyond backend data
    const lt = localToday();
    const end = lt > last ? lt : last;
    // Build full timeline from first to end
    const timeline: string[] = [];
    const [fy, fm, fd] = first.split("-").map(Number);
    const [ey, em, ed] = end.split("-").map(Number);
    let curMs = Date.UTC(fy, fm - 1, fd);
    const endMsNum = Date.UTC(ey, em - 1, ed, 23, 59, 59, 999);
    while (curMs <= endMsNum) {
      timeline.push(new Date(curMs).toISOString().slice(0, 10));
      curMs += 86400000;
    }
    // Shared timeline built — all 5 sparklines use identical dates.
    // Map each trend onto the shared timeline. The backend returns a dense,
    // point-in-time series (one entry per day), so gaps only occur at the very
    // start of the axis (before a given metric had any data). Those leading
    // gaps are seeded from the metric's EARLIEST value (never the latest), so a
    // change to today's value can never propagate backward into history.
    return trends.map((trend) => {
      if (trend.length === 0) return [];
      const chron = [...trend].sort((a, b) => a.date.localeCompare(b.date));
      const byDate = new Map(chron.map((p) => [p.date, p.value]));
      let lastVal = chron[0].value;
      return timeline.map((d) => {
        if (byDate.has(d)) lastVal = byDate.get(d)!;
        return { date: d, value: lastVal };
      });
    });
  }, [localToday]);

  // Shared refresh function
  const refreshAll = useCallback(async () => {
    setLoading(true);
    setChartsLoading(true);
    setOpsLoading(true);
    try {
      const dids = filteredDeviceIds;
      const hidden = orgHidden;
      await Promise.all([
        api.executiveSummary(rangeDays, customerId || undefined, dids, localToday(), localTzOffset())
          .then((s) => {
            if (!s) { setSummary(null); return; }
            const [scoreT, critT, highT, devT, protT] = alignTrends(
              s.score_trend, s.critical_trend, s.high_trend,
              s.device_trend, s.protection_trend,
            );
            setSummary({ ...s,
              score_trend: scoreT, critical_trend: critT,
              high_trend: highT, device_trend: devT,
              protection_trend: protT,
            });
          }).catch(() => {}),
        api.dashboardCharts(rangeDays, customerId || undefined, dids, localToday(), localTzOffset()).then((c) => {
          if (!c || hidden.length === 0) { setCharts(c); return; }
          const dist = { ...c.severity_distribution };
          let removed = 0;
          for (const s of hidden) { removed += dist[s]?.count || 0; delete dist[s]; }
          const newTotal = (c.total_findings || 0) - removed;
          // Recalculate percentages against the filtered total
          for (const k of Object.keys(dist)) {
            dist[k] = { ...dist[k], pct: newTotal > 0 ? Math.round((dist[k].count / newTotal) * 1000) / 10 : 0 };
          }
          setCharts({ ...c, severity_distribution: dist, total_findings: newTotal });
        }).catch(() => {}),
        api.riskTrend(rangeDays, customerId || undefined, dids, localToday(), localTzOffset())
          .then((rt) => {
            if (!rt || hidden.length === 0) { setRiskTrend(rt); return; }
            setRiskTrend({
              ...rt,
              trend: rt.trend.map((p: any) => { const r = { ...p }; for (const s of hidden) delete r[s]; return r; }),
              deltas: (() => { const d = { ...rt.deltas }; for (const s of hidden) delete d[s]; return d; })(),
            });
          }).catch(() => {}),
        api.operationalSummary(rangeDays, customerId || undefined, dids).then(setOps).catch(() => {}),
        api.firmwareCompliance().then(setFwCompliance).catch(() => {}),
      ]);
      setLastUpdated(new Date());
    } finally {
      setLoading(false);
      setChartsLoading(false);
      setOpsLoading(false);
    }
  }, [rangeDays, customerId, filteredDeviceIds, orgHidden]);

  // Replace individual load effects with refreshAll
  useEffect(() => { refreshAll(); }, [refreshAll]);

  // Auto-refresh interval
  useEffect(() => {
    if (autoRefresh <= 0) return;
    const id = setInterval(refreshAll, autoRefresh * 1000);
    return () => clearInterval(id);
  }, [autoRefresh, refreshAll]);

  // Report the dynamic subtitle to the top title bar (header consolidation).
  useEffect(() => {
    if (!onSubtitle) return;
    let s = "Executive posture overview";
    if (customerId) s += ` · Customer: ${customerName(customerId)}`;
    if (summary) s += ` · ${summary.total_devices} device${summary.total_devices !== 1 ? "s" : ""}`;
    if (lastUpdated) s += ` · Updated ${timeAgo(lastUpdated.toISOString())}`;
    onSubtitle(s);
    return () => onSubtitle(null);
  }, [onSubtitle, customerId, summary, lastUpdated, customers]);

  // ── Render ─────────────────────────────────────────────────────────
  return (
    <div className="max-w-[1440px] fade-in space-y-5">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Center: Customer filter (MSP only) */}
        {isMsp && (
          <div className="flex-1 flex justify-center">
            <label className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Customer</span>
              <select value={customerId} onChange={(e) => setCustomerId(e.target.value)}
                      className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                <option value="">All customers</option>
                {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
            </label>
          </div>
        )}
        <div className="flex items-center gap-3">
          <button onClick={() => setGlobalVisOpen(true)}
                  className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
            Global Filter
          </button>
          {/* Time range selector */}
          <div className="flex items-center gap-0.5 bg-base-800 border border-base-500 rounded-lg p-0.5">
            {RANGES.map((r) => {
              const active = rangeDays === r.days;
              return (
                <button key={r.days} onClick={() => setRangeDays(r.days)}
                        className={`px-3 py-1.5 text-[11px] font-mono rounded-md transition-all duration-200 ${
                          active
                            ? "bg-accent text-white font-bold shadow-[0_0_8px_rgba(79,140,255,0.3)]"
                            : "text-ink-400 hover:text-ink-200 hover:bg-base-700/60"
                        }`}>
                  {r.label}
                </button>
              );
            })}
          </div>
          <button onClick={refreshAll}
                  className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all font-mono"
                  title="Refresh dashboard">
            ↻ Refresh
          </button>
          <select value={autoRefresh} onChange={(e) => setAutoRefresh(Number(e.target.value))}
                  className="bg-base-800 border border-base-500 rounded-lg px-2 py-2 text-[11px] font-mono text-ink-400 focus:outline-none focus:border-accent">
            <option value={0}>Auto: Off</option>
            <option value={30}>30s</option>
            <option value={60}>1m</option>
            <option value={300}>5m</option>
          </select>
        </div>
      </div>

      {/* Active filter chips + breadcrumb */}
      {(gradeFilter || severityFilter || firmwareFilter || findingFilter) && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[10px] text-ink-500 mr-1">Filters:</span>
          {gradeFilter && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono"
                  style={{ background: `${gradeColor(gradeFilter)}18`, color: gradeColor(gradeFilter), border: `1px solid ${gradeColor(gradeFilter)}44` }}>
              Grade {gradeFilter}
              <button onClick={() => setGradeFilter(null)} className="hover:opacity-70">×</button>
            </span>
          )}
          {severityFilter && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono"
                  style={{ background: `${sevColor[severityFilter] || "#7a879b"}18`, color: sevColor[severityFilter] || "#7a879b", border: `1px solid ${sevColor[severityFilter] || "#7a879b"}44` }}>
              {severityFilter}
              <button onClick={() => setSeverityFilter(null)} className="hover:opacity-70">×</button>
            </span>
          )}
          {firmwareFilter && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono bg-accent/10 text-accent border border-accent/30">
              {firmwareFilter}
              <button onClick={() => setFirmwareFilter(null)} className="hover:opacity-70">×</button>
            </span>
          )}
          {findingFilter && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono bg-accent/10 text-accent border border-accent/30">
              Finding
              <button onClick={() => setFindingFilter(null)} className="hover:opacity-70">×</button>
            </span>
          )}
          <button onClick={() => { setGradeFilter(null); setSeverityFilter(null); setFirmwareFilter(null); setFindingFilter(null); }}
                  className="px-2 py-1 rounded text-[10px] font-mono text-accent hover:bg-accent/10 transition-all ml-1">
            Clear All
          </button>
        </div>
      )}

      {/* ── Error state ────────────────────────────────────────────── */}
      {error && (
        <div className="bg-sev-critical/10 border border-sev-critical/30 rounded-panel px-5 py-4">
          <p className="text-sev-critical text-sm font-mono">{error}</p>
        </div>
      )}

      {/* ── Executive Summary Cards ────────────────────────────────── */}
      {loading ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)}
        </div>
      ) : summary && summary.total_devices === 0 ? (
        <div className="card-glow p-16 text-center fade-in">
          <div className="text-5xl mb-4 opacity-30">📊</div>
          <h2 className="font-display font-semibold text-ink-100 text-lg mb-2">No Devices Found</h2>
          <p className="text-ink-500 text-sm max-w-sm mx-auto font-mono">
            Add your first device to begin monitoring.
          </p>
        </div>
      ) : summary ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {/* Card 1: Overall Security Score */}
          <SummaryCard
            title="Overall Security Score"
            icon={<IconShield />}
            primaryValue={
              summary.overall_grade
                ? <><AnimatedValue value={`${summary.overall_score}`} /><span className="text-ink-500 text-lg font-normal">/100</span></>
                : "No Data"
            }
            secondaryLines={[
              <><span style={{ color: gradeColor(summary.overall_grade) }}>Grade {summary.overall_grade}</span></>,
              <span style={{ color: deltaColor(summary.score_delta, "score") }}>
                {summary.score_delta > 0 ? "↑" : summary.score_delta < 0 ? "↓" : "—"} {Math.abs(summary.score_delta)}
              </span>,
            ]}
            sparklineData={summary.score_trend}
            sparklineColor={gradeColor(summary.overall_grade)}
            sparklineLabel="Security Score"
            tooltip="The average security posture score across all configured devices."
            onClick={() => { setGradeFilter(null); setSeverityFilter(null); setFirmwareFilter(null); setFindingFilter(null); setDeviceStatusFilter(null); setFirmwareComplianceFilter(null); }}
          />

          {/* Card 2: Critical Findings */}
          <SummaryCard
            title="Critical Findings"
            icon={<IconAlert />}
            primaryValue={<AnimatedValue value={String(summary.critical_count)} />}
            secondaryLines={[
              <Delta value={summary.critical_delta} sense="finding" />,
            ]}
            sparklineData={summary.critical_trend}
            sparklineColor="#ff4d4d"
            sparklineLabel="Critical Findings"
            tooltip="Total unresolved Critical findings."
            onClick={() => setSeverityFilter(severityFilter === "Critical" ? null : "Critical")}
          />

          {/* Card 3: High Findings */}
          <SummaryCard
            title="High Findings"
            icon={<IconFlag />}
            primaryValue={<AnimatedValue value={String(summary.high_count)} />}
            secondaryLines={[
              <Delta value={summary.high_delta} sense="finding" />,
            ]}
            sparklineData={summary.high_trend}
            sparklineColor="#ff8a3d"
            sparklineLabel="High Findings"
            tooltip="Total unresolved High severity findings."
            onClick={() => setSeverityFilter(severityFilter === "High" ? null : "High")}
          />

          {/* Card 4: Risk Trend */}
          <RiskTrendWidget data={riskTrend} loading={chartsLoading} rangeDays={rangeDays} />
        </div>
      ) : null}

      {/* ══════════════════════════════════════════════════════════════
          Phase 2 — Analytics Charts
         ══════════════════════════════════════════════════════════════ */}
      {!chartsLoading && charts ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <FindingsBySeverityWidget
            distribution={charts.severity_distribution}
            total={charts.total_findings}
            onSeverityClick={(sev) => setSeverityFilter(severityFilter === sev ? null : sev)}
            activeSeverity={severityFilter}
          />
           <GradeDistributionWidget
            distribution={charts.grade_distribution} totalDevices={charts.total_graded_devices}
            onGradeClick={(g) => setGradeFilter(gradeFilter === g ? null : g)}
            activeGrade={gradeFilter}
          />
          <DevicesWidget
            configured={summary?.configured_devices ?? 0}
            notConfigured={(summary?.total_devices ?? 0) - (summary?.configured_devices ?? 0)}
            active={summary?.active_devices || 0}
            expired={summary?.expired_devices || 0}
            total={summary?.total_devices ?? 0}
            onFilter={(kind) => setDeviceStatusFilter(kind)}
            activeFilter={deviceStatusFilter}
          />
          <FirmwareComplianceWidget
            data={fwCompliance}
            onOlderClick={(gen) => setFirmwareComplianceFilter(firmwareComplianceFilter === gen ? null : gen)}
            activeFilter={firmwareComplianceFilter}
          />
          <FirmwareDistributionWidget
            data={charts.all_firmware_list.length > 0 ? charts.all_firmware_list : charts.firmware_distribution} totalDevices={charts.total_firmware_devices}
            onFirmwareClick={(fw) => setFirmwareFilter(firmwareFilter === fw ? null : fw)}
            activeFirmware={firmwareFilter}
          />
        </div>
      ) : chartsLoading ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="bg-base-800 border border-base-500 rounded-panel p-5 animate-pulse">
              <div className="h-24 bg-base-700 rounded" />
            </div>
          ))}
        </div>
      ) : null}

      {/* ══════════════════════════════════════════════════════════════
          Phase 3 — Operational Intelligence Widgets
         ══════════════════════════════════════════════════════════════ */}
      {!opsLoading && ops ? (
         <div className={`grid grid-cols-2 sm:grid-cols-3 gap-3 ${ops.is_msp ? "lg:grid-cols-5" : "lg:grid-cols-4"}`}>
          <AnalysisActivityWidget data={ops.analysis_activity} />
          <ApiStatusWidget
            data={ops.api_status}
            onFilter={(kind) => {
              if (kind === "api_failed") { /* filter devices */ }
            }}
          />
          <RecentlyChangedWidget
            data={ops.recently_changed}
            onDeviceClick={(id) => navigate(`/security-analytics/device-findings?device=${id}`)}
          />
          <MostCommonFindingsWidget
            findings={charts?.all_findings_list?.length ? charts.all_findings_list : charts?.top_findings ?? []}
            totalUnique={charts?.total_unique_findings ?? 0}
            onFindingClick={(ruleId) => setFindingFilter(findingFilter === ruleId ? null : ruleId)}
            activeFinding={findingFilter}
          />
          {ops.is_msp && (
            <CustomerOverviewWidget
              data={ops.customer_overview}
              onCustomerClick={(id) => setCustomerId(customerId === id ? "" : id)}
            />
          )}
        </div>
      ) : opsLoading ? (
        <div className={`grid grid-cols-2 sm:grid-cols-3 gap-3 ${isMsp ? "lg:grid-cols-5" : "lg:grid-cols-4"}`}>
          {Array.from({ length: isMsp ? 5 : 4 }).map((_, i) => (
            <div key={i} className="bg-base-800 border border-base-500 rounded-panel p-5 animate-pulse">
              <div className="h-24 bg-base-700 rounded" />
            </div>
          ))}
        </div>
      ) : null}

      {/* ── Visibility modal ─────────────────────────────────────────── */}
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
                {(["Medium", "Low", "Info"] as string[]).map((sev: string) => {
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

      {/* ── Phase 4 — Advanced Device Inventory Table ────────────────── */}
      <DeviceTable
        devices={scopedDevices}
        customers={customers}
        isMsp={isMsp}
        customerName={customerName}
        searchQ={searchQ}
        setSearchQ={setSearchQ}
        clearFilters={() => { setSearchQ(""); setGradeFilter(null); setSeverityFilter(null); setFirmwareFilter(null); setFindingFilter(null); setDeviceStatusFilter(null); setFirmwareComplianceFilter(null); }}
      />
    </div>
  );
}