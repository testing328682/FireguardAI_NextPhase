import { useEffect, useState } from "react";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  PieChart, Pie, Cell,
} from "recharts";
import { api } from "../lib/api";
import type { DashboardData, FleetSummary } from "../lib/types";
import { navigate } from "../lib/router";
import { gradeColor } from "../lib/ui";

// ── Tenant Dashboard ──────────────────────────────────────────────────
export function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [isMsp, setIsMsp] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.dashboard(),
      api.fleet().catch(() => null),
      api.getOrganization().then((o) => o.is_msp).catch(() => false),
    ]).then(([d, f, msp]) => { setData(d); setFleet(f); setIsMsp(msp); })
      .catch((e) => setErr(e instanceof Error ? e.message : "Failed to load"));
  }, []);

  if (err) return <PageShell><ErrorBanner msg={err} /></PageShell>;
  if (!data) return <PageShell><LoadingSkeleton /></PageShell>;

  const fp = data.fleet_posture;
  const ff = data.findings_funnel;
  const complianceVals = Object.values(data.compliance);
  const avgCompliance = complianceVals.length
    ? Math.round(complianceVals.reduce((a, b) => a + b, 0) / complianceVals.length) : 100;

  return (
    <PageShell>
      {/* ── Hero heading ──────────────────────────────────────────── */}
      <div className="mb-6 fade-in">
        <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Security Dashboard</h1>
        <p className="font-mono text-[11px] text-ink-500 mt-1 flex items-center gap-2">
          <span className="pulse-dot" style={{ background: "#39d98a", color: "#39d98a" }} />
          {fp.device_count} device{fp.device_count !== 1 ? "s" : ""} monitored · {fp.scored_device_count} scored
        </p>
      </div>

      {/* ── KPI strip ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6 fade-in">
        <KpiCard
          label="Avg Posture"
          value={fp.average_score.toFixed(0)}
          suffix="/100"
          color={gradeColor(gradeOf(fp.average_score))}
          sub={`${fp.scored_device_count} scored`}
          icon={<IconShield />}
        />
        <KpiCard
          label="Open Critical"
          value={ff.critical_open}
          color="#ff4d4d"
          sub={ff.critical_delta_24h > 0 ? `+${ff.critical_delta_24h} in 24h` : "No new"}
          alert={ff.critical_open > 0}
          icon={<IconAlert />}
        />
        <KpiCard
          label="Open High"
          value={ff.high_open}
          color="#ff8a3d"
          sub={ff.high_delta_24h > 0 ? `+${ff.high_delta_24h} in 24h` : "No new"}
          icon={<IconFlag />}
        />
        <KpiCard
          label="Devices"
          value={fp.device_count}
          color="#4f8cff"
          sub={isMsp ? "Across customers" : "Monitored"}
          icon={<IconServer />}
        />
        <KpiCard
          label="Compliance"
          value={avgCompliance}
          suffix="%"
          color={passColor(avgCompliance)}
          sub="Avg pass rate"
          icon={<IconCheck />}
        />
      </div>

      {/* ── Main grid ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6 fade-in">
        {/* Left column: fleet + trend */}
        <div className="lg:col-span-2 space-y-4">
          <FleetPostureTable fleet={fleet} isMsp={isMsp} />
          <div className="card-glow p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="font-display font-semibold text-sm text-ink-100">Fleet Score Trend</h3>
                <p className="font-mono text-[10px] text-ink-500 mt-0.5">Average posture · last 90 days</p>
              </div>
            </div>
            <TrendArea points={fp.trend_90d} />
          </div>
        </div>

        {/* Right column: grade donut + findings funnel */}
        <div className="space-y-4">
          <div className="card-glow p-5">
            <h3 className="font-display font-semibold text-sm text-ink-100 mb-1">Grade Distribution</h3>
            <p className="font-mono text-[10px] text-ink-500 mb-3">Scored devices</p>
            <GradeDonut dist={fp.grade_distribution} total={fp.scored_device_count} />
          </div>
          <div className="card-glow p-5">
            <h3 className="font-display font-semibold text-sm text-ink-100 mb-1">Open Findings</h3>
            <p className="font-mono text-[10px] text-ink-500 mb-3">Funnel</p>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <FunnelStat label="Critical" value={ff.critical_open} delta={ff.critical_delta_24h} color="#ff4d4d" />
              <FunnelStat label="High" value={ff.high_open} delta={ff.high_delta_24h} color="#ff8a3d" />
            </div>
            <button onClick={() => navigate("/findings")}
                    className="w-full px-4 py-2.5 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[13px] font-semibold hover:bg-accent/20 transition-all">
              View all {ff.total_open} open findings →
            </button>
          </div>
        </div>
      </div>

      {/* ── Lower grid ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 fade-in">
        <div className="card-glow p-5">
          <h3 className="font-display font-semibold text-sm text-ink-100 mb-1">Devices Needing Attention</h3>
          <p className="font-mono text-[10px] text-ink-500 mb-3">Triage</p>
          {data.devices_needing_attention.length === 0 ? (
            <div className="py-8 text-center">
              <div className="text-3xl mb-2 opacity-30">✓</div>
              <p className="text-ink-500 text-sm font-mono">All devices healthy</p>
            </div>
          ) : (
            <ul className="space-y-2">
              {data.devices_needing_attention.map((d) => (
                <li key={d.device_id}
                    onClick={() => navigate(`/findings?device=${d.device_id}`)}
                    className="flex items-center justify-between gap-3 stat-card !py-2.5 !px-3.5 cursor-pointer group">
                  <div className="min-w-0">
                    <div className="text-ink-100 text-[13px] truncate font-medium group-hover:text-accent transition-colors">{d.friendly_name || d.model || d.serial}</div>
                    <div className="font-mono text-[11px] text-ink-500 truncate">{d.serial}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {d.reasons.map((r) => (
                      <span key={r} className="badge" style={{ color: "#ff8a3d", borderColor: "#ff8a3d55", background: "#ff8a3d14" }}>{r}</span>
                    ))}
                    <span className="font-display font-bold text-sm" style={{ color: gradeColor(d.grade) }}>{d.grade || "—"}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card-glow p-5">
          <h3 className="font-display font-semibold text-sm text-ink-100 mb-1">Compliance</h3>
          <p className="font-mono text-[10px] text-ink-500 mb-3">Pass rate by framework</p>
          <div className="space-y-3">
            {Object.entries(data.compliance).map(([fw, pct]) => (
              <div key={fw}>
                <div className="flex justify-between font-mono text-[11px] mb-1.5">
                  <span className="text-ink-300">{fw}</span>
                  <span className="tabular-nums font-semibold" style={{ color: passColor(pct) }}>{pct.toFixed(0)}%</span>
                </div>
                <div className="h-2.5 w-full rounded-full bg-base-700 overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: `linear-gradient(90deg, ${passColor(pct)}88, ${passColor(pct)})` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </PageShell>
  );
}

// ── Sub-components ────────────────────────────────────────────────────

function PageShell({ children }: { children: React.ReactNode }) {
  return <div className="space-y-0 max-w-[1440px]">{children}</div>;
}

function ErrorBanner({ msg }: { msg: string }) {
  return <div className="card-glow p-6 text-center"><p className="text-sev-high text-sm font-mono">{msg}</p></div>;
}

function LoadingSkeleton() {
  return (
    <div className="space-y-4 fade-in">
      <div className="skeleton h-8 w-56 mb-4" />
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {Array.from({ length: 5 }).map((_, i) => <div key={i} className="skeleton h-24 rounded-xl" />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 skeleton h-72 rounded-xl" />
        <div className="skeleton h-72 rounded-xl" />
      </div>
    </div>
  );
}

function KpiCard({ label, value, suffix, color, sub, alert, icon }: {
  label: string; value: string | number; suffix?: string; color: string; sub: string;
  alert?: boolean; icon: React.ReactNode;
}) {
  return (
    <div className={`stat-card group ${alert ? "animate-pulse" : ""}`}
         style={{ borderColor: alert ? `${color}55` : undefined }}>
      <div className="flex items-start justify-between">
        <div className="space-y-0.5">
          <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</div>
          <div className="flex items-baseline gap-1">
            <span className="font-display text-[28px] font-bold leading-none tabular-nums" style={{ color }}>
              {typeof value === "number" ? value.toLocaleString() : value}
            </span>
            {suffix && <span className="font-display text-sm font-semibold text-ink-500">{suffix}</span>}
          </div>
          <div className="font-mono text-[10px] text-ink-500">{sub}</div>
        </div>
        <div className="opacity-30 group-hover:opacity-60 transition-opacity" style={{ color }}>{icon}</div>
      </div>
      <div className="absolute left-0 top-[12%] bottom-[12%] w-[3px] rounded-r-sm" style={{ background: color }} />
    </div>
  );
}

function TrendArea({ points }: { points: { date: string; score: number }[] }) {
  if (points.length < 2) return <p className="font-mono text-[11px] text-ink-500 py-8 text-center">Not enough history yet — run more scans.</p>;
  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={points} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#4f8cff" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#4f8cff" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="rgb(var(--base-500))" strokeDasharray="3 3" strokeOpacity={0.5} />
        <XAxis dataKey="date" tick={{ fontSize: 10, fill: "rgb(var(--ink-500))" }} minTickGap={32} axisLine={false} tickLine={false} />
        <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "rgb(var(--ink-500))" }} axisLine={false} tickLine={false} />
        <Tooltip contentStyle={{ background: "rgb(15,21,33)", border: "1px solid rgb(42,52,71)", borderRadius: 8, fontSize: 12, boxShadow: "0 8px 24px rgba(0,0,0,0.4)" }} />
        <Area type="monotone" dataKey="score" stroke="#4f8cff" strokeWidth={2.5} fill="url(#trendFill)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function GradeDonut({ dist, total }: { dist: Record<string, number>; total: number }) {
  const grades = ["A", "B", "C", "D", "F"];
  const data = grades.map((g) => ({ name: g, value: dist[g] || 0 })).filter((d) => d.value > 0);
  if (data.length === 0) return <p className="text-ink-500 text-sm py-6 text-center font-mono">No scored devices yet.</p>;
  return (
    <div className="flex items-center gap-4">
      <div className="relative" style={{ width: 130, height: 130 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" innerRadius={42} outerRadius={60} paddingAngle={3} stroke="none">
              {data.map((d) => <Cell key={d.name} fill={gradeColor(d.name)} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 grid place-items-center pointer-events-none">
          <div className="text-center">
            <div className="font-display font-bold text-lg text-ink-100 leading-none">{total}</div>
            <div className="font-mono text-[9px] text-ink-500 mt-0.5">devices</div>
          </div>
        </div>
      </div>
      <div className="space-y-1.5">
        {grades.map((g) => (
          <div key={g} className="flex items-center gap-2 text-[12px]">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ background: gradeColor(g) }} />
            <span className="font-display font-bold w-4" style={{ color: gradeColor(g) }}>{g}</span>
            <span className="font-mono text-ink-500 tabular-nums">{dist[g] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FleetPostureTable({ fleet, isMsp }: { fleet: FleetSummary | null; isMsp: boolean }) {
  const rows = (fleet?.rows ?? []).slice(0, 10);
  return (
    <div className="card-glow">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-base-500/60">
        <div>
          <h3 className="font-display font-semibold text-sm text-ink-100">Fleet Security Posture</h3>
          <p className="font-mono text-[10px] text-ink-500 mt-0.5">{isMsp ? "Worst devices across all customers" : "Worst devices first"}</p>
        </div>
        {fleet && <span className="badge" style={{ color: "#6b7689", borderColor: "#6b768955", background: "#6b768914" }}>{fleet.device_count} devices</span>}
      </div>
      {rows.length === 0 ? (
        <div className="p-8 text-center">
          <div className="text-3xl mb-2 opacity-30">📡</div>
          <p className="text-ink-500 text-sm font-mono">No scored devices yet. Upload a TSR or connect a firewall.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                <th className="py-2.5 px-4">Device</th>
                {isMsp && <th className="py-2.5 px-4">Customer</th>}
                <th className="py-2.5 px-4 hidden md:table-cell">Firmware</th>
                <th className="py-2.5 px-4">Posture</th>
                <th className="py-2.5 px-4">Findings</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.device_id}
                    onClick={() => navigate(`/findings?device=${d.device_id}`)}
                    className="table-row border-b border-base-500/40 cursor-pointer">
                  <td className="py-2.5 px-4">
                    <span className="text-ink-100 font-medium">{d.model || d.serial}</span>
                    <div className="font-mono text-[10px] text-ink-500">{d.serial}</div>
                  </td>
                  {isMsp && <td className="py-2.5 px-4 text-ink-300">{d.customer_name || "—"}</td>}
                  <td className="py-2.5 px-4 font-mono text-[11px] text-ink-500 hidden md:table-cell">{d.firmware || "—"}</td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-2">
                      <div className="h-2 flex-1 max-w-[80px] rounded-full bg-base-700 overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${d.score || 0}%`, background: gradeColor(d.grade) }} />
                      </div>
                      <span className="font-display font-bold text-sm tabular-nums" style={{ color: gradeColor(d.grade) }}>{d.grade || "—"}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <SevDot color="#ff4d4d" n={d.critical_count} />
                      <SevDot color="#ff8a3d" n={d.high_count} />
                      <SevDot color="#f5c451" n={(d as any).medium_count || 0} />
                      <SevDot color="#4a9eff" n={(d as any).low_count || 0} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FunnelStat({ label, value, delta, color }: { label: string; value: number; delta: number; color: string }) {
  return (
    <div className="stat-card !py-3 !px-3.5 text-center">
      <div className="font-display text-2xl font-bold tabular-nums" style={{ color }}>{value}</div>
      <div className="font-mono text-[10px] uppercase tracking-wider text-ink-500 mt-0.5">{label}</div>
      {delta !== 0 && (
        <div className="font-mono text-[10px] mt-0.5" style={{ color: delta > 0 ? "#ff4d4d" : "#39d98a" }}>
          {delta > 0 ? `↑${delta}` : `↓${Math.abs(delta)}`} / 24h
        </div>
      )}
    </div>
  );
}

function gradeOf(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function SevDot({ color, n }: { color: string; n: number }) {
  return (
    <span className="inline-flex items-center gap-0.5 font-mono text-[10px] font-semibold tabular-nums"
          style={{ color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      {n}
    </span>
  );
}

function passColor(pct: number): string {
  if (pct >= 90) return "#39d98a";
  if (pct >= 70) return "#f5c451";
  return "#ff4d4d";
}

// ── Inline icons ───────────────────────────────────────────────────────
function IconShield() { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>; }
function IconAlert()  { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>; }
function IconFlag()   { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>; }
function IconServer() { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>; }
function IconCheck()  { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>; }
