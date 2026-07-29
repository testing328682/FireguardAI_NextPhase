import { useEffect, useState } from "react";
import {
  ResponsiveContainer, LineChart, Line, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend,
} from "recharts";
import { api } from "../lib/api";
import type { Trends as TrendsData } from "../lib/types";
import { Panel, Stat } from "./primitives";
import { sevColor } from "../lib/ui";

const AXIS = { fontSize: 11, fill: "#6b7689" };
const GRID = "#2a3447";

// Advanced analytics: score progression, MTTR, recurrence, top rules, categories.
export function Trends() {
  const [data, setData] = useState<TrendsData | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.trends().then(setData).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load analytics"));
  }, []);

  if (err) return <Panel title="Trends"><p className="text-sev-high text-sm">{err}</p></Panel>;
  if (!data) return <Panel title="Trends"><p className="font-mono text-ink-500 text-sm animate-pulse">Loading analytics…</p></Panel>;

  // Merge per-device monthly scores into one chart series keyed by month.
  const scoreMonths: Record<string, any> = {};
  for (const dev of data.score_progression) {
    for (const p of dev.points) {
      scoreMonths[p.month] = scoreMonths[p.month] || { month: p.month };
      scoreMonths[p.month][dev.serial] = p.score;
    }
  }
  const scoreSeries = Object.values(scoreMonths).sort((a: any, b: any) => a.month.localeCompare(b.month));
  const deviceSerials = data.score_progression.map((d) => d.serial).slice(0, 6);
  const lineColors = ["#4f8cff", "#39d98a", "#f5c451", "#ff8a3d", "#ff4d4d", "#9ad94a"];

  const mttrData = Object.entries(data.mttr_by_severity).map(([sev, days]) => ({ sev, days }));

  const catMonths = data.category_evolution.map((m) => {
    const row: any = { month: m.month };
    for (const [cat, n] of Object.entries(m.categories)) row[cat] = n;
    return row;
  });
  const allCats = Array.from(new Set(
    data.category_evolution.flatMap((m) => Object.keys(m.categories)))).slice(0, 6);

  return (
    <div className="space-y-5">
      <div className="grid gap-5 sm:grid-cols-3">
        <Stat label="Findings tracked" value={data.recurrence.total_findings} />
        <Stat label="Recurring findings" value={data.recurrence.recurring_findings}
              sub={`${(data.recurrence.rate * 100).toFixed(1)}% recurrence rate`} />
        <Stat label="Devices trended" value={data.score_progression.length} />
      </div>

      <Panel title="Score progression" eyebrow="12-month trend per device">
        {scoreSeries.length === 0 ? <Empty /> : (
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={scoreSeries} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
              <XAxis dataKey="month" tick={AXIS} />
              <YAxis domain={[0, 100]} tick={AXIS} />
              <Tooltip contentStyle={{ background: "#0f1521", border: "1px solid #2a3447", fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {deviceSerials.map((s, i) => (
                <Line key={s} type="monotone" dataKey={s} stroke={lineColors[i % lineColors.length]}
                      strokeWidth={2} dot={false} connectNulls />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Mean time to remediate" eyebrow="Days, by severity">
          {mttrData.length === 0 ? <Empty /> : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={mttrData} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
                <XAxis dataKey="sev" tick={AXIS} />
                <YAxis tick={AXIS} />
                <Tooltip contentStyle={{ background: "#0f1521", border: "1px solid #2a3447", fontSize: 12 }} />
                <Bar dataKey="days" radius={[3, 3, 0, 0]}
                     fill="#4f8cff"
                     // per-bar color by severity
                     shape={(props: any) => (
                       <rect x={props.x} y={props.y} width={props.width} height={props.height}
                             rx={3} fill={sevColor[props.payload.sev] || "#4f8cff"} />
                     )} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>

        <Panel title="Top 10 firing rules" eyebrow="Across the fleet">
          {data.top_rules.length === 0 ? <Empty /> : (
            <ul className="space-y-1.5">
              {data.top_rules.map((r) => (
                <li key={r.rule_id} className="flex items-center gap-2 text-[13px]">
                  <span className="font-mono text-[11px] text-ink-500 w-20 shrink-0">{r.rule_id}</span>
                  <div className="flex-1 h-2 rounded-full bg-base-700 overflow-hidden">
                    <div className="h-full rounded-full bg-accent"
                         style={{ width: `${(r.count / data.top_rules[0].count) * 100}%` }} />
                  </div>
                  <span className="font-mono text-[11px] text-ink-300 w-8 text-right tabular-nums">{r.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title="Category breakdown evolution" eyebrow="Findings by category, monthly">
        {catMonths.length === 0 ? <Empty /> : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={catMonths} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
              <XAxis dataKey="month" tick={AXIS} />
              <YAxis tick={AXIS} />
              <Tooltip contentStyle={{ background: "#0f1521", border: "1px solid #2a3447", fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {allCats.map((c, i) => (
                <Bar key={c} dataKey={c} stackId="a"
                     fill={["#4f8cff", "#39d98a", "#f5c451", "#ff8a3d", "#ff4d4d", "#9ad94a"][i % 6]} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </Panel>
    </div>
  );
}

function Empty() {
  return <p className="text-ink-500 text-sm py-6 text-center">Not enough data yet — run more scans.</p>;
}
