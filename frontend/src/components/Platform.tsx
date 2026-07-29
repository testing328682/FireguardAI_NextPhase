import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { PlatformOverview } from "../lib/types";
import { gradeColor } from "../lib/ui";

// ── Platform operator dashboard ──────────────────────────────────────
export function Platform() {
  const [data, setData] = useState<PlatformOverview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    api.platformOverview().then(setData).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load"));
  }, []);

  if (err) return <PageShell><ErrorBanner msg={err} /></PageShell>;
  if (!data) return <PageShell><LoadingSkeleton /></PageShell>;

  const s = data.stats;
  return (
    <PageShell>
      {/* ── Hero row: platform heartbeat + key metrics ─────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 fade-in">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">
            Platform Overview
          </h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1 flex items-center gap-2">
            <span className="pulse-dot" style={{ background: "#39d98a", color: "#39d98a" }} />
            {s.organizations} organisation{s.organizations !== 1 ? "s" : ""} · {s.total_firewalls} firewall{s.total_firewalls !== 1 ? "s" : ""} monitored
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="stat-card flex items-center gap-3 !py-2 !px-4">
            <span className="font-mono text-[10px] uppercase tracking-widest text-ink-500">Avg Score</span>
            <span className="font-display text-xl font-bold tabular-nums"
                  style={{ color: gradeColor(gradeOf(s.organizations ? 75 : 0)) }}>
              {s.organizations ? "—" : "—"}
            </span>
          </div>
        </div>
      </div>

      {/* ── KPI grid ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6 fade-in">
        <KpiCard label="Organisations" value={s.organizations}   color="#4f8cff" icon={<IconBuildings />} />
        <KpiCard label="MSP Tenants"    value={s.msp_count}      color="#39d98a" icon={<IconLayers />} />
        <KpiCard label="Direct"          value={s.direct_count}    color="#9ad94a" icon={<IconBuilding />} />
        <KpiCard label="Customers"       value={s.total_customers} color="#f5c451" icon={<IconUsers />} />
        <KpiCard label="Firewalls"       value={s.total_firewalls} color="#ff8a3d" icon={<IconShield />} />
        <KpiCard label="Users"           value={s.total_users}     color="#c084fc" icon={<IconPerson />} />
      </div>

      {/* ── Plan Distribution ────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6 fade-in">
        <div className="card-glow">
          <h2 className="font-display font-semibold text-ink-100 mb-3 px-5 pt-5">Plan Distribution</h2>
          <div className="flex flex-wrap gap-3 px-5 pb-5">
            {Object.entries(s.plan_distribution || {}).length === 0 ? (
              <span className="text-ink-500 font-mono text-sm">No plan data available.</span>
            ) : (
              Object.entries(s.plan_distribution || {}).map(([plan, count]) => (
                <PlanCard key={plan} plan={plan} count={count as number} />
              ))
            )}
          </div>
        </div>
        <div className="card-glow">
          <h2 className="font-display font-semibold text-ink-100 mb-3 px-5 pt-5">Region Distribution</h2>
          <div className="flex flex-wrap gap-3 px-5 pb-5">
            {Object.entries(s.region_distribution || {}).length === 0 ? (
              <span className="text-ink-500 font-mono text-sm">No region data available.</span>
            ) : (
              Object.entries(s.region_distribution || {}).map(([region, count]) => (
                <RegionCard key={region} region={region} count={count as number} />
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── Organisations table ─────────────────────────────────────── */}
      <div className="card-glow fade-in">
        <div className="overflow-x-auto">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-[0.1em] text-ink-500 bg-base-800/50">
                <Th>Organization</Th>
                <Th>Type</Th>
                <Th>Plan</Th>
                <Th>Region</Th>
                <Th right>Customers</Th>
                <Th right>Firewalls</Th>
                <Th right>Users</Th>
                <Th right>Avg Score</Th>
                <Th right>Open Critical</Th>
                <Th>Actions</Th>
              </tr>
            </thead>
            <tbody>
            {data.organizations.map((o, i) => (
              <tr key={o.id} className="table-row border-b border-base-500/40" style={{ animationDelay: `${i * 40}ms` }}>
                <Td>
                  <span className="text-ink-100 font-medium">{o.name}</span>
                </Td>
                <Td>
                  <span className="badge" style={{
                    color: o.type === "MSP" ? "#39d98a" : "#9ad94a",
                    borderColor: o.type === "MSP" ? "#39d98a55" : "#9ad94a55",
                    background: o.type === "MSP" ? "#39d98a12" : "#9ad94a12",
                  }}>{o.type}</span>
                </Td>
                <Td>
                  <PlanBadge plan={o.plan} />
                </Td>
                <Td>
                  <span className="font-mono text-[11px] text-ink-500 uppercase">{o.region}</span>
                </Td>
                <Td right>{o.customers}</Td>
                <Td right>{o.firewalls}</Td>
                <Td right>{o.users}</Td>
                <Td right>
                  {o.avg_score != null ? (
                    <span className="font-display font-bold tabular-nums text-sm"
                          style={{ color: gradeColor(gradeOf(o.avg_score)) }}>
                      {o.avg_score.toFixed(0)}
                    </span>
                  ) : <span className="text-ink-500">—</span>}
                </Td>
                <Td right>
                  {o.open_critical > 0 ? (
                    <span className="badge" style={{ color: "#ff4d4d", borderColor: "#ff4d4d55", background: "#ff4d4d12" }}>
                      {o.open_critical}
                    </span>
                  ) : <span className="text-ink-500 font-mono text-[11px]">0</span>}
                </Td>
                <Td>
                  <div className="flex items-center gap-2">
                    {o.plan !== "free" && (
                      <button onClick={async () => {
                        if (!window.confirm(`Reset ${o.name}'s subscription to Free? This clears all licenses.`)) return;
                        try { await api.resetSubscription(o.id); window.location.reload(); }
                        catch (e) { alert(e instanceof Error ? e.message : "Reset failed"); }
                      }}
                      className="text-[11px] text-ink-500 hover:text-sev-high font-mono transition-colors">
                        Reset
                      </button>
                    )}
                    <button onClick={async () => {
                      if (!window.confirm(`WIPE ${o.name}? This deletes ALL devices, customers, findings, TSRs, and resets to fresh sign-up state. This cannot be undone.`)) return;
                      if (!window.confirm("Are you absolutely sure? This action is irreversible.")) return;
                      try { await api.factoryReset(o.id); window.location.reload(); }
                      catch (e) { alert(e instanceof Error ? e.message : "Wipe failed"); }
                    }}
                    className="text-[11px] text-sev-high/60 hover:text-sev-high font-mono transition-colors">
                      Wipe
                    </button>
                    <button onClick={() => { setDeleteTarget({ id: o.id, name: o.name }); setConfirmText(""); }}
                    className="text-[11px] text-ink-600 hover:text-sev-critical font-mono transition-colors">
                      Delete
                    </button>
                  </div>
                </Td>
              </tr>
            ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Delete confirmation modal ──────────────────────────────── */}
      {deleteTarget !== null && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => { if (!deleting) { setDeleteTarget(null); setConfirmText(""); } }} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in">
            <div className="w-full max-w-[480px] bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
                 onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h3 className="font-display text-lg font-bold text-sev-critical">Delete Organization</h3>
                <button onClick={() => { if (!deleting) { setDeleteTarget(null); setConfirmText(""); } }}
                        className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors"
                        disabled={deleting}>×</button>
              </div>
              <p className="text-ink-300 text-sm">
                You are about to <span className="text-sev-critical font-semibold">permanently delete</span>:
              </p>
              <div className="bg-base-700/40 rounded-lg p-4 space-y-2 font-mono text-sm">
                <div className="flex justify-between">
                  <span className="text-ink-500">Organization</span>
                  <span className="text-ink-100 font-semibold">{deleteTarget.name}</span>
                </div>
              </div>
              <div className="bg-sev-critical/10 border border-sev-critical/30 rounded-lg p-3 text-[12px] text-sev-critical leading-relaxed">
                This action will permanently remove the organization and <strong>ALL</strong> associated data — users, devices, TSRs, analyses, findings, reports, licenses, and audit history. This cannot be undone.
              </div>
              <div>
                <label className="block text-[11px] font-mono text-ink-500 mb-2">
                  Type <span className="text-ink-200 font-semibold">{deleteTarget.name}</span> to confirm:
                </label>
                <input
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder={deleteTarget.name}
                  disabled={deleting}
                  className="w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-sev-critical placeholder:text-ink-500/50"
                  autoFocus
                />
              </div>
              <div className="flex items-center justify-end gap-3 pt-2">
                <button onClick={() => { setDeleteTarget(null); setConfirmText(""); }}
                        disabled={deleting}
                        className="px-4 py-2 rounded-lg border border-base-500 text-ink-300 text-sm hover:border-base-400 transition-all">
                  Cancel
                </button>
                <button
                  onClick={async () => {
                    setDeleting(true);
                    try {
                      await api.deleteOrganization(deleteTarget.id);
                      window.location.reload();
                    } catch (e) {
                      alert(e instanceof Error ? e.message : "Deletion failed");
                      setDeleting(false);
                    }
                  }}
                  disabled={deleting || confirmText !== deleteTarget.name}
                  className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${confirmText === deleteTarget.name && !deleting ? "bg-sev-critical text-white hover:bg-red-700" : "bg-base-700 text-ink-600 cursor-not-allowed"}`}>
                  {deleting ? "Deleting…" : "Delete Permanently"}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

    </PageShell>
  );
}

// ── Sub-components ───────────────────────────────────────────────────

function PageShell({ children }: { children: React.ReactNode }) {
  return <div className="space-y-0 max-w-[1440px]">{children}</div>;
}

function ErrorBanner({ msg }: { msg: string }) {
  return (
    <div className="card-glow p-6 text-center">
      <div className="text-4xl mb-3 opacity-40">⚠</div>
      <p className="text-sev-critical font-mono text-sm">{msg}</p>
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-4 fade-in">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="card-glow p-4 animate-pulse">
          <div className="h-4 bg-base-700 rounded w-3/4 mb-3" />
          <div className="h-3 bg-base-700 rounded w-1/2" />
        </div>
      ))}
    </div>
  );
}

function KpiCard({ label, value, color, icon }: { label: string; value: number; color: string; icon: React.ReactNode }) {
  return (
    <div className="stat-card group" style={{ ["--accent-bar" as string]: color }}>
      <div className="flex items-center gap-2 mb-2">
        <span style={{ color }}>{icon}</span>
        <span className="font-mono text-[10px] uppercase tracking-widest text-ink-500">{label}</span>
      </div>
      <div className="font-display text-2xl font-bold text-ink-100 tabular-nums">{value.toLocaleString()}</div>
    </div>
  );
}

function Th({ children, right }: { children: React.ReactNode; right?: boolean }) {
  return <th className={`py-2.5 px-3 ${right ? "text-right" : ""}`}>{children}</th>;
}
function Td({ children, right }: { children: React.ReactNode; right?: boolean }) {
  return <td className={`py-2.5 px-3 ${right ? "text-right tabular-nums text-ink-300" : ""}`}>{children}</td>;
}

function PlanBadge({ plan }: { plan: string }) {
  const colors: Record<string, string> = { free: "#6b7689", professional: "#4f8cff", msp: "#39d98a" };
  const c = colors[plan] || "#6b7689";
  return (
    <span className="badge capitalize" style={{ color: c, borderColor: `${c}55`, background: `${c}14` }}>
      {plan}
    </span>
  );
}

function PlanCard({ plan, count }: { plan: string; count: number }) {
  const colors: Record<string, string> = { free: "#6b7689", professional: "#4f8cff", msp: "#39d98a" };
  const c = colors[plan] || "#6b7689";
  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: `${c}12`, border: `1px solid ${c}33` }}>
      <span className="font-mono text-[11px] capitalize" style={{ color: c }}>{plan}</span>
      <span className="font-mono text-sm font-bold tabular-nums text-ink-100">{count}</span>
    </div>
  );
}

function RegionCard({ region, count }: { region: string; count: number }) {
  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: "#4f8cff12", border: "1px solid #4f8cff33" }}>
      <span className="font-mono text-[11px] uppercase text-ink-300">{region || "unknown"}</span>
      <span className="font-mono text-sm font-bold tabular-nums text-ink-100">{count}</span>
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

// ── Inline SVG icons ──────────────────────────────────────────────────

function IconBuildings() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="2" width="16" height="20" rx="2" ry="2" />
      <path d="M9 22v-4h6v4" />
      <line x1="8" y1="6" x2="10" y2="6" />
      <line x1="14" y1="6" x2="16" y2="6" />
      <line x1="8" y1="10" x2="10" y2="10" />
      <line x1="14" y1="10" x2="16" y2="10" />
      <line x1="8" y1="14" x2="10" y2="14" />
      <line x1="14" y1="14" x2="16" y2="14" />
    </svg>
  );
}

function IconLayers() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 22 8 12 14 2 8 12 2" />
      <polyline points="2 16 12 22 22 16" />
      <polyline points="2 12 12 18 22 12" />
    </svg>
  );
}

function IconBuilding() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="2" width="16" height="20" rx="2" ry="2" />
      <line x1="9" y1="6" x2="9.01" y2="6" />
      <line x1="15" y1="6" x2="15.01" y2="6" />
      <line x1="9" y1="10" x2="9.01" y2="10" />
      <line x1="15" y1="10" x2="15.01" y2="10" />
    </svg>
  );
}

function IconUsers() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

function IconShield() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function IconPerson() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
}
