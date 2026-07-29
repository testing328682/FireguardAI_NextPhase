import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { Rule, User } from "../lib/types";
import { navigate } from "../lib/router";
import { SEVERITIES, sevColor } from "../lib/ui";

const STATE_COLOR: Record<string, string> = {
  draft: "#7a879b", submitted: "#f5c451", approved: "#39d98a",
};
const STATE_BG: Record<string, string> = {
  draft: "#7a879b14", submitted: "#f5c45114", approved: "#39d98a14",
};

const RULE_CATEGORIES = [
  "Management Security", "Authentication", "Access Control",
  "VPN Security", "SSL VPN", "Security Services", "Firmware Security",
  "Wireless Security", "Logging & Monitoring", "High Availability",
  "Address Objects", "NAT Policies", "Performance", "Licensing",
  "Certificates", "Custom",
];

// ── Rule library ──────────────────────────────────────────────────────
export function Rules({ user }: { user?: User }) {
  const [rows, setRows] = useState<Rule[]>([]);
  // Format view: "gui" shows the catalog as collected from the firewall GUI;
  // "api" annotates each rule with whether it can be evaluated on an API-collected
  // TSR (table-heavy sections are lost in the API format — see normalize.py).
  const [view, setView] = useState<"gui" | "api">("gui");
  const [source, setSource] = useState<string>(user?.is_superadmin ? "system" : "");
  const [severity, setSeverity] = useState<string>("");
  const [q, setQ] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    try {
      const params: Record<string, string> = {};
      if (source) params.source = source;
      if (severity) params.severity = severity;
      if (q) params.q = q;
      setRows(await api.listRules(params));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load rules");
    }
  }, [source, severity, q]);

  useEffect(() => { load(); }, [load]);

  const apiSupported = rows.filter((r) => (r.api_support ?? "full") === "full").length;

  return (
    <div className="space-y-0 max-w-[1440px] fade-in">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Rule Library</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">
            Detection catalog · {rows.length} rule{rows.length !== 1 ? "s" : ""}
            {view === "api" && (
              <> · <span className="text-[#39d98a]">{apiSupported}</span> evaluable on API TSRs</>
            )}
          </p>
        </div>
        <button onClick={() => setCreating(true)}
                className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
          + New rule
        </button>
      </div>

      {/* Format view toggle — annotates rules with API-TSR compatibility */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="inline-flex rounded-lg border border-base-500 bg-base-800 p-0.5">
          {(["gui", "api"] as const).map((v) => (
            <button key={v} onClick={() => setView(v)}
                    className={`px-3.5 py-1.5 rounded-md text-[12px] font-semibold transition-all ${
                      view === v ? "bg-accent text-white shadow-[0_0_16px_-6px_rgba(79,140,255,0.5)]"
                                 : "text-ink-500 hover:text-ink-200"}`}>
              {v === "gui" ? "GUI TSR" : "API TSR"}
            </button>
          ))}
        </div>
        <span className="font-mono text-[10px] text-ink-500">
          {view === "gui"
            ? "Catalog as collected from the firewall GUI."
            : "API-collected TSRs are normalized to recover every section — the full rule set applies."}
        </span>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3 mb-4">
        <Sel label="Source" value={source} onChange={setSource}
             options={["", "system", "custom"]} labels={{ "": "All" }} />
        <Sel label="Severity" value={severity} onChange={setSeverity}
             options={["", ...SEVERITIES]} labels={{ "": "All" }} />
        <label className="block">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Search</span>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rule ID or title…"
                 className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-all placeholder:text-ink-500/60 w-52" />
        </label>
      </div>

      {err && (
        <div className="card-glow p-4 mb-4 border-sev-high/30">
          <p className="text-sev-high text-[13px] font-mono">{err}</p>
        </div>
      )}
      {creating && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setCreating(false)} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={() => setCreating(false)}>
            <div className="w-full max-w-[560px] bg-base-800 border border-base-500 rounded-xl shadow-xl"
                 onClick={(e) => e.stopPropagation()}>
              <CreateRule onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); navigate(`/rules/${id}`); }} />
            </div>
          </div>
        </>
      )}

      {/* Table */}
      <div className="card-glow">
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                <th className="py-3 px-4">Rule ID</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">State</th>
                {view === "api" && <th className="py-3 px-4">API TSR</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const apiOk = (r.api_support ?? "full") === "full";
                const dim = view === "api" && !apiOk;
                return (
                <tr key={r.id} onClick={() => navigate(`/rules/${r.id}`)}
                    className={`table-row border-b border-base-500/40 cursor-pointer ${dim ? "opacity-45" : ""}`}>
                  <td className="py-3 px-4">
                    <span className="font-mono text-[11px] text-ink-300 font-medium">{r.key}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-ink-100">{r.title}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="font-mono text-[11px] text-ink-500">{r.category}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="badge" style={{
                      color: sevColor[r.severity],
                      borderColor: `${sevColor[r.severity]}55`,
                      background: `${sevColor[r.severity]}14`,
                    }}>{r.severity}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="badge capitalize" style={{
                      color: r.source === "system" ? "#c084fc" : "#6b7689",
                      borderColor: r.source === "system" ? "#c084fc55" : "#6b768955",
                      background: r.source === "system" ? "#c084fc14" : "#6b768914",
                    }}>{r.source}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="badge" style={{
                      color: STATE_COLOR[r.state],
                      borderColor: `${STATE_COLOR[r.state]}55`,
                      background: STATE_BG[r.state],
                    }}>{r.state}</span>
                  </td>
                  {view === "api" && (
                    <td className="py-3 px-4">
                      <span className="badge" style={{
                        color: apiOk ? "#39d98a" : "#6b7689",
                        borderColor: apiOk ? "#39d98a55" : "#6b768955",
                        background: apiOk ? "#39d98a14" : "#6b768914",
                      }}>{apiOk ? "Supported" : "GUI only"}</span>
                    </td>
                  )}
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {rows.length === 0 && (
          <div className="py-12 text-center">
            <div className="text-4xl mb-3 opacity-30">⚡</div>
            <p className="text-ink-500 text-sm font-mono">No rules match your filters</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Create rule form ──────────────────────────────────────────────────
function CreateRule({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("Medium");
  const [category, setCategory] = useState("Custom");
  const [condition, setCondition] = useState("snapshot.security_services.ips_enabled == false");
  const [remediation, setRemediation] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setErr(null); setBusy(true);
    try {
      const r = await api.createRule({ title, severity, category, condition, remediation });
      onCreated(r.id);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Create failed");
    } finally { setBusy(false); }
  }

  return (
    <div className="p-5 space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="font-display font-semibold text-ink-100 text-sm">New Rule</h3>
        <button onClick={onClose} className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 hover:border-base-400 transition-colors text-sm">✕</button>
      </div>
      {err && <p className="text-sev-high text-[12px] font-mono">{err}</p>}
      <Field label="Title"><input value={title} onChange={(e) => setTitle(e.target.value)} className={inputCls} placeholder="e.g. IPS Disabled on Trusted Zone" /></Field>
      <div className="flex gap-3">
        <Field label="Severity">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={inputCls}>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Category">
          <select value={category} onChange={(e) => setCategory(e.target.value)} className={inputCls}>
            {RULE_CATEGORIES.map((c) => <option key={c}>{c}</option>)}
          </select>
        </Field>
      </div>
      <Field label="CEL Condition">
        <textarea value={condition} onChange={(e) => setCondition(e.target.value)} rows={3}
                  className={`${inputCls} font-mono text-[12px]`} placeholder="snapshot.security_services.ips_enabled == false" />
      </Field>
      <Field label="Remediation">
        <input value={remediation} onChange={(e) => setRemediation(e.target.value)} className={inputCls} placeholder="Enable IPS on all security zones" />
      </Field>
      <div className="flex items-center gap-3">
        <button onClick={submit} disabled={!title || !condition || busy}
                className="px-5 py-2.5 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all shadow-[0_0_20px_-8px_rgba(79,140,255,0.4)]">
          {busy ? "Creating…" : "Create Rule"}
        </button>
        <span className="font-mono text-[11px] text-ink-500">
          Starts as <span className="text-ink-300">Draft</span> — Submit → Approve to activate
        </span>
      </div>
    </div>
  );
}

const inputCls = "mt-1.5 w-full bg-base-900 border border-base-500 rounded-lg px-3.5 py-2.5 text-[13px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-all placeholder:text-ink-500/50";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block flex-1">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</span>
      {children}
    </label>
  );
}

function Sel({ label, value, onChange, options, labels = {} }:
  { label: string; value: string; onChange: (v: string) => void;
    options: readonly string[]; labels?: Record<string, string> }) {
  return (
    <label className="block">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
              className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-all">
        {options.map((o) => <option key={o} value={o}>{labels[o] ?? o}</option>)}
      </select>
    </label>
  );
}

export { STATE_COLOR };
