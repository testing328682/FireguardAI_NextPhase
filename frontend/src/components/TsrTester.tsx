import { useRef, useState } from "react";
import { api } from "../lib/api";
import type { TsrTestResult } from "../lib/types";
import { sevColor } from "../lib/ui";

type Fmt = "auto" | "gui" | "api";

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

// ── Superadmin TSR Analysis tester ────────────────────────────────────
// Ad-hoc upload → analyze a TSR (GUI- or API-collected) without persisting
// anything. API-collected TSRs are normalized to the GUI text shape and rules
// that depend on lost table data are suppressed (see backend normalize.py /
// rule_engine.api_unsupported_system_keys).
export function TsrTester() {
  const [fmt, setFmt] = useState<Fmt>("auto");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<TsrTestResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  async function run() {
    if (!file) return;
    setErr(null); setBusy(true); setResult(null);
    try {
      setResult(await api.platformAnalyzeTsr(file, fmt));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Analysis failed");
    } finally { setBusy(false); }
  }

  return (
    <div className="space-y-5 max-w-[1100px] fade-in">
      {/* Header */}
      <div>
        <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">TSR Analysis Tester</h1>
        <p className="font-mono text-[11px] text-ink-500 mt-1">
          Operator tool · upload a Tech Support Report and run the full pipeline. Nothing is stored.
        </p>
      </div>

      {/* Upload card */}
      <div className="card-glow p-5 space-y-4">
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">TSR format</span>
            <div className="mt-1.5 inline-flex rounded-lg border border-base-500 bg-base-800 p-0.5">
              {(["auto", "gui", "api"] as const).map((f) => (
                <button key={f} onClick={() => setFmt(f)}
                        className={`px-3.5 py-1.5 rounded-md text-[12px] font-semibold transition-all ${
                          fmt === f ? "bg-accent text-white shadow-[0_0_16px_-6px_rgba(79,140,255,0.5)]"
                                    : "text-ink-500 hover:text-ink-200"}`}>
                  {f === "auto" ? "Auto-detect" : f === "gui" ? "GUI TSR" : "API TSR"}
                </button>
              ))}
            </div>
          </div>
          <div className="flex-1 min-w-[220px]">
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">File</span>
            <div className="mt-1.5 flex items-center gap-3">
              <button onClick={() => inputRef.current?.click()}
                      className="px-3.5 py-2 rounded-lg border border-base-500 bg-base-800 text-[13px] text-ink-200 hover:border-base-400 transition-colors">
                Choose TSR…
              </button>
              <span className="font-mono text-[12px] text-ink-400 truncate">
                {file ? file.name : "No file selected"}
              </span>
              <input ref={inputRef} type="file" className="hidden"
                     accept=".wri,.txt,.log,.csv,.tsr,text/plain"
                     onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null); }} />
            </div>
          </div>
          <button onClick={run} disabled={!file || busy}
                  className="px-5 py-2.5 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all shadow-[0_0_20px_-8px_rgba(79,140,255,0.4)]">
            {busy ? "Analyzing…" : "Analyze"}
          </button>
        </div>
        <p className="font-mono text-[10px] text-ink-500">
          Auto-detect inspects the report structure. API-collected TSRs are normalized to the GUI shape —
          every configuration section is reconstructed, so the full rule set applies and results match a
          GUI TSR from the same firewall.
        </p>
      </div>

      {err && (
        <div className="card-glow p-4 border-sev-high/30">
          <p className="text-sev-high text-[13px] font-mono">{err}</p>
        </div>
      )}

      {result && <ResultView result={result} />}
    </div>
  );
}

function ResultView({ result }: { result: TsrTestResult }) {
  const grouped = SEV_ORDER
    .map((s) => ({ sev: s, items: result.findings.filter((f) => f.severity === s) }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="space-y-5 fade-in">
      {/* Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="Score" value={`${result.score.toFixed(1)}`} sub={`Grade ${result.grade}`} />
        <Stat label="Format"
              value={result.detected_format === "api" ? "API" : "GUI"}
              sub={result.requested_format === "auto" ? "auto-detected" : `forced ${result.requested_format}`} />
        <Stat label="Findings" value={`${result.finding_count}`} sub={`${result.filename}`} />
        <Stat label="Suppressed rules" value={`${result.suppressed_rule_count}`}
              sub={result.detected_format === "api" ? "API-incompatible" : "none"} />
      </div>

      {/* Severity counts */}
      <div className="card-glow p-4">
        <div className="flex flex-wrap gap-2">
          {SEV_ORDER.map((s) => (
            <span key={s} className="badge" style={{
              color: sevColor[s], borderColor: `${sevColor[s]}55`, background: `${sevColor[s]}14`,
            }}>
              {s}: {result.severity_counts[s] ?? 0}
            </span>
          ))}
        </div>
      </div>

      {result.detected_format === "api" && result.suppressed_rule_count > 0 && (
        <div className="card-glow p-4 border-[#f5c451]/30">
          <p className="text-[12px] text-ink-300">
            <span className="font-semibold text-[#f5c451]">Note:</span>{" "}
            {result.suppressed_rule_count} system rule{result.suppressed_rule_count !== 1 ? "s were" : " was"} skipped
            because the relevant configuration tables are not recoverable from an API-collected TSR. The score reflects
            only the rules that can be evaluated on this format.
          </p>
        </div>
      )}

      {/* Findings */}
      <div className="card-glow">
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                <th className="py-3 px-4">Rule</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Object</th>
              </tr>
            </thead>
            <tbody>
              {grouped.flatMap((g) =>
                g.items.map((f, i) => (
                  <tr key={`${f.rule_id}-${i}`} className="border-b border-base-500/40">
                    <td className="py-3 px-4">
                      <span className="font-mono text-[11px] text-ink-300">{f.rule_id}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="badge" style={{
                        color: sevColor[f.severity], borderColor: `${sevColor[f.severity]}55`,
                        background: `${sevColor[f.severity]}14`,
                      }}>{f.severity}</span>
                    </td>
                    <td className="py-3 px-4 text-ink-100">{f.title}</td>
                    <td className="py-3 px-4">
                      <span className="font-mono text-[11px] text-ink-500">{f.category}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="font-mono text-[11px] text-ink-400">{f.object_name || "—"}</span>
                    </td>
                  </tr>
                )))}
            </tbody>
          </table>
        </div>
        {result.findings.length === 0 && (
          <div className="py-12 text-center">
            <div className="text-4xl mb-3 opacity-30">✓</div>
            <p className="text-ink-500 text-sm font-mono">No findings fired for this TSR</p>
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="card-glow p-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</div>
      <div className="font-display text-2xl font-bold text-ink-100 mt-1">{value}</div>
      {sub && <div className="font-mono text-[10px] text-ink-500 mt-0.5 truncate">{sub}</div>}
    </div>
  );
}
