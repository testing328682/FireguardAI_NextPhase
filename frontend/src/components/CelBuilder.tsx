import React, { useEffect, useState, useMemo, useCallback, useRef } from "react";
import { api } from "../lib/api";
import type { BuilderSnapshotRef, RuleTestResult, User } from "../lib/types";
import { navigate } from "../lib/router";

// ── Types ──────────────────────────────────────────────────────────────
interface ConditionClause {
  id: string;
  path: string;       // e.g. "snapshot.security_services.ips_enabled"
  operator: string;   // ==, !=, contains, >, <, >=, <=, exists, !exists
  value: string;      // comparison value
  negate: boolean;    // NOT
}

type Junction = "and" | "or";

// ── Operators ──────────────────────────────────────────────────────────
const OPERATORS: { value: string; label: string; needsValue: boolean }[] = [
  { value: "==", label: "equals (==)", needsValue: true },
  { value: "!=", label: "not equals (!=)", needsValue: true },
  { value: "contains", label: "contains", needsValue: true },
  { value: ">", label: "greater than (>)", needsValue: true },
  { value: "<", label: "less than (<)", needsValue: true },
  { value: ">=", label: "greater or equal (>=)", needsValue: true },
  { value: "<=", label: "less or equal (<=)", needsValue: true },
  { value: "exists", label: "exists (non-empty)", needsValue: false },
  { value: "!exists", label: "does not exist (empty)", needsValue: false },
  { value: "true", label: "is true", needsValue: false },
  { value: "false", label: "is false", needsValue: false },
];

// ── CEL Builder ────────────────────────────────────────────────────────
export function CelBuilder({ user }: { user: User }) {
  // TSR selection — restore persisted snapshot from server on mount.
  const [snapshots, setSnapshots] = useState<BuilderSnapshotRef[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [snapshot, setSnapshot] = useState<Record<string, unknown> | null>(null);
  const [uploadedFilename, setUploadedFilename] = useState<string>("");
  const [loadingTsr, setLoadingTsr] = useState(false);
  const [restoringSaved, setRestoringSaved] = useState(true);

  // On mount, try to restore the user's saved snapshot from the server.
  useEffect(() => {
    api.getSavedBuilderSnapshot()
      .then((result) => {
        setSnapshot(result.snapshot as Record<string, unknown>);
        setUploadedFilename(result.filename);
        setSelectedId("__uploaded__");
      })
      .catch(() => { /* no saved snapshot — that's fine */ })
      .finally(() => setRestoringSaved(false));
  }, []);

  // Condition building
  const [clauses, setClauses] = useState<ConditionClause[]>([]);
  const [junction, setJunction] = useState<Junction>("and");

  // New clause form
  const [selPath, setSelPath] = useState("");
  const [selOp, setSelOp] = useState("==");
  const [selVal, setSelVal] = useState("");
  const [selNegate, setSelNegate] = useState(false);

  // Test
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [testing, setTesting] = useState(false);

  // Upload
  const [uploading, setUploading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  // Save
  const [ruleTitle, setRuleTitle] = useState("");
  const [ruleKey, setRuleKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Load snapshots
  const loadSnapshots = useCallback(() => {
    api.listBuilderSnapshots().then(setSnapshots).catch(() => {});
  }, []);
  useEffect(() => { loadSnapshots(); }, [loadSnapshots]);

  // Load selected snapshot
  const loadSnapshot = useCallback(async (id: string) => {
    setSelectedId(id);
    setSnapshot(null);
    if (!id) return;
    setLoadingTsr(true);
    try {
      setSnapshot(await api.getBuilderSnapshot(id));
    } catch { setErr("Failed to load TSR snapshot"); }
    finally { setLoadingTsr(false); }
  }, []);

  // Upload TSR for reference
  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true); setErr(null); setSnapshot(null); setClauses([]);
    try {
      const result = await api.uploadBuilderTsr(file);
      const snap = result.snapshot as Record<string, unknown>;
      setSnapshot(snap);
      setSelectedId("__uploaded__");
      setUploadedFilename(result.filename);
      // Persisted server-side by the upload endpoint — no localStorage needed.
      loadSnapshots();
    } catch (ex) {
      const msg = ex instanceof Error ? ex.message : "Upload failed";
      if (ex instanceof DOMException && ex.name === "AbortError") {
        setErr("Upload timed out — the TSR file may be too large. Try a smaller file.");
      } else if (msg.includes("Failed to fetch") || msg.includes("NetworkError")) {
        setErr("Cannot reach the server. Check that the API is running and try again.");
      } else {
        setErr(msg);
      }
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  // Build CEL expression
  const celExpression = useMemo(() => {
    if (clauses.length === 0) return "";
    const quote = (v: string) =>
      looksNumeric(v) || v === "true" || v === "false" ? v : `"${v}"`;

    const parts = clauses.map((c) => {
      let expr = "";
      const op = c.operator;

      if (op === "exists") {
        expr = `size(${c.path}) > 0`;
      } else if (op === "!exists") {
        expr = `size(${c.path}) == 0`;
      } else if (op === "true") {
        expr = `${c.path} == true`;
      } else if (op === "false") {
        expr = `${c.path} == false`;
      } else if (op === "contains") {
        expr = `${c.path}.contains(${quote(c.value)})`;
      } else {
        expr = `${c.path} ${op} ${quote(c.value)}`;
      }

      if (c.negate) expr = `!(${expr})`;
      return expr;
    });
    const junctionOp = junction === "and" ? "&&" : "||";
    return parts.join(` ${junctionOp} `);
  }, [clauses, junction]);

  // Add clause
  function addClause() {
    if (!selPath) return;
    const op = OPERATORS.find((o) => o.value === selOp)!;
    if (op.needsValue && !selVal.trim()) return;
    setClauses([...clauses, {
      id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36),
      path: selPath, operator: selOp, value: selVal, negate: selNegate,
    }]);
    setSelPath(""); setSelVal(""); setSelNegate(false); setSelOp("==");
  }

  function removeClause(id: string) {
    setClauses(clauses.filter((c) => c.id !== id));
  }

  // Test
  async function runTest() {
    if ((!selectedId && !snapshot) || !celExpression) return;
    setTesting(true); setTestResult(null); setErr(null);
    try {
      // For uploaded TSRs, pass the snapshot directly; for stored analyses, pass the analysis_id.
      const snap = selectedId === "__uploaded__" ? snapshot : undefined;
      const aid = selectedId === "__uploaded__" ? "" : selectedId;
      setTestResult(await api.testBuilderCondition(aid, celExpression, snap ?? undefined));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Test failed");
    } finally { setTesting(false); }
  }

  // Save
  async function saveRule() {
    if (!ruleTitle.trim() || !ruleKey.trim() || !celExpression) return;
    setSaving(true); setErr(null);
    try {
      const r = await api.createRule({
        title: ruleTitle, condition: celExpression, severity: "Medium",
        source: "system", key: ruleKey, category: "Custom",
      } as Record<string, unknown> as Parameters<typeof api.createRule>[0]);
      navigate(`/rules/${r.id}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    } finally { setSaving(false); }
  }

  return (
    <div className="max-w-[1440px] fade-in space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">CEL Rule Builder</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">Build CEL conditions visually from parsed TSR data</p>
        </div>
      </div>

      {/* TSR Selector */}
      <div className="card-glow p-5">
        <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Reference TSR</h3>
        {err && <p className="font-mono text-[12px] text-sev-high mb-3">{err}</p>}
        <div className="flex flex-wrap items-end gap-3">
          <label className="block flex-1 min-w-[280px]">
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">
              {snapshots.length > 0 ? "Select a completed analysis" : "No analyses yet — upload a TSR below"}
            </span>
            <select value={selectedId} onChange={(e) => loadSnapshot(e.target.value)}
                    className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-all">
              <option value="">— Choose a TSR snapshot —</option>
              {snapshots.map((s) => (
                <option key={s.analysis_id} value={s.analysis_id}>
                  {s.device_model || s.device_serial} · {s.device_firmware} · {s.generated_at?.slice(0, 10) || "unknown date"}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-end gap-2">
            <input ref={fileRef} type="file" accept=".wri,.txt,.tsr" onChange={handleUpload}
                   className="hidden" id="builder-tsr-upload" />
            <label htmlFor="builder-tsr-upload"
                   className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all cursor-pointer shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
              {uploading ? "Uploading…" : "📂 Upload TSR"}
            </label>
          </div>
        </div>
        {uploading && <div className="mt-3 flex items-center gap-2 text-ink-500 text-[12px] font-mono"><span className="skeleton h-3 w-3 rounded-full inline-block" /> Parsing TSR…</div>}
        {loadingTsr && <div className="mt-3 skeleton h-6 w-48 rounded" />}
        {snapshot && selectedId === "__uploaded__" && (
          <div className="mt-3 rounded-lg border border-signal/30 bg-signal/5 px-3 py-2 text-[12px] text-signal font-mono">
            ✓ {uploadedFilename || "TSR"} loaded — browse the tree below to build conditions. Upload a new TSR to replace it.
          </div>
        )}
      </div>

      {snapshot && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Left: Tree browser + clause builder */}
          <div className="space-y-5">
            {/* Tree */}
            <div className="card-glow p-5">
              <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">TSR Configuration</h3>
              <p className="font-mono text-[10px] text-ink-500 mb-3">Click a field to build a condition</p>
              <div className="max-h-[500px] overflow-y-auto space-y-0.5">
                <SnapshotTree data={snapshot} onSelect={(path) => { setSelPath(path); setSelVal(""); }} selectedPath={selPath} />
              </div>
            </div>

            {/* Clause builder */}
            {selPath && (
              <div className="card-glow p-5">
                <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Add Condition</h3>
                <div className="space-y-3">
                  <div>
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Path</span>
                    <pre className="mt-1 bg-base-900 border border-base-500 rounded-lg px-3 py-2 font-mono text-[12px] text-accent">{selPath}</pre>
                  </div>
                  <div className="flex gap-3 flex-wrap">
                    <label className="block">
                      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Operator</span>
                      <select value={selOp} onChange={(e) => setSelOp(e.target.value)}
                              className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                        {OPERATORS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                      </select>
                    </label>
                    {OPERATORS.find((o) => o.value === selOp)?.needsValue && (
                      <label className="block flex-1 min-w-[150px]">
                        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Value</span>
                        <input value={selVal} onChange={(e) => setSelVal(e.target.value)}
                               placeholder='e.g. "disabled" or 0'
                               className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 font-mono focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30" />
                      </label>
                    )}
                  </div>
                  <label className="flex items-center gap-2 text-[13px] text-ink-300 cursor-pointer">
                    <input type="checkbox" checked={selNegate} onChange={(e) => setSelNegate(e.target.checked)}
                           className="rounded accent-accent" />
                    NOT (negate this condition)
                  </label>
                  <button onClick={addClause}
                          className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all">
                    + Add to rule
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right: CEL preview + test + save */}
          <div className="space-y-5">
            {/* Junction selector + clause list */}
            <div className="card-glow p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-display font-semibold text-sm text-ink-100">Conditions</h3>
                {clauses.length > 1 && (
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-ink-500">Join with:</span>
                    <button onClick={() => setJunction("and")}
                            className={`px-3 py-1 rounded-lg text-[12px] font-mono transition-all ${junction === "and" ? "bg-accent/20 text-accent border border-accent/40" : "text-ink-500 border border-base-500"}`}>AND</button>
                    <button onClick={() => setJunction("or")}
                            className={`px-3 py-1 rounded-lg text-[12px] font-mono transition-all ${junction === "or" ? "bg-accent/20 text-accent border border-accent/40" : "text-ink-500 border border-base-500"}`}>OR</button>
                  </div>
                )}
              </div>
              {clauses.length === 0 ? (
                <p className="text-ink-500 text-sm font-mono py-4 text-center">Select a field from the TSR tree to add a condition.</p>
              ) : (
                <ul className="space-y-2 mb-3">
                  {clauses.map((c, i) => (
                    <li key={c.id} className="flex items-start justify-between gap-2 bg-base-800/80 border border-base-500 rounded-lg px-3 py-2 group">
                      <div className="min-w-0 text-[12px]">
                        {i > 0 && <span className="font-mono text-[10px] text-accent uppercase mr-1">{junction} </span>}
                        {c.negate && <span className="font-mono text-[10px] text-sev-high mr-1">NOT </span>}
                        <span className="font-mono text-ink-300">{c.path}</span>
                        <span className="text-ink-500 mx-1">{c.operator}</span>
                        {c.value && <span className="font-mono text-ink-100">"{c.value}"</span>}
                      </div>
                      <button onClick={() => removeClause(c.id)}
                              className="text-ink-500 hover:text-sev-high shrink-0 opacity-0 group-hover:opacity-100 transition-opacity text-sm">✕</button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* CEL Preview */}
            <div className="card-glow p-5">
              <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Generated CEL</h3>
              {celExpression ? (
                <pre className="bg-base-900 border border-base-500 rounded-lg p-3 font-mono text-[12px] text-ink-100 whitespace-pre-wrap break-all">{celExpression}</pre>
              ) : (
                <p className="text-ink-500 text-sm font-mono py-2">Add conditions to generate a CEL expression.</p>
              )}
            </div>

            {/* Test */}
            <div className="card-glow p-5">
              <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Test Against TSR</h3>
              <button onClick={runTest} disabled={!celExpression || testing || !selectedId}
                      className="px-4 py-2 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[13px] font-semibold hover:bg-accent/20 disabled:opacity-40 transition-all">
                {testing ? "Testing…" : "▶ Run test"}
              </button>
              {testResult && (
                <div className="mt-3 rounded-lg p-3 border" style={{
                  borderColor: testResult.fired ? "#ff8a3d55" : "#39d98a55",
                  background: testResult.fired ? "#ff8a3d10" : "#39d98a10",
                }}>
                  {testResult.error ? (
                    <p className="font-mono text-[12px] text-sev-high">{testResult.error}</p>
                  ) : (
                    <p className="font-mono text-[13px] font-semibold" style={{ color: testResult.fired ? "#ff8a3d" : "#39d98a" }}>
                      {testResult.fired ? "● Rule FIRES — condition matches the TSR" : "○ Rule does NOT fire — condition does not match"}
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Save */}
            <div className="card-glow p-5">
              <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Save as System Rule</h3>
              <div className="space-y-3">
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Rule Key (e.g. FW-CUSTOM-001)</span>
                  <input value={ruleKey} onChange={(e) => setRuleKey(e.target.value)}
                         className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 font-mono focus:outline-none focus:border-accent" />
                </label>
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Rule Title</span>
                  <input value={ruleTitle} onChange={(e) => setRuleTitle(e.target.value)}
                         className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
                </label>
                {err && <p className="font-mono text-[12px] text-sev-high">{err}</p>}
                <button onClick={saveRule} disabled={!celExpression || !ruleTitle.trim() || !ruleKey.trim() || saving}
                        className="w-full px-4 py-2.5 rounded-lg bg-signal text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
                  {saving ? "Saving…" : "Save System Rule"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Snapshot tree browser ──────────────────────────────────────────────
function SnapshotTree({ data, onSelect, selectedPath, prefix = "snapshot" }: {
  data: unknown; onSelect: (path: string) => void; selectedPath: string; prefix?: string;
}) {
  if (data === null || data === undefined) {
    return <span className="font-mono text-[11px] text-ink-500 pl-2">null</span>;
  }

  if (typeof data !== "object") {
    const val = typeof data === "string" ? `"${data}"` : String(data);
    return (
      <button onClick={() => onSelect(prefix)}
              className={`block w-full text-left font-mono text-[11px] px-2 py-1 rounded hover:bg-accent/10 transition-colors ${
                selectedPath === prefix ? "bg-accent/20 text-accent" : "text-ink-300"
              }`}>
        <span className="text-ink-500">{prefix.split(".").pop()}</span>
        <span className="text-ink-500 mx-1">=</span>
        <span className="text-ink-100">{val.slice(0, 60)}</span>
      </button>
    );
  }

  if (Array.isArray(data)) {
    const hasItems = data.length > 0;
    return (
      <details className="pl-2" open={hasItems && data.length <= 10}>
        <summary className="cursor-pointer font-mono text-[11px] text-ink-300 hover:text-ink-100 py-0.5">
          <span className="text-ink-500">{prefix.split(".").pop()}</span>
          <span className="text-ink-500 ml-1">[{data.length}]</span>
        </summary>
        {hasItems && data.slice(0, 20).map((item, i) => (
          typeof item === "object" && item !== null && !Array.isArray(item)
            ? <SnapshotTree key={i} data={item} onSelect={onSelect} selectedPath={selectedPath} prefix={`${prefix}[${i}]`} />
            : <SnapshotTree key={i} data={item} onSelect={onSelect} selectedPath={selectedPath} prefix={`${prefix}[${i}]`} />
        ))}
        {data.length > 20 && <span className="font-mono text-[10px] text-ink-500 pl-4">…{data.length - 20} more items</span>}
        {!hasItems && <span className="font-mono text-[10px] text-ink-500 pl-4">empty</span>}
      </details>
    );
  }

  // Object
  const entries = Object.entries(data as Record<string, unknown>);
  const isTopSection = prefix === "snapshot";
  return (
    <details className="pl-2" open={isTopSection || entries.length <= 8}>
      <summary className="cursor-pointer font-mono text-[11px] text-ink-300 hover:text-ink-100 py-0.5">
        <span className={isTopSection ? "text-accent font-semibold uppercase text-[10px] tracking-wider" : "text-ink-500"}>
          {prefix.split(".").pop()?.replace(/[[\]']/g, "")}
        </span>
        <span className="text-ink-500 ml-1">{"{}"}</span>
      </summary>
      {entries.map(([k, v]) => {
        const childPath = `${prefix}.${k}`;
        if (typeof v === "object" && v !== null) {
          return <SnapshotTree key={k} data={v} onSelect={onSelect} selectedPath={selectedPath} prefix={childPath} />;
        }
        const val = typeof v === "string" ? `"${v}"` : String(v);
        const isSelected = selectedPath === childPath;
        return (
          <button key={k} onClick={() => onSelect(childPath)}
                  className={`block w-full text-left font-mono text-[11px] px-2 py-1 rounded hover:bg-accent/10 transition-colors ${
                    isSelected ? "bg-accent/20 text-accent" : "text-ink-300"
                  }`}>
            <span className="text-ink-500">{k}</span>
            <span className="text-ink-500 mx-1">=</span>
            <span className="text-ink-100">{val.slice(0, 60)}</span>
          </button>
        );
      })}
    </details>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────
function looksNumeric(s: string): boolean {
  return /^-?\d+(\.\d+)?$/.test(s.trim());
}
