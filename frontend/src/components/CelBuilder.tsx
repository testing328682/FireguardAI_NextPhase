import React, { useEffect, useState, useMemo, useCallback, useRef } from "react";
import { api } from "../lib/api";
import type { BuilderSnapshotRef, RuleTestResult, User } from "../lib/types";
import { navigate } from "../lib/router";
import { SEVERITIES, RULE_CATEGORIES } from "../lib/ui";

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
  // Paths that traverse an array default to matching ANY element — indexes
  // shift between TSRs and scans — but the user may pin the clicked index.
  const [selAnyItem, setSelAnyItem] = useState(true);
  const selHasIndex = /\[\d+\]/.test(selPath);
  const effectiveSelPath =
    selHasIndex && selAnyItem ? selPath.replace(/\[\d+\]/g, "[*]") : selPath;

  // Test
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [testing, setTesting] = useState(false);

  // Upload
  const [uploading, setUploading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  // Save — same rule metadata as the Rules page creation form.
  const [ruleTitle, setRuleTitle] = useState("");
  const [ruleKey, setRuleKey] = useState("");
  const [ruleSeverity, setRuleSeverity] = useState("Medium");
  const [ruleCategory, setRuleCategory] = useState("Custom");
  const [ruleRemediation, setRuleRemediation] = useState("");
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

  // Build CEL expression. Clauses whose paths contain a collection wildcard
  // ([*]) and share the same collection are folded into ONE exists() so all
  // of their conditions are evaluated against the SAME element.
  const celExpression = useMemo(() => {
    if (clauses.length === 0) return "";
    const joiner = junction === "and" ? " && " : " || ";
    return buildCelParts(clauses.map((c) => ({ c, path: c.path })), junction, 0).join(joiner);
  }, [clauses, junction]);

  // Select a path from the explorer: prefill operator/value from the actual
  // TSR value so "equals current value" conditions are one click away.
  function handleSelectPath(path: string, value: unknown) {
    setSelPath(path);
    setSelAnyItem(true);
    if (typeof value === "boolean") {
      setSelOp(value ? "true" : "false");
      setSelVal("");
    } else if (value !== null && value !== undefined && typeof value !== "object" && value !== "") {
      setSelOp("==");
      setSelVal(String(value));
    } else {
      setSelVal("");
    }
  }

  // Add clause
  function addClause() {
    if (!selPath) return;
    const op = OPERATORS.find((o) => o.value === selOp)!;
    if (op.needsValue && !selVal.trim()) return;
    setClauses([...clauses, {
      id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36),
      path: effectiveSelPath, operator: selOp, value: selVal, negate: selNegate,
    }]);
    setSelPath(""); setSelVal(""); setSelNegate(false); setSelOp("=="); setSelAnyItem(true);
  }

  function removeClause(id: string) {
    setClauses(clauses.filter((c) => c.id !== id));
  }

  // Test
  async function runTest() {
    if ((!selectedId && !snapshot) || !celExpression) return;
    setTesting(true); setTestResult(null); setErr(null);
    try {
      // For uploaded TSRs the server falls back to the persisted builder
      // snapshot, so the (multi-megabyte) snapshot is never re-sent here.
      const aid = selectedId === "__uploaded__" ? "" : selectedId;
      setTestResult(await api.testBuilderCondition(aid, celExpression));
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
        title: ruleTitle, condition: celExpression, severity: ruleSeverity,
        source: "system", key: ruleKey, category: ruleCategory,
        remediation: ruleRemediation,
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
              <p className="font-mono text-[10px] text-ink-500 mb-3">
                Browse or search the complete parsed TSR — the <span className="text-accent">config</span> branch holds every section of the report. Click a field to build a condition.
              </p>
              <SnapshotExplorer snapshot={snapshot} selectedPath={selPath} onSelect={handleSelectPath} />
            </div>

            {/* Clause builder */}
            {selPath && (
              <div className="card-glow p-5">
                <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Add Condition</h3>
                <div className="space-y-3">
                  <div>
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Path</span>
                    <pre className="mt-1 bg-base-900 border border-base-500 rounded-lg px-3 py-2 font-mono text-[12px] text-accent">{effectiveSelPath}</pre>
                  </div>
                  {selHasIndex && (
                    <div>
                      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Collection match</span>
                      <div className="mt-1 flex items-center gap-2">
                        <button onClick={() => setSelAnyItem(true)}
                                className={`px-3 py-1 rounded-lg text-[12px] font-mono transition-all ${selAnyItem ? "bg-accent/20 text-accent border border-accent/40" : "text-ink-500 border border-base-500"}`}>
                          Any item (recommended)
                        </button>
                        <button onClick={() => setSelAnyItem(false)}
                                className={`px-3 py-1 rounded-lg text-[12px] font-mono transition-all ${!selAnyItem ? "bg-accent/20 text-accent border border-accent/40" : "text-ink-500 border border-base-500"}`}>
                          This index only
                        </button>
                      </div>
                      <p className="mt-1.5 font-mono text-[10px] text-ink-500">
                        Any item matches regardless of position — collection order can change
                        between TSRs. Conditions added on the same collection must match a
                        single item.
                      </p>
                    </div>
                  )}
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
              {clauses.some((c) => c.path.includes("[*]")) && (
                <p className="font-mono text-[10px] text-ink-500">
                  Clauses with [*] on the same collection are combined into a single
                  exists() — they must all match the same item.
                </p>
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
                <div className="flex gap-3">
                  <label className="block flex-1">
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Severity</span>
                    <select value={ruleSeverity} onChange={(e) => setRuleSeverity(e.target.value)}
                            className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                      {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
                    </select>
                  </label>
                  <label className="block flex-1">
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Category</span>
                    <select value={ruleCategory} onChange={(e) => setRuleCategory(e.target.value)}
                            className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                      {RULE_CATEGORIES.map((c) => <option key={c}>{c}</option>)}
                    </select>
                  </label>
                </div>
                <label className="block">
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Remediation</span>
                  <input value={ruleRemediation} onChange={(e) => setRuleRemediation(e.target.value)}
                         placeholder="e.g. Enable IPS on all security zones"
                         className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent placeholder:text-ink-500/50" />
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

// ── Snapshot explorer ──────────────────────────────────────────────────
// Lazily rendered tree over the full parsed snapshot (including the complete
// `config` sweep of the TSR). Children mount only when a node is expanded,
// so multi-megabyte snapshots stay responsive. Paths are emitted in the CEL
// convention used by the rule engine: dot access for identifier-like keys,
// index syntax (`config["System : Time"]`) for everything else.

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CHUNK = 150;           // children rendered per "Show more" page
const SEARCH_LIMIT = 200;    // max search hits collected

function joinPath(prefix: string, key: string): string {
  return IDENT_RE.test(key) ? `${prefix}.${key}` : `${prefix}[${JSON.stringify(key)}]`;
}
function isLeaf(v: unknown): boolean {
  return v === null || typeof v !== "object";
}
function leafText(v: unknown): string {
  if (v === null || v === undefined) return "null";
  return typeof v === "string" ? `"${v}"` : String(v);
}
function containerSummary(v: object): string {
  return Array.isArray(v) ? `[${v.length}]` : `{${Object.keys(v).length}}`;
}

interface SearchHit {
  path: string;        // full CEL path
  ancestors: string[]; // container paths to expand for reveal
  label: string;       // the matched key / index
  preview: string;     // value preview (leaves) or child summary
  leaf: boolean;
  value: unknown;
}

function searchSnapshot(root: unknown, query: string): SearchHit[] {
  const q = query.toLowerCase();
  const hits: SearchHit[] = [];
  const walk = (node: unknown, path: string, label: string, ancestors: string[]) => {
    if (hits.length >= SEARCH_LIMIT) return;
    if (isLeaf(node)) {
      const preview = leafText(node);
      if (label.toLowerCase().includes(q) || preview.toLowerCase().includes(q)) {
        hits.push({ path, ancestors, label, preview, leaf: true, value: node });
      }
      return;
    }
    if (label.toLowerCase().includes(q)) {
      hits.push({ path, ancestors, label, preview: containerSummary(node as object), leaf: false, value: node });
    }
    const childAncestors = [...ancestors, path];
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        if (hits.length >= SEARCH_LIMIT) return;
        walk(node[i], `${path}[${i}]`, `[${i}]`, childAncestors);
      }
    } else {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (hits.length >= SEARCH_LIMIT) return;
        walk(v, joinPath(path, k), k, childAncestors);
      }
    }
  };
  if (root && typeof root === "object" && !Array.isArray(root)) {
    for (const [k, v] of Object.entries(root as Record<string, unknown>)) {
      walk(v, joinPath("snapshot", k), k, []);
    }
  }
  return hits;
}

function SnapshotExplorer({ snapshot, selectedPath, onSelect }: {
  snapshot: Record<string, unknown>;
  selectedPath: string;
  onSelect: (path: string, value: unknown) => void;
}) {
  // Explicit expand/collapse decisions; anything not present falls back to
  // the default (small nested containers open, everything else closed).
  const [expandState, setExpandState] = useState<Map<string, boolean>>(new Map());
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => { setExpandState(new Map()); setQuery(""); setDebounced(""); }, [snapshot]);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]);

  const hits = useMemo(
    () => (debounced.length >= 2 ? searchSnapshot(snapshot, debounced) : []),
    [snapshot, debounced],
  );

  const toggle = useCallback((path: string, next: boolean) => {
    setExpandState((prev) => { const m = new Map(prev); m.set(path, next); return m; });
  }, []);

  const reveal = (hit: SearchHit) => {
    setExpandState((prev) => {
      const m = new Map(prev);
      hit.ancestors.forEach((a) => m.set(a, true));
      if (!hit.leaf) m.set(hit.path, true);
      return m;
    });
    onSelect(hit.path, hit.value);
    // Best-effort scroll to the revealed row once it has rendered.
    requestAnimationFrame(() => {
      const esc = hit.path.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      containerRef.current?.querySelector(`[data-path="${esc}"]`)
        ?.scrollIntoView({ block: "center" });
    });
  };

  return (
    <div>
      <input value={query} onChange={(e) => setQuery(e.target.value)}
             placeholder="Search keys and values (e.g. SDWAN, 192.168., disabled)…"
             className="mb-2 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[12px] text-ink-100 font-mono focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30" />
      {debounced.length >= 2 && (
        <div className="mb-2 max-h-[220px] overflow-y-auto rounded-lg border border-base-500 bg-base-900/60">
          <div className="px-2 py-1 font-mono text-[10px] text-ink-500 border-b border-base-500 sticky top-0 bg-base-900">
            {hits.length === 0 ? "No matches" :
              `${hits.length}${hits.length >= SEARCH_LIMIT ? "+" : ""} match${hits.length === 1 ? "" : "es"} — click to select`}
          </div>
          {hits.map((h) => (
            <button key={h.path} onClick={() => reveal(h)}
                    className="block w-full text-left px-2 py-1 font-mono text-[11px] text-ink-300 hover:bg-accent/10 transition-colors">
              <span className="text-ink-100">{h.label}</span>
              <span className="text-ink-500 mx-1">{h.leaf ? "=" : ""}</span>
              <span className="text-ink-500">{h.preview.slice(0, 48)}</span>
              <span className="block text-[10px] text-ink-500 truncate">{h.path}</span>
            </button>
          ))}
        </div>
      )}
      <div ref={containerRef} className="max-h-[500px] overflow-y-auto space-y-0.5">
        {Object.entries(snapshot).map(([k, v]) => (
          <TreeNode key={k} label={k} data={v} path={joinPath("snapshot", k)} depth={0}
                    expandState={expandState} toggle={toggle}
                    onSelect={onSelect} selectedPath={selectedPath} />
        ))}
      </div>
    </div>
  );
}

function TreeNode({ label, data, path, depth, expandState, toggle, onSelect, selectedPath }: {
  label: string; data: unknown; path: string; depth: number;
  expandState: Map<string, boolean>;
  toggle: (path: string, next: boolean) => void;
  onSelect: (path: string, value: unknown) => void;
  selectedPath: string;
}) {
  const [limit, setLimit] = useState(CHUNK);
  const isSelected = selectedPath === path;

  if (isLeaf(data)) {
    return (
      <button data-path={path} onClick={() => onSelect(path, data)}
              className={`block w-full text-left font-mono text-[11px] px-2 py-1 rounded hover:bg-accent/10 transition-colors ${
                isSelected ? "bg-accent/20 text-accent" : "text-ink-300"
              }`} style={{ paddingLeft: depth * 12 + 8 }}>
        <span className="text-ink-500">{label}</span>
        <span className="text-ink-500 mx-1">=</span>
        <span className="text-ink-100">{leafText(data).slice(0, 60)}</span>
      </button>
    );
  }

  const entries: [string, unknown][] = Array.isArray(data)
    ? data.map((v, i) => [`[${i}]`, v] as [string, unknown])
    : Object.entries(data as Record<string, unknown>);
  const expanded = expandState.get(path) ?? (depth >= 1 && entries.length > 0 && entries.length <= 10);
  const isTop = depth === 0;

  return (
    <div>
      <div data-path={path}
           className={`flex items-center gap-1 rounded transition-colors group ${isSelected ? "bg-accent/20" : "hover:bg-accent/5"}`}
           style={{ paddingLeft: depth * 12 + 2 }}>
        <button onClick={() => toggle(path, !expanded)}
                className="flex-1 min-w-0 text-left font-mono text-[11px] py-1 cursor-pointer">
          <span className="text-ink-500 inline-block w-3">{expanded ? "▾" : "▸"}</span>
          <span className={isTop ? "text-accent font-semibold uppercase text-[10px] tracking-wider" : "text-ink-300"}>
            {label}
          </span>
          <span className="text-ink-500 ml-1">{containerSummary(data as object)}</span>
        </button>
        <button onClick={() => onSelect(path, data)}
                title="Use this path in a condition (e.g. exists / size checks)"
                className={`shrink-0 px-1.5 font-mono text-[10px] rounded transition-opacity ${
                  isSelected ? "text-accent opacity-100" : "text-ink-500 opacity-0 group-hover:opacity-100 hover:text-accent"
                }`}>
          ⊕
        </button>
      </div>
      {expanded && (
        <div>
          {entries.slice(0, limit).map(([k, v]) => (
            <TreeNode key={k} label={k} data={v}
                      path={Array.isArray(data) ? `${path}${k}` : joinPath(path, k)}
                      depth={depth + 1} expandState={expandState} toggle={toggle}
                      onSelect={onSelect} selectedPath={selectedPath} />
          ))}
          {entries.length > limit && (
            <button onClick={() => setLimit(limit + CHUNK)}
                    className="block font-mono text-[10px] text-accent hover:underline px-2 py-1"
                    style={{ paddingLeft: (depth + 1) * 12 + 8 }}>
              Show {Math.min(CHUNK, entries.length - limit)} more ({entries.length - limit} remaining)
            </button>
          )}
          {entries.length === 0 && (
            <span className="block font-mono text-[10px] text-ink-500 px-2 py-0.5"
                  style={{ paddingLeft: (depth + 1) * 12 + 8 }}>empty</span>
          )}
        </div>
      )}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────
function looksNumeric(s: string): boolean {
  return /^-?\d+(\.\d+)?$/.test(s.trim());
}

// ── CEL generation with collection wildcards ──────────────────────────
// A clause path may contain "[*]" where an array index would be. Clauses
// sharing the same collection prefix fold into a single
// `collection.exists(x, cond1 && cond2 ...)`, so every condition binds to
// the SAME element (never one exists() per condition, which could match
// different elements). Nested wildcards produce nested exists().
const EXISTS_VARS = ["x", "y", "z"];
const varFor = (depth: number) => EXISTS_VARS[depth] ?? `v${depth}`;

function clauseExpr(c: ConditionClause, path: string): string {
  const quote = (v: string) =>
    looksNumeric(v) || v === "true" || v === "false" ? v : `"${v}"`;
  let expr: string;
  const op = c.operator;
  if (op === "exists") expr = `size(${path}) > 0`;
  else if (op === "!exists") expr = `size(${path}) == 0`;
  else if (op === "true") expr = `${path} == true`;
  else if (op === "false") expr = `${path} == false`;
  else if (op === "contains") expr = `${path}.contains(${quote(c.value)})`;
  else expr = `${path} ${op} ${quote(c.value)}`;
  return c.negate ? `!(${expr})` : expr;
}

function buildCelParts(items: { c: ConditionClause; path: string }[],
                       junction: Junction, depth: number): string[] {
  const joiner = junction === "and" ? " && " : " || ";
  const parts: string[] = [];
  const groups = new Map<string, { c: ConditionClause; path: string }[]>();
  for (const it of items) {
    const star = it.path.indexOf("[*]");
    if (star === -1) {
      parts.push(clauseExpr(it.c, it.path));
      continue;
    }
    const prefix = it.path.slice(0, star);
    const rest = it.path.slice(star + 3);
    const group = groups.get(prefix);
    if (group) group.push({ c: it.c, path: rest });
    else groups.set(prefix, [{ c: it.c, path: rest }]);
  }
  for (const [prefix, subs] of groups) {
    const v = varFor(depth);
    const inner = buildCelParts(
      subs.map((s) => ({ c: s.c, path: v + s.path })), junction, depth + 1);
    parts.push(`${prefix}.exists(${v}, ${inner.join(joiner)})`);
  }
  return parts;
}
