import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { ApiFlowConfig as Cfg, ApiFlowStep, ApiFlowTestResult } from "../lib/types";

const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"];
const AUTH_TYPES = ["basic", "bearer", "none"];
const STEP_AUTH = ["inherit", "basic", "bearer", "none"];

const inputCls =
  "block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent";

function DEFAULT_STEP(): ApiFlowStep {
  return { name: "New step", method: "GET", path: "/", auth: "inherit",
           headers: { Accept: "application/json" }, query: {}, body: "",
           success: { status_codes: [200] }, extract: {}, is_tsr: false, continue_on_error: false };
}

// ── JSON field: edits an object via a textarea, parses on change ──────────
function JsonField({ label, value, onChange, rows = 3 }:
  { label: string; value: unknown; onChange: (v: unknown) => void; rows?: number }) {
  const [text, setText] = useState(() => JSON.stringify(value ?? {}, null, 2));
  const [err, setErr] = useState<string | null>(null);
  return (
    <label className="block">
      <span className="font-mono text-[10px] uppercase tracking-wide text-ink-500">{label}</span>
      <textarea rows={rows} value={text}
                onChange={(e) => {
                  setText(e.target.value);
                  try { onChange(JSON.parse(e.target.value || "null")); setErr(null); }
                  catch { setErr("invalid JSON"); }
                }}
                className={`${inputCls} font-mono text-[11px] mt-1 ${err ? "border-sev-high" : ""}`} />
      {err && <span className="text-sev-high text-[10px] font-mono">{err}</span>}
    </label>
  );
}

// ── API TSR Parser Config (superadmin) ───────────────────────────────────
export function ApiFlowConfigPage() {
  const [configs, setConfigs] = useState<Cfg[]>([]);
  const [draft, setDraft] = useState<Cfg | null>(null);
  const [dirty, setDirty] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async (selectId?: string) => {
    setErr(null);
    try {
      const list = await api.listApiConfigs();
      setConfigs(list);
      const pick = list.find((c) => c.id === selectId) || list.find((c) => c.is_active) || list[0];
      if (pick) { setDraft(structuredClone(pick)); setDirty(false); }
    } catch (e) { setErr(e instanceof Error ? e.message : "Failed to load"); }
  }, []);

  useEffect(() => { load(); }, [load]);

  function patch(p: Partial<Cfg>) { setDraft((d) => (d ? { ...d, ...p } : d)); setDirty(true); }
  function patchStep(i: number, p: Partial<ApiFlowStep>) {
    setDraft((d) => {
      if (!d) return d;
      const steps = d.steps.map((s, idx) => (idx === i ? { ...s, ...p } : s));
      return { ...d, steps };
    });
    setDirty(true);
  }
  function moveStep(i: number, dir: -1 | 1) {
    setDraft((d) => {
      if (!d) return d;
      const j = i + dir;
      if (j < 0 || j >= d.steps.length) return d;
      const steps = [...d.steps];
      [steps[i], steps[j]] = [steps[j], steps[i]];
      return { ...d, steps };
    });
    setDirty(true);
  }
  function addStep() { setDraft((d) => (d ? { ...d, steps: [...d.steps, DEFAULT_STEP()] } : d)); setDirty(true); }
  function delStep(i: number) {
    setDraft((d) => (d ? { ...d, steps: d.steps.filter((_, idx) => idx !== i) } : d));
    setDirty(true);
  }

  async function save() {
    if (!draft) return;
    setErr(null); setMsg(null);
    try {
      await api.updateApiConfig(draft.id, draft);
      setMsg("Saved."); setDirty(false); await load(draft.id);
    } catch (e) { setErr(e instanceof Error ? e.message : "Save failed"); }
  }
  async function createNew() {
    setErr(null); setMsg(null);
    try {
      const c = await api.createApiConfig({
        name: `Config ${configs.length + 1}`, version_label: "", description: "",
        auth_type: "basic", verify_tls: false, timeout_seconds: 30, api_base: "/api/sonicos",
        steps: [DEFAULT_STEP()],
      });
      await load(c.id);
    } catch (e) { setErr(e instanceof Error ? e.message : "Create failed"); }
  }
  async function activate(id: string) {
    try { await api.activateApiConfig(id); await load(id); setMsg("Activated."); }
    catch (e) { setErr(e instanceof Error ? e.message : "Activate failed"); }
  }
  async function remove(id: string) {
    try { await api.deleteApiConfig(id); await load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Delete failed"); }
  }

  return (
    <div className="space-y-5 max-w-[1400px] fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">API TSR Parser Config</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">
            Configure the SonicOS API workflow that customers use when connecting via API. The active
            configuration is used automatically. No code changes required.
          </p>
        </div>
        <button onClick={createNew}
                className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110">
          + New version
        </button>
      </div>

      {err && <div className="card-glow p-3 border-sev-high/30"><p className="text-sev-high text-[12px] font-mono">{err}</p></div>}
      {msg && <p className="text-signal text-[12px] font-mono">{msg}</p>}

      <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-5">
        {/* Versions */}
        <div className="space-y-2">
          <div className="font-mono text-[10px] uppercase tracking-wide text-ink-500">Versions</div>
          {configs.map((c) => (
            <div key={c.id}
                 onClick={() => { setDraft(structuredClone(c)); setDirty(false); }}
                 className={`card-glow p-3 cursor-pointer ${draft?.id === c.id ? "border-accent" : ""}`}>
              <div className="flex items-center justify-between">
                <span className="text-ink-100 text-[13px] font-semibold">{c.name}</span>
                {c.is_active
                  ? <span className="badge" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>Active</span>
                  : <button onClick={(e) => { e.stopPropagation(); activate(c.id); }}
                            className="text-[10px] font-mono text-accent hover:underline">Activate</button>}
              </div>
              <div className="font-mono text-[10px] text-ink-500 mt-1">
                {c.version_label || "—"} · {c.steps.length} steps
              </div>
            </div>
          ))}
        </div>

        {/* Editor */}
        {draft && (
          <div className="space-y-4">
            <div className="card-glow p-4 space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <label className="block"><span className="font-mono text-[10px] text-ink-500">Name</span>
                  <input value={draft.name} onChange={(e) => patch({ name: e.target.value })} className={`${inputCls} mt-1`} /></label>
                <label className="block"><span className="font-mono text-[10px] text-ink-500">Version label</span>
                  <input value={draft.version_label} onChange={(e) => patch({ version_label: e.target.value })}
                         placeholder="Gen7" className={`${inputCls} mt-1`} /></label>
                <label className="block"><span className="font-mono text-[10px] text-ink-500">Auth type</span>
                  <select value={draft.auth_type} onChange={(e) => patch({ auth_type: e.target.value })} className={`${inputCls} mt-1`}>
                    {AUTH_TYPES.map((a) => <option key={a}>{a}</option>)}</select></label>
                <label className="block"><span className="font-mono text-[10px] text-ink-500">API base path</span>
                  <input value={draft.api_base} onChange={(e) => patch({ api_base: e.target.value })} className={`${inputCls} mt-1`} /></label>
                <label className="block"><span className="font-mono text-[10px] text-ink-500">Timeout (s)</span>
                  <input type="number" value={draft.timeout_seconds}
                         onChange={(e) => patch({ timeout_seconds: Number(e.target.value) })} className={`${inputCls} mt-1`} /></label>
                <label className="flex items-end gap-2 pb-2">
                  <input type="checkbox" checked={draft.verify_tls} onChange={(e) => patch({ verify_tls: e.target.checked })} className="accent-accent" />
                  <span className="font-mono text-[11px] text-ink-300">Verify TLS</span></label>
              </div>
              <label className="block"><span className="font-mono text-[10px] text-ink-500">Description</span>
                <input value={draft.description} onChange={(e) => patch({ description: e.target.value })} className={`${inputCls} mt-1`} /></label>
              <p className="font-mono text-[10px] text-ink-500">
                Template variables for paths/headers/body: <span className="text-ink-300">{`{{ip}} {{port}} {{username}} {{password}} {{basic_credentials}}`}</span>, plus any extracted values.
              </p>
            </div>

            {/* Steps */}
            <div className="flex items-center justify-between">
              <div className="font-mono text-[10px] uppercase tracking-wide text-ink-500">Request sequence</div>
              <button onClick={addStep} className="text-[12px] font-mono text-accent hover:underline">+ Add step</button>
            </div>
            {draft.steps.map((s, i) => (
              <div key={i} className="card-glow p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-ink-500">#{i + 1}</span>
                  <input value={s.name} onChange={(e) => patchStep(i, { name: e.target.value })}
                         className={`${inputCls} flex-1`} />
                  <button onClick={() => moveStep(i, -1)} className="px-2 text-ink-400 hover:text-ink-100">↑</button>
                  <button onClick={() => moveStep(i, 1)} className="px-2 text-ink-400 hover:text-ink-100">↓</button>
                  <button onClick={() => delStep(i)} className="px-2 text-sev-high hover:brightness-125">✕</button>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <label className="block"><span className="font-mono text-[10px] text-ink-500">Method</span>
                    <select value={s.method} onChange={(e) => patchStep(i, { method: e.target.value })} className={`${inputCls} mt-1`}>
                      {METHODS.map((m) => <option key={m}>{m}</option>)}</select></label>
                  <label className="block col-span-2"><span className="font-mono text-[10px] text-ink-500">Path (after API base)</span>
                    <input value={s.path} onChange={(e) => patchStep(i, { path: e.target.value })} className={`${inputCls} mt-1`} /></label>
                  <label className="block"><span className="font-mono text-[10px] text-ink-500">Auth</span>
                    <select value={s.auth || "inherit"} onChange={(e) => patchStep(i, { auth: e.target.value })} className={`${inputCls} mt-1`}>
                      {STEP_AUTH.map((a) => <option key={a}>{a}</option>)}</select></label>
                </div>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={!!s.is_tsr} onChange={(e) => patchStep(i, { is_tsr: e.target.checked })} className="accent-accent" />
                    <span className="font-mono text-[11px] text-ink-300">This step returns the TSR</span></label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={!!s.continue_on_error} onChange={(e) => patchStep(i, { continue_on_error: e.target.checked })} className="accent-accent" />
                    <span className="font-mono text-[11px] text-ink-300">Continue on error</span></label>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <JsonField label="Headers" value={s.headers} onChange={(v) => patchStep(i, { headers: v as Record<string, string> })} />
                  <JsonField label="Query params" value={s.query} onChange={(v) => patchStep(i, { query: v as Record<string, string> })} />
                </div>
                <label className="block"><span className="font-mono text-[10px] text-ink-500">Body</span>
                  <textarea rows={2} value={s.body || ""} onChange={(e) => patchStep(i, { body: e.target.value })}
                            className={`${inputCls} font-mono text-[11px] mt-1`} /></label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <JsonField label="Success conditions" value={s.success} onChange={(v) => patchStep(i, { success: v as ApiFlowStep["success"] })} />
                  <JsonField label="Extract values" value={s.extract} onChange={(v) => patchStep(i, { extract: v as ApiFlowStep["extract"] })} />
                </div>
              </div>
            ))}

            <div className="flex items-center gap-3">
              <button onClick={save} disabled={!dirty}
                      className="px-5 py-2.5 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40">
                Save configuration
              </button>
              {!draft.is_active && (
                <button onClick={() => activate(draft.id)} className="text-[12px] font-mono text-accent hover:underline">Make active</button>)}
              {configs.length > 1 && (
                <button onClick={() => remove(draft.id)} className="text-[12px] font-mono text-sev-high hover:underline ml-auto">Delete version</button>)}
            </div>

            <Tester configId={draft.id} />
          </div>
        )}
      </div>
    </div>
  );
}

// ── Connection tester ────────────────────────────────────────────────────
function Tester({ configId }: { configId: string }) {
  const [hostname, setHostname] = useState("");
  const [port, setPort] = useState(443);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [verifyTls, setVerifyTls] = useState(false);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<ApiFlowTestResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await api.testApiConfig({ config_id: configId, hostname, port, username, password, verify_tls: verifyTls }));
    } catch (e) { setErr(e instanceof Error ? e.message : "Test failed"); }
    finally { setBusy(false); }
  }

  return (
    <div className="card-glow p-4 space-y-3">
      <div className="font-mono text-[10px] uppercase tracking-wide text-ink-500">API Connection Tester</div>
      <p className="font-mono text-[10px] text-ink-500">Runs the saved configuration step by step. Nothing is stored.</p>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Firewall IP</span>
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} className={`${inputCls} mt-1`} /></label>
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Port</span>
          <input type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} className={`${inputCls} mt-1`} /></label>
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Username</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} className={`${inputCls} mt-1`} /></label>
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={`${inputCls} mt-1`} /></label>
      </div>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={verifyTls} onChange={(e) => setVerifyTls(e.target.checked)} className="accent-accent" />
        <span className="font-mono text-[11px] text-ink-300">Verify TLS certificate</span></label>
      <button onClick={run} disabled={busy || !hostname || !username || !password}
              className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40">
        {busy ? "Running…" : "Run flow"}
      </button>
      {err && <p className="text-sev-high text-[12px] font-mono">{err}</p>}
      {res && (
        <div className="space-y-2">
          <p className={`text-[13px] font-semibold ${res.success ? "text-signal" : "text-sev-high"}`}>
            {res.success ? `✓ Flow succeeded — TSR ${res.tsr_bytes.toLocaleString()} bytes` : `✕ ${res.error}`}
          </p>
          {res.traces.map((t, i) => (
            <details key={i} className="border border-base-500/50 rounded-lg p-2 bg-base-900/40">
              <summary className="cursor-pointer text-[12px] flex items-center gap-2">
                <span style={{ color: t.success ? "#39d98a" : "#ff4d4d" }}>{t.success ? "✓" : "✕"}</span>
                <span className="text-ink-200 font-medium">{t.step}</span>
                <span className="font-mono text-[11px] text-ink-500">
                  {t.method} → {t.status_code ?? "—"} · {t.elapsed_ms} ms{t.error ? ` · ${t.error}` : ""}
                </span>
              </summary>
              <div className="mt-2 space-y-1 font-mono text-[11px] text-ink-400">
                <div><span className="text-ink-500">URL:</span> {t.url}</div>
                <div><span className="text-ink-500">Headers:</span> {JSON.stringify(t.request_headers)}</div>
                <div><span className="text-ink-500">Response:</span></div>
                <pre className="whitespace-pre-wrap break-all bg-base-900 rounded p-2 max-h-48 overflow-auto">{t.response_excerpt}</pre>
              </div>
            </details>
          ))}
          {Object.keys(res.extracted || {}).length > 0 && (
            <div className="font-mono text-[11px] text-ink-500">Extracted: {JSON.stringify(res.extracted)}</div>
          )}
        </div>
      )}
    </div>
  );
}
