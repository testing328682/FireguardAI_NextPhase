import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type {
  DeviceGeneration, FirmwareRule, FirmwareVersionOut,
} from "../lib/types";
import { SEVERITIES, sevColor } from "../lib/ui";
import { useConfirm } from "./Modal";

const inputCls = "mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-all";
const labelCls = "font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500";
const miniInputCls = "bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 font-mono focus:outline-none focus:border-accent";

const DEFAULT_RULE: FirmwareRule = {
  enabled: true, key: "FW-FIRMWARE-COMPLIANCE", title: "", description: "",
  severity: "Critical", category: "Firmware Compliance", remediation: "",
};

// ── Product & Platform Configuration ──────────────────────────────────
export function ProductConfig() {
  const [gens, setGens] = useState<DeviceGeneration[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.listGenerations().then(setGens).catch((e) => setErr(e.message));
  }, []);
  useEffect(() => { load(); }, [load]);

  // ── New generation form ──────────────────────────────────────────
  const [newName, setNewName] = useState("");
  const confirm = useConfirm();
  async function createGen() {
    if (!newName.trim()) return;
    setBusy(true); setErr(null);
    try { await api.createGeneration({ name: newName.trim() }); setNewName(""); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
    finally { setBusy(false); }
  }

  // ── Add device to generation ─────────────────────────────────────
  async function addDevice(genId: string, model: string) {
    if (!model.trim()) return;
    setErr(null);
    try { await api.addDeviceToGeneration(genId, model.trim()); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }

  // ── Remove device ────────────────────────────────────────────────
  async function removeDevice(genId: string, devId: string) {
    try { await api.removeDeviceFromGeneration(genId, devId); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }

  // ── Delete generation ────────────────────────────────────────────
  async function deleteGen(id: string, name: string) {
    if (!await confirm("Delete Generation", `Remove "${name}" and all its devices? This cannot be undone.`)) return;
    try { await api.deleteGeneration(id); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }

  return (
    <div className="max-w-[1100px] fade-in space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Product Configuration</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">Device generations · model mappings · firmware compliance</p>
        </div>
      </div>

      {err && (
        <div className="card-glow p-4 border-sev-high/30">
          <p className="text-sev-high text-[13px] font-mono">{err}</p>
        </div>
      )}

      {/* ── New generation ─────────────────────────────────────────── */}
      <div className="card-glow p-5">
        <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Add Generation</h3>
        <div className="flex items-end gap-3">
          <label className="block flex-1 max-w-xs">
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Generation name</span>
            <input value={newName} onChange={(e) => setNewName(e.target.value)}
                   onKeyDown={(e) => e.key === "Enter" && createGen()}
                   placeholder="e.g. Gen 9"
                   className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 font-mono focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30" />
          </label>
          <button onClick={createGen} disabled={busy || !newName.trim()}
                  className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
            {busy ? "Adding…" : "Add Generation"}
          </button>
        </div>
      </div>

      {/* ── Generations list ────────────────────────────────────────── */}
      {gens.length === 0 ? (
        <div className="card-glow p-12 text-center">
          <div className="text-4xl mb-3 opacity-30">⚙</div>
          <p className="text-ink-500 text-sm font-mono">No generations configured yet. Add one above.</p>
        </div>
      ) : (
        gens.map((g) => (
          <div key={g.id} className="card-glow fade-in">
            {/* Header */}
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-base-500/60">
              <div className="flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-accent" />
                <h3 className="font-display font-semibold text-ink-100">{g.name}</h3>
                <span className="badge" style={{ color: "#6b7689", borderColor: "#6b768955", background: "#6b768914" }}>
                  {g.devices.length} device{g.devices.length !== 1 ? "s" : ""}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="badge font-mono" style={{
                  color: g.firmware_rule?.enabled === false ? "#7a879b" : "#39d98a",
                  borderColor: g.firmware_rule?.enabled === false ? "#7a879b55" : "#39d98a55",
                  background: g.firmware_rule?.enabled === false ? "#7a879b14" : "#39d98a14",
                }}>
                  Latest: {g.firmware_version || "not set"}
                  {g.firmware_rule?.enabled === false ? " · rule disabled" : ""}
                </span>
                <button onClick={() => deleteGen(g.id, g.name)}
                        className="px-2 py-1.5 rounded-lg text-ink-500 hover:text-sev-high text-[12px] transition-colors">✕</button>
              </div>
            </div>

            {/* Devices */}
            <div className="p-5 border-b border-base-500/60">
              <h4 className={`${labelCls} mb-3 block`}>Device Models</h4>
              <div className="flex flex-wrap gap-2 mb-4">
                {g.devices.map((d) => (
                  <span key={d.id} className="inline-flex items-center gap-1.5 badge"
                        style={{ color: "#c084fc", borderColor: "#c084fc55", background: "#c084fc14" }}>
                    {d.model}
                    <button onClick={() => removeDevice(g.id, d.id)}
                            className="ml-1 text-ink-500 hover:text-sev-high">×</button>
                  </span>
                ))}
              </div>

              {/* Add device form */}
              <AddDeviceForm genId={g.id} onAdd={addDevice} />
            </div>

            {/* Firmware compliance rule */}
            <FirmwareRulePanel gen={g} onSaved={load} onError={setErr} />

            {/* Previous firmware versions (firmware intelligence) */}
            <FirmwareVersionsPanel gen={g} onChanged={load} onError={setErr} />
          </div>
        ))
      )}
    </div>
  );
}

// ── Firmware compliance rule editor ─────────────────────────────────────
function FirmwareRulePanel({ gen, onSaved, onError }: {
  gen: DeviceGeneration; onSaved: () => void; onError: (m: string) => void;
}) {
  const rule = gen.firmware_rule ?? DEFAULT_RULE;
  const [open, setOpen] = useState(false);
  const [version, setVersion] = useState(gen.firmware_version);
  const [draft, setDraft] = useState<FirmwareRule>({ ...rule });
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    setVersion(gen.firmware_version);
    setDraft({ ...(gen.firmware_rule ?? DEFAULT_RULE) });
  }, [gen]);

  async function save() {
    setSaving(true); onError("");
    try {
      await api.updateFirmwareConfig(gen.id, {
        version: version.trim(),
        rule_enabled: draft.enabled, rule_key: draft.key.trim(),
        rule_title: draft.title, rule_description: draft.description,
        rule_severity: draft.severity, rule_category: draft.category,
        rule_remediation: draft.remediation,
      });
      onSaved();
    } catch (e) { onError(e instanceof Error ? e.message : "Save failed"); }
    finally { setSaving(false); }
  }

  return (
    <div className="px-5 py-4 border-b border-base-500/60">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between">
        <span className={labelCls}>
          {open ? "▾" : "▸"} Firmware Compliance Rule
        </span>
        <span className="flex items-center gap-2 font-mono text-[11px]">
          <span className="badge" style={{
            color: sevColor[rule.severity] ?? "#7a879b",
            borderColor: `${sevColor[rule.severity] ?? "#7a879b"}55`,
            background: `${sevColor[rule.severity] ?? "#7a879b"}14`,
          }}>{rule.severity}</span>
          <span className={rule.enabled ? "text-signal" : "text-ink-500"}>
            {rule.enabled ? "Enabled" : "Disabled"}
          </span>
        </span>
      </button>
      {open && (
        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="block">
            <span className={labelCls}>Latest Recommended Firmware</span>
            <input value={version} onChange={(e) => setVersion(e.target.value)}
                   placeholder="e.g. 7.3.3-7013-R8777" className={`${inputCls} font-mono`} />
          </label>
          <label className="block">
            <span className={labelCls}>Rule Key</span>
            <input value={draft.key} onChange={(e) => setDraft({ ...draft, key: e.target.value })}
                   className={`${inputCls} font-mono`} />
          </label>
          <label className="block">
            <span className={labelCls}>Title (empty = built-in default)</span>
            <input value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })}
                   placeholder="e.g. Outdated SonicOS Firmware" className={inputCls} />
          </label>
          <div className="flex gap-3">
            <label className="block flex-1">
              <span className={labelCls}>Severity</span>
              <select value={draft.severity}
                      onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
                      className={inputCls}>
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </label>
            <label className="block flex-1">
              <span className={labelCls}>Category</span>
              <input value={draft.category}
                     onChange={(e) => setDraft({ ...draft, category: e.target.value })}
                     className={inputCls} />
            </label>
          </div>
          <label className="block md:col-span-2">
            <span className={labelCls}>Description (empty = built-in default)</span>
            <textarea value={draft.description} rows={2}
                      onChange={(e) => setDraft({ ...draft, description: e.target.value })}
                      className={inputCls} />
          </label>
          <label className="block md:col-span-2">
            <span className={labelCls}>Remediation (empty = built-in default)</span>
            <input value={draft.remediation}
                   onChange={(e) => setDraft({ ...draft, remediation: e.target.value })}
                   placeholder="e.g. Upgrade to the latest recommended firmware version."
                   className={inputCls} />
          </label>
          <div className="flex items-center gap-4 md:col-span-2">
            <label className="flex items-center gap-2 text-[13px] text-ink-300 cursor-pointer">
              <input type="checkbox" checked={draft.enabled}
                     onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
                     className="rounded accent-accent" />
              Rule enabled — when off, no firmware compliance finding is generated
            </label>
            <button onClick={save} disabled={saving || !draft.key.trim()}
                    className="ml-auto px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
              {saving ? "Saving…" : "Save Rule"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Previous firmware versions (firmware intelligence) ──────────────────
function FirmwareVersionsPanel({ gen, onChanged, onError }: {
  gen: DeviceGeneration; onChanged: () => void; onError: (m: string) => void;
}) {
  const versions = gen.firmware_versions ?? [];
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<Record<string, FirmwareVersionOut>>({});
  const [newVersion, setNewVersion] = useState("");
  const confirm = useConfirm();

  async function refreshDetail() {
    try {
      const rows = await api.listFirmwareVersions(gen.id);
      setDetail(Object.fromEntries(rows.map((r) => [r.id, r])));
    } catch (e) { onError(e instanceof Error ? e.message : "Failed to load versions"); }
  }

  async function toggle(id: string) {
    if (expanded === id) { setExpanded(null); return; }
    if (!detail[id]) await refreshDetail();
    setExpanded(id);
  }

  async function addVersion() {
    if (!newVersion.trim()) return;
    onError("");
    try {
      await api.addFirmwareVersion(gen.id, { version: newVersion.trim() });
      setNewVersion("");
      onChanged();
      await refreshDetail();
    } catch (e) { onError(e instanceof Error ? e.message : "Failed"); }
  }

  async function removeVersion(fv: FirmwareVersionOut) {
    if (!await confirm("Delete Firmware Version",
        `Remove "${fv.version}" and its configured CVEs/issues? Existing findings keep their evidence.`)) return;
    try {
      await api.deleteFirmwareVersion(fv.id);
      onChanged();
      await refreshDetail();
    } catch (e) { onError(e instanceof Error ? e.message : "Failed"); }
  }

  return (
    <div className="px-5 py-4">
      <div className="flex items-center justify-between mb-3">
        <span className={labelCls}>Previous Firmware Versions ({versions.length})</span>
        <div className="flex items-center gap-2">
          <input value={newVersion} onChange={(e) => setNewVersion(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && addVersion()}
                 placeholder="e.g. 7.3.0-7012" className={miniInputCls} />
          <button onClick={addVersion} disabled={!newVersion.trim()}
                  className="px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[12px] font-semibold hover:bg-accent/20 disabled:opacity-40 transition-all">
            + Add Version
          </button>
        </div>
      </div>
      {versions.length === 0 ? (
        <p className="text-ink-500 text-[12px] font-mono py-2">
          No previous firmware versions configured — add releases to attach CVE and known-issue intelligence.
        </p>
      ) : (
        <div className="space-y-1">
          {versions.map((fv) => {
            const d = detail[fv.id] ?? fv;
            const isOpen = expanded === fv.id;
            return (
              <div key={fv.id} className="rounded-lg border border-base-500/60 bg-base-800/40">
                <div className="flex items-center gap-3 px-3 py-2">
                  <button onClick={() => toggle(fv.id)}
                          className="flex-1 text-left font-mono text-[13px] text-ink-100">
                    <span className="text-ink-500 mr-1">{isOpen ? "▾" : "▸"}</span>
                    {fv.version}
                  </button>
                  <span className="font-mono text-[11px] text-ink-500">
                    CVEs: {d.cve_count} · Issues: {d.issue_count}
                  </span>
                  <button onClick={() => removeVersion(fv)}
                          className="text-ink-500 hover:text-sev-high text-[12px]">✕</button>
                </div>
                {isOpen && detail[fv.id] && (
                  <FirmwareVersionDetail fv={detail[fv.id]} onChanged={async () => {
                    await refreshDetail(); onChanged();
                  }} onError={onError} />
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function FirmwareVersionDetail({ fv, onChanged, onError }: {
  fv: FirmwareVersionOut; onChanged: () => Promise<void>; onError: (m: string) => void;
}) {
  const [remediation, setRemediation] = useState(fv.remediation);
  const [cve, setCve] = useState({ cve_id: "", description: "", cvss: "", remediation: "" });
  const [issue, setIssue] = useState({ title: "", description: "", severity: "", remediation: "" });

  async function run(fn: () => Promise<unknown>) {
    onError("");
    try { await fn(); await onChanged(); }
    catch (e) { onError(e instanceof Error ? e.message : "Failed"); }
  }

  return (
    <div className="px-3 pb-3 space-y-4 border-t border-base-500/40 pt-3">
      {/* Version remediation */}
      <div className="flex items-end gap-2">
        <label className="block flex-1">
          <span className={labelCls}>Remediation for this version</span>
          <input value={remediation} onChange={(e) => setRemediation(e.target.value)}
                 placeholder="e.g. Upgrade to 7.3.3-7013-R8777" className={inputCls} />
        </label>
        <button onClick={() => run(() => api.updateFirmwareVersion(fv.id, { remediation }))}
                className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:border-accent hover:text-accent transition-all">
          Save
        </button>
      </div>

      {/* CVEs */}
      <div>
        <span className={labelCls}>Known CVEs</span>
        <div className="mt-1 space-y-1">
          {(fv.cves ?? []).map((c) => (
            <div key={c.id} className="flex items-start gap-2 font-mono text-[12px] bg-base-900/60 rounded-lg px-2.5 py-1.5">
              <span className="text-sev-high">{c.cve_id}</span>
              {c.cvss != null && <span className="text-ink-500">CVSS {c.cvss}</span>}
              <span className="text-ink-300 flex-1">{c.description}</span>
              {c.remediation && <span className="text-ink-500">fix: {c.remediation}</span>}
              <button onClick={() => run(() => api.deleteFirmwareCve(c.id))}
                      className="text-ink-500 hover:text-sev-high shrink-0">✕</button>
            </div>
          ))}
          {(fv.cves ?? []).length === 0 && (
            <p className="font-mono text-[11px] text-ink-500">No CVEs configured.</p>
          )}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <input value={cve.cve_id} onChange={(e) => setCve({ ...cve, cve_id: e.target.value })}
                 placeholder="CVE-2026-12345" className={`${miniInputCls} w-40`} />
          <input value={cve.cvss} onChange={(e) => setCve({ ...cve, cvss: e.target.value })}
                 placeholder="CVSS (optional)" className={`${miniInputCls} w-28`} />
          <input value={cve.description} onChange={(e) => setCve({ ...cve, description: e.target.value })}
                 placeholder="Description" className={`${miniInputCls} flex-1 min-w-[160px]`} />
          <input value={cve.remediation} onChange={(e) => setCve({ ...cve, remediation: e.target.value })}
                 placeholder="Remediation" className={`${miniInputCls} flex-1 min-w-[160px]`} />
          <button onClick={() => run(async () => {
                    await api.addFirmwareCve(fv.id, {
                      cve_id: cve.cve_id.trim(), description: cve.description,
                      cvss: cve.cvss.trim() === "" ? null : cve.cvss,
                      remediation: cve.remediation,
                    });
                    setCve({ cve_id: "", description: "", cvss: "", remediation: "" });
                  })}
                  disabled={!cve.cve_id.trim()}
                  className="px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[12px] font-semibold hover:bg-accent/20 disabled:opacity-40 transition-all">
            + CVE
          </button>
        </div>
      </div>

      {/* Known issues */}
      <div>
        <span className={labelCls}>Known Bugs / Issues</span>
        <div className="mt-1 space-y-1">
          {(fv.issues ?? []).map((i) => (
            <div key={i.id} className="flex items-start gap-2 font-mono text-[12px] bg-base-900/60 rounded-lg px-2.5 py-1.5">
              <span className="text-ink-100">{i.title}</span>
              {i.severity && <span style={{ color: sevColor[i.severity] }}>[{i.severity}]</span>}
              <span className="text-ink-300 flex-1">{i.description}</span>
              {i.remediation && <span className="text-ink-500">fix: {i.remediation}</span>}
              <button onClick={() => run(() => api.deleteFirmwareIssue(i.id))}
                      className="text-ink-500 hover:text-sev-high shrink-0">✕</button>
            </div>
          ))}
          {(fv.issues ?? []).length === 0 && (
            <p className="font-mono text-[11px] text-ink-500">No known issues configured.</p>
          )}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <input value={issue.title} onChange={(e) => setIssue({ ...issue, title: e.target.value })}
                 placeholder="Issue title" className={`${miniInputCls} w-48`} />
          <select value={issue.severity} onChange={(e) => setIssue({ ...issue, severity: e.target.value })}
                  className={miniInputCls}>
            <option value="">Severity (optional)</option>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <input value={issue.description} onChange={(e) => setIssue({ ...issue, description: e.target.value })}
                 placeholder="Description" className={`${miniInputCls} flex-1 min-w-[160px]`} />
          <input value={issue.remediation} onChange={(e) => setIssue({ ...issue, remediation: e.target.value })}
                 placeholder="Remediation / workaround" className={`${miniInputCls} flex-1 min-w-[160px]`} />
          <button onClick={() => run(async () => {
                    await api.addFirmwareIssue(fv.id, issue);
                    setIssue({ title: "", description: "", severity: "", remediation: "" });
                  })}
                  disabled={!issue.title.trim()}
                  className="px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[12px] font-semibold hover:bg-accent/20 disabled:opacity-40 transition-all">
            + Issue
          </button>
        </div>
      </div>
    </div>
  );
}

function AddDeviceForm({ genId, onAdd }: { genId: string; onAdd: (genId: string, model: string) => Promise<void> }) {
  const [model, setModel] = useState("");
  const [adding, setAdding] = useState(false);

  async function submit() {
    if (!model.trim()) return;
    setAdding(true);
    await onAdd(genId, model.trim());
    setModel("");
    setAdding(false);
  }

  return (
    <div className="flex items-end gap-2">
      <label className="block flex-1 max-w-xs">
        <span className="font-mono text-[10px] text-ink-500">Add model</span>
        <input value={model} onChange={(e) => setModel(e.target.value)}
               onKeyDown={(e) => e.key === "Enter" && submit()}
               placeholder="e.g. NSA 3700"
               className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-1.5 text-[13px] text-ink-100 font-mono focus:outline-none focus:border-accent" />
      </label>
      <button onClick={submit} disabled={adding || !model.trim()}
              className="px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[12px] font-semibold hover:bg-accent/20 disabled:opacity-40 transition-all">
        {adding ? "…" : "+ Add"}
      </button>
    </div>
  );
}
