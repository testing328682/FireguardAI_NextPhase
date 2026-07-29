import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { DeviceGeneration } from "../lib/types";
import { useConfirm, usePrompt } from "./Modal";

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
  const prompt = usePrompt();
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

  // ── Set firmware recommendation ──────────────────────────────────
  async function setFirmware(genId: string) {
    const v = await prompt("Firmware Version", "", "e.g. 7.0.1-5171");
    if (!v) return;
    setErr(null);
    try { await api.setFirmwareRecommendation(genId, v.trim()); load(); }
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
                <button onClick={() => setFirmware(g.id)}
                        className="px-3 py-1.5 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:border-accent hover:text-accent transition-all font-mono">
                  Firmware: {g.firmware_version || "not set"}
                </button>
                <button onClick={() => deleteGen(g.id, g.name)}
                        className="px-2 py-1.5 rounded-lg text-ink-500 hover:text-sev-high text-[12px] transition-colors">✕</button>
              </div>
            </div>

            {/* Devices */}
            <div className="p-5">
              <h4 className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500 mb-3">Device Models</h4>
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
          </div>
        ))
      )}
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
