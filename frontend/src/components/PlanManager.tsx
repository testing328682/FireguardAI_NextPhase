import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { PlanData } from "../lib/types";
import { useConfirm } from "./Modal";

export function PlanManager() {
  const [plans, setPlans] = useState<PlanData[]>([]);
  const [features, setFeatures] = useState<{ id: string; key: string; label: string; description: string; is_active: boolean }[]>([]);
  const [editing, setEditing] = useState<PlanData | null>(null);
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const confirm = useConfirm();

  const load = useCallback(() => {
    api.listPlans().then(setPlans).catch((e) => setErr(e.message));
    api.listAdminFeatures().then(setFeatures).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  async function handleDelete(id: string, name: string) {
    if (!await confirm("Delete Plan", `Remove "${name}"?`)) return;
    try { await api.deletePlan(id); load(); } catch (e) { setErr(e instanceof Error ? e.message : "Delete failed"); }
  }
  async function handleClone(id: string) {
    try { await api.clonePlan(id); load(); } catch (e) { setErr(e instanceof Error ? e.message : "Clone failed"); }
  }

  return (
    <div className="max-w-[1400px] fade-in space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Plan Management</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">{plans.length} plan{plans.length !== 1 ? "s" : ""} · {features.length} features</p>
        </div>
        <button onClick={() => setCreating(true)} className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all">+ Create Plan</button>
      </div>
      {err && <div className="card-glow p-4 border-sev-high/30"><p className="text-sev-high text-[13px] font-mono">{err}</p></div>}

      {(creating || editing) && (
        <PlanEditor key={editing?.id || "new"} plan={editing} features={features}
          onClose={() => { setCreating(false); setEditing(null); }}
          onSaved={() => { setCreating(false); setEditing(null); load(); }} />
      )}

      <div className="card-glow">
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                <th className="py-3 px-4">Name</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4 hidden lg:table-cell">Features</th>
                <th className="py-3 px-4 hidden md:table-cell">Pricing</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 w-10"></th>
              </tr>
            </thead>
            <tbody>
              {plans.map((p) => (
                <tr key={p.id} className="table-row border-b border-base-500/40">
                  <td className="py-3 px-4">
                    <button onClick={() => setEditing(p)} className="text-ink-100 font-medium hover:text-accent text-left">{p.name}</button>
                    <div className="font-mono text-[10px] text-ink-500 mt-0.5 line-clamp-1">{p.description || "—"}</div>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5">
                      <span className={`badge capitalize ${p.plan_type === "msp" ? "" : ""}`}
                            style={{ color: p.plan_type === "msp" ? "#c084fc" : "#4f8cff", borderColor: p.plan_type === "msp" ? "#c084fc55" : "#4f8cff55", background: p.plan_type === "msp" ? "#c084fc14" : "#4f8cff14" }}>
                        {p.plan_type}
                      </span>
                      {p.is_testing && (
                        <span className="badge text-[9px]" style={{ color: "#f5c451", borderColor: "#f5c45155", background: "#f5c45114" }}>
                          TEST
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 hidden lg:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(p.features || {}).filter(([, v]) => v).slice(0, 3).map(([k]) => {
                        const f = features.find((x) => x.key === k);
                        return <span key={k} className="badge text-[9px]" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>{f?.label || k}</span>;
                      })}
                      {Object.entries(p.features || {}).filter(([, v]) => v).length > 3 && (
                        <span className="font-mono text-[9px] text-ink-500">+{Object.entries(p.features).filter(([, v]) => v).length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[10px] text-ink-500 hidden md:table-cell">
                    {p.plan_type === "msp"
                      ? `${Object.keys(p.pricing_tiers || {}).length} tiers`
                      : p.price_per_device > 0 ? `$${p.price_per_device}/device/mo` : "—"}
                  </td>
                  <td className="py-3 px-4">
                    <span className="badge" style={{ color: p.is_active ? "#39d98a" : "#7a879b", borderColor: p.is_active ? "#39d98a55" : "#7a879b55", background: p.is_active ? "#39d98a14" : "#7a879b14" }}>{p.is_active ? "Active" : "Inactive"}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1">
                      <button onClick={() => setEditing(p)} title="Edit" className="w-6 h-6 grid place-items-center rounded border border-base-500 text-ink-500 hover:text-accent text-xs">✎</button>
                      <button onClick={() => handleClone(p.id)} title="Clone" className="w-6 h-6 grid place-items-center rounded border border-base-500 text-ink-500 hover:text-accent text-xs">⧉</button>
                      <button onClick={() => handleDelete(p.id, p.name)} title="Delete" className="w-6 h-6 grid place-items-center rounded border border-base-500 text-ink-500 hover:text-sev-high text-xs">×</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function PlanEditor({ plan, features, onClose, onSaved }: {
  plan: PlanData | null; features: { id: string; key: string; label: string; description: string; is_active: boolean }[];
  onClose: () => void; onSaved: () => void;
}) {
  const isNew = !plan;
  const [name, setName] = useState(plan?.name || "");
  const [desc, setDesc] = useState(plan?.description || "");
  const [planType, setPlanType] = useState(plan?.plan_type || "professional");
  const [active, setActive] = useState(plan?.is_active ?? true);
  const [visible, setVisible] = useState(plan?.is_visible ?? true);
  const [yearlyDiscount, setYearlyDiscount] = useState(plan?.yearly_discount_pct ?? 20);
  const [testing, setTesting] = useState(plan?.is_testing ?? false);
  const [validityMins, setValidityMins] = useState(plan?.validity_minutes || 0);
  const [planFeatures, setPlanFeatures] = useState<Record<string, boolean>>(plan?.features || {});
  const [pricePerDevice, setPricePerDevice] = useState<number>(plan?.price_per_device || 0);
  const [pricingTiers, setPricingTiers] = useState<Record<string, any>>(plan?.pricing_tiers || {});
  const [mspTiers, setMspTiers] = useState<string[]>(() => Object.keys(plan?.pricing_tiers || {}));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function save() {
    if (!name.trim()) { setErr("Plan name is required."); return; }
    setBusy(true); setErr(null);
    try {
      const body: any = { name: name.trim(), description: desc, plan_type: planType,
                          is_active: active, is_visible: visible,
                          yearly_discount_pct: yearlyDiscount,
                          is_testing: testing, validity_minutes: validityMins,
                          features: planFeatures, price_per_device: pricePerDevice,
                          pricing_tiers: pricingTiers };
      if (isNew) await api.createPlan(body);
      else await api.updatePlan(plan!.id, body);
      onSaved();
    } catch (e) { setErr(e instanceof Error ? e.message : "Save failed"); }
    finally { setBusy(false); }
  }

  function addMspTier() {
    const tier = prompt("Device count for this tier?");
    if (!tier || isNaN(Number(tier))) return;
    const key = tier;
    if (mspTiers.includes(key)) return;
    setMspTiers((t) => [...t, key]);
    setPricingTiers((p) => ({ ...p, [key]: 0 }));
  }

  return (
    <>
      <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={onClose} />
      <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={onClose}>
        <div className="w-full max-w-[720px] max-h-[85vh] overflow-y-auto bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-5"
             onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center justify-between">
            <h3 className="font-display font-semibold text-ink-100 text-lg">{isNew ? "Create Plan" : `Edit: ${plan?.name}`}</h3>
            <button onClick={onClose} className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100">×</button>
          </div>
          {err && <p className="text-sev-high text-[12px] font-mono">{err}</p>}

          <div className="grid grid-cols-2 gap-3">
            <Field label="Plan Name"><input value={name} onChange={(e) => setName(e.target.value)} className={inputCls} placeholder="e.g. Enterprise" /></Field>
            <Field label="Plan Type">
              <select value={planType} onChange={(e) => setPlanType(e.target.value)} className={inputCls}>
                <option value="professional">Professional (per-device)</option>
                <option value="msp">MSP (tier-based)</option>
              </select>
            </Field>
            <Field label="Description"><input value={desc} onChange={(e) => setDesc(e.target.value)} className={inputCls} placeholder="Short description" /></Field>
            <Field label="Yearly Discount %">
              <input type="number" min={0} max={100} value={yearlyDiscount}
                     onChange={(e) => setYearlyDiscount(Math.min(100, Math.max(0, Number(e.target.value))))}
                     className={inputCls + " w-24"} />
            </Field>
            <Field label="Status" className="flex items-center gap-4 mt-2">
              <div><label className="flex items-center gap-2 text-[13px] text-ink-300"><input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} /> Active</label></div>
              <div><label className="flex items-center gap-2 text-[13px] text-ink-300"><input type="checkbox" checked={visible} onChange={(e) => setVisible(e.target.checked)} /> Visible</label></div>
            </Field>
            <Field label="Testing Plan" className="flex items-center gap-4 mt-2">
              <div><label className="flex items-center gap-2 text-[13px] text-ink-300"><input type="checkbox" checked={testing}
                onChange={(e) => {
                  setTesting(e.target.checked);
                  // Seed a valid validity so the controlled <select> below matches
                  // an option (otherwise it shows "5 minutes" but state stays 0 and
                  // no onChange fires, posting validity_minutes: 0).
                  if (e.target.checked && !validityMins) setValidityMins(5);
                }} /> Testing</label></div>
              {testing && (
                <select value={validityMins || 5} onChange={(e) => setValidityMins(Number(e.target.value))}
                        className={inputCls + " w-32"}>
                  <option value={5}>5 minutes</option>
                  <option value={30}>30 minutes</option>
                  <option value={60}>1 hour</option>
                  <option value={360}>6 hours</option>
                  <option value={720}>12 hours</option>
                  <option value={1440}>1 day</option>
                  <option value={2880}>2 days</option>
                  <option value={10080}>7 days</option>
                </select>
              )}
            </Field>
          </div>

          {/* Features */}
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-2">Features</div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {features.filter((f) => f.is_active !== false).map((f) => (
                <label key={f.key} className="flex items-center gap-2 text-[13px] text-ink-300 cursor-pointer py-1 px-2 rounded hover:bg-base-700/30">
                  <input type="checkbox" checked={!!planFeatures[f.key]}
                         onChange={(e) => setPlanFeatures((pf) => ({ ...pf, [f.key]: e.target.checked }))}
                         className="rounded accent-accent" /> {f.label}
                </label>
              ))}
            </div>
          </div>

          {/* Pricing */}
          {planType === "professional" ? (
            <div>
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-2">Price Per Device Per Month</div>
              <label className="block max-w-[200px]">
                <span className="font-mono text-[10px] text-ink-500">$ / device / month</span>
                <input type="number" step="0.01" value={pricePerDevice ?? ""} placeholder="0"
                       onChange={(e) => setPricePerDevice(Number(e.target.value))}
                       className={`${inputCls} mt-1`} />
              </label>
              {pricePerDevice > 0 && (
                <div className="mt-2 font-mono text-[10px] text-ink-500">
                  Example: 10 devices × ${pricePerDevice}/mo = ${10 * pricePerDevice}/mo
                </div>
              )}
            </div>
          ) : (
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">MSP Tiers</span>
                <button onClick={addMspTier} className="text-[11px] text-accent hover:underline font-mono">+ Add Tier</button>
              </div>
              {mspTiers.length === 0 && <p className="text-ink-500 text-[12px] font-mono mb-2">No tiers defined. Add at least one.</p>}
              {mspTiers.map((tier) => (
                <div key={tier} className="mb-3 p-3 rounded bg-base-800/50 border border-base-500 flex items-center justify-between gap-3">
                  <span className="text-ink-100 font-semibold text-[13px]">{tier} Devices</span>
                  <div className="flex items-center gap-3">
                    <label className="block">
                      <span className="font-mono text-[9px] text-ink-500">$ / month</span>
                      <input type="number" step="0.01" value={(pricingTiers as any)[tier] ?? ""} placeholder="0"
                             onChange={(e) => setPricingTiers((p) => ({ ...p, [tier]: Number(e.target.value) }))}
                             className={`${inputCls} mt-1 w-32`} />
                    </label>
                    <button onClick={() => {
                      setMspTiers((t) => t.filter((x) => x !== tier));
                      setPricingTiers((p) => { const n = { ...p }; delete n[tier]; return n; });
                    }} className="text-sev-high text-[11px] hover:underline font-mono">Remove</button>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="flex items-center gap-3 pt-2 border-t border-base-500">
            <button onClick={save} disabled={busy} className="px-5 py-2.5 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40">
              {busy ? "Saving…" : isNew ? "Create Plan" : "Save Changes"}
            </button>
            <button onClick={onClose} className="px-4 py-2 rounded-lg border border-base-500 text-ink-300 text-[13px] hover:text-ink-100">Cancel</button>
          </div>
        </div>
      </div>
    </>
  );
}

const inputCls = "w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent";
function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return <label className={`block ${className || ""}`}><span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">{label}</span>{children}</label>;
}
