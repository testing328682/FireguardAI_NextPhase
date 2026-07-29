import { useEffect, useState, useCallback, useMemo } from "react";
import { api } from "../lib/api";
import { useConfirm } from "./Modal";
import type { CustomerDetail } from "../lib/types";
import { navigate } from "../lib/router";

function KpiCard({ label, value, color, sub, icon }: { label: string; value: number; color: string; sub: string; icon: React.ReactNode }) {
  return (
    <div className="stat-card group">
      <div className="flex items-start justify-between">
        <div className="space-y-0.5 min-w-0">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 truncate">{label}</div>
          <div className="font-display text-[26px] font-bold leading-none tabular-nums" style={{ color }}>{value.toLocaleString()}</div>
          <div className="font-mono text-[10px] text-ink-500">{sub}</div>
        </div>
        <div className="opacity-25 group-hover:opacity-50 transition-opacity shrink-0" style={{ color }}>{icon}</div>
      </div>
    </div>
  );
}
function IconUsers() { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>; }
function IconServer() { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>; }
function IconShield() { return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>; }

export function Customers() {
  const [items, setItems] = useState<CustomerDetail[]>([]);
  const [adding, setAdding] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [orgName, setOrgName] = useState("");
  const [infoTitle, setInfoTitle] = useState("");
  const [infoBody, setInfoBody] = useState("");
  const confirm = useConfirm();

  useEffect(() => { api.getOrganization().then(o => setOrgName(o.name)).catch(() => {}); }, []);
  const load = useCallback(() => {
    api.listCustomers().then((cs) => setItems(cs as CustomerDetail[]))
      .catch((e) => setErr(e instanceof Error ? e.message : "Failed to load customers"));
  }, []);
  useEffect(() => { load(); }, [load]);

  const totalDevices = items.reduce((s, c) => s + (c.device_count || 0), 0);
  const filtered = useMemo(() => items.filter((c) =>
    !q || c.name.toLowerCase().includes(q.toLowerCase()) ||
    (c.contact_email || "").toLowerCase().includes(q.toLowerCase()) ||
    (c.country || "").toLowerCase().includes(q.toLowerCase())
  ), [items, q]);

  async function deleteCustomer(c: CustomerDetail) {
    if (c.name === "My Organization" || c.name === orgName || c.name.includes("(default)")) {
      setInfoTitle("Cannot Delete"); setInfoBody("This is your organization's default customer and cannot be deleted.");
      return;
    }
    if ((c.device_count || 0) > 0) {
      setInfoTitle("Cannot Delete"); setInfoBody("This customer has registered devices. Please delete all associated devices first.");
      return;
    }
    if (!await confirm("Delete Customer", `Remove "${c.name}"?`)) return;
    try { await api.deleteCustomer(c.id); load(); }
    catch (e) { setInfoTitle("Error"); setInfoBody(e instanceof Error ? e.message : "Delete failed"); }
  }

  return (
    <div className="max-w-[1440px] fade-in space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Customers</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">{items.length} customer{items.length !== 1 ? "s" : ""}</p>
        </div>
        <button onClick={() => setAdding(true)}
                className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
          + Add Customer
        </button>
      </div>

      {err && <div className="card-glow p-4 border-sev-high/30"><p className="text-sev-high text-[13px] font-mono">{err}</p></div>}

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <KpiCard label="Total Customers" value={items.length} color="#4f8cff" sub="managed" icon={<IconUsers />} />
        <KpiCard label="Total Devices" value={totalDevices} color="#39d98a" sub="across all customers" icon={<IconServer />} />
        <KpiCard label="Avg Devices/Customer" value={items.length > 0 ? Math.round(totalDevices / items.length) : 0} color="#c084fc" sub="average" icon={<IconShield />} />
      </div>

      {adding && (
        <CustomerModal onClose={() => setAdding(false)} onSaved={() => { setAdding(false); load(); }} />
      )}

      {items.length === 0 ? (
        <div className="card-glow p-16 text-center fade-in">
          <div className="text-5xl mb-4 opacity-30">🏢</div>
          <h2 className="font-display font-semibold text-ink-100 text-lg mb-2">No customers yet</h2>
          <p className="text-ink-500 text-sm mb-5 max-w-sm mx-auto font-mono">
            Add your first managed customer to start onboarding devices.
          </p>
          <button onClick={() => setAdding(true)}
                  className="px-5 py-2.5 rounded-lg bg-accent text-white text-[14px] font-semibold hover:brightness-110 transition-all">
            + Add Your First Customer
          </button>
        </div>
      ) : (
        <div className="card-glow">
          <div className="px-5 py-3.5 border-b border-base-500/60 flex flex-wrap items-center gap-3">
            <label className="block">
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Search</span>
              <input value={q} onChange={(e) => setQ(e.target.value)}
                     placeholder="name, email, country…"
                     className="mt-1 block bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent w-48 placeholder:text-ink-500/50" />
            </label>
            <span className="font-mono text-[10px] text-ink-500 self-end pb-0.5">{filtered.length} of {items.length} customers</span>
          </div>
          {filtered.length === 0 ? (
            <div className="p-8 text-center"><p className="text-ink-500 text-[13px] font-mono">No customers match your search.</p></div>
          ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                  <th className="py-3 px-4">Customer</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Email</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Country</th>
                  <th className="py-3 px-4 hidden md:table-cell">Devices</th>
                  <th className="py-3 px-4 w-10"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => (
                  <tr key={c.id} onClick={() => navigate(`/customers/${c.id}`)}
                      className="table-row border-b border-base-500/40 cursor-pointer hover:bg-base-700/30 transition-colors">
                    <td className="py-3 px-4">
                      <div className="text-ink-100 font-medium">{c.name}</div>
                      <div className="font-mono text-[10px] text-ink-500 mt-0.5">
                        {c.business_unit || c.location || c.timezone || "—"}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden lg:table-cell">{c.contact_email || "—"}</td>
                    <td className="py-3 px-4 text-ink-500 hidden lg:table-cell">{c.country || "—"}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden md:table-cell">{c.device_count ?? "—"}</td>
                    <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                      <button onClick={() => deleteCustomer(c)}
                              className="text-ink-500 hover:text-sev-high text-[11px] font-mono transition-colors">Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          )}
        </div>
      )}

      {/* ── Info modal ──────────────────────────────────────── */}
      {infoTitle && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => { setInfoTitle(""); setInfoBody(""); }} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={() => { setInfoTitle(""); setInfoBody(""); }}>
            <div className="w-full max-w-sm bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
                 onClick={(e) => e.stopPropagation()}>
              <h3 className="font-display font-semibold text-ink-100 text-lg">{infoTitle}</h3>
              <p className="text-ink-300 text-[13px]">{infoBody}</p>
              <div className="flex justify-end">
                <button onClick={() => { setInfoTitle(""); setInfoBody(""); }}
                        className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all">
                  OK
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function CustomerModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({
    name: "", primary_contact: "", contact_email: "",
    phone: "", country: "", timezone: "", location: "", business_unit: "", notes: "",
  });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function save() {
    if (!form.name.trim()) { setErr("Organization name is required."); return; }
    if (!form.contact_email.trim()) { setErr("Email address is required."); return; }
    setBusy(true); setErr(null);
    try {
      await api.createCustomerFull?.(form);
      onSaved();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    } finally { setBusy(false); }
  }

  const inp = "w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent placeholder:text-ink-500/40";
  const set = (f: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((s) => ({ ...s, [f]: e.target.value }));

  return (
    <>
      <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={onClose} />
      <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={onClose}>
        <div className="w-full max-w-[600px] max-h-[85vh] overflow-y-auto bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
             onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-display font-semibold text-ink-100 text-lg">Add Customer</h3>
              <p className="font-mono text-[11px] text-ink-500 mt-0.5">Managed client information</p>
            </div>
            <button onClick={onClose}
                    className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors text-lg leading-none">×</button>
          </div>

          {err && <p className="text-sev-high text-[12px] font-mono">{err}</p>}

          <div className="grid grid-cols-2 gap-3">
            <label className="block col-span-2"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Organization Name *</span><input value={form.name} onChange={set("name")} className={`${inp} mt-1`} /></label>
            <label className="block"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Primary Contact</span><input value={form.primary_contact} onChange={set("primary_contact")} className={`${inp} mt-1`} /></label>
            <label className="block"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Email Address *</span><input value={form.contact_email} onChange={set("contact_email")} type="email" className={`${inp} mt-1`} /></label>
            <label className="block"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Phone</span><input value={form.phone} onChange={set("phone")} type="tel" className={`${inp} mt-1`} /></label>
            <label className="block"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Country</span><input value={form.country} onChange={set("country")} className={`${inp} mt-1`} /></label>
            <label className="block"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Time Zone</span><input value={form.timezone} onChange={set("timezone")} className={`${inp} mt-1`} /></label>
            <label className="block"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Location</span><input value={form.location} onChange={set("location")} className={`${inp} mt-1`} /></label>
            <label className="block"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Business Unit</span><input value={form.business_unit} onChange={set("business_unit")} className={`${inp} mt-1`} /></label>
            <label className="block col-span-2"><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Notes</span><textarea value={form.notes} onChange={set("notes")} className={`${inp} mt-1`} rows={2} /></label>
          </div>

          <div className="flex items-center gap-3 pt-2 border-t border-base-500">
            <button onClick={save} disabled={busy}
                    className="px-5 py-2.5 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
              {busy ? "Creating…" : "Create Customer"}
            </button>
            <button onClick={onClose}
                    className="px-4 py-2 rounded-lg border border-base-500 text-ink-300 text-[13px] hover:text-ink-100 transition-colors">
              Cancel
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
