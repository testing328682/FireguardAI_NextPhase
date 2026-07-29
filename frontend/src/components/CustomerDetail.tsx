import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { CustomerDetail, Device } from "../lib/types";
import { navigate } from "../lib/router";
import { fmtDate } from "../lib/ui";

export function CustomerDetailView({ id }: { id: string }) {
  const [customer, setCustomer] = useState<CustomerDetail | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api.listCustomers().then((cs) => {
      const c = (cs as CustomerDetail[]).find((x) => x.id === id);
      setCustomer(c || null);
    }).catch(() => setErr("Failed to load"));
    api.listDevices().then((ds) => {
      setDevices(ds.filter((d) => d.customer_id === id));
    }).catch(() => {});
  }, [id]);
  useEffect(() => { load(); }, [load]);

  if (err) return <div className="card-glow p-8 text-center"><p className="text-sev-high">{err}</p></div>;
  if (!customer) return <div className="min-h-[300px] grid place-items-center"><span className="animate-pulse text-ink-500">Loading…</span></div>;

  return (
    <div className="max-w-[1200px] fade-in space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <button onClick={() => navigate("/customers")} className="text-ink-500 hover:text-ink-100 text-[12px] font-mono mb-1 inline-block">← Customers</button>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">{customer.name}</h1>
        </div>
        <button onClick={() => navigate(`/devices?customer=${id}`)}
                className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all">
          + Register Device
        </button>
      </div>

      {/* Info card */}
      <div className="card-glow p-5">
        <h2 className="font-display font-semibold text-sm text-ink-100 mb-4">Customer Information</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
          <F label="Name" v={customer.name} />
          <F label="Primary Contact" v={customer.primary_contact} />
          <F label="Email" v={customer.contact_email} mono />
          <F label="Phone" v={customer.phone} />
          <F label="Country" v={customer.country} />
          <F label="Time Zone" v={customer.timezone} />
          <F label="Location" v={customer.location} />
          <F label="Business Unit" v={customer.business_unit} />
          <F label="Devices" v={String(devices.length)} />
          <F label="Notes" v={customer.notes || "—"} />
        </div>
      </div>

      {/* Devices */}
      <div className="card-glow">
        <div className="p-5 border-b border-base-500/40">
          <h2 className="font-display font-semibold text-sm text-ink-100">Devices</h2>
          <p className="font-mono text-[10px] text-ink-500 mt-0.5">{devices.length} device{devices.length !== 1 ? "s" : ""}</p>
        </div>
        {devices.length === 0 ? (
          <div className="p-8 text-center"><p className="text-ink-500 text-[13px] font-mono">No devices registered for this customer.</p></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                  <th className="py-3 px-4">Device</th>
                  <th className="py-3 px-4">Serial</th>
                  <th className="py-3 px-4 hidden md:table-cell">Model</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Firmware</th>
                  <th className="py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id} onClick={() => navigate(`/devices/${d.id}`)}
                      className="table-row border-b border-base-500/40 cursor-pointer hover:bg-base-700/30">
                    <td className="py-3 px-4 text-ink-100 font-medium">{d.friendly_name || d.model || d.serial}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500">{d.serial}</td>
                    <td className="py-3 px-4 text-ink-300 hidden md:table-cell">{d.model || "—"}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden lg:table-cell">{d.firmware || "—"}</td>
                    <td className="py-3 px-4">
                      {d.configured ? <span className="badge" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>Configured</span>
                        : <span className="badge" style={{ color: "#f5c451", borderColor: "#f5c45155", background: "#f5c45114" }}>Not Configured</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function F({ label, v, mono }: { label: string; v: string; mono?: boolean }) {
  return (
    <div>
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-0.5">{label}</div>
      <div className={`text-[13px] text-ink-100 ${mono ? "font-mono" : ""}`}>{v || "—"}</div>
    </div>
  );
}
