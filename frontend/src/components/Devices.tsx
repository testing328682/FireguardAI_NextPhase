import { useEffect, useLayoutEffect, useState, useCallback, useMemo, useRef } from "react";
import { useConfirm, usePrompt } from "./Modal";
import { api } from "../lib/api";
import type { Device, Customer, AnalysisSummary, ConnectStep, LicenseBundle } from "../lib/types";
import { UploadPanel } from "./UploadPanel";
import { navigate } from "../lib/router";
import { gradeColor, fmtDate } from "../lib/ui";

// ── Devices page ──────────────────────────────────────────────────────
export function Devices({ customers }: { customers: Customer[] }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [isMsp, setIsMsp] = useState(false);
  const confirm = useConfirm();
  const [customerFilter, setCustomerFilter] = useState("");
  const [searchQ, setSearchQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [licenseFilter, setLicenseFilter] = useState<string[]>([]);
  const [firmwareFilter, setFirmwareFilter] = useState<string[]>([]);
  const [postureFilter, setPostureFilter] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [regOpen, setRegOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // Config modal state
  const [configDeviceId, setConfigDeviceId] = useState<string | null>(null);
  // Decommissioned view
  const [showDecommissioned, setShowDecommissioned] = useState(false);
  const [decomDevices, setDecomDevices] = useState<Device[]>([]);

  useEffect(() => {
    api.getOrganization().then((o) => setIsMsp(o.is_msp)).catch(() => {});
  }, []);

  const load = useCallback(() => {
    api.listDevices().then(setDevices).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load"));
  }, []);
  useEffect(() => { load(); }, [load]);

  const loadDecommissioned = useCallback(() => {
    api.listDevicesDecommissioned().then(setDecomDevices).catch(() => {});
  }, []);
  useEffect(() => { if (showDecommissioned) loadDecommissioned(); }, [showDecommissioned, loadDecommissioned]);

  function licenseStatus(d: Device): string | null {
    if (!d.license_expiry) return null;
    return new Date(d.license_expiry) > new Date() ? "Active" : "Expired";
  }

  const allFirmwares = useMemo(() => {
    const fws = new Set<string>();
    for (const d of devices) if (d.firmware) fws.add(d.firmware);
    return [...fws].sort();
  }, [devices]);

  const allPostures = useMemo(() => {
    const grades = new Set<string>();
    for (const d of devices) if (d.configured && d.latest_grade) grades.add(d.latest_grade);
    return [...grades].sort();
  }, [devices]);

  const filtered = useMemo(() => {
    let d = devices;
    if (customerFilter) d = d.filter((dev) => dev.customer_id === customerFilter);
    if (statusFilter.length) d = d.filter((dev) => statusFilter.includes(dev.configured ? "Configured" : "Not Configured"));
    if (licenseFilter.length) d = d.filter((dev) => licenseFilter.includes(licenseStatus(dev) || ""));
    if (firmwareFilter.length) d = d.filter((dev) => firmwareFilter.includes(dev.firmware));
    if (postureFilter.length) d = d.filter((dev) => postureFilter.includes(dev.latest_grade));
    if (searchQ) {
      const q = searchQ.toLowerCase();
      d = d.filter((dev) =>
        (dev.friendly_name || "").toLowerCase().includes(q) ||
        (dev.model || "").toLowerCase().includes(q) ||
        (dev.serial || "").toLowerCase().includes(q)
      );
    }
    return d;
  }, [devices, customerFilter, statusFilter, licenseFilter, firmwareFilter, postureFilter, searchQ]);

  // Reset page when filters or page size change.
  const _filtersKey = `${customerFilter}|${statusFilter.join(",")}|${licenseFilter.join(",")}|${firmwareFilter.join(",")}|${postureFilter.join(",")}|${searchQ}|${pageSize}`;
  useEffect(() => { setPage(1); setSelected(new Set()); }, [_filtersKey]);  // eslint-disable-line react-hooks/exhaustive-deps

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const paginated = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, safePage, pageSize]);

  const customerName = (id: string) => customers.find((c) => c.id === id)?.name || id;

  const visibleSelected = useMemo(() => {
    const filteredIds = new Set(filtered.map((d) => d.id));
    return new Set([...selected].filter((id) => filteredIds.has(id)));
  }, [selected, filtered]);

  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function toggleAll() {
    const allIds = new Set(filtered.map((d) => d.id));
    const allSelected = filtered.every((d) => selected.has(d.id));
    setSelected(allSelected ? new Set() : allIds);
  }

  async function bulkDelete() {
    const ids = [...selected];
    if (ids.length === 0) return;
    const extra = selected.size !== visibleSelected.size
      ? ` (${visibleSelected.size} visible with current filters)` : "";
    if (!await confirm(`Delete ${ids.length} device${ids.length !== 1 ? "s" : ""}?${extra} This cannot be undone.`)) return;
    try {
      await api.deleteDevices(ids);
      setSelected(new Set());
      load();
    } catch (e) {
      alert(e instanceof Error ? e.message : "Bulk delete failed");
    }
  }

  return (
    <div className="max-w-[1440px] fade-in space-y-5">
      {/* ── Header ────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Devices</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">
            {filtered.length} device{filtered.length !== 1 ? "s" : ""}
            {customerFilter || searchQ ? " shown" : " onboarded"}
            {devices.filter(d => !d.configured).length > 0 && (
              <span className="ml-2 text-ink-300">
                · {devices.filter(d => !d.configured).length} not configured
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isMsp && (
            <label className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Customer</span>
              <select value={customerFilter} onChange={(e) => setCustomerFilter(e.target.value)}
                      className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                <option value="">All customers</option>
                {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
            </label>
          )}
          <label className="flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Search</span>
            <input value={searchQ} onChange={(e) => setSearchQ(e.target.value)}
                   placeholder="name, model, serial…"
                   className="bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent w-44 placeholder:text-ink-500/50" />
          </label>
          <button onClick={() => { setShowDecommissioned(!showDecommissioned); setSelected(new Set()); }}
                  className={`px-4 py-2 rounded-lg border text-[13px] font-medium transition-all ${
                    showDecommissioned
                      ? "border-[#c084fc55] text-[#c084fc] bg-[#c084fc10]"
                      : "border-base-500 text-ink-300 hover:text-ink-100"
                  }`}>
            {showDecommissioned ? "Active Devices" : "Decommissioned"}
          </button>
          <button onClick={() => setRegOpen(!regOpen)}
                  className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
            + Add Device
          </button>
        </div>
      </div>

      {/* ── Filter bar ─────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-end gap-3">
        <MultiSelect label="Status" values={statusFilter}
          onChange={setStatusFilter}
          options={["Configured", "Not Configured"]} />
        <MultiSelect label="License" values={licenseFilter}
          onChange={setLicenseFilter}
          options={["Active", "Expired"]} />
        <MultiSelect label="Firmware" values={firmwareFilter}
          onChange={setFirmwareFilter}
          options={allFirmwares} />
        <MultiSelect label="Posture" values={postureFilter}
          onChange={setPostureFilter}
          options={allPostures} />
        {(statusFilter.length > 0 || licenseFilter.length > 0 || firmwareFilter.length > 0 || postureFilter.length > 0 || customerFilter || searchQ) && (
          <button onClick={() => {
            setStatusFilter([]); setLicenseFilter([]); setFirmwareFilter([]); setPostureFilter([]);
            setCustomerFilter(""); setSearchQ(""); setSelected(new Set());
          }}
                  className="px-3 py-2 rounded-lg border border-base-500 text-ink-300 text-[12px] hover:text-accent hover:border-accent transition-all">
            Reset
          </button>
        )}
      </div>

      {/* ── Active filter chips ────────────────────────────────────── */}
      {[...statusFilter, ...licenseFilter, ...firmwareFilter, ...postureFilter].length > 0 && (
        <div className="flex flex-wrap gap-2">
          {[...statusFilter.map(v => ({ type: "Status", val: v })),
            ...licenseFilter.map(v => ({ type: "License", val: v })),
            ...firmwareFilter.map(v => ({ type: "Firmware", val: v })),
            ...postureFilter.map(v => ({ type: "Posture", val: v })),
          ].map(({ type, val }) => (
            <span key={`${type}-${val}`} className="badge flex items-center gap-1.5" style={{ color: "#4f8cff", borderColor: "#4f8cff55", background: "#4f8cff14" }}>
              {type}: {val}
              <button onClick={() => {
                if (type === "Status") setStatusFilter(statusFilter.filter(v => v !== val));
                if (type === "License") setLicenseFilter(licenseFilter.filter(v => v !== val));
                if (type === "Firmware") setFirmwareFilter(firmwareFilter.filter(v => v !== val));
                if (type === "Posture") setPostureFilter(postureFilter.filter(v => v !== val));
              }} className="text-ink-500 hover:text-sev-high leading-none text-[14px]">×</button>
            </span>
          ))}
        </div>
      )}

      {/* ── Decommissioned Devices view ────────────────────────────── */}
      {showDecommissioned && (
        <div className="card-glow">
          <div className="p-5 border-b border-base-500/40">
            <h2 className="font-display font-semibold text-sm text-ink-100">Decommissioned Devices</h2>
            <p className="font-mono text-[10px] text-ink-500 mt-0.5">
              {decomDevices.length} device{decomDevices.length !== 1 ? "s" : ""} · licenses remain consumed until expiry
            </p>
          </div>
          {decomDevices.length === 0 ? (
            <div className="p-16 text-center fade-in">
              <div className="text-5xl mb-4 opacity-30">🗄️</div>
              <h2 className="font-display font-semibold text-ink-100 text-lg mb-2">No decommissioned devices</h2>
              <p className="text-ink-500 text-sm max-w-sm mx-auto font-mono">
                Decommissioned configured devices will appear here. Their licenses remain consumed until expiry.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                    <th className="py-3 px-4">Device</th>
                    <th className="py-3 px-4">Serial</th>
                    <th className="py-3 px-4 hidden sm:table-cell">License</th>
                    <th className="py-3 px-4 hidden sm:table-cell">Expiry</th>
                    <th className="py-3 px-4 hidden md:table-cell">Decommissioned</th>
                    <th className="py-3 px-4 w-10"></th>
                  </tr>
                </thead>
                <tbody>
                  {decomDevices.map((d) => (
                    <tr key={d.id} className="table-row border-b border-base-500/40">
                      <td className="py-3 px-4">
                        <span className="text-ink-100 font-medium">{d.friendly_name || d.model || d.serial}</span>
                        <div className="font-mono text-[10px] text-ink-500 mt-0.5">{d.model || "—"}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-ink-300">{d.serial || "—"}</td>
                      <td className="py-3 px-4 hidden sm:table-cell">
                        {d.license_bundle === "Active (Trial)" ? (
                          <span className="badge" style={{ color: "#4a9eff", borderColor: "#4a9eff55", background: "#4a9eff14" }}>Active (Trial)</span>
                        ) : d.license_expiry && new Date(d.license_expiry) > new Date() ? (
                          <span className="badge" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>Active</span>
                        ) : (
                          <span className="badge" style={{ color: "#ff4d4d", borderColor: "#ff4d4d55", background: "#ff4d4d14" }}>Expired</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-[10px] hidden sm:table-cell">
                        {d.license_expiry ? (() => {
                          const exp = new Date(d.license_expiry);
                          const now = new Date();
                          const diffMs = exp.getTime() - now.getTime();
                          if (diffMs <= 0) return <span style={{ color: "#ff4d4d" }}>Expired</span>;
                          const days = Math.floor(diffMs / 86400000);
                          if (days >= 30) return <span style={{ color: "#39d98a" }}>{Math.floor(days / 30)}mo left</span>;
                          if (days >= 1) return <span style={{ color: days < 7 ? "#f5c451" : "#39d98a" }}>{days}d left</span>;
                          const hrs = Math.floor(diffMs / 3600000);
                          return <span style={{ color: "#f5c451" }}>{hrs}h left</span>;
                        })() : "—"}
                      </td>
                      <td className="py-3 px-4 font-mono text-[10px] text-ink-500 hidden md:table-cell">
                        {d.decommissioned_at ? fmtDate(d.decommissioned_at) : "—"}
                      </td>
                      <td className="py-3 px-4">
                        <button onClick={async () => {
                          if (!await confirm("Recommission Device", `Restore "${d.friendly_name || d.serial}" to active devices? The existing license assignment will be kept. The device must be reconfigured.`)) return;
                          try {
                            await api.recommissionDevice(d.id);
                            loadDecommissioned();
                            load();
                          } catch (e) {
                            alert(e instanceof Error ? e.message : "Recommission failed");
                          }
                        }}
                                title="Recommission"
                                className="px-3 py-1.5 rounded-lg border border-[#c084fc55] text-[#c084fc] text-[12px] font-medium hover:bg-[#c084fc10] transition-all whitespace-nowrap">
                          Recommission
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Normal device content (hidden when viewing decommissioned) ── */}
      {!showDecommissioned && (
        <>
      {/* ── Bulk action bar ────────────────────────────────────────── */}
      {visibleSelected.size > 0 && (
        <div className="card-glow p-3 flex items-center justify-between gap-4 fade-in"
             style={{ borderColor: "#4f8cff55", background: "#4f8cff08" }}>
          <span className="font-mono text-[13px] text-ink-100">
            {visibleSelected.size} device{visibleSelected.size !== 1 ? "s" : ""} selected
          </span>
          <button onClick={bulkDelete}
                  className="px-4 py-2 rounded-lg bg-[#ff4d4d] text-white text-[13px] font-semibold hover:brightness-110 transition-all">
            Delete Selected
          </button>
        </div>
      )}

      {/* ── Registration modal ────────────────────────────────────── */}
      {regOpen && (
        <>
          <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={() => setRegOpen(false)} />
          <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={() => setRegOpen(false)}>
            <div className="w-full max-w-[600px] bg-base-800 border border-base-500 rounded-xl shadow-xl"
                 onClick={(e) => e.stopPropagation()}>
              <RegisterPanel
                customers={customers}
                preselectedCustomerId={new URLSearchParams(window.location.hash.split("?")[1] || "").get("customer") || undefined}
                onComplete={() => { load(); setRegOpen(false); }}
                onCancel={() => setRegOpen(false)}
              />
            </div>
          </div>
        </>
      )}

      {err && (
        <div className="card-glow p-4 border-sev-high/30">
          <p className="text-sev-high text-[13px] font-mono">{err}</p>
        </div>
      )}

      {/* ── Device table ──────────────────────────────────────────── */}
      {filtered.length === 0 ? (
        devices.length > 0 ? (
          <div className="card-glow p-16 text-center fade-in">
            <div className="text-5xl mb-4 opacity-30">🔍</div>
            <h2 className="font-display font-semibold text-ink-100 text-lg mb-2">No matching devices found</h2>
            <p className="text-ink-500 text-sm mb-5 max-w-sm mx-auto font-mono">
              No devices match the selected filters. Try adjusting or clearing your filters.
            </p>
            <button onClick={() => {
              setStatusFilter([]); setLicenseFilter([]); setFirmwareFilter([]); setPostureFilter([]);
              setCustomerFilter(""); setSearchQ(""); setSelected(new Set());
            }}
                    className="px-5 py-2.5 rounded-lg border border-base-500 text-ink-300 text-[14px] hover:text-accent hover:border-accent transition-all">
              Clear all filters
            </button>
          </div>
        ) : (
          <div className="card-glow p-16 text-center fade-in">
            <div className="text-5xl mb-4 opacity-30">📡</div>
            <h2 className="font-display font-semibold text-ink-100 text-lg mb-2">No devices yet</h2>
            <p className="text-ink-500 text-sm mb-5 max-w-sm mx-auto font-mono">
              Register a device first, then configure it with a TSR upload or API connection.
            </p>
            <button onClick={() => setRegOpen(true)}
                    className="px-5 py-2.5 rounded-lg bg-accent text-white text-[14px] font-semibold hover:brightness-110 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
              + Add Your First Device
            </button>
          </div>
        )
      ) : (
        <div className="card-glow">
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
               <thead>
                <tr className="text-left font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 bg-base-800/50">
                  <th className="py-3 px-2 w-8">
                    <label className="flex items-center justify-center cursor-pointer" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={filtered.length > 0 && filtered.every((d) => selected.has(d.id))}
                             onChange={toggleAll}
                             className="accent-accent w-3.5 h-3.5 rounded" />
                    </label>
                  </th>
                  <th className="py-3 px-1 w-10 text-center">#</th>
                  <th className="py-3 px-4">Device</th>
                  <th className="py-3 px-4">Serial</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Customer</th>
                  <th className="py-3 px-4 hidden lg:table-cell">License</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Expiry</th>
                  <th className="py-3 px-4 hidden md:table-cell">Model</th>
                  <th className="py-3 px-4 hidden lg:table-cell">Firmware</th>
                  <th className="py-3 px-4 hidden md:table-cell">Last Analysis</th>
                  <th className="py-3 px-4">Posture</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4 w-10"></th>
                </tr>
              </thead>
              <tbody>
                {paginated.map((d, i) => (
                  <tr key={d.id}
                      onClick={() => { if (d.configured) navigate(`/devices/${d.id}`); else setConfigDeviceId(d.id); }}
                      className={`table-row border-b border-base-500/40 ${d.configured ? "cursor-pointer hover:bg-base-700/30" : "cursor-pointer hover:bg-base-700/30"} transition-colors`}>
                    <td className="py-3 px-2" onClick={(e) => e.stopPropagation()}>
                      <label className="flex items-center justify-center cursor-pointer">
                        <input type="checkbox" checked={selected.has(d.id)}
                               onChange={() => toggleOne(d.id)}
                               className="accent-accent w-3.5 h-3.5 rounded" />
                      </label>
                    </td>
                    <td className="py-3 px-1 text-center font-mono text-[11px] text-ink-500">{(safePage - 1) * pageSize + i + 1}</td>
                    <td className="py-3 px-4">
                      <span className={`font-medium ${d.configured ? "text-ink-100" : "text-ink-300"}`}>
                        {d.friendly_name || d.model || d.serial}
                      </span>
                      <div className="font-mono text-[10px] text-ink-500 mt-0.5">
                        {d.configured && (
                          <>{d.model || d.serial} · {d.connection_method === "api" ? "API" : "TSR"}</>
                        )}
                        {d.last_connection_status === "ok" && <span className="text-signal ml-1">●</span>}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-300">{d.serial || "—"}</td>
                    <td className="py-3 px-4">
                      {d.configured ? (
                        <span className="badge" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>
                          Configured
                        </span>
                      ) : (
                        <span className="badge" style={{ color: "#f5c451", borderColor: "#f5c45155", background: "#f5c45114" }}>
                          Not Configured
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px] text-ink-500 hidden lg:table-cell">
                      {customerName(d.customer_id)}
                    </td>
                    <td className="py-3 px-4 hidden lg:table-cell">
                      {d.license_bundle === "Active (Trial)" ? (
                        <span className="badge" style={{ color: "#4a9eff", borderColor: "#4a9eff55", background: "#4a9eff14" }}>Active (Trial)</span>
                      ) : d.license_bundle === "Expired (Trial)" ? (
                        <span className="badge" style={{ color: "#ff4d4d", borderColor: "#ff4d4d55", background: "#ff4d4d14" }}>Expired (Trial)</span>
                      ) : d.license_expiry ? (
                        new Date(d.license_expiry) > new Date() ? (
                          <span className="badge" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>Active</span>
                        ) : (
                          <span className="badge" style={{ color: "#ff4d4d", borderColor: "#ff4d4d55", background: "#ff4d4d14" }}>Expired</span>
                        )
                      ) : "—"}
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px] hidden lg:table-cell">
                      {d.license_expiry ? (() => {
                        const exp = new Date(d.license_expiry);
                        const now = new Date();
                        const diffMs = exp.getTime() - now.getTime();
                        const expired = diffMs <= 0;
                        if (expired) {
                          const dStr = exp.toISOString().replace("T", " ").slice(0, 19);
                          return <span style={{ color: "#ff4d4d" }} title={dStr}>Expired {dStr}</span>;
                        }
                        const mins = Math.floor(diffMs / 60000);
                        const hrs = Math.floor(mins / 60);
                        const days = Math.floor(hrs / 24);
                        let label: string;
                        if (days >= 30) label = `${Math.floor(days / 30)}mo left`;
                        else if (days >= 1) label = `${days}d left`;
                        else if (hrs >= 1) label = `${hrs}h left`;
                        else label = `${mins}m left`;
                        return <span style={{ color: days < 1 ? "#f5c451" : "#39d98a" }}>{label}</span>;
                      })() : "—"}
                    </td>
                    <td className="py-3 px-4 text-ink-300 hidden md:table-cell">{d.model || "—"}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden lg:table-cell">{d.firmware || "—"}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-ink-500 hidden md:table-cell">
                      {d.last_analysis_at ? fmtDate(d.last_analysis_at) : "—"}
                    </td>
                    <td className="py-3 px-4">
                      {d.configured ? (
                        <div className="flex items-center gap-1.5 min-w-[80px]">
                          <div className="h-1.5 flex-1 rounded-full bg-base-700 overflow-hidden">
                            <div className="h-full rounded-full transition-all duration-500"
                                 style={{ width: `${d.latest_score || 0}%`,
                                          background: gradeColor(d.latest_grade) }} />
                          </div>
                          <span className="font-display font-bold text-xs tabular-nums w-5 text-right"
                                style={{ color: gradeColor(d.latest_grade) }}>
                            {d.latest_grade || "—"}
                          </span>
                        </div>
                      ) : (
                        <span className="text-ink-500 text-[12px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {d.configured ? (
                        <div className="flex items-center gap-2">
                          <SevDot color="#ff4d4d" n={d.critical_count} />
                          <SevDot color="#ff8a3d" n={d.high_count} />
                          <SevDot color="#f5c451" n={d.medium_count} />
                          <SevDot color="#4a9eff" n={d.low_count} />
                        </div>
                      ) : (
                        <span className="text-ink-500 text-[12px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <DeviceMenu device={d} onUpdated={load} onConfigure={() => setConfigDeviceId(d.id)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Pagination (only for normal view, not decommissioned) ── */}
      {!showDecommissioned && filtered.length > pageSize && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px] text-ink-500">
              Showing <span className="text-ink-300">{(safePage - 1) * pageSize + 1}–{Math.min(safePage * pageSize, filtered.length)}</span> of <span className="text-ink-300">{filtered.length}</span>
            </span>
            <select value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))}
                    className="bg-base-800 border border-base-500 rounded px-2 py-1 text-[11px] text-ink-300 font-mono focus:outline-none focus:border-accent">
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={safePage <= 1}
                    className="px-3 py-1.5 rounded border border-base-500 text-[12px] text-ink-300 hover:text-accent hover:border-accent disabled:opacity-30 disabled:cursor-default transition-colors">
              Previous
            </button>
            {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
              let pageNum: number;
              if (totalPages <= 7) {
                pageNum = i + 1;
              } else if (safePage <= 4) {
                pageNum = i + 1;
              } else if (safePage >= totalPages - 3) {
                pageNum = totalPages - 6 + i;
              } else {
                pageNum = safePage - 3 + i;
              }
              return (
                <button key={pageNum}
                        onClick={() => setPage(pageNum)}
                        className={`w-8 h-8 grid place-items-center rounded text-[12px] font-mono transition-colors ${
                          pageNum === safePage
                            ? "bg-accent text-white"
                            : "text-ink-300 hover:text-accent hover:bg-base-700/50"
                        }`}>
                  {pageNum}
                </button>
              );
            })}
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={safePage >= totalPages}
                    className="px-3 py-1.5 rounded border border-base-500 text-[12px] text-ink-300 hover:text-accent hover:border-accent disabled:opacity-30 disabled:cursor-default transition-colors">
              Next
            </button>
          </div>
        </div>
      )}

      {/* ── Configure modal ──────────────────────────────────────── */}
      {configDeviceId && (
        <ConfigureModal
          deviceId={configDeviceId}
          customers={customers}
          onClose={() => setConfigDeviceId(null)}
          onConfigured={() => { load(); setConfigDeviceId(null); }}
        />
      )}
        </>
      )}
    </div>
  );
}

// ── Registration panel ───────────────────────────────────────────────
function RegisterPanel({ customers, preselectedCustomerId, onComplete, onCancel }: {
  customers: Customer[]; preselectedCustomerId?: string; onComplete: () => void; onCancel: () => void;
}) {
  const [customerId, setCustomerId] = useState(preselectedCustomerId || (customers[0]?.id ?? ""));
  const [deviceName, setDeviceName] = useState("");
  const [serial, setSerial] = useState("");
  const [confirmSerial, setConfirmSerial] = useState("");
  const [bundleIdx, setBundleIdx] = useState(0);
  const [bundles, setBundles] = useState<LicenseBundle[]>([]);
  const [bundlesFree, setBundlesFree] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    api.fetchLicenseBundles().then((res) => {
      setBundles(res.bundles);
      setBundlesFree(res.free);
      setBundleIdx(0);
    }).catch(() => {});
  }, []);

  async function register() {
    setErr(null); setMsg(null);
    if (!deviceName.trim()) { setErr("Device name is required."); return; }
    if (!serial.trim()) { setErr("Serial number is required."); return; }
    if (serial.trim() !== confirmSerial.trim()) {
      setErr("Serial numbers do not match. Please confirm the serial number."); return;
    }
    const selected = bundles[bundleIdx];
    if (!selected) { setErr("No license bundle selected."); return; }
    setBusy(true);
    try {
      const device = await api.registerDevice({
        customer_id: customerId,
        friendly_name: deviceName.trim(),
        serial: serial.trim(),
        license_purchase_id: selected.purchase_id,
      });
      setMsg(`Device "${device.friendly_name}" registered. Serial: ${device.serial}`);
      setDeviceName(""); setSerial(""); setConfirmSerial("");
      onComplete();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  const noLicenses = !bundlesFree && bundles.length === 0;

  return (
    <div className="p-5 space-y-4">
      <h3 className="font-display font-semibold text-sm text-ink-100">Register Device</h3>
      <p className="font-mono text-[11px] text-ink-500">
        Register this device first. You'll configure connectivity in a separate step.
      </p>

      <div className="flex flex-wrap items-end gap-3">
        <label className="block flex-1 min-w-[160px]">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Customer</span>
          <select value={customerId} onChange={(e) => setCustomerId(e.target.value)}
                  className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
            {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <label className="block flex-1 min-w-[160px]">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Device Name *</span>
          <input value={deviceName} onChange={(e) => setDeviceName(e.target.value)}
                 placeholder="e.g. HQ Firewall"
                 className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent placeholder:text-ink-500/40" />
        </label>
        <label className="block flex-1 min-w-[160px]">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Serial Number *</span>
          <input value={serial} onChange={(e) => setSerial(e.target.value)}
                 placeholder="e.g. S123456789"
                 className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 font-mono focus:outline-none focus:border-accent placeholder:text-ink-500/40" />
        </label>
        <label className="block flex-1 min-w-[160px]">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Confirm Serial *</span>
          <input value={confirmSerial} onChange={(e) => setConfirmSerial(e.target.value)}
                 placeholder="Re-type serial number"
                 className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 font-mono focus:outline-none focus:border-accent placeholder:text-ink-500/40" />
        </label>
      </div>

      {/* License bundle selection */}
      {bundles.length > 0 && (
        <label className="block">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">
            License Bundle{bundlesFree ? " (Free Plan)" : ""}
          </span>
          <select value={bundleIdx} onChange={(e) => setBundleIdx(Number(e.target.value))}
                  className="mt-1 block w-full max-w-sm bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
            {bundles.map((b, i) => (
              <option key={b.purchase_id || i} value={i} disabled={b.remaining <= 0}>
                {b.label}{b.expiry_date ? ` · expires ${new Date(b.expiry_date).toLocaleString()}` : ""}
              </option>
            ))}
          </select>
        </label>
      )}

      {bundles.length === 0 && !bundlesFree && (
        <div className="p-4 rounded-lg bg-base-800/50 border border-[#f5c45155] space-y-2">
          <p className="text-[#f5c451] text-[13px] font-mono">No licenses available</p>
          <p className="text-ink-500 text-[12px] font-mono">
            You have no available license bundles. Please purchase licenses from the Organization → Plan & Billing page.
          </p>
          <button onClick={() => navigate("/settings/organization")}
                  className="px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[12px] font-medium hover:bg-accent/20 transition-all">
            Purchase Licenses →
          </button>
        </div>
      )}

      {bundles.length === 0 && bundlesFree && (
        <div className="p-4 rounded-lg bg-base-800/50 border border-[#f5c45155] space-y-2">
          <p className="text-[#f5c451] text-[13px] font-mono">Free license expired or used</p>
          <p className="text-ink-500 text-[12px] font-mono">
            Your free license has been consumed or expired. Upgrade to a paid plan to add more devices.
          </p>
          <button onClick={() => navigate("/settings/organization")}
                  className="px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[12px] font-medium hover:bg-accent/20 transition-all">
            View Plans →
          </button>
        </div>
      )}

      {err && <p className="text-sev-high text-[12px] font-mono">{err}</p>}
      {msg && <p className="text-signal text-[12px] font-mono">{msg}</p>}

      <div className="flex items-center gap-3">
        <button onClick={register} disabled={busy || noLicenses}
                className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
          {noLicenses ? "No Licenses" : busy ? "Registering…" : "Register Device"}
        </button>
        <button onClick={onCancel}
                className="px-4 py-2 rounded-lg border border-base-500 text-[13px] text-ink-300 hover:text-ink-100 transition-colors">
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Configure modal ─────────────────────────────────────────────────
function ConfigureModal({ deviceId, customers, onClose, onConfigured }: {
  deviceId: string; customers: Customer[]; onClose: () => void; onConfigured: () => void;
}) {
  const [mode, setMode] = useState<"manual" | "api">("manual");
  const [device, setDevice] = useState<Device | null>(null);

  useEffect(() => {
    api.getDevice(deviceId).then(setDevice).catch(() => {});
  }, [deviceId]);

  return (
    <>
      <div className="fixed inset-0 z-30 bg-black/50 fade-in" onClick={onClose} />
      <div className="fixed inset-0 z-40 grid place-items-center p-4 fade-in" onClick={onClose}>
        <div className="w-full max-w-[640px] bg-base-800 border border-base-500 rounded-xl shadow-xl p-6 space-y-4"
             onClick={(e) => e.stopPropagation()}>
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-display font-semibold text-ink-100 text-lg">Configure Device</h3>
              <p className="font-mono text-[11px] text-ink-500 mt-0.5">
                {device?.friendly_name} · Serial: <span className="font-mono text-ink-300">{device?.serial}</span>
              </p>
            </div>
            <button onClick={onClose}
                    className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors text-lg leading-none">
              ×
            </button>
          </div>

          {/* Mode tabs */}
          <div className="flex gap-1 rounded-lg border border-base-500 p-0.5 w-fit">
            <button onClick={() => setMode("manual")}
                    className={`px-4 py-1.5 rounded-md text-[12px] font-medium transition-colors ${mode === "manual" ? "bg-accent text-white" : "text-ink-300 hover:text-accent"}`}>
              Upload TSR
            </button>
            <button onClick={() => setMode("api")}
                    className={`px-4 py-1.5 rounded-md text-[12px] font-medium transition-colors ${mode === "api" ? "bg-accent text-white" : "text-ink-300 hover:text-accent"}`}>
              Connect via API
            </button>
          </div>

          {/* Content */}
          {mode === "manual" ? (
            <UploadPanel customers={customers} deviceId={deviceId} customerId={device?.customer_id}
                         onComplete={(analysisId, analysis) => { onConfigured(); }} />
          ) : (
            <ConnectInline deviceId={deviceId} onConnected={onConfigured} />
          )}
        </div>
      </div>
    </>
  );
}

// ── Device row actions menu ────────────────────────────────────────────
function DeviceMenu({ device, onUpdated, onConfigure }: {
  device: Device; onUpdated: () => void; onConfigure: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState<React.CSSProperties>({});
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const confirm = useConfirm();
  const prompt = usePrompt();

  function openMenu(e: React.MouseEvent) {
    e.stopPropagation();
    if (open) { setOpen(false); return; }

    // Read button position BEFORE the menu enters the DOM so the table
    // layout is undisturbed. We set position:fixed immediately, which
    // keeps the menu out of document flow on every render.
    const rect = btnRef.current!.getBoundingClientRect();
    const menuW = 176; // w-44 = 11rem @ 16px base
    const gap = 4;
    const margin = 8;

    // Estimate menu height from item count to decide flip direction.
    // useLayoutEffect will correct it if the actual height differs.
    const estimatedH = !device.configured ? 152
      : device.connection_method === "api" ? 228 : 192;

    const left = Math.max(margin, Math.min(rect.right - menuW, window.innerWidth - menuW - margin));
    const spaceBelow = window.innerHeight - rect.bottom - gap - margin;
    const top = spaceBelow >= estimatedH || rect.top < estimatedH + gap + margin
      ? rect.bottom + gap
      : rect.top - estimatedH - gap;

    setMenuStyle({ position: "fixed", top: Math.max(margin, top), left, zIndex: 20 });
    setOpen(true);
  }

  // Fine-tune vertical position after render using the real menu height.
  // Fires synchronously before the browser paints — no visible flash.
  useLayoutEffect(() => {
    if (!open || !menuRef.current || !btnRef.current) return;
    const menuH = menuRef.current.offsetHeight;
    const rect = btnRef.current.getBoundingClientRect();
    const margin = 8;
    const gap = 4;
    setMenuStyle(prev => {
      const bottom = (prev.top as number) + menuH;
      if (bottom > window.innerHeight - margin) {
        return { ...prev, top: Math.max(margin, rect.top - menuH - gap) };
      }
      return prev;
    });
  }, [open]);

  // Close on scroll or resize — simpler and more reliable than recalculating.
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  async function rename() {
    const name = await prompt("Rename Device", device.friendly_name || "", "e.g. HQ Firewall");
    if (!name) return;
    try { await api.updateDevice(device.id, { friendly_name: name }); onUpdated(); }
    catch (e) { alert(e instanceof Error ? e.message : "Rename failed"); }
    setOpen(false);
  }

  async function deleteDev() {
    const name = device.friendly_name || device.model || device.serial;
    const everConfigured = device.was_ever_configured;
    const title = everConfigured ? "Decommission Device" : "Delete Device";
    const message = everConfigured
      ? `Decommission "${name}"? All data will be permanently removed but the license remains consumed until expiry. The device can be recommissioned later.`
      : `Delete "${name}"? This device was never configured, so its license will be released. This cannot be undone.`;
    if (!await confirm(title, message)) return;
    try { await api.deleteDevice(device.id); onUpdated(); }
    catch (e) { alert(e instanceof Error ? e.message : "Delete failed"); }
    setOpen(false);
  }

  return (
    <div className="relative">
      <button ref={btnRef} onClick={openMenu}
              className="w-8 h-8 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 hover:border-base-400 transition-colors text-lg leading-none">
        ⋯
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={(e) => { e.stopPropagation(); setOpen(false); }} />
          <div ref={menuRef}
               style={menuStyle}
               onClick={(e) => e.stopPropagation()}
               className="w-44 bg-base-800 border border-base-500 rounded-lg shadow-lg py-1">
            {!device.configured && (
              <button onClick={() => { setOpen(false); onConfigure(); }}
                      className="w-full text-left px-3 py-2 text-[13px] text-accent hover:bg-accent/10 transition-colors font-medium">
                Configure…
              </button>
            )}
            <button onClick={rename}
                    className="w-full text-left px-3 py-2 text-[13px] text-ink-300 hover:bg-accent/10 hover:text-accent transition-colors">Rename</button>
            {device.configured && (
              <button onClick={() => navigate(`/security-analytics/device-findings?device=${device.id}`)}
                      className="w-full text-left px-3 py-2 text-[13px] text-ink-300 hover:bg-accent/10 hover:text-accent transition-colors">View findings</button>
            )}
            {device.configured && (
              <button onClick={() => { navigate(`/devices/${device.id}`); setOpen(false); }}
                      className="w-full text-left px-3 py-2 text-[13px] text-ink-300 hover:bg-accent/10 hover:text-accent transition-colors">View details</button>
            )}
            {device.connection_method === "api" && device.configured && (
              <button onClick={async () => {
                try { await api.pullDevice?.(device.id); onUpdated(); }
                catch { /* */ }
                setOpen(false);
              }}
              className="w-full text-left px-3 py-2 text-[13px] text-ink-300 hover:bg-accent/10 hover:text-accent transition-colors">Pull now</button>
            )}
            <hr className="border-base-500 my-1" />
            <button onClick={deleteDev}
                    className="w-full text-left px-3 py-2 text-[13px] text-sev-high hover:bg-sev-high/10 transition-colors">{device.was_ever_configured ? "Decommission" : "Delete"}</button>
          </div>
        </>
      )}
    </div>
  );
}

// ── API Connect inline (for pre-registered device) ────────────────────
function ConnectInline({ deviceId, onConnected }: { deviceId: string; onConnected: () => void }) {
  const [hostname, setHostname] = useState("");
  const [port, setPort] = useState(443);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [verifyTls, setVerifyTls] = useState(false);
  const [savePassword, setSavePassword] = useState(true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [steps, setSteps] = useState<ConnectStep[]>([]);

  async function connect() {
    setBusy(true); setErr(null); setMsg(null); setSteps([]);
    try {
      const res = await api.connectDevice({
        device_id: deviceId, hostname, port, username, password,
        verify_tls: verifyTls, save_password: savePassword });
      setSteps(res.steps || []);
      if (res.connection_status === "ok") {
        setMsg(res.message || "Connected. TSR downloaded and analyzed.");
        setPassword("");
        onConnected();
      } else {
        const code = res.http_status ? ` (HTTP ${res.http_status})` : "";
        setErr((res.message || "Connection failed.") + code);
      }
    } catch (e) { setErr(e instanceof Error ? e.message : "Connection failed"); }
    finally { setBusy(false); }
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Hostname / IP</span>
          <input value={hostname} onChange={(e) => setHostname(e.target.value)}
                 className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
        </label>
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Port</span>
          <input type="number" value={port} onChange={(e) => setPort(Number(e.target.value))}
                 className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
        </label>
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Admin username</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)}
                 className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
        </label>
        <label className="block"><span className="font-mono text-[10px] text-ink-500">Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
        </label>
      </div>
      <label className="flex items-center gap-2 cursor-pointer select-none">
        <input type="checkbox" checked={verifyTls} onChange={(e) => setVerifyTls(e.target.checked)}
               className="accent-accent" />
        <span className="font-mono text-[11px] text-ink-300">Verify TLS certificate</span>
        <span className="font-mono text-[10px] text-ink-500">— leave off for self-signed appliance certificates</span>
      </label>
      <label className="flex items-center gap-2 cursor-pointer select-none">
        <input type="checkbox" checked={savePassword} onChange={(e) => setSavePassword(e.target.checked)}
               className="accent-accent" />
        <span className="font-mono text-[11px] text-ink-300">Save password</span>
        <span className="font-mono text-[10px] text-ink-500">— stored encrypted for future API pulls</span>
      </label>

      {err && <p className="text-sev-high text-[12px] font-mono">{err}</p>}
      {msg && <p className="text-signal text-[12px] font-mono">{msg}</p>}

      {steps.length > 0 && (
        <ul className="space-y-1 border border-base-500/50 rounded-lg p-3 bg-base-900/40">
          {steps.map((s, i) => (
            <li key={i} className="flex items-start gap-2 text-[12px]">
              <span style={{ color: s.status === "ok" ? "#39d98a" : s.status === "failed" ? "#ff4d4d"
                            : s.status === "warn" ? "#f5c451" : "#7a879b" }}>
                {s.status === "ok" ? "✓" : s.status === "failed" ? "✕" : s.status === "warn" ? "!" : "·"}
              </span>
              <span className="text-ink-200 font-medium min-w-[120px]">{s.step}</span>
              <span className="text-ink-500 font-mono text-[11px]">{s.detail}</span>
            </li>
          ))}
        </ul>
      )}

      <button onClick={connect} disabled={busy || !hostname || !username || !password}
              className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
        {busy ? "Connecting…" : "Test & Connect"}
      </button>
    </div>
  );
}

// ── Severity dot ──────────────────────────────────────────────────────
function SevDot({ color, n }: { color: string; n: number }) {
  return (
    <span className="inline-flex items-center gap-0.5 font-mono text-[10px] font-semibold tabular-nums"
          style={{ color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      {n}
    </span>
  );
}

// ── Multi-select helpers ────────────────────────────────────────────────
function toggleArray(arr: string[], val: string): string[] {
  return arr.includes(val) ? arr.filter((v) => v !== val) : [...arr, val];
}

function MultiSelect({ label, values, onChange, options, labels = {} }: {
  label: string; values: string[]; onChange: (vals: string[]) => void;
  options: readonly string[]; labels?: Record<string, string>;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const active = values.length > 0;
  const display = values.length === 0
    ? "All " + label.toLowerCase() + "s"
    : values.length === 1
      ? (labels[values[0]] || values[0])
      : `${values.length} selected`;

  return (
    <div ref={ref} className="relative">
      <label className="block">
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</span>
        <button onClick={() => setOpen(!open)}
                className={`mt-1 flex items-center gap-2 bg-base-800 border rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none transition-all min-w-[140px] ${
                  active ? "border-accent/50" : "border-base-500"
                }`}>
          <span className="flex-1 text-left truncate" style={active ? { color: "#4f8cff" } : {}}>
            {display}
          </span>
          <span className="text-ink-500 text-[10px]">{open ? "▲" : "▼"}</span>
        </button>
      </label>
      {open && (
        <div className="absolute z-20 mt-1 w-56 max-h-64 overflow-y-auto bg-base-800 border border-base-500 rounded-lg shadow-lg py-1">
          {options.map((opt) => {
            const checked = values.includes(opt);
            return (
              <label key={opt}
                     className="flex items-center gap-2 px-3 py-1.5 hover:bg-base-700/50 cursor-pointer text-[13px] text-ink-300"
                     onClick={() => onChange(toggleArray(values, opt))}>
                <span className={`w-4 h-4 flex items-center justify-center rounded border text-[10px] transition-colors ${
                  checked ? "bg-accent border-accent text-white" : "border-base-500 bg-base-900"
                }`}>
                  {checked ? "✓" : ""}
                </span>
                {labels[opt] || opt}
              </label>
            );
          })}
        </div>
      )}
    </div>
  );
}
