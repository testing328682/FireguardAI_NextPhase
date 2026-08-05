/**
 * Advanced Dashboard — Phase 1: Toolbar.
 *
 * Filter / action bar below the page title.  No widgets yet.
 */
import { useEffect, useState, useCallback, useRef } from "react";
import { api } from "../lib/api";
import type { Customer } from "../lib/types";

// ── Time ranges ───────────────────────────────────────────────────────────
interface Range { label: string; days: number }
const RANGES: Range[] = [
  { label: "Today", days: 1 },
  { label: "Last 7 Days", days: 7 },
  { label: "Last 30 Days", days: 30 },
  { label: "Last 90 Days", days: 90 },
  { label: "Last 365 Days", days: 365 },
];
const CUSTOM_RANGE: Range = { label: "Custom Range", days: -1 };

// ── Helpers ───────────────────────────────────────────────────────────────
function fmtTime(d: Date) {
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" }) + ", " +
    d.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", hour12: true });
}

// ── Icons (inline SVGs) ───────────────────────────────────────────────────
const ICON = {
  org: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>,
  calendar: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>,
  refresh: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>,
  customize: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>,
  search: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  chevron: <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>,
};

// ── Shared button & input base ────────────────────────────────────────────
const btnBase = "inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border text-[12px] font-mono transition-all";
const selectBase = "bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[12px] font-mono text-ink-300 focus:outline-none focus:border-accent appearance-none cursor-pointer";

// ── Customer Filter (MSP only) ────────────────────────────────────────────
function CustomerFilter({ customers, value, onChange }: {
  customers: Customer[]; value: string; onChange: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);

  const filtered = customers.filter((c) => c.name.toLowerCase().includes(q.toLowerCase()));
  const selected = value === "" ? "All Customers" : (customers.find((c) => c.id === value)?.name || "All Customers");

  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen(!open)} className={`${btnBase} border-base-500 text-ink-300 hover:border-accent hover:text-accent min-w-[180px] justify-between`}>
        <span className="flex items-center gap-1.5">
          <span className="text-ink-500">{ICON.org}</span>
          <span className="truncate max-w-[160px]">{selected}</span>
        </span>
        {ICON.chevron}
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-1 w-64 bg-base-800 border border-base-500 rounded-xl shadow-xl z-50 overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2 border-b border-base-500/40">
            {ICON.search}
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search customers…"
                   className="flex-1 bg-transparent text-[12px] text-ink-200 placeholder:text-ink-600 focus:outline-none font-mono" />
          </div>
          <div className="max-h-56 overflow-y-auto">
            <button onClick={() => { onChange(""); setOpen(false); }}
                    className={`w-full text-left px-3 py-2 text-[12px] font-mono hover:bg-accent/10 transition-colors ${value === "" ? "text-accent" : "text-ink-300"}`}>
              All Customers
            </button>
            {filtered.map((c) => (
              <button key={c.id} onClick={() => { onChange(c.id); setOpen(false); }}
                      className={`w-full text-left px-3 py-2 text-[12px] font-mono hover:bg-accent/10 transition-colors ${value === c.id ? "text-accent" : "text-ink-300"}`}>
                {c.name}
              </button>
            ))}
            {filtered.length === 0 && (
              <p className="px-3 py-4 text-[12px] text-ink-600 text-center font-mono">No customers match</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function TimeRangeFilter({ value, onChange }: { value: Range; onChange: (r: Range) => void }) {
  return (
    <div className={`${btnBase} border-base-500 text-ink-300 gap-2 cursor-pointer`}>
      <span className="text-ink-500">{ICON.calendar}</span>
      <select value={value.days} onChange={(e) => {
        const v = Number(e.target.value);
        const found = [...RANGES, CUSTOM_RANGE].find((r) => r.days === v);
        if (found) onChange(found);
      }} className={selectBase + " !text-ink-300 !border-none !bg-transparent !px-0 !py-0 focus:!outline-none cursor-pointer"}>
        {RANGES.map((r) => <option key={r.days} value={r.days}>{r.label}</option>)}
        <option value={CUSTOM_RANGE.days}>Custom Range</option>
      </select>
      {ICON.chevron}
    </div>
  );
}

function LastUpdated({ date }: { date: Date | null }) {
  if (!date) return null;
  return (
    <span className="text-[11px] text-ink-600 font-mono">
      Last Updated<br /><span className="text-ink-500">{fmtTime(date)}</span>
    </span>
  );
}

function RefreshButton({ onClick }: { onClick: () => void }) {
  return (
    <button onClick={onClick} className={`${btnBase} border-base-500 text-ink-400 hover:text-accent hover:border-accent`} title="Refresh dashboard">
      {ICON.refresh}
      <span>Refresh</span>
    </button>
  );
}

function CustomizeButton() {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <button onClick={() => setShow(!show)} className={`${btnBase} border-base-500 text-ink-400 hover:text-accent hover:border-accent`}>
        {ICON.customize}
        <span>Customize</span>
      </button>
      {show && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setShow(false)} />
          <div className="absolute right-0 top-full mt-2 bg-base-800 border border-base-500 rounded-xl shadow-xl z-40 px-5 py-4 w-56">
            <p className="text-[13px] text-ink-300 font-mono text-center">Coming Soon</p>
          </div>
        </>
      )}
    </div>
  );
}

// ── Toolbar ───────────────────────────────────────────────────────────────
function DashboardToolbar({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 py-3">
      {children}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────
export function AdvancedDashboard() {
  const [isMsp, setIsMsp] = useState(false);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [customerId, setCustomerId] = useState("");
  const [range, setRange] = useState<Range>(RANGES[2]); // default: Last 30 Days
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    api.getOrganization().then((o) => {
      setIsMsp(!!(o as any).is_msp);
    }).catch(() => {});
    api.listCustomers().then(setCustomers).catch(() => {});
  }, []);

  const refresh = useCallback(() => {
    setLastUpdated(new Date());
    // Widgets will add their own data fetching here in Phase 2.
  }, [customerId, range]);

  useEffect(() => { refresh(); }, [refresh]);

  return (
    <div className="max-w-[1440px] fade-in space-y-5 pb-8">
      {/* ── Page title ──────────────────────────────────────────────────── */}
      <div>
        <h1 className="font-display text-[22px] font-semibold text-ink-100 tracking-tight">Advanced Security Dashboard</h1>
        <p className="text-ink-500 text-[12px] mt-0.5">Comprehensive security posture and risk analytics</p>
      </div>

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <DashboardToolbar>
        <div className="flex flex-wrap items-center gap-3">
          {isMsp && (
            <CustomerFilter customers={customers} value={customerId} onChange={setCustomerId} />
          )}
          <TimeRangeFilter value={range} onChange={setRange} />
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <LastUpdated date={lastUpdated} />
          <RefreshButton onClick={refresh} />
          <CustomizeButton />
        </div>
      </DashboardToolbar>
    </div>
  );
}
