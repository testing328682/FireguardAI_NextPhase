import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { PageControlItem } from "../lib/types";

// ── Page Control (superadmin) ────────────────────────────────────────────
// Central Server Admin page for enabling/disabling customer-facing pages and
// features. New entries are added backend-side (PAGE_CONTROL_CATALOG) and show
// up here automatically — no frontend changes required per page.
export function PageControl() {
  const [items, setItems] = useState<PageControlItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setErr(null);
    try {
      setItems(await api.listPageControls());
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load page controls");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function toggle(it: PageControlItem) {
    setBusyKey(it.key);
    setErr(null);
    setMsg(null);
    try {
      const updated = await api.updatePageControl(it.key, !it.enabled);
      setItems((list) => list.map((x) => (x.key === updated.key ? updated : x)));
      setMsg(`${updated.label} ${updated.enabled ? "enabled" : "disabled"}.`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Update failed");
    } finally {
      setBusyKey(null);
    }
  }

  return (
    <div className="space-y-4">
      {err && (
        <div className="rounded-lg border border-sev-high/30 bg-sev-high/5 px-3 py-2 font-mono text-[12px] text-sev-high">
          {err}
        </div>
      )}
      {msg && (
        <div className="rounded-lg border border-signal/30 bg-signal/5 px-3 py-2 font-mono text-[12px] text-signal">
          {msg}
        </div>
      )}
      {loading ? (
        <p className="font-mono text-ink-500 text-sm animate-pulse">Loading…</p>
      ) : (
        <div className="space-y-3">
          {items.map((it) => (
            <div key={it.key} className="card-glow">
              <div className="flex flex-wrap items-center justify-between gap-4 p-5">
                <div className="min-w-0">
                  <div className="font-display font-semibold text-sm text-ink-100">{it.label}</div>
                  <p className="font-mono text-[11px] text-ink-500 mt-1">{it.description}</p>
                </div>
                <button
                  onClick={() => toggle(it)}
                  disabled={busyKey === it.key}
                  title={it.enabled ? "Disable this page for customers" : "Enable this page for customers"}
                  className={`shrink-0 inline-flex items-center gap-2.5 px-3 py-2 rounded-lg border text-[12px] font-semibold transition-all ${
                    it.enabled
                      ? "border-signal/40 text-signal bg-signal/10"
                      : "border-base-500 text-ink-400 hover:border-accent hover:text-ink-200"
                  } disabled:opacity-60`}>
                  <span className={`relative w-10 h-5 rounded-full transition-colors ${it.enabled ? "bg-signal" : "bg-base-700"}`}>
                    <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${it.enabled ? "translate-x-5" : ""}`} />
                  </span>
                  {busyKey === it.key ? "Saving…" : it.enabled ? "Enabled" : "Disabled"}
                </button>
              </div>
            </div>
          ))}
          {items.length === 0 && (
            <p className="font-mono text-ink-500 text-sm">No controllable pages configured yet.</p>
          )}
        </div>
      )}
    </div>
  );
}