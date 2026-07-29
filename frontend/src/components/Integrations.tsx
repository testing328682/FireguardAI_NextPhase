import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { Integration } from "../lib/types";
import { Panel } from "./primitives";
import { fmtDate } from "../lib/ui";

const EVENTS = [
  { key: "new_critical", label: "New critical findings" },
  { key: "scan_failed", label: "Scan failures" },
  { key: "weekly_digest", label: "Weekly digest" },
];

// Integrations page. Phase 2 ships the Slack card; others follow the same shape.
export function Integrations() {
  const [items, setItems] = useState<Integration[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api.listIntegrations().then(setItems).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load integrations"));
  }, []);
  useEffect(() => { load(); }, [load]);

  const slack = items.find((i) => i.type === "slack");

  return (
    <div className="space-y-5">
      {err && <Panel title="Integrations"><p className="text-sev-high text-sm">{err}</p></Panel>}
      <SlackCard existing={slack} onChange={load} />
    </div>
  );
}

function SlackCard({ existing, onChange }: { existing?: Integration; onChange: () => void }) {
  const [webhook, setWebhook] = useState("");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [toggles, setToggles] = useState<Record<string, boolean>>(
    () => Object.fromEntries(EVENTS.map((e) => [e.key, (existing?.config as any)?.[e.key] ?? true])));
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setEnabled(existing?.enabled ?? true);
    setToggles(Object.fromEntries(EVENTS.map((e) => [e.key, (existing?.config as any)?.[e.key] ?? true])));
  }, [existing]);

  async function save() {
    setErr(null); setMsg(null);
    try {
      await api.saveIntegration({
        type: "slack", name: "Slack", enabled,
        webhook_url: webhook || undefined, config: toggles,
      });
      setWebhook("");
      setMsg("Saved.");
      onChange();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    }
  }

  async function test() {
    if (!existing) return;
    setErr(null); setMsg(null);
    try { await api.testIntegration(existing.id); setMsg("Test message sent."); onChange(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Test failed"); }
  }

  return (
    <Panel title="Slack" eyebrow="Integration"
           right={
             <span className="font-mono text-[11px]" style={{ color: existing?.has_secret ? "#39d98a" : "#7a879b" }}>
               {existing?.has_secret ? "configured" : "not configured"}
             </span>
           }>
      {err && <p className="text-sev-high text-[12px] mb-2">{err}</p>}
      {msg && <p className="text-signal text-[12px] mb-2">{msg}</p>}

      <label className="block mb-3">
        <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500">
          Incoming webhook URL {existing?.has_secret && "(leave blank to keep current)"}
        </span>
        <input value={webhook} onChange={(e) => setWebhook(e.target.value)}
               placeholder="https://hooks.slack.com/services/…"
               className="mt-1 w-full bg-base-700 border border-base-500 rounded-panel px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
      </label>

      <div className="space-y-1 mb-3">
        <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500">Notify on</span>
        {EVENTS.map((e) => (
          <label key={e.key} className="flex items-center justify-between py-1 cursor-pointer">
            <span className="text-[13px] text-ink-300">{e.label}</span>
            <input type="checkbox" checked={toggles[e.key]}
                   onChange={(ev) => setToggles((t) => ({ ...t, [e.key]: ev.target.checked }))} />
          </label>
        ))}
        <label className="flex items-center justify-between py-1 cursor-pointer">
          <span className="text-[13px] text-ink-300">Enabled</span>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        </label>
      </div>

      <div className="flex gap-2">
        <button onClick={save}
                className="px-3 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
          Save
        </button>
        {existing?.has_secret && (
          <button onClick={test}
                  className="px-3 py-2 rounded-panel border border-base-500 text-ink-300 text-[13px] hover:border-accent hover:text-accent">
            Send test
          </button>
        )}
      </div>
      {existing?.last_delivery_at && (
        <p className="font-mono text-[11px] text-ink-500 mt-2">
          Last delivery: {fmtDate(existing.last_delivery_at)} ({existing.last_status})
        </p>
      )}
    </Panel>
  );
}
