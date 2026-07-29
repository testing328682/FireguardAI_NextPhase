import { useEffect, useState, useCallback } from "react";
import { useConfirm } from "./Modal";
import { api } from "../lib/api";
import type { ApiToken } from "../lib/types";
import { Panel } from "./primitives";
import { fmtDate } from "../lib/ui";

// Programmatic API token management. The plaintext token is shown once.
export function ApiTokens() {
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [name, setName] = useState("");
  const [adminScope, setAdminScope] = useState(false);
  const [created, setCreated] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const confirm = useConfirm();

  const load = useCallback(() => {
    api.listTokens().then(setTokens).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load tokens"));
  }, []);
  useEffect(() => { load(); }, [load]);

  async function create() {
    setErr(null);
    try {
      const res = await api.createToken({ name, scopes: adminScope ? ["admin"] : [] });
      setCreated(res.token);
      setName("");
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Create failed");
    }
  }

  async function revoke(id: string) {
    if (!await confirm("Revoke Token", "Clients using this token will stop working immediately.")) return;
    await api.revokeToken(id);
    load();
  }

  return (
    <div className="space-y-5">
      <Panel title="Create API token" eyebrow="Programmatic access">
        {err && <p className="text-sev-high text-[12px] mb-2">{err}</p>}
        <div className="flex flex-wrap items-end gap-3">
          <label className="block">
            <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500">Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="CI pipeline"
                   className="mt-1 block bg-base-700 border border-base-500 rounded-panel px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
          </label>
          <label className="flex items-center gap-2 text-[13px] text-ink-300 pb-2">
            <input type="checkbox" checked={adminScope} onChange={(e) => setAdminScope(e.target.checked)} />
            admin scope
          </label>
          <button onClick={create} disabled={!name}
                  className="px-3 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90 disabled:opacity-50">
            Create token
          </button>
        </div>
        {created && (
          <div className="mt-4 bg-base-700 border border-signal/40 rounded-panel p-3">
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-signal mb-1">
              Copy this token now — it will not be shown again
            </div>
            <code className="font-mono text-[12px] text-ink-100 break-all">{created}</code>
            <div className="mt-2">
              <button onClick={() => setCreated(null)} className="font-mono text-[11px] text-ink-500 hover:text-ink-100">
                Dismiss
              </button>
            </div>
            <p className="font-mono text-[11px] text-ink-500 mt-2">
              Use as <code>Authorization: Bearer &lt;token&gt;</code>.
            </p>
          </div>
        )}
      </Panel>

      <Panel title="Active tokens" eyebrow="Tokens">
        {tokens.length === 0 ? (
          <p className="text-ink-500 text-sm">No tokens yet.</p>
        ) : (
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500 border-b border-base-500">
                <th className="py-2 pr-3">Name</th>
                <th className="py-2 pr-3">Prefix</th>
                <th className="py-2 pr-3">Scopes</th>
                <th className="py-2 pr-3">Last used</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2"></th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id} className="border-b border-base-500/60">
                  <td className="py-2 pr-3 text-ink-100">{t.name}</td>
                  <td className="py-2 pr-3 font-mono text-[11px] text-ink-500">fgat_{t.prefix}…</td>
                  <td className="py-2 pr-3 font-mono text-[11px] text-ink-500">{t.scopes.join(", ") || "—"}</td>
                  <td className="py-2 pr-3 font-mono text-[11px] text-ink-500">
                    {t.last_used_at ? fmtDate(t.last_used_at) : "never"}
                  </td>
                  <td className="py-2 pr-3">
                    <span style={{ color: t.revoked ? "#ff4d4d" : "#39d98a" }} className="font-mono text-[11px]">
                      {t.revoked ? "revoked" : "active"}
                    </span>
                  </td>
                  <td className="py-2 text-right">
                    {!t.revoked && (
                      <button onClick={() => revoke(t.id)} className="text-ink-500 hover:text-sev-high text-[12px]">
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
