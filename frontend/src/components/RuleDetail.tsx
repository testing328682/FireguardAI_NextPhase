import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { Rule, RuleTestResult, Suppression, User } from "../lib/types";
import { navigate } from "../lib/router";
import { Panel } from "./primitives";
import { sevColor, fmtDate } from "../lib/ui";
import { STATE_COLOR } from "./Rules";
import { useConfirm, usePrompt } from "./Modal";

type Tab = "overview" | "condition" | "test" | "history" | "overrides";
const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "condition", label: "Condition" },
  { key: "test", label: "Test" },
  { key: "history", label: "History" },
  { key: "overrides", label: "Overrides" },
];

export function RuleDetail({ id, user }: { id: string; user: User }) {
  const [rule, setRule] = useState<Rule | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api.getRule(id).then(setRule).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load rule"));
  }, [id]);
  useEffect(() => { load(); }, [load]);

  if (err && !rule) return <Panel title="Rule"><p className="text-sev-high text-sm">{err}</p></Panel>;
  if (!rule) return <Panel title="Rule"><p className="font-mono text-ink-500 animate-pulse text-sm">Loading…</p></Panel>;

  const isCustom = rule.source === "custom";
  // System rules are editable by platform superadmins.
  const isSystemEditable = rule.source === "system" && user?.is_superadmin;
  const editable = isCustom || isSystemEditable;
  const confirm = useConfirm();

  async function stateChange(action: "submit" | "approve") {
    try { setRule(await api.ruleStateChange(id, action)); }
    catch (e) { setErr(e instanceof Error ? e.message : "Action failed"); }
  }

  async function deleteRule() {
    if (!await confirm("Delete Rule", `Remove "${rule?.key}"? This cannot be undone.`)) return;
    setErr(null);
    try {
      await api.deleteRule(id);
      navigate("/rules");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Delete failed");
    }
  }

  return (
    <div className="space-y-5">
      <button onClick={() => navigate("/rules")} className="font-mono text-[12px] text-ink-300 hover:text-accent">
        ← Back to rules
      </button>

      <Panel eyebrow={rule.key} title={rule.title}
             right={
               <div className="flex items-center gap-2">
                 <span className="font-mono text-[11px]" style={{ color: STATE_COLOR[rule.state] }}>{rule.state}</span>
                 {isCustom && rule.state === "draft" && (
                   <Btn onClick={() => stateChange("submit")}>Submit</Btn>
                 )}
                  {isCustom && rule.state === "submitted" && (
                    <Btn onClick={() => stateChange("approve")}>Approve</Btn>
                  )}
                  {editable && (
                    <Btn onClick={deleteRule}>
                      <span className="text-sev-high">Delete</span>
                    </Btn>
                  )}
                </div>
             }>
        <div className="flex gap-1 border-b border-base-500 mb-4">
          {TABS.map((t) => (
            <button key={t.key} onClick={() => setTab(t.key)}
                    className={`px-3 py-2 text-[13px] border-b-2 -mb-px ${
                      tab === t.key ? "border-accent text-accent" : "border-transparent text-ink-300 hover:text-ink-100"
                    }`}>
              {t.label}
            </button>
          ))}
        </div>

        {err && <p className="text-sev-high text-[13px] mb-3">{err}</p>}

        {isCustom && rule.state !== "approved" && (
          <div className="mb-4 rounded-panel border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-[12px] text-ink-300">
            This rule is <span className="font-semibold" style={{ color: STATE_COLOR[rule.state] }}>{rule.state}</span> and
            does <span className="font-semibold">not</span> evaluate during scans yet.
            {rule.state === "draft" && " Click Submit, then Approve."}
            {rule.state === "submitted" && " An admin must Approve it."}
          </div>
        )}
        {isSystemEditable && (
          <div className="mb-4 rounded-panel border border-accent/40 bg-accent/10 px-3 py-2 text-[12px] text-ink-300">
            You are editing a built-in system rule as a platform operator.
            Changes take effect immediately on the next scan.
          </div>
        )}

        {tab === "overview" && <Overview rule={rule} editable={editable} onSaved={setRule} />}
        {tab === "condition" && <Condition rule={rule} editable={editable} onSaved={setRule} />}
        {tab === "test" && <TestTab rule={rule} />}
        {tab === "history" && <History rule={rule} />}
        {tab === "overrides" && <Overrides rule={rule} />}
      </Panel>
    </div>
  );
}

function Overview({ rule, editable, onSaved }: { rule: Rule; editable: boolean; onSaved: (r: Rule) => void }) {
  return (
    <dl className="grid grid-cols-[140px_1fr] gap-y-2 text-[13px]">
      <dt className="text-ink-500">Severity</dt>
      <dd style={{ color: sevColor[rule.severity] }} className="font-semibold">{rule.severity}</dd>
      <dt className="text-ink-500">Category</dt><dd className="text-ink-100">{rule.category}</dd>
      <dt className="text-ink-500">Source</dt><dd className="text-ink-100">{rule.source}</dd>
      <dt className="text-ink-500">Version</dt><dd className="text-ink-100">v{rule.current_version}</dd>
      <dt className="text-ink-500">Description</dt><dd className="text-ink-300">{rule.description || "—"}</dd>
      <dt className="text-ink-500">Remediation</dt><dd className="text-ink-300">{rule.remediation || "—"}</dd>
      <dt className="text-ink-500">Compliance</dt>
      <dd className="text-ink-300 font-mono text-[11px]">
        {Object.keys(rule.compliance || {}).length
          ? Object.entries(rule.compliance).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ")
          : "—"}
      </dd>
      {!editable && (
        <dd className="col-span-2 font-mono text-[11px] text-ink-500 mt-2">
          System rules are read-only. Use the Overrides tab to disable or change severity for your tenant.
        </dd>
      )}
    </dl>
  );
}

function Condition({ rule, editable, onSaved }: { rule: Rule; editable: boolean; onSaved: (r: Rule) => void }) {
  const [cond, setCond] = useState(rule.condition);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  if (!editable) {
    return (
      <div className="space-y-3">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-500 mb-1">Detection logic</div>
          <p className="text-[13px] text-ink-300 leading-relaxed">
            {rule.description || `Fires when the configuration shows: ${rule.title}.`}
          </p>
        </div>
        {rule.condition && (
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-500 mb-1">CEL equivalent</div>
            <pre className="bg-base-900 border border-base-500 rounded-panel p-3 font-mono text-[12px] text-ink-300 whitespace-pre-wrap">
              {rule.condition}
            </pre>
          </div>
        )}
        <p className="font-mono text-[11px] text-ink-500">
          This is a built-in rule evaluated by the analysis engine. To customize detection,
          create a custom CEL rule or add a tenant override.
        </p>
      </div>
    );
  }

  async function save() {
    setErr(null); setSaved(false);
    try {
      onSaved(await api.updateRule(rule.id, { condition: cond, change_note: "Edited condition" }));
      setSaved(true);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    }
  }

  return (
    <div className="space-y-3">
      <p className="font-mono text-[11px] text-ink-500">
        CEL expression evaluated against <code>snapshot</code>. Must return a boolean.
      </p>
      <textarea value={cond} onChange={(e) => setCond(e.target.value)} rows={4}
                className="w-full bg-base-900 border border-base-500 rounded-panel p-3 font-mono text-[12px] text-ink-100 focus:outline-none focus:border-accent" />
      {err && <p className="text-sev-high text-[12px]">{err}</p>}
      {saved && <p className="text-signal text-[12px]">
        {rule.source === "system"
          ? "Saved — changes take effect on the next scan."
          : "Saved — rule returned to Draft for re-approval."}
      </p>}
      <button onClick={save}
              className="px-3 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
        Save condition
      </button>
    </div>
  );
}

function TestTab({ rule }: { rule: Rule }) {
  const [analysisId, setAnalysisId] = useState("");
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    setErr(null); setResult(null);
    try {
      setResult(await api.testRule(rule.id, { analysis_id: analysisId || undefined }));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Test failed");
    }
  }

  return (
    <div className="space-y-3">
      <p className="font-mono text-[11px] text-ink-500">
        Evaluate this rule against a prior analysis snapshot. Paste an analysis ID.
      </p>
      <div className="flex gap-2">
        <input value={analysisId} onChange={(e) => setAnalysisId(e.target.value)} placeholder="analysis id"
               className="flex-1 bg-base-900 border border-base-500 rounded-panel px-3 py-2 text-[13px] font-mono text-ink-100 focus:outline-none focus:border-accent" />
        <button onClick={run} className="px-4 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
          Evaluate
        </button>
      </div>
      {err && <p className="text-sev-high text-[12px]">{err}</p>}
      {result && (
        <div className="bg-base-900 border border-base-500 rounded-panel p-3 text-[13px]">
          {result.error ? (
            <span className="text-sev-high font-mono text-[12px]">{result.error}</span>
          ) : (
            <span style={{ color: result.fired ? "#ff8a3d" : "#39d98a" }} className="font-semibold">
              {result.fired ? "● Rule FIRES on this snapshot" : "○ Rule does not fire"}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function History({ rule }: { rule: Rule }) {
  const versions = (rule.versions || []).slice().sort((a, b) => b.version - a.version);
  if (versions.length === 0) return <p className="text-ink-500 text-sm">No version history.</p>;
  return (
    <ol className="space-y-3">
      {versions.map((v) => (
        <li key={v.version} className="border-l-2 border-base-500 pl-3">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[12px] text-accent">v{v.version}</span>
            <span className="text-ink-100 text-[13px]">{v.change_note || "—"}</span>
          </div>
          <pre className="mt-1 font-mono text-[11px] text-ink-500 whitespace-pre-wrap">{v.condition}</pre>
          <span className="font-mono text-[10px] text-ink-500">{fmtDate(v.edited_at)}</span>
        </li>
      ))}
    </ol>
  );
}

function Overrides({ rule }: { rule: Rule }) {
  const [items, setItems] = useState<Suppression[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const prompt = usePrompt();

  const load = useCallback(() => {
    api.listSuppressions(rule.key).then(setItems).catch(() => setItems([]));
  }, [rule.key]);
  useEffect(() => { load(); }, [load]);

  async function disable() {
    setErr(null);
    const reason = await prompt("Disable Rule", "", "Reason for disabling this rule for your tenant");
    if (!reason) return;
    try { await api.createSuppression({ rule_key: rule.key, action: "disable", reason }); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  async function override() {
    setErr(null);
    const value = await prompt("Override Severity", "", "Critical / High / Medium / Low / Info");
    if (!value) return;
    const reason = await prompt("Override Reason", "", "Reason for overriding") || "";
    try { await api.createSuppression({ rule_key: rule.key, action: "override_severity", value, reason }); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  async function remove(idv: string) {
    await api.deleteSuppression(idv); load();
  }

  return (
    <div className="space-y-3">
      {err && <p className="text-sev-high text-[12px]">{err}</p>}
      <div className="flex gap-2">
        <Btn onClick={disable}>Disable for tenant</Btn>
        <Btn onClick={override}>Override severity</Btn>
      </div>
      {items.length === 0 ? (
        <p className="text-ink-500 text-sm">No active overrides for this rule.</p>
      ) : (
        <ul className="space-y-2">
          {items.map((s) => (
            <li key={s.id} className="flex items-center justify-between bg-base-900 border border-base-500 rounded-panel px-3 py-2 text-[13px]">
              <span className="text-ink-100">
                {s.action === "disable" ? "Disabled" : `Severity → ${s.value}`}
                {s.device_id ? " (one device)" : " (tenant-wide)"}
                {s.reason && <span className="text-ink-500"> · {s.reason}</span>}
              </span>
              <button onClick={() => remove(s.id)} className="text-ink-500 hover:text-sev-high text-[12px]">Remove</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Btn({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button onClick={onClick}
            className="px-2.5 py-1 rounded-panel border border-base-500 text-ink-300 text-[12px] hover:border-accent hover:text-accent">
      {children}
    </button>
  );
}
