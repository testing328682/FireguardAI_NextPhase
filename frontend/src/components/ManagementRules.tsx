import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import type {
  ManagementCondition, ManagementRule, ManagementRuleOptions, ManagementTestResult,
} from "../lib/types";
import { SEVERITIES, RULE_CATEGORIES, sevColor } from "../lib/ui";
import { useConfirm } from "./Modal";

// Structured, reference-resolving detection rules for firewall management
// access. Unlike the CEL Rule Builder (direct value comparisons), semantic
// conditions such as "Destination matches All Interface IPs" resolve the
// access rule's address references through the TSR's address objects and
// nested groups, then compare the concrete addresses against interface IPs.

const FIELD_LABELS: Record<string, string> = {
  src_zone: "Source Zone", dst_zone: "Destination Zone", action: "Action",
  service: "Service Name", src: "Source Name", dst: "Destination Name",
  name: "Rule Name", comment: "Comment", ipver: "IP Version",
  enabled: "Enabled", management: "Management Flag", auto_rule: "Auto Rule",
  src_address: "Source Address (resolved)", dst_address: "Destination Address (resolved)",
  service_ports: "Service (resolved)",
};
// Fields whose value accepts the "*" wildcard with an obvious quick-select.
const ZONE_FIELDS = new Set(["src_zone", "dst_zone"]);
const OPERATOR_LABELS: Record<string, string> = {
  equals: "is", not_equals: "is not", contains: "contains",
  not_contains: "does not contain",
  is: "matches", is_not: "does not match",
};

const inputCls = "mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-all";
const labelCls = "font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500";

const DEFAULT_CONDITIONS: ManagementCondition[] = [
  { field: "src_zone", operator: "equals", value: "WAN", target: "" },
  { field: "dst_zone", operator: "equals", value: "WAN", target: "" },
  { field: "dst_address", operator: "is", value: "", target: "all_interface_ips" },
];

interface Draft {
  id: string | null;
  key: string;
  title: string;
  severity: string;
  category: string;
  description: string;
  remediation: string;
  enabled: boolean;
  conditions: ManagementCondition[];
}

const emptyDraft = (): Draft => ({
  id: null, key: "", title: "", severity: "Medium", category: "Firewall Management",
  description: "", remediation: "", enabled: true,
  conditions: DEFAULT_CONDITIONS.map((c) => ({ ...c })),
});

export function ManagementRules() {
  const [rules, setRules] = useState<ManagementRule[]>([]);
  const [options, setOptions] = useState<ManagementRuleOptions | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ManagementTestResult | null>(null);
  const [testErr, setTestErr] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const confirm = useConfirm();

  const load = useCallback(() => {
    api.listManagementRules().then(setRules)
      .catch((e) => setErr(e instanceof Error ? e.message : "Failed to load rules"));
  }, []);
  useEffect(() => {
    load();
    api.managementRuleOptions().then(setOptions).catch(() => {});
  }, [load]);

  function openEditor(rule?: ManagementRule) {
    setErr(null); setTestResult(null); setTestErr(null);
    setDraft(rule ? {
      id: rule.id, key: rule.key, title: rule.title, severity: rule.severity,
      category: rule.category, description: rule.description,
      remediation: rule.remediation, enabled: rule.enabled,
      conditions: rule.conditions.map((c) => ({ ...c })),
    } : emptyDraft());
  }

  async function save() {
    if (!draft) return;
    setSaving(true); setErr(null);
    const body = {
      key: draft.key, title: draft.title, severity: draft.severity,
      category: draft.category, description: draft.description,
      remediation: draft.remediation, enabled: draft.enabled,
      conditions: draft.conditions,
    };
    try {
      if (draft.id) await api.updateManagementRule(draft.id, body);
      else await api.createManagementRule(body);
      setDraft(null);
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    } finally { setSaving(false); }
  }

  async function remove(rule: ManagementRule) {
    if (!await confirm("Delete Management Rule",
        `"${rule.title}" will stop generating findings on future analyses.`)) return;
    try { await api.deleteManagementRule(rule.id); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Delete failed"); }
  }

  async function toggleEnabled(rule: ManagementRule) {
    try {
      await api.updateManagementRule(rule.id, { ...rule, enabled: !rule.enabled });
      load();
    } catch (e) { setErr(e instanceof Error ? e.message : "Update failed"); }
  }

  async function runTest() {
    if (!draft) return;
    setTesting(true); setTestResult(null); setTestErr(null);
    try {
      setTestResult(await api.testManagementRule(draft.conditions));
    } catch (e) {
      setTestErr(e instanceof Error ? e.message : "Test failed");
    } finally { setTesting(false); }
  }

  const semanticFields = options?.semantic_fields ?? ["dst_address", "src_address"];
  const directFields = options?.direct_fields ?? [];
  const boolFields = options?.bool_fields ?? [];
  const operators = options?.operators ?? ["equals", "not_equals", "contains", "not_contains"];
  const boolOperators = options?.bool_operators ?? ["equals", "not_equals"];
  const semanticOperators = options?.semantic_operators ?? ["is", "is_not"];
  const targets = options?.targets ?? [];
  const allFields = [...semanticFields, ...directFields, ...boolFields];

  function setCondition(i: number, patch: Partial<ManagementCondition>) {
    if (!draft) return;
    const next = draft.conditions.map((c, j) => (j === i ? { ...c, ...patch } : c));
    setDraft({ ...draft, conditions: next });
  }

  const domainOf = (field: string) =>
    options?.semantic_field_domains?.[field] ?? (field === "service_ports" ? "service" : "address");
  const targetsFor = (field: string) => {
    const domain = domainOf(field);
    return targets.filter((t) => !t.domains || t.domains.includes(domain));
  };

  function changeField(i: number, field: string) {
    const semantic = semanticFields.includes(field);
    const bool = boolFields.includes(field);
    const applicable = targetsFor(field);
    const defaultTarget = applicable.find((t) => t.key !== "any") ?? applicable[0];
    setCondition(i, {
      field,
      operator: semantic ? "is" : "equals",
      target: semantic ? (defaultTarget?.key ?? "") : "",
      value: bool ? "true" : "",
    });
  }

  return (
    <div className="max-w-[1440px] fade-in space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-ink-100 tracking-tight">Management Rules</h1>
          <p className="font-mono text-[11px] text-ink-500 mt-1">
            Semantic detection rules for management access — address references are resolved
            through the TSR's address objects and nested groups before comparison
          </p>
        </div>
        <button onClick={() => openEditor()}
                className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
          + New Management Rule
        </button>
      </div>

      {err && <p className="font-mono text-[12px] text-sev-high">{err}</p>}

      {/* Rule list */}
      <div className="card-glow p-5">
        <h3 className="font-display font-semibold text-sm text-ink-100 mb-3">Rules</h3>
        {rules.length === 0 ? (
          <p className="text-ink-500 text-sm font-mono py-6 text-center">
            No management rules yet — create one to detect exposed firewall management access.
          </p>
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500 border-b border-base-500">
                <th className="py-2 pr-3">Key</th>
                <th className="py-2 pr-3">Title</th>
                <th className="py-2 pr-3">Severity</th>
                <th className="py-2 pr-3">Category</th>
                <th className="py-2 pr-3">Conditions</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="border-b border-base-500/50 text-[13px]">
                  <td className="py-2.5 pr-3 font-mono text-[12px] text-ink-500">{r.key}</td>
                  <td className="py-2.5 pr-3 text-ink-100">{r.title}</td>
                  <td className="py-2.5 pr-3">
                    <span className="badge" style={{
                      color: sevColor[r.severity], borderColor: `${sevColor[r.severity]}55`,
                      background: `${sevColor[r.severity]}14`,
                    }}>{r.severity}</span>
                  </td>
                  <td className="py-2.5 pr-3 font-mono text-[11px] text-ink-500">{r.category}</td>
                  <td className="py-2.5 pr-3 font-mono text-[11px] text-ink-300">
                    {r.conditions.map((c) =>
                      semanticFields.includes(c.field)
                        ? `${FIELD_LABELS[c.field] ?? c.field} ${OPERATOR_LABELS[c.operator || "is"] ?? "matches"} ${targets.find((t) => t.key === c.target)?.label ?? c.target}${c.value ? ` (${c.value})` : ""}`
                        : `${FIELD_LABELS[c.field] ?? c.field} ${OPERATOR_LABELS[c.operator] ?? c.operator} ${c.value}`,
                    ).join("; ")}
                  </td>
                  <td className="py-2.5 pr-3">
                    <button onClick={() => toggleEnabled(r)}
                            className={`badge cursor-pointer ${r.enabled ? "" : "opacity-60"}`}
                            style={r.enabled
                              ? { color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }
                              : { color: "#7a879b", borderColor: "#7a879b55", background: "#7a879b14" }}
                            title="Click to toggle">
                      {r.enabled ? "Enabled" : "Disabled"}
                    </button>
                  </td>
                  <td className="py-2.5 text-right whitespace-nowrap">
                    <button onClick={() => openEditor(r)}
                            className="font-mono text-[12px] text-accent hover:underline mr-3">Edit</button>
                    <button onClick={() => remove(r)}
                            className="font-mono text-[12px] text-sev-high hover:underline">Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Editor */}
      {draft && (
        <div className="card-glow p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-display font-semibold text-sm text-ink-100">
              {draft.id ? "Edit Management Rule" : "New Management Rule"}
            </h3>
            <button onClick={() => setDraft(null)}
                    className="w-7 h-7 grid place-items-center rounded-lg border border-base-500 text-ink-500 hover:text-ink-100 transition-colors text-sm">✕</button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="block">
              <span className={labelCls}>Rule Key (e.g. MGMT-RULE-001)</span>
              <input value={draft.key} disabled={!!draft.id}
                     onChange={(e) => setDraft({ ...draft, key: e.target.value })}
                     className={`${inputCls} font-mono disabled:opacity-50`} />
            </label>
            <label className="block">
              <span className={labelCls}>Title</span>
              <input value={draft.title}
                     onChange={(e) => setDraft({ ...draft, title: e.target.value })}
                     placeholder="e.g. Firewall Management Exposed to WAN"
                     className={inputCls} />
            </label>
            <label className="block">
              <span className={labelCls}>Severity</span>
              <select value={draft.severity}
                      onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
                      className={inputCls}>
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </label>
            <label className="block">
              <span className={labelCls}>Category</span>
              <select value={draft.category}
                      onChange={(e) => setDraft({ ...draft, category: e.target.value })}
                      className={inputCls}>
                {!RULE_CATEGORIES.includes(draft.category) && <option>{draft.category}</option>}
                {RULE_CATEGORIES.map((c) => <option key={c}>{c}</option>)}
              </select>
            </label>
            <label className="block md:col-span-2">
              <span className={labelCls}>Description</span>
              <textarea value={draft.description} rows={2}
                        onChange={(e) => setDraft({ ...draft, description: e.target.value })}
                        placeholder="What this rule detects and why it matters"
                        className={inputCls} />
            </label>
            <label className="block md:col-span-2">
              <span className={labelCls}>Remediation</span>
              <input value={draft.remediation}
                     onChange={(e) => setDraft({ ...draft, remediation: e.target.value })}
                     placeholder="e.g. Restrict management access to trusted source addresses"
                     className={inputCls} />
            </label>
          </div>

          {/* Conditions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className={labelCls}>Conditions (all must match the same access rule)</span>
              <button onClick={() => setDraft({ ...draft, conditions: [...draft.conditions,
                        { field: "src_zone", operator: "equals", value: "", target: "" }] })}
                      className="font-mono text-[12px] text-accent hover:underline">+ Add Condition</button>
            </div>
            <div className="space-y-2">
              {draft.conditions.map((c, i) => {
                const semantic = semanticFields.includes(c.field);
                const bool = boolFields.includes(c.field);
                const applicableTargets = targetsFor(c.field);
                const target = applicableTargets.find((t) => t.key === c.target);
                const isZone = ZONE_FIELDS.has(c.field);
                return (
                  <div key={i} className="flex flex-wrap items-center gap-2 bg-base-800/80 border border-base-500 rounded-lg px-3 py-2">
                    <select value={c.field} onChange={(e) => changeField(i, e.target.value)}
                            className="bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 focus:outline-none focus:border-accent">
                      {allFields.map((f) => <option key={f} value={f}>{FIELD_LABELS[f] ?? f}</option>)}
                    </select>
                    {semantic ? (
                      <>
                        <select value={c.operator || "is"}
                                onChange={(e) => setCondition(i, { operator: e.target.value })}
                                title="matches = any resolved value satisfies the target; does not match = the reference resolves and none of its values satisfy it"
                                className="bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 focus:outline-none focus:border-accent">
                          {semanticOperators.map((o) => <option key={o} value={o}>{OPERATOR_LABELS[o] ?? o}</option>)}
                        </select>
                        <select value={c.target}
                                onChange={(e) => setCondition(i, { target: e.target.value, value: "" })}
                                className="bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 focus:outline-none focus:border-accent">
                          {applicableTargets.map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}
                        </select>
                        {target?.needs_value && (
                          <input value={c.value} placeholder={target.value_hint || "Value"}
                                 onChange={(e) => setCondition(i, { value: e.target.value })}
                                 className="flex-1 min-w-[160px] bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 font-mono focus:outline-none focus:border-accent" />
                        )}
                      </>
                    ) : (
                      <>
                        <select value={c.operator}
                                onChange={(e) => setCondition(i, { operator: e.target.value })}
                                className="bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 focus:outline-none focus:border-accent">
                          {(bool ? boolOperators : operators).map((o) =>
                            <option key={o} value={o}>{OPERATOR_LABELS[o] ?? o}</option>)}
                        </select>
                        {bool ? (
                          <select value={c.value}
                                  onChange={(e) => setCondition(i, { value: e.target.value })}
                                  className="bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 focus:outline-none focus:border-accent">
                            <option value="true">true</option>
                            <option value="false">false</option>
                          </select>
                        ) : (
                          <>
                            <input value={c.value}
                                   placeholder={isZone ? "e.g. WAN — or * for any zone" : "e.g. WAN"}
                                   onChange={(e) => setCondition(i, { value: e.target.value })}
                                   className="flex-1 min-w-[160px] bg-base-900 border border-base-500 rounded-lg px-2 py-1.5 text-[12px] text-ink-100 font-mono focus:outline-none focus:border-accent" />
                            {isZone && (
                              <button onClick={() => setCondition(i, { value: "*" })}
                                      title="Match any zone"
                                      className={`px-2 py-1 rounded-lg text-[11px] font-mono border transition-all ${
                                        c.value === "*"
                                          ? "bg-accent/20 text-accent border-accent/40"
                                          : "text-ink-500 border-base-500 hover:text-ink-100"
                                      }`}>
                                ＊ Any
                              </button>
                            )}
                          </>
                        )}
                      </>
                    )}
                    <button onClick={() => setDraft({ ...draft,
                              conditions: draft.conditions.filter((_, j) => j !== i) })}
                            className="ml-auto text-ink-500 hover:text-sev-high text-sm shrink-0">✕</button>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Test against reference TSR */}
          <div className="border-t border-base-500 pt-3">
            <button onClick={runTest} disabled={testing || draft.conditions.length === 0}
                    className="px-4 py-2 rounded-lg bg-accent/10 border border-accent/30 text-accent text-[13px] font-semibold hover:bg-accent/20 disabled:opacity-40 transition-all">
              {testing ? "Testing…" : "▶ Test against reference TSR"}
            </button>
            <span className="ml-3 font-mono text-[10px] text-ink-500">
              Uses the TSR uploaded in the CEL Rule Builder as reference data.
            </span>
            {testErr && <p className="mt-2 font-mono text-[12px] text-sev-high">{testErr}</p>}
            {testResult && (
              <div className="mt-3 rounded-lg border p-3" style={{
                borderColor: testResult.matches.length ? "#ff8a3d55" : "#39d98a55",
                background: testResult.matches.length ? "#ff8a3d10" : "#39d98a10",
              }}>
                <p className="font-mono text-[13px] font-semibold"
                   style={{ color: testResult.matches.length ? "#ff8a3d" : "#39d98a" }}>
                  {testResult.error
                    ? testResult.error
                    : `${testResult.matches.length} matching access rule(s) out of ${testResult.access_rules_evaluated}`}
                </p>
                {testResult.matches.slice(0, 10).map((m, i) => (
                  <div key={i} className="mt-2 font-mono text-[11px] text-ink-300">
                    <span className="text-ink-100">Rule {m.num}</span> {m.name && `'${m.name}'`} — {m.src_zone} → {m.dst_zone}, service '{m.service}', dst '{m.dst}'
                    {m.hits.map((h, j) => (
                      <span key={j} className="block pl-4 text-ink-500">↳ {h.summary}</span>
                    ))}
                  </div>
                ))}
                {testResult.matches.length > 10 && (
                  <p className="mt-1 font-mono text-[10px] text-ink-500">…{testResult.matches.length - 10} more</p>
                )}
              </div>
            )}
          </div>

          <div className="flex items-center gap-3 border-t border-base-500 pt-3">
            <button onClick={save}
                    disabled={saving || !draft.title.trim() || (!draft.id && !draft.key.trim()) || draft.conditions.length === 0}
                    className="px-5 py-2.5 rounded-lg bg-signal text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
              {saving ? "Saving…" : draft.id ? "Save Changes" : "Create Management Rule"}
            </button>
            <label className="flex items-center gap-2 text-[13px] text-ink-300 cursor-pointer">
              <input type="checkbox" checked={draft.enabled}
                     onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
                     className="rounded accent-accent" />
              Enabled
            </label>
            <span className="font-mono text-[11px] text-ink-500">
              Findings inherit this rule's title, severity, category, description and remediation.
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
