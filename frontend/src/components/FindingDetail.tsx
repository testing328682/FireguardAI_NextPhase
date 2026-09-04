import { useEffect, useState, useCallback } from "react";
import { usePrompt } from "./Modal";
import { api } from "../lib/api";
import type { FindingDetail as FD, FindingGroupDetail, FindingRow, FindingStatus } from "../lib/types";
import { navigate } from "../lib/router";
import { Panel } from "./primitives";
import { sevColor, STATUS_LABEL, statusColor, fmtDate } from "../lib/ui";

// FIXED-classified = the underlying condition is resolved.
// OPEN-classified   = open, acknowledged, in_progress, suppressed — everything
// else. Suppressed is a silence, not a fix, so it still blocks a parent
// finding from resolving. Mirrors app.finding_groups.RESOLVED_STATES.
const RESOLVED = new Set<FindingStatus>(["fixed", "false_positive", "accepted_risk"]);
const ALL_STATUSES: FindingStatus[] = [
  "open", "acknowledged", "in_progress", "fixed", "false_positive", "accepted_risk", "suppressed",
];
// Any status may move directly to any other status — mirrors the backend's
// fully-connected transition graph (app/routers/findings.py _ALLOWED).
const NEXT: Record<string, FindingStatus[]> = Object.fromEntries(
  ALL_STATUSES.map((s) => [s, ALL_STATUSES.filter((x) => x !== s)]),
);

export function FindingDetailView({ id, backBase }: { id: string; backBase?: string }) {
  const [f, setF] = useState<FD | null>(null);
  const [group, setGroup] = useState<FindingGroupDetail | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [err, setErr] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const prompt = usePrompt();

  const load = useCallback(() => {
    api.getFinding(id).then((fd) => {
      setF(fd);
      // Load the logical finding this instance belongs to (rule + all affected
      // objects on the device) so multi-object findings render as one finding
      // with a checklist of affected instances.
      api.getFindingGroup(fd.device_id, fd.rule_id)
        .then((g) => { setGroup(g); setSelected(new Set()); })
        .catch(() => setGroup(null));
    }).catch((e) => setErr(e instanceof Error ? e.message : "Failed to load finding"));
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const isGroup = !!group && group.affected_total > 1;

  // Prompts for a comment (and, for FP/accepted-risk, a justification/expiry)
  // — shared by the single-finding controls, per-child rows, and bulk action.
  async function promptTransitionExtras(to: FindingStatus, label: string) {
    const note = await prompt(label, "", `Moving to ${STATUS_LABEL[to]} — add a comment`);
    if (!note) return null;
    let justification: string | undefined;
    let accepted_risk_expiry: string | undefined;
    if (to === "false_positive" || to === "accepted_risk") {
      justification = await prompt("Justification", "", "Reason for this classification") || undefined;
      if (!justification) return null;
    }
    if (to === "accepted_risk") {
      const days = await prompt("Accept Risk", "30", "Number of days");
      if (!days) return null;
      accepted_risk_expiry = new Date(Date.now() + Number(days) * 86400000).toISOString();
    }
    return { comment: note, justification, accepted_risk_expiry };
  }

  async function transition(to: FindingStatus) {
    const extras = await promptTransitionExtras(to, "Transition Finding");
    if (!extras) return;
    try {
      const updated = await api.transitionFinding(id, { to_status: to, ...extras });
      setF(updated);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Transition failed");
    }
  }

  // Per-child (affected instance) status change — any of the six statuses,
  // reachable directly from any other, at any time.
  async function transitionChild(instanceId: string, to: FindingStatus) {
    const extras = await promptTransitionExtras(to, "Change Affected Object Status");
    if (!extras) return;
    try {
      await api.transitionFinding(instanceId, { to_status: to, ...extras });
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Transition failed");
    }
  }

  // Bulk status change across every selected affected instance.
  async function bulkChangeStatus(to: FindingStatus) {
    if (selected.size === 0) return;
    const extras = await promptTransitionExtras(to, "Change Status of Selected");
    if (!extras) return;
    try {
      await api.bulkTransition({ finding_ids: [...selected], to_status: to, ...extras });
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Bulk transition failed");
    }
  }

  // Parent (logical finding) status change. The backend enforces: an
  // OPEN-classified status is always allowed; a FIXED-classified status is
  // rejected while any affected instance remains OPEN-classified. The parent
  // is never auto-resolved — this is the only way it changes.
  async function transitionParent(to: FindingStatus) {
    if (!group) return;
    const extras = await promptTransitionExtras(to, "Change Finding Status");
    if (!extras) return;
    try {
      const updated = await api.transitionFindingGroup({
        device_id: group.device_id, rule_id: group.rule_id, to_status: to, ...extras,
      });
      setGroup(updated);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Transition failed");
    }
  }

  function toggleInstance(iid: string) {
    setSelected((s) => { const n = new Set(s); n.has(iid) ? n.delete(iid) : n.add(iid); return n; });
  }
  function selectAll() {
    if (!group) return;
    setSelected(new Set(group.instances.map((i) => i.id)));
  }

  async function addComment() {
    if (!comment.trim()) return;
    try {
      await api.commentFinding(id, comment.trim());
      setComment("");
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Comment failed");
    }
  }

  if (err && !f) return <Panel title="Finding"><p className="text-sev-high text-sm">{err}</p></Panel>;
  if (!f) return <Panel title="Finding"><p className="font-mono text-ink-500 text-sm animate-pulse">Loading…</p></Panel>;

  const headerStatus = isGroup ? group!.status : f.status;

  return (
    <div className="space-y-5">
      <button onClick={() => {
        if (backBase) { navigate(f.device_id ? `${backBase}?device=${f.device_id}` : backBase); }
        else { navigate(f.device_id ? `/security-analytics/device-findings?device=${f.device_id}` : "/security-analytics"); }
      }}
              className="font-mono text-[12px] text-ink-300 hover:text-accent">
        ← Back to findings
      </button>

      <Panel
        eyebrow={f.rule_id}
        title={f.title}
        right={
          <span className="font-mono text-[11px] px-2 py-0.5 rounded-chip border"
                style={{ color: statusColor[headerStatus],
                         borderColor: `${statusColor[headerStatus]}55`,
                         background: `${statusColor[headerStatus]}14` }}>
            {STATUS_LABEL[headerStatus]}
          </span>
        }>
        <div className="flex flex-wrap gap-2 mb-4">
          <span className="font-mono text-[11px] font-semibold px-2 py-0.5 rounded-chip border"
                style={{ color: sevColor[f.severity], borderColor: `${sevColor[f.severity]}55` }}>
            {f.severity}
          </span>
          <span className="font-mono text-[11px] text-ink-500 px-2 py-0.5">
            {f.category}
          </span>
          {isGroup ? (
            <span className="font-mono text-[11px] text-ink-300 border border-base-500 rounded-chip px-2 py-0.5">
              Affected: {group!.affected_total} {group!.affected_total === 1 ? "policy" : "policies"}
            </span>
          ) : f.object_name && (
            <span className="font-mono text-[11px] text-ink-300 border border-base-500 rounded-chip px-2 py-0.5">
              {f.object_type}: {f.object_name}
            </span>
          )}
          <span className="font-mono text-[11px] text-ink-500 px-2 py-0.5">
            Exploitability {f.exploitability}
          </span>
        </div>

        {err && <p className="text-sev-high text-[13px] mb-3">{err}</p>}

        {isGroup ? (
          <AffectedInstances
            group={group!} selected={selected}
            onToggle={toggleInstance} onSelectAll={selectAll}
            onChildTransition={transitionChild}
            onBulkChangeStatus={bulkChangeStatus}
            onParentTransition={transitionParent} />
        ) : (
          /* Single-object finding — existing per-finding transition controls */
          <div className="flex flex-wrap gap-2 mb-5">
            {(NEXT[f.status] || []).map((s) => (
              <button key={s} onClick={() => transition(s)}
                      className="px-3 py-1.5 rounded-panel border border-base-500 text-[12px] hover:border-accent transition-colors"
                      style={{ color: statusColor[s] }}>
                → {STATUS_LABEL[s]}
              </button>
            ))}
          </div>
        )}

        <Section title="Description">{f.description}</Section>
        <Section title="Business impact">{f.business_impact}</Section>
        <Section title="Technical impact">{f.technical_impact}</Section>
        <Section title="Remediation">{f.remediation}</Section>
        {f.evidence.length > 0 && (
          <Section title="Evidence">
            <ul className="font-mono text-[12px] text-ink-300 space-y-1">
              {f.evidence.map((e, i) => <li key={i}>• {e}</li>)}
            </ul>
          </Section>
        )}
        {f.ticket_ref && (
          <Section title="Linked ticket">
            <span className="font-mono text-[12px]">
              {f.ticket_system || "ticket"} {" "}
              {f.ticket_url ? (
                <a href={f.ticket_url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                  {f.ticket_ref}
                </a>
              ) : f.ticket_ref}
              {f.ticket_status && <span className="text-ink-500"> · {f.ticket_status}</span>}
            </span>
          </Section>
        )}
        {f.justification && <Section title="Justification">{f.justification}</Section>}
        {f.accepted_risk_expiry && (
          <Section title="Accepted-risk expiry">{fmtDate(f.accepted_risk_expiry)}</Section>
        )}
      </Panel>

      {/* History timeline + comments */}
      <Panel title="History & comments" eyebrow="Timeline">
        <div className="flex gap-2 mb-4">
          <input value={comment} onChange={(e) => setComment(e.target.value)}
                 placeholder="Add a comment…"
                 onKeyDown={(e) => e.key === "Enter" && addComment()}
                 className="flex-1 bg-base-700 border border-base-500 rounded-panel px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
          <button onClick={addComment}
                  className="px-4 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
            Comment
          </button>
        </div>
        {f.comments.length === 0 ? (
          <p className="text-ink-500 text-sm">No history yet.</p>
        ) : (
          <ol className="space-y-3">
            {f.comments.map((c) => (
              <li key={c.id} className="flex gap-3">
                <span className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
                      style={{ background: c.comment_type === "status_change"
                        ? statusColor[c.to_status] || "#4f8cff" : "#6b7689" }} />
                <div className="min-w-0">
                  <div className="text-[13px] text-ink-100">
                    {c.comment_type === "status_change" ? (
                      <span>
                        <span className="text-ink-500">{c.from_status || "—"} →</span>{" "}
                        <span style={{ color: statusColor[c.to_status] }}>
                          {STATUS_LABEL[c.to_status] || c.to_status}
                        </span>
                        {" — "}{c.body}
                      </span>
                    ) : c.body}
                  </div>
                  <div className="font-mono text-[10px] text-ink-500 mt-0.5">
                    {c.author_email} · {fmtDate(c.created_at)}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

const STATUS_COUNT_ORDER: FindingStatus[] = [
  "fixed", "accepted_risk", "false_positive", "acknowledged", "in_progress", "suppressed", "open",
];

function AffectedInstances({ group, selected, onToggle, onSelectAll,
                             onChildTransition, onBulkChangeStatus, onParentTransition }: {
  group: FindingGroupDetail;
  selected: Set<string>;
  onToggle: (id: string) => void;
  onSelectAll: () => void;
  onChildTransition: (instanceId: string, to: FindingStatus) => void;
  onBulkChangeStatus: (to: FindingStatus) => void;
  onParentTransition: (to: FindingStatus) => void;
}) {
  const [bulkTarget, setBulkTarget] = useState<FindingStatus | "">("");
  const breakdown = STATUS_COUNT_ORDER
    .map((s) => [s, group.status_counts[s] || 0] as const)
    .filter(([, n]) => n > 0);

  return (
    <div className="mb-5">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <span className="font-mono text-[11px] text-ink-300">
          {group.affected_total} affected ·{" "}
          {breakdown.map(([s, n], i) => (
            <span key={s}>
              {i > 0 && " · "}
              <span style={{ color: statusColor[s] }}>{n} {STATUS_LABEL[s].toLowerCase()}</span>
            </span>
          ))}
        </span>
      </div>

      <div className="border border-base-500 rounded-panel divide-y divide-base-500/60 mb-3">
        {group.instances.map((inst: FindingRow) => (
          <div key={inst.id} className="flex items-center gap-3 px-3 py-2 hover:bg-base-700/40">
            <input type="checkbox" className="rounded accent-accent cursor-pointer"
                   checked={selected.has(inst.id)}
                   onChange={() => onToggle(inst.id)} />
            <span className="flex-1 min-w-0 text-[13px] text-ink-100 truncate">
              {inst.object_name || inst.object_type || "(object)"}
            </span>
            <select value="" onChange={(e) => {
                      const v = e.target.value as FindingStatus;
                      if (v) onChildTransition(inst.id, v);
                    }}
                    className="bg-base-800 border border-base-500 rounded-chip px-1.5 py-0.5 text-[10px] font-mono focus:outline-none focus:border-accent"
                    style={{ color: statusColor[inst.status] }}>
              <option value="">{STATUS_LABEL[inst.status]}</option>
              {NEXT[inst.status].map((s) => <option key={s} value={s}>→ {STATUS_LABEL[s]}</option>)}
            </select>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2 mb-4">
        <button onClick={onSelectAll}
                className="px-3 py-1.5 rounded-panel border border-base-500 text-[12px] text-ink-300 hover:border-accent transition-colors">
          Select All
        </button>
        <select value={bulkTarget} onChange={(e) => setBulkTarget(e.target.value as FindingStatus | "")}
                className="bg-base-800 border border-base-500 rounded-panel px-2 py-1.5 text-[12px] text-ink-100 focus:outline-none focus:border-accent">
          <option value="">Change status to…</option>
          {ALL_STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
        </select>
        <button onClick={() => { if (bulkTarget) { onBulkChangeStatus(bulkTarget); setBulkTarget(""); } }}
                disabled={selected.size === 0 || !bulkTarget}
                className="px-3 py-1.5 rounded-panel bg-accent text-white text-[12px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
          Apply to Selected{selected.size > 0 ? ` (${selected.size})` : ""}
        </button>
      </div>

      {/* Parent (logical finding) status control */}
      <div className="border-t border-base-500/60 pt-3">
        <div className="flex items-center gap-2 mb-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Finding Status</span>
          <span className="font-mono text-[11px] px-2 py-0.5 rounded-chip border"
                style={{ color: statusColor[group.status], borderColor: `${statusColor[group.status]}55`, background: `${statusColor[group.status]}14` }}>
            {STATUS_LABEL[group.status]}
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {NEXT[group.status].map((s) => {
            const blocked = RESOLVED.has(s) && !group.can_resolve;
            return (
              <button key={s} onClick={() => !blocked && onParentTransition(s)}
                      disabled={blocked}
                      title={blocked ? `Resolve all ${group.affected_open} open affected object(s) first` : undefined}
                      className="px-3 py-1.5 rounded-panel border border-base-500 text-[12px] hover:border-accent disabled:opacity-30 disabled:hover:border-base-500 transition-colors"
                      style={{ color: statusColor[s] }}>
                → {STATUS_LABEL[s]}
              </button>
            );
          })}
        </div>
        {!group.can_resolve && group.affected_open > 0 && (
          <p className="font-mono text-[10px] text-ink-500 mt-2">
            {group.affected_open} affected object(s) still open — the finding cannot be
            marked Fixed, False Positive, or Accepted Risk until all are resolved.
          </p>
        )}
        {group.can_resolve && RESOLVED.has(group.status) === false && (
          <p className="font-mono text-[10px] text-signal mt-2">
            All affected objects are resolved — this finding is eligible to be closed above.
          </p>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  if (!children) return null;
  return (
    <div className="mb-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-500 mb-1">
        {title}
      </div>
      <div className="text-[13px] text-ink-300 leading-relaxed">{children}</div>
    </div>
  );
}
