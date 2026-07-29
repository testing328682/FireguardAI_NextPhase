import { useEffect, useState, useCallback } from "react";
import { usePrompt } from "./Modal";
import { api } from "../lib/api";
import type { FindingDetail as FD, FindingStatus } from "../lib/types";
import { navigate } from "../lib/router";
import { Panel } from "./primitives";
import { sevColor, STATUS_LABEL, statusColor, fmtDate } from "../lib/ui";

// Allowed next-states from each current state (mirrors the backend map).
const NEXT: Record<string, FindingStatus[]> = {
  open: ["acknowledged", "in_progress", "fixed", "false_positive", "accepted_risk", "suppressed"],
  acknowledged: ["in_progress", "fixed", "false_positive", "accepted_risk", "suppressed", "open"],
  in_progress: ["fixed", "acknowledged", "false_positive", "accepted_risk", "suppressed", "open"],
  fixed: ["open", "in_progress"],
  false_positive: ["open"],
  accepted_risk: ["open"],
  suppressed: ["open"],
};

export function FindingDetailView({ id, backBase }: { id: string; backBase?: string }) {
  const [f, setF] = useState<FD | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const prompt = usePrompt();

  const load = useCallback(() => {
    api.getFinding(id).then(setF).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load finding"));
  }, [id]);

  useEffect(() => { load(); }, [load]);

  async function transition(to: FindingStatus) {
    const note = await prompt("Transition Finding", "", `Moving to ${STATUS_LABEL[to]} — add a comment`);
    if (!note) return;
    let justification: string | undefined;
    let accepted_risk_expiry: string | undefined;
    if (to === "false_positive" || to === "accepted_risk") {
      justification = await prompt("Justification", "", "Reason for this classification") || undefined;
      if (!justification) return;
    }
    if (to === "accepted_risk") {
      const days = await prompt("Accept Risk", "30", "Number of days");
      if (!days) return;
      accepted_risk_expiry = new Date(Date.now() + Number(days) * 86400000).toISOString();
    }
    try {
      const updated = await api.transitionFinding(id, { to_status: to, comment: note,
        justification, accepted_risk_expiry });
      setF(updated);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Transition failed");
    }
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

  return (
    <div className="space-y-5">
      <button onClick={() => {
        if (backBase) { navigate(f.device_id ? `${backBase}?device=${f.device_id}` : backBase); }
        else { navigate(f.device_id ? `/findings?device=${f.device_id}` : "/findings"); }
      }}
              className="font-mono text-[12px] text-ink-300 hover:text-accent">
        ← Back to findings
      </button>

      <Panel
        eyebrow={f.rule_id}
        title={f.title}
        right={
          <span className="font-mono text-[11px] px-2 py-0.5 rounded-chip border"
                style={{ color: statusColor[f.status],
                         borderColor: `${statusColor[f.status]}55`,
                         background: `${statusColor[f.status]}14` }}>
            {STATUS_LABEL[f.status]}
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
          {f.object_name && (
            <span className="font-mono text-[11px] text-ink-300 border border-base-500 rounded-chip px-2 py-0.5">
              {f.object_type}: {f.object_name}
            </span>
          )}
          <span className="font-mono text-[11px] text-ink-500 px-2 py-0.5">
            Exploitability {f.exploitability}
          </span>
        </div>

        {err && <p className="text-sev-high text-[13px] mb-3">{err}</p>}

        {/* State-change buttons */}
        <div className="flex flex-wrap gap-2 mb-5">
          {(NEXT[f.status] || []).map((s) => (
            <button key={s} onClick={() => transition(s)}
                    className="px-3 py-1.5 rounded-panel border border-base-500 text-[12px] hover:border-accent transition-colors"
                    style={{ color: statusColor[s] }}>
              → {STATUS_LABEL[s]}
            </button>
          ))}
        </div>

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
