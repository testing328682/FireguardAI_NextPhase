import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { Finding } from "../lib/types";
import { sevColor, sevTextClass, SEVERITIES } from "../lib/ui";

function ComplianceText({ c }: { c: Finding["compliance"] }) {
  if (!c) return null;
  let text = "";
  if (Array.isArray(c)) text = c.join("; ");
  else text = Object.entries(c).map(([k, v]) => `${k}: ${v.join(", ")}`).join("  •  ");
  if (!text) return null;
  return <span className="font-mono text-[11px] text-ink-500">{text}</span>;
}

function Row({ f, index }: { f: Finding; index: number }) {
  const [open, setOpen] = useState(false);
  const c = sevColor[f.severity];
  return (
    <>
      <tr
        className="border-t border-base-500 hover:bg-base-700/60 cursor-pointer transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <td className="px-3 py-2.5 text-ink-500 font-mono text-xs tabular-nums">{index}</td>
        <td className="px-3 py-2.5">
          <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-semibold"
                style={{ color: c }}>
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />
            {f.severity}
          </span>
        </td>
        <td className="px-3 py-2.5">
          <div className="text-ink-100 text-sm">{f.title}</div>
          <div className="font-mono text-[10px] text-ink-500 mt-0.5">{f.rule_id} · {f.category}</div>
        </td>
        <td className="px-3 py-2.5">
          {f.object_name ? (
            <span className="font-mono text-[11px] text-ink-300">{f.object_name}</span>
          ) : (
            <span className="text-ink-500">—</span>
          )}
          {f.object_type && (
            <div className="font-mono text-[10px] text-ink-500 mt-0.5">{f.object_type}</div>
          )}
        </td>
        <td className="px-3 py-2.5 text-right">
          <span className="font-mono text-[11px] text-ink-300">{f.exploitability}</span>
        </td>
        <td className="px-2 py-2.5 text-ink-500 text-xs">{open ? "▾" : "▸"}</td>
      </tr>
      {open && (
        <tr className="bg-base-900/50">
          <td colSpan={6} className="px-6 py-4">
            <div className="grid md:grid-cols-2 gap-x-8 gap-y-3 text-sm">
              {f.object_detail && (
                <Field label={`Affected ${f.object_type || "object"}`} mono>
                  {f.object_detail}
                </Field>
              )}
              <Field label="Description">{f.description}</Field>
              <Field label="Business impact">{f.business_impact}</Field>
              <Field label="Technical impact">{f.technical_impact}</Field>
              <Field label="Remediation">{f.remediation}</Field>
              {f.evidence?.length > 0 && (
                <Field label="Evidence" mono>
                  <ul className="space-y-0.5">
                    {f.evidence.slice(0, 8).map((e, i) => (
                      <li key={i}>• {e}</li>
                    ))}
                  </ul>
                </Field>
              )}
              {f.verification?.length > 0 && (
                <Field label="Verification">
                  <ul className="space-y-0.5">
                    {f.verification.map((v, i) => (
                      <li key={i}>• {v}</li>
                    ))}
                  </ul>
                </Field>
              )}
            </div>
            <div className="mt-3 pt-3 border-t border-base-500 flex flex-wrap items-center gap-x-6 gap-y-1">
              <ComplianceText c={f.compliance} />
              {f.references?.filter(Boolean).map((r) => (
                <a key={r} href={r} target="_blank" rel="noreferrer"
                   className="font-mono text-[11px] text-accent hover:underline">
                  {r.replace(/^https?:\/\//, "").slice(0, 48)}
                </a>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function Field({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500 mb-1">
        {label}
      </div>
      <div className={`text-ink-300 leading-relaxed ${mono ? "font-mono text-[11px]" : "text-[13px]"}`}>
        {children}
      </div>
    </div>
  );
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [sev, setSev] = useState<string>("All");
  const [q, setQ] = useState("");

  const categories = useMemo(
    () => Array.from(new Set(findings.map((f) => f.category))).sort(),
    [findings],
  );
  const [cat, setCat] = useState<string>("All");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings.filter((f) => {
      if (sev !== "All" && f.severity !== sev) return false;
      if (cat !== "All" && f.category !== cat) return false;
      if (needle) {
        const hay = `${f.title} ${f.rule_id} ${f.object_name} ${f.category}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [findings, sev, cat, q]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="flex rounded-panel border border-base-500 overflow-hidden">
          {["All", ...SEVERITIES].map((s) => (
            <button
              key={s}
              onClick={() => setSev(s)}
              className={`px-2.5 py-1.5 text-[11px] font-mono border-r border-base-500 last:border-r-0 transition-colors ${
                sev === s ? "bg-base-600 text-ink-100" : "text-ink-500 hover:text-ink-300"
              }`}
              style={sev === s && s !== "All" ? { color: sevColor[s] } : undefined}
            >
              {s}
            </button>
          ))}
        </div>
        <select
          value={cat}
          onChange={(e) => setCat(e.target.value)}
          className="bg-base-700 border border-base-500 rounded-panel px-2.5 py-1.5 text-[12px] text-ink-300 font-mono focus:outline-none"
        >
          <option value="All">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by rule, object, text…"
          className="flex-1 min-w-[180px] bg-base-700 border border-base-500 rounded-panel px-3 py-1.5 text-[13px] text-ink-100 placeholder:text-ink-500 focus:outline-none"
        />
        <span className="font-mono text-[11px] text-ink-500 tabular-nums">
          {filtered.length} / {findings.length}
        </span>
      </div>

      <div className="overflow-x-auto border border-base-500 rounded-panel">
        <table className="w-full border-collapse">
          <thead>
            <tr className="bg-base-700 text-left">
              {["#", "Severity", "Finding", "Affected object", "Exploit.", ""].map((h, i) => (
                <th key={i}
                    className={`px-3 py-2 font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500 ${
                      h === "Exploit." ? "text-right" : ""
                    }`}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => (
              <Row key={`${f.rule_id}-${i}`} f={f} index={i + 1} />
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-ink-500 text-sm">
                  No findings match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
