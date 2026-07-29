import type { ReactNode } from "react";
import { sevColor, SEVERITIES } from "../lib/ui";

export function Panel({
  title,
  eyebrow,
  right,
  children,
  className = "",
}: {
  title?: string;
  eyebrow?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`bg-base-800 border border-base-500 rounded-panel shadow-panel transition-colors hover:border-base-600 ${className}`}
    >
      {(title || right) && (
        <header className="flex items-center justify-between gap-3 px-5 py-3.5 border-b border-base-500">
          <div className="flex items-center gap-3 min-w-0">
            <span className="hidden sm:block w-1 h-8 rounded-full bg-gradient-to-b from-accent to-signal/70 shrink-0" />
            <div className="min-w-0">
              {eyebrow && (
                <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-500 truncate">
                  {eyebrow}
                </div>
              )}
              {title && (
                <h2 className="font-display font-semibold text-ink-100 text-[15px] truncate">
                  {title}
                </h2>
              )}
            </div>
          </div>
          {right}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function SevChip({ severity, count }: { severity: string; count?: number }) {
  const c = sevColor[severity] ?? "#7a879b";
  return (
    <span
      className="inline-flex items-center gap-1.5 font-mono text-[11px] px-2 py-0.5 rounded-chip border tabular-nums"
      style={{ color: c, borderColor: `${c}55`, background: `${c}14` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />
      {count !== undefined && <span className="font-semibold">{count}</span>}
      {severity}
    </span>
  );
}

// Horizontal stacked bar of severity counts — a compact distribution readout.
export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = SEVERITIES.reduce((s, k) => s + (counts[k] || 0), 0) || 1;
  return (
    <div className="space-y-2">
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-base-700">
        {SEVERITIES.map((s) =>
          counts[s] ? (
            <div
              key={s}
              title={`${s}: ${counts[s]}`}
              style={{ width: `${(counts[s] / total) * 100}%`, background: sevColor[s] }}
            />
          ) : null,
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        {SEVERITIES.map((s) => (
          <SevChip key={s} severity={s} count={counts[s] || 0} />
        ))}
      </div>
    </div>
  );
}

export function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: string }) {
  return (
    <div className="bg-base-700 border border-base-500 rounded-panel px-4 py-3">
      <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-500">
        {label}
      </div>
      <div className="font-display text-xl font-semibold text-ink-100 mt-1 leading-tight">
        {value}
      </div>
      {sub && <div className="font-mono text-[11px] text-ink-500 mt-0.5">{sub}</div>}
    </div>
  );
}
