import type { AttackPath, FirmwareIntel } from "../lib/types";
import { sevColor } from "../lib/ui";
import { Panel } from "./primitives";

export function AttackPaths({ paths }: { paths: AttackPath[] }) {
  if (!paths?.length) return null;
  return (
    <Panel eyebrow="Correlation" title="Attack paths">
      <div className="space-y-4">
        {paths.map((ap) => {
          const c = sevColor[ap.severity] ?? "#7a879b";
          return (
            <div key={ap.path_id} className="border border-base-500 rounded-panel overflow-hidden">
              <div className="flex items-center gap-3 px-4 py-2.5 bg-base-700">
                <span className="font-mono text-[11px] text-ink-500">{ap.path_id}</span>
                <span className="font-display font-semibold text-ink-100 text-sm flex-1">
                  {ap.name}
                </span>
                <span className="font-mono text-[11px] font-semibold px-2 py-0.5 rounded-chip"
                      style={{ color: c, background: `${c}18`, border: `1px solid ${c}55` }}>
                  {ap.severity}
                </span>
              </div>
              <div className="px-4 py-3">
                <p className="text-ink-300 text-[13px] leading-relaxed mb-3">{ap.narrative}</p>
                <ol className="relative border-l border-base-500 ml-1 space-y-2.5">
                  {ap.stages.map((s, i) => (
                    <li key={i} className="pl-4 relative">
                      <span className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full"
                            style={{ background: c }} />
                      <span className="font-mono text-[11px] uppercase tracking-wide text-ink-100">
                        {s.stage}
                      </span>
                      <span className="text-ink-300 text-[13px]"> — {s.detail}</span>
                    </li>
                  ))}
                </ol>
                {ap.contributing_rules?.length > 0 && (
                  <div className="mt-3 font-mono text-[10px] text-ink-500">
                    Contributing: {ap.contributing_rules.join(", ")}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

export function FirmwarePanel({ fw }: { fw: FirmwareIntel }) {
  if (!fw) return null;
  const has = fw.advisory_count > 0;
  return (
    <Panel
      eyebrow="Firmware intelligence"
      title="PSIRT advisories"
      right={
        <span className="font-mono text-[11px] text-ink-500">
          {fw.generation} · max CVSS {fw.max_cvss}
        </span>
      }
    >
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1 mb-4">
        <div>
          <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500">
            Running
          </span>
          <div className="font-mono text-sm text-ink-100">{fw.firmware}</div>
        </div>
        {fw.recommended_firmware && (
          <div>
            <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500">
              Recommended
            </span>
            <div className="font-mono text-sm text-signal">{fw.recommended_firmware}</div>
          </div>
        )}
        <div>
          <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500">
            Platform
          </span>
          <div className="font-mono text-sm text-ink-100 capitalize">{fw.eol?.status}</div>
        </div>
      </div>

      {has ? (
        <div className="space-y-2.5">
          {fw.matched_advisories.map((a) => {
            const c = sevColor[a.severity] ?? "#ff8a3d";
            return (
              <div key={a.advisory_id} className="border border-base-500 rounded-panel px-4 py-3">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <a href={a.url} target="_blank" rel="noreferrer"
                     className="font-mono text-[12px] text-accent hover:underline">
                    {a.advisory_id}
                  </a>
                  <span className="font-mono text-[11px] font-semibold px-1.5 py-0.5 rounded-chip"
                        style={{ color: c, background: `${c}18` }}>
                    CVSS {a.cvss}
                  </span>
                  <span className="font-mono text-[10px] text-ink-500">
                    {a.cve.join(", ")}
                  </span>
                </div>
                <p className="text-ink-300 text-[13px] leading-relaxed">{a.summary}</p>
                <div className="font-mono text-[11px] text-signal mt-1.5">
                  → fixed in {a.fixed_in}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="text-ink-300 text-sm">
          No advisories match the running firmware in the current PSIRT dataset.
        </p>
      )}
      <p className="font-mono text-[10px] text-ink-500 mt-3 leading-relaxed">{fw.disclaimer}</p>
    </Panel>
  );
}
