import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { ComplianceMatrix } from "../lib/types";
import { navigate } from "../lib/router";
import { Panel } from "./primitives";

// Per-framework compliance matrix: devices as columns, controls as rows.
export function Compliance() {
  const [frameworks, setFrameworks] = useState<string[]>([]);
  const [active, setActive] = useState<string>("");
  const [matrix, setMatrix] = useState<ComplianceMatrix | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.complianceFrameworks().then((r) => {
      setFrameworks(r.frameworks);
      setActive(r.frameworks[0] || "");
    }).catch((e) => setErr(e instanceof Error ? e.message : "Failed to load frameworks"));
  }, []);

  const load = useCallback(() => {
    if (!active) return;
    api.complianceMatrix(active).then(setMatrix).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load matrix"));
  }, [active]);
  useEffect(() => { load(); }, [load]);

  return (
    <Panel title="Compliance" eyebrow="Framework coverage">
      <div className="flex flex-wrap gap-1 border-b border-base-500 mb-4">
        {frameworks.map((f) => (
          <button key={f} onClick={() => setActive(f)}
                  className={`px-3 py-2 text-[13px] border-b-2 -mb-px ${
                    active === f ? "border-accent text-accent" : "border-transparent text-ink-300 hover:text-ink-100"
                  }`}>
            {f}
          </button>
        ))}
      </div>

      {err && <p className="text-sev-high text-[13px] mb-3">{err}</p>}
      {!matrix ? (
        <p className="font-mono text-ink-500 text-sm animate-pulse">Loading matrix…</p>
      ) : matrix.devices.length === 0 ? (
        <p className="text-ink-500 text-sm">No scanned devices yet.</p>
      ) : matrix.controls.length === 0 ? (
        <p className="text-signal text-sm">No open findings map to {active} — full pass.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="text-[12px] border-collapse">
            <thead>
              <tr>
                <th className="text-left font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500 py-2 pr-4 sticky left-0 bg-base-800">
                  Control
                </th>
                {matrix.devices.map((d) => (
                  <th key={d.device_id} className="px-2 py-2 font-mono text-[10px] text-ink-500 whitespace-nowrap"
                      title={`${d.model} ${d.serial}`}>
                    {d.serial.slice(-6)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {matrix.controls.map((ctrl) => (
                <tr key={ctrl} className="border-t border-base-500/50">
                  <td className="py-1.5 pr-4 text-ink-300 sticky left-0 bg-base-800">{ctrl}</td>
                  {matrix.devices.map((d) => {
                    const cell = matrix.cells[`${d.device_id}|${ctrl}`];
                    const fail = cell?.status === "fail";
                    return (
                      <td key={d.device_id} className="px-2 py-1.5 text-center">
                        <button
                          disabled={!fail}
                          onClick={() => fail && cell.finding_ids[0] && navigate(`/findings/${cell.finding_ids[0]}`)}
                          title={fail ? `${cell.finding_ids.length} finding(s) — click to open` : "pass"}
                          className="w-5 h-5 rounded-sm inline-block"
                          style={{ background: fail ? "#ff4d4d" : "#39d98a", cursor: fail ? "pointer" : "default" }}
                        />
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="font-mono text-[11px] text-ink-500 mt-3">
            <span className="inline-block w-3 h-3 align-middle rounded-sm mr-1" style={{ background: "#39d98a" }} /> pass
            <span className="inline-block w-3 h-3 align-middle rounded-sm ml-3 mr-1" style={{ background: "#ff4d4d" }} /> fail (click to open finding)
          </p>
        </div>
      )}
    </Panel>
  );
}
