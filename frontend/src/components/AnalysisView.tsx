import { useState } from "react";
import type { Analysis } from "../lib/types";
import { fmtDate, triggerDownload } from "../lib/ui";
import { api } from "../lib/api";
import { ScoreGauge } from "./ScoreGauge";
import { SeverityBar } from "./primitives";
import { FindingsTable } from "./FindingsTable";
import { AttackPaths, FirmwarePanel } from "./Intel";

function DownloadBar({ analysisId, demo }: { analysisId: string | null; demo: boolean }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function grab(kind: "executive" | "technical" | "csv" | "json") {
    if (!analysisId) return;
    setErr(null);
    setBusy(kind);
    try {
      const blob = await api.downloadReport(analysisId, kind);
      const ext = kind === "csv" ? "csv" : kind === "json" ? "json" : "pdf";
      const label = kind === "executive" || kind === "technical" ? `${kind}-report` : `findings`;
      triggerDownload(blob, `firelint-${label}-${analysisId.slice(0, 8)}.${ext}`);
    } catch {
      setErr("Download failed. Confirm the analysis is complete and you are signed in.");
    } finally {
      setBusy(null);
    }
  }

  const btn =
    "px-3 py-2 rounded-panel border border-base-500 bg-base-700 text-ink-100 text-[13px] font-medium hover:border-accent hover:bg-base-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed";

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        <button className={btn} disabled={demo || !!busy} onClick={() => grab("executive")}>
          {busy === "executive" ? "Preparing…" : "Executive PDF"}
        </button>
        <button className={btn} disabled={demo || !!busy} onClick={() => grab("technical")}>
          {busy === "technical" ? "Preparing…" : "Technical PDF"}
        </button>
        <button className={btn} disabled={demo || !!busy} onClick={() => grab("csv")}>
          CSV
        </button>
        <button className={btn} disabled={demo || !!busy} onClick={() => grab("json")}>
          JSON
        </button>
      </div>
      {demo && (
        <p className="font-mono text-[11px] text-ink-500">
          Downloads are available when connected to the backend. This is sample data.
        </p>
      )}
      {err && <p className="font-mono text-[11px] text-sev-high">{err}</p>}
    </div>
  );
}

export function AnalysisView({
  analysis,
  analysisId,
  demo,
}: {
  analysis: Analysis;
  analysisId: string | null;
  demo: boolean;
}) {
  const d = analysis.device;
  const sc = analysis.score;
  return (
    <div className="space-y-5">
      {/* Posture header: gauge + identity + downloads */}
      <div className="card-glow overflow-hidden p-6">
        <div className="grid lg:grid-cols-[220px_1fr_auto] gap-6 items-center">
          <div className="flex justify-center">
            <ScoreGauge score={sc} />
          </div>

          <div className="min-w-0">
            <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-500">
              {d.model} · {fmtDate(analysis.generated_at)}
            </div>
            <h1 className="font-display text-2xl font-bold text-ink-100 mt-1">
              Security posture
            </h1>
            <div className="grid sm:grid-cols-2 gap-2 mt-3 max-w-md">
              <KV k="Serial" v={d.serial} />
              <KV k="Firmware" v={d.firmware} />
              <KV k="HA mode" v={d.ha_mode || "—"} />
              <KV k="Findings" v={String(analysis.finding_count)} />
            </div>
            <div className="mt-4">
              <SeverityBar counts={sc.severity_counts} />
            </div>
          </div>

          <div className="lg:border-l lg:border-base-500 lg:pl-6">
            <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-500 mb-2">
              Reports
            </div>
            <DownloadBar analysisId={analysisId} demo={demo} />
          </div>
        </div>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="stat-card"><div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Grade</div><div className="font-display text-xl font-semibold text-ink-100 mt-1">{sc.grade_label}</div><div className="font-mono text-[10px] text-ink-500 mt-0.5">{sc.grade} · {sc.score.toFixed(0)}/100</div></div>
        <div className="stat-card"><div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Critical + High</div><div className="font-display text-xl font-semibold text-ink-100 mt-1">{(sc.severity_counts.Critical || 0) + (sc.severity_counts.High || 0)}</div><div className="font-mono text-[10px] text-ink-500 mt-0.5">urgent findings</div></div>
        <div className="stat-card"><div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Attack paths</div><div className="font-display text-xl font-semibold text-ink-100 mt-1">{analysis.attack_paths.length}</div><div className="font-mono text-[10px] text-ink-500 mt-0.5">correlated chains</div></div>
        <div className="stat-card"><div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Firmware CVEs</div><div className="font-display text-xl font-semibold text-ink-100 mt-1">{analysis.firmware_intelligence?.all_cves?.length || 0}</div><div className="font-mono text-[10px] text-ink-500 mt-0.5">max CVSS {analysis.firmware_intelligence?.max_cvss ?? 0}</div></div>
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        <AttackPaths paths={analysis.attack_paths} />
        <FirmwarePanel fw={analysis.firmware_intelligence} />
      </div>

      <div className="card-glow p-5">
        <div className="flex items-center gap-3 mb-4">
          <span className="w-1 h-7 rounded-full bg-gradient-to-b from-accent to-signal/70 shrink-0" />
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-500">Detail</div>
            <h2 className="font-display font-semibold text-ink-100 text-[15px]">Findings ({analysis.finding_count})</h2>
          </div>
        </div>
        <FindingsTable findings={analysis.findings} />
      </div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline gap-2 min-w-0">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500 w-16 shrink-0">
        {k}
      </span>
      <span className="font-mono text-[12px] text-ink-100 truncate">{v}</span>
    </div>
  );
}