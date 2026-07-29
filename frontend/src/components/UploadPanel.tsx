import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { Analysis, Customer } from "../lib/types";

type Phase = "idle" | "uploading" | "analyzing" | "done" | "error";

export function UploadPanel({
  customers,
  deviceId,
  customerId: propCustomerId,
  onComplete,
}: {
  customers: Customer[];
  deviceId?: string;
  customerId?: string;
  onComplete: (analysisId: string, analysis: Analysis) => void;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [msg, setMsg] = useState<string>("");
  const [customerId, setCustomerId] = useState<string>(propCustomerId || (customers[0]?.id ?? ""));
  // Sync when prop updates (device loads asynchronously)
  useEffect(() => {
    if (propCustomerId) setCustomerId(propCustomerId);
  }, [propCustomerId]);
  const [drag, setDrag] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    if (!customerId) { setPhase("error"); setMsg("Select a customer."); return; }
    if (!deviceId) { setPhase("error"); setMsg("No device selected. Register a device first."); return; }
    setPhase("uploading"); setMsg(`Uploading ${file.name}…`);
    try {
      const summary = await api.uploadTsr(customerId, deviceId, file);
      setPhase("analyzing"); setMsg("Analyzing…");
      const final = await poll(summary.id);
      if (final.status === "complete") {
        const detail = await api.getAnalysis(summary.id);
        setPhase("done"); setMsg("Complete.");
        onComplete(summary.id, detail.result_json);
      } else { setPhase("error"); setMsg("Analysis failed."); }
    } catch (e) {
      setPhase("error"); setMsg(e instanceof Error ? e.message : "Upload failed.");
    }
  }

  async function poll(id: string) {
    for (let i = 0; i < 120; i++) {
      const s = await api.getAnalysis(id);
      if (s.status === "complete" || s.status === "failed") return s;
      await new Promise((r) => setTimeout(r, 1500));
    }
    return api.getAnalysis(id);
  }

  const working = phase === "uploading" || phase === "analyzing";

  return (
    <div className="space-y-3">
      {/* Customer selector (only when no deviceId — registration flow shows it) */}
      {!deviceId && (
        <label className="block">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">Customer</span>
          <select value={customerId} onChange={(e) => setCustomerId(e.target.value)}
                  className="mt-1 block w-full bg-base-800 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
            {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
      )}

      {/* Dropzone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files?.[0]; if (f) handleFile(f); }}
        onClick={() => inputRef.current?.click()}
        role="button" tabIndex={0}
        onKeyDown={(e) => e.key === "Enter" && inputRef.current?.click()}
        className={`flex items-center justify-center gap-3 px-4 py-4 rounded-lg border-2 border-dashed cursor-pointer transition-colors ${
          drag ? "border-accent bg-accent/5" : "border-base-500 hover:border-base-400 bg-base-800/50"
        }`}
      >
        <span className="text-accent text-lg">↑</span>
        <div>
          <div className="text-ink-100 text-[13px] font-medium">
            {working ? msg : "Drop a TSR file or click to browse"}
          </div>
          <div className="font-mono text-[10px] text-ink-500">.wri / .txt · up to 64 MB</div>
        </div>
        <input ref={inputRef} type="file" accept=".wri,.txt,text/plain" className="hidden"
               onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
      </div>

      {/* Progress + status */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-3">
          {(["uploading", "analyzing", "done"] as Phase[]).map((s, i) => {
            const active = working && phase === s;
            const done = phase === "done" || (working && i === 0 && (phase === "analyzing"));
            const isDone = phase === "done" ? true : i === 0 && phase !== "idle" && phase !== "error";
            return (
              <div key={s} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${isDone ? "bg-signal" : active ? "bg-accent animate-pulse" : "bg-base-600"}`} />
                <span className={`font-mono text-[10px] ${isDone ? "text-ink-300" : "text-ink-500"}`}>{s === "uploading" ? "Upload" : s === "analyzing" ? "Analyze" : "Done"}</span>
                {i < 2 && <span className="text-ink-500 text-[10px] mx-1">→</span>}
              </div>
            );
          })}
        </div>
        {msg && !working && (
          <span className={`font-mono text-[11px] ${phase === "error" ? "text-sev-high" : "text-signal"}`}>{msg}</span>
        )}
      </div>
    </div>
  );
}
