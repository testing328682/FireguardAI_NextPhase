import { useState, useCallback, createContext, useContext, useEffect } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";

// ── Types ──────────────────────────────────────────────────────────────
interface ModalConfig {
  title: string;
  message?: string;
  type: "confirm" | "prompt";
  defaultValue?: string;
  placeholder?: string;
  onResolve: (value: string | boolean) => void;
}

// ── Context ────────────────────────────────────────────────────────────
const ModalCtx = createContext<{
  open: (cfg: ModalConfig) => void;
} | null>(null);

// ── Provider ───────────────────────────────────────────────────────────
export function ModalHost({ children }: { children: ReactNode }) {
  const [cfg, setCfg] = useState<ModalConfig | null>(null);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);

  const open = useCallback((c: ModalConfig) => {
    setCfg(c);
    setValue(c.defaultValue || "");
  }, []);

  function close(result: string | boolean) {
    cfg?.onResolve(result);
    setCfg(null);
  }

  return (
    <ModalCtx.Provider value={{ open }}>
      {children}
      {cfg && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 fade-in"
             onClick={() => close(false)}>
          {/* Backdrop */}
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          {/* Card */}
          <div className="relative w-full max-w-sm bg-base-800 border border-base-500 rounded-xl shadow-2xl p-5"
               onClick={(e) => e.stopPropagation()}>
            <h2 className="font-display font-semibold text-ink-100 text-[15px]">{cfg.title}</h2>
            {cfg.message && (
              <p className="text-ink-300 text-[13px] mt-2 leading-relaxed">{cfg.message}</p>
            )}
            {cfg.type === "prompt" && (
              <input
                autoFocus
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={cfg.placeholder}
                onKeyDown={(e) => { if (e.key === "Enter" && value.trim()) close(value); if (e.key === "Escape") close(false); }}
                className="mt-4 block w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2.5 text-[14px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 placeholder:text-ink-500/40"
              />
            )}
            <div className="flex justify-end gap-2 mt-5">
              <button onClick={() => close(false)}
                      className="px-4 py-2 rounded-lg border border-base-500 text-ink-300 text-[13px] hover:border-base-400 hover:text-ink-100 transition-all">
                Cancel
              </button>
              <button onClick={() => close(cfg.type === "confirm" ? true : value)}
                      disabled={cfg.type === "prompt" && !value.trim()}
                      className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
                {cfg.type === "confirm" ? "Confirm" : "OK"}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )}
    </ModalCtx.Provider>
  );
}

// ── Hook ───────────────────────────────────────────────────────────────
function useModal() {
  const ctx = useContext(ModalCtx);
  if (!ctx) throw new Error("ModalHost required");
  return ctx;
}

// ── Public API ─────────────────────────────────────────────────────────
export function useConfirm() {
  const { open } = useModal();
  return (title: string, message?: string): Promise<boolean> =>
    new Promise((resolve) => open({ title, message, type: "confirm", onResolve: (v) => resolve(v as boolean) }));
}

export function usePrompt() {
  const { open } = useModal();
  // Explicit overload to satisfy TypeScript's arity check
  const fn: {
    (title: string): Promise<string | null>;
    (title: string, defaultValue: string): Promise<string | null>;
    (title: string, defaultValue: string, placeholder: string): Promise<string | null>;
  } = (title: string, defaultValue?: string, placeholder?: string) =>
    new Promise((resolve) => open({
      title, defaultValue, placeholder, type: "prompt",
      onResolve: (v) => resolve(v === false ? null : v as string),
    }));
  return fn;
}
