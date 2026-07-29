import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../lib/api";
import type { User } from "../lib/types";

// ── Authentication page ──────────────────────────────────────────────
export function Login({ onAuthed, onDemo }: { onAuthed: (u: User) => void; onDemo: () => void }) {
  const [view, setView] = useState<"signin" | "register">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [reg, setReg] = useState({
    full_name: "", company_name: "", email: "", phone: "", address: "", password: "", is_msp: false,
  });

  async function submit(e: FormEvent) {
    e.preventDefault(); setErr(null); setBusy(true);
    try {
      const res = await api.login(email, password);
      if (res.mfa_required && res.mfa_token) { setMfaToken(res.mfa_token); }
      else { onAuthed(await api.me()); }
    } catch (e) { setErr(e instanceof Error ? e.message : "Sign in failed."); }
    finally { setBusy(false); }
  }

  async function submitRegister(e: FormEvent) {
    e.preventDefault(); setErr(null); setBusy(true);
    try { onAuthed(await api.register(reg)); }
    catch (e) { setErr(e instanceof Error ? e.message : "Registration failed."); }
    finally { setBusy(false); }
  }

  async function submitMfa(e: FormEvent) {
    e.preventDefault(); if (!mfaToken) return; setErr(null); setBusy(true);
    try { onAuthed(await api.mfaVerify(mfaToken, code.trim())); }
    catch (e) { setErr(e instanceof Error ? e.message : "Invalid code."); }
    finally { setBusy(false); }
  }

  const isRegister = view === "register" && !mfaToken;
  function setR<K extends keyof typeof reg>(k: K, v: (typeof reg)[K]) { setReg((r) => ({ ...r, [k]: v })); }

  return (
    <div className="min-h-full grid place-items-center px-4 py-10 relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full bg-accent/5 blur-[120px]" />
        <div className="absolute bottom-0 left-1/4 w-[400px] h-[400px] rounded-full bg-signal/5 blur-[100px]" />
      </div>

      <div className={`relative w-full ${isRegister ? "max-w-md" : "max-w-sm"} fade-in`}>
        {/* Branding */}
        <div className="flex flex-col items-center gap-2 mb-8">
          <Logo />
          <span className="font-display font-bold text-ink-100 text-xl tracking-tight">
            FirewallGuard<span className="text-accent"> AI</span>
          </span>
          <p className="font-mono text-[11px] text-ink-500">Continuous SonicWall Security Posture</p>
        </div>

        {/* Card */}
        <div className="glass p-6">
          {mfaToken ? (
            <>
              <div className="text-center mb-5">
                <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-accent/10 border border-accent/30 grid place-items-center">
                  <span className="text-accent text-xl">🔐</span>
                </div>
                <h1 className="font-display font-semibold text-ink-100">Two-Factor Authentication</h1>
                <p className="text-ink-500 text-[13px] mt-1">Enter the code from your authenticator app.</p>
              </div>
              <form onSubmit={submitMfa} className="space-y-4">
                <Input label="6-Digit Code" type="text" value={code} onChange={setCode} autoFocus placeholder="000000" />
                {err && <ErrorMsg msg={err} />}
                <Submit busy={busy} label="Verify" busyLabel="Verifying…" />
              </form>
            </>
          ) : isRegister ? (
            <>
              <h1 className="font-display font-semibold text-ink-100 text-center">Create Your Account</h1>
              <p className="text-ink-500 text-[13px] text-center mt-1 mb-5">Set up your organization and start analysing firewalls.</p>
              <form onSubmit={submitRegister} className="space-y-3">
                <Input label="Full name" type="text" value={reg.full_name} onChange={(v) => setR("full_name", v)} autoFocus />
                <Input label="Company name" type="text" value={reg.company_name} onChange={(v) => setR("company_name", v)} />
                <Input label="Email" type="email" value={reg.email} onChange={(v) => setR("email", v)} />
                <div className="grid grid-cols-2 gap-3">
                  <Input label="Phone" type="tel" value={reg.phone} onChange={(v) => setR("phone", v)} />
                  <Input label="Password (min 12)" type="password" value={reg.password} onChange={(v) => setR("password", v)} />
                </div>
                <Input label="Address" type="text" value={reg.address} onChange={(v) => setR("address", v)} />
                <label className="flex items-center gap-2 text-[13px] text-ink-300 pt-1 cursor-pointer">
                  <input type="checkbox" checked={reg.is_msp} onChange={(e) => setR("is_msp", e.target.checked)}
                         className="rounded border-base-500 bg-base-700 accent-accent" />
                  We are an MSP managing multiple customers
                </label>
                {err && <ErrorMsg msg={err} />}
                <Submit busy={busy} label="Create account" busyLabel="Creating…" />
              </form>
              <p className="text-center text-[13px] text-ink-500 mt-4">
                Already have an account?{" "}
                <button onClick={() => { setView("signin"); setErr(null); }} className="text-accent hover:underline font-medium">Sign in</button>
              </p>
            </>
          ) : (
            <>
              <h1 className="font-display font-semibold text-ink-100 text-center">Welcome Back</h1>
              <p className="text-ink-500 text-[13px] text-center mt-1 mb-5">Sign in to your FirewallGuard account.</p>
              <form onSubmit={submit} className="space-y-4">
                <Input label="Email" type="email" value={email} onChange={setEmail} autoFocus placeholder="you@example.com" />
                <Input label="Password" type="password" value={password} onChange={setPassword} placeholder="········" />
                {err && <ErrorMsg msg={err} />}
                <Submit busy={busy} label="Sign in" busyLabel="Signing in…" />
              </form>
              <p className="text-center text-[13px] text-ink-500 mt-4">
                New to FirewallGuard?{" "}
                <button onClick={() => { setView("register"); setErr(null); }} className="text-accent hover:underline font-medium">Create an account</button>
              </p>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="mt-5 text-center">
          <button onClick={onDemo} className="font-mono text-[12px] text-ink-300 hover:text-accent transition-colors">
            Explore with sample data →
          </button>
          <p className="font-mono text-[10px] text-ink-500/60 mt-2">Sample data shows a real NSa 3700 analysis.</p>
        </div>
      </div>
    </div>
  );
}

// ── Form elements ─────────────────────────────────────────────────────
function Submit({ busy, label, busyLabel }: { busy: boolean; label: string; busyLabel: string }) {
  return (
    <button type="submit" disabled={busy}
            className="w-full mt-1 px-4 py-3 rounded-lg bg-accent text-white text-sm font-semibold hover:brightness-110 disabled:opacity-40 transition-all shadow-[0_0_20px_-6px_rgba(79,140,255,0.4)]">
      {busy ? busyLabel : label}
    </button>
  );
}

function Input({ label, type, value, onChange, autoFocus, placeholder }: {
  label: string; type: string; value: string; onChange: (v: string) => void; autoFocus?: boolean; placeholder?: string;
}) {
  return (
    <label className="block">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-500">{label}</span>
      <input type={type} value={value} autoFocus={autoFocus} placeholder={placeholder}
             onChange={(e) => onChange(e.target.value)}
             className="mt-1 w-full bg-base-900/80 border border-base-500 rounded-lg px-3.5 py-2.5 text-[14px] text-ink-100 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-all placeholder:text-ink-500/40" />
    </label>
  );
}

function ErrorMsg({ msg }: { msg: string }) {
  return (
    <div className="rounded-lg border border-sev-high/30 bg-sev-high/5 px-3 py-2">
      <p className="font-mono text-[11px] text-sev-high">{msg}</p>
    </div>
  );
}

// ── Logo ──────────────────────────────────────────────────────────────
export function Logo() {
  return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="logoGrad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#4f8cff" />
          <stop offset="100%" stopColor="#39d98a" />
        </linearGradient>
      </defs>
      <path d="M20 3 34 8v10c0 9-6 16-14 19C12 34 6 27 6 18V8L20 3Z"
            stroke="url(#logoGrad)" strokeWidth="2" fill="#4f8cff10" />
      <path d="M20 12v10m0 0 4-3m-4 3-4-3" stroke="#39d98a" strokeWidth="2"
            strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
