import { useEffect, useState } from "react";
import { usePrompt } from "./Modal";
import { api } from "../lib/api";
import type { User, MfaEnroll, OrganizationDetail } from "../lib/types";
import { Panel } from "./primitives";

// Profile settings: MFA enrollment/disable and email notification preferences.
export function Profile({ user, onUserChange }:
  { user: User; onUserChange: (u: User) => void }) {
  return (
    <div className="space-y-5">
      <OrgPanel />
      <ContactPanel user={user} onUserChange={onUserChange} />
      <MfaPanel user={user} onUserChange={onUserChange} />
      <NotificationsPanel user={user} onUserChange={onUserChange} />
    </div>
  );
}

function OrgPanel() {
  const [org, setOrg] = useState<OrganizationDetail | null>(null);
  useEffect(() => { api.getOrganization().then(setOrg).catch(() => {}); }, []);
  if (!org) return null;
  return (
    <Panel title="Organization">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[13px]">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-0.5">Name</div>
          <div className="text-ink-100">{org.name || "—"}</div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-0.5">Type</div>
          <div className="text-ink-100 capitalize">{org.is_msp ? "MSP" : "Direct"}</div>
        </div>
      </div>
    </Panel>
  );
}

function ContactPanel({ user, onUserChange }: { user: User; onUserChange: (u: User) => void }) {
  const [form, setForm] = useState({
    full_name: user.full_name, phone: user.phone, address: user.address,
  });
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function save() {
    setErr(null); setMsg(null);
    try { onUserChange(await api.updateProfile(form)); setMsg("Saved."); }
    catch (e) { setErr(e instanceof Error ? e.message : "Save failed"); }
  }

  return (
    <Panel title="Profile" eyebrow="Account">
      {err && <p className="text-sev-high text-[12px] mb-2">{err}</p>}
      {msg && <p className="text-signal text-[12px] mb-2">{msg}</p>}
      <div className="grid md:grid-cols-2 gap-3">
        <Field label="Full name"><input value={form.full_name}
          onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))} className={inputCls} /></Field>
        <Field label="Phone"><input value={form.phone}
          onChange={(e) => setForm((f) => ({ ...f, phone: e.target.value }))} className={inputCls} /></Field>
        <Field label="Address"><input value={form.address}
          onChange={(e) => setForm((f) => ({ ...f, address: e.target.value }))} className={inputCls} /></Field>
        <Field label="Email (read-only)"><input value={user.email} disabled
          className={`${inputCls} opacity-60`} /></Field>
      </div>
      <div className="flex items-center justify-between mt-3">
        <span className="font-mono text-[11px] text-ink-500 capitalize">Role: {user.role}</span>
        <button onClick={save} className="px-3 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
          Save profile
        </button>
      </div>
    </Panel>
  );
}

const inputCls = "mt-1 w-full bg-base-700 border border-base-500 rounded-panel px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500">{label}</span>
      {children}
    </label>
  );
}

function MfaPanel({ user, onUserChange }: { user: User; onUserChange: (u: User) => void }) {
  const prompt = usePrompt();
  const [enroll, setEnroll] = useState<MfaEnroll | null>(null);
  const [code, setCode] = useState("");
  const [backup, setBackup] = useState<string[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function start() {
    setErr(null);
    try { setEnroll(await api.mfaEnroll()); }
    catch (e) { setErr(e instanceof Error ? e.message : "Enrollment failed"); }
  }

  async function activate() {
    setErr(null); setBusy(true);
    try {
      const res = await api.mfaActivate(code.trim());
      setBackup(res.backup_codes);
      setEnroll(null);
      onUserChange(await api.me());
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Invalid code");
    } finally { setBusy(false); }
  }

  async function disable() {
    const c = await prompt("Disable MFA", "", "Enter a current TOTP or backup code");
    if (!c) return;
    setErr(null);
    try {
      await api.mfaDisable(c.trim());
      setBackup(null);
      onUserChange(await api.me());
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Disable failed");
    }
  }

  return (
    <Panel title="Two-factor authentication" eyebrow="Security">
      {err && <p className="text-sev-high text-[13px] mb-3">{err}</p>}

      {user.mfa_enabled ? (
        <div className="space-y-3">
          <p className="text-ink-300 text-[13px]">
            MFA is active on your account. You will be asked for a code at each sign-in.
          </p>
          {backup && <BackupCodes codes={backup} />}
          <button onClick={disable}
                  className="px-3 py-2 rounded-panel border border-sev-high text-sev-high text-[13px] hover:bg-sev-high/10">
            Disable MFA
          </button>
        </div>
      ) : enroll ? (
        <div className="space-y-4">
          <p className="text-ink-300 text-[13px]">
            Add this secret to your authenticator app, then enter the 6-digit code to confirm.
          </p>
          <div className="bg-base-700 border border-base-500 rounded-panel p-3">
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500 mb-1">
              Secret
            </div>
            <code className="font-mono text-[13px] text-ink-100 break-all">{enroll.secret}</code>
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-500 mt-3 mb-1">
              otpauth URI
            </div>
            <code className="font-mono text-[11px] text-ink-300 break-all">{enroll.otpauth_uri}</code>
          </div>
          <div className="flex gap-2">
            <input value={code} onChange={(e) => setCode(e.target.value)}
                   placeholder="123456" inputMode="numeric"
                   className="bg-base-700 border border-base-500 rounded-panel px-3 py-2 text-[14px] font-mono tracking-widest text-ink-100 focus:outline-none focus:border-accent w-40" />
            <button onClick={activate} disabled={busy}
                    className="px-4 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90 disabled:opacity-50">
              {busy ? "Verifying…" : "Activate"}
            </button>
          </div>
        </div>
      ) : backup ? (
        <BackupCodes codes={backup} />
      ) : (
        <div className="space-y-3">
          <p className="text-ink-300 text-[13px]">
            Protect your account with a time-based one-time password (TOTP).
          </p>
          <button onClick={start}
                  className="px-3 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
            Enable MFA
          </button>
        </div>
      )}
    </Panel>
  );
}

function BackupCodes({ codes }: { codes: string[] }) {
  return (
    <div className="bg-base-700 border border-signal/40 rounded-panel p-3">
      <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-signal mb-2">
        Backup codes — store these now, they are shown only once
      </div>
      <div className="grid grid-cols-2 gap-1 font-mono text-[12px] text-ink-100">
        {codes.map((c) => <code key={c}>{c}</code>)}
      </div>
    </div>
  );
}

function NotificationsPanel({ user, onUserChange }:
  { user: User; onUserChange: (u: User) => void }) {
  const [err, setErr] = useState<string | null>(null);

  async function toggle(field: "notify_new_critical" | "notify_scan_failed", value: boolean) {
    setErr(null);
    try { onUserChange(await api.updateProfile({ [field]: value })); }
    catch (e) { setErr(e instanceof Error ? e.message : "Update failed"); }
  }

  return (
    <Panel title="Email notifications" eyebrow="Preferences">
      {err && <p className="text-sev-high text-[13px] mb-3">{err}</p>}
      <Toggle label="New critical findings" checked={user.notify_new_critical}
              onChange={(v) => toggle("notify_new_critical", v)} />
      <Toggle label="Scan failures" checked={user.notify_scan_failed}
              onChange={(v) => toggle("notify_scan_failed", v)} />
    </Panel>
  );
}

function Toggle({ label, checked, onChange }:
  { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center justify-between py-2 cursor-pointer">
      <span className="text-[13px] text-ink-300">{label}</span>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </label>
  );
}
