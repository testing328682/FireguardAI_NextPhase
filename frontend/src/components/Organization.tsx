import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import type { OrganizationDetail, SSOConfig, PsirtRefresh, PlanData, CustomerPlanInfo, LicensePurchase, FreeLicenseInfo } from "../lib/types";
import { Panel } from "./primitives";
import { fmtDate } from "../lib/ui";

// /settings/organization — plan & billing, residency & branding, SSO, PSIRT.
export function Organization() {
  return (
    <div className="space-y-5">
      <BillingCard />
      <ResidencyBrandingCard />
      <SSOCard />
      <PsirtCard />
    </div>
  );
}

function ResidencyBrandingCard() {
  const [org, setOrg] = useState<OrganizationDetail | null>(null);
  const [regions, setRegions] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(() => {
    api.getOrganization().then(setOrg).catch(() => {});
    api.regions().then((r) => setRegions(r.regions)).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  function set<K extends keyof OrganizationDetail>(k: K, v: OrganizationDetail[K]) {
    setOrg((o) => (o ? { ...o, [k]: v } : o));
  }

  async function save() {
    if (!org) return;
    setErr(null); setMsg(null);
    try {
      setOrg(await api.updateOrganization({
        region: org.region,
        brand_company_name: org.brand_company_name, brand_logo_url: org.brand_logo_url,
        brand_primary_color: org.brand_primary_color, brand_contact: org.brand_contact,
      }));
      setMsg("Saved.");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    }
  }

  if (!org) return <Panel title="Residency & branding"><p className="font-mono text-ink-500 text-sm animate-pulse">Loading…</p></Panel>;

  const color = org.brand_primary_color || "#4f8cff";

  return (
    <Panel title="Data residency & white-label branding" eyebrow="MSP">
      {err && <p className="text-sev-high text-[12px] mb-2">{err}</p>}
      {msg && <p className="text-signal text-[12px] mb-2">{msg}</p>}
      <div className="grid md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <Field label="Data residency region">
            <select value={org.region} onChange={(e) => set("region", e.target.value)} className={inputCls}>
              {regions.map((r) => <option key={r} value={r}>{r.toUpperCase()}</option>)}
            </select>
          </Field>
          <Field label="Company name (on reports)">
            <input value={org.brand_company_name} onChange={(e) => set("brand_company_name", e.target.value)} className={inputCls} />
          </Field>
          <Field label="Logo URL">
            <input value={org.brand_logo_url} onChange={(e) => set("brand_logo_url", e.target.value)} className={inputCls} />
          </Field>
          <Field label="Primary color (hex)">
            <input value={org.brand_primary_color} onChange={(e) => set("brand_primary_color", e.target.value)}
                   placeholder="#1d4ed8" className={inputCls} />
          </Field>
          <Field label="Contact / tagline">
            <input value={org.brand_contact} onChange={(e) => set("brand_contact", e.target.value)} className={inputCls} />
          </Field>
          <button onClick={save}
                  className="px-3 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
            Save
          </button>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-500 mb-2">Report header preview</div>
          <div className="bg-white rounded-panel p-4 border border-base-500">
            <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: "#e2e8f0" }}>
              <span className="font-bold text-sm" style={{ color }}>
                {org.brand_company_name || "FireLint"}
              </span>
              <span className="text-[10px]" style={{ color: "#64748b" }}>
                {org.brand_contact || "Continuous Security Analysis for SonicWall Firewalls"}
              </span>
            </div>
            <div className="mt-3 text-[11px]" style={{ color: "#0f172a" }}>Executive Security Report</div>
            <div className="text-[10px]" style={{ color: "#64748b" }}>NSa 3700 · Serial 18C2…  ·  Grade A</div>
          </div>
        </div>
      </div>
    </Panel>
  );
}

function PlanSelectCard({ plan, discount, busy, onSelect }: {
  plan: PlanData; discount: number;
  busy: boolean; onSelect: (plan: PlanData, term: "monthly" | "yearly") => void;
}) {
  const [term, setTerm] = useState<"monthly" | "yearly">("monthly");
  const isTesting = plan.is_testing;

  if (isTesting) {
    const mins = plan.validity_minutes || 0;
    const validityLabel = mins < 60 ? `${mins}min` : mins < 1440 ? `${(mins / 60).toFixed(0)}hr` : `${(mins / 1440).toFixed(0)}d`;
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <span className="badge text-[9px]" style={{ color: "#f5c451", borderColor: "#f5c45155", background: "#f5c45114" }}>TEST</span>
          <span className="font-mono text-[10px] text-ink-500">{validityLabel} validity</span>
        </div>
        <button onClick={() => onSelect(plan, "monthly")} disabled={busy}
                className="w-full px-3 py-1.5 rounded-md bg-accent text-white text-[12px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
          {busy ? "Selecting…" : "Select Plan"}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="inline-flex rounded-md bg-base-700 border border-base-500 p-0.5 w-full">
        <button onClick={() => setTerm("monthly")}
                className={`flex-1 py-1.5 rounded text-[11px] font-medium transition-all ${
                  term === "monthly" ? "bg-accent text-white shadow-sm" : "text-ink-500 hover:text-ink-300"
                }`}>
          Monthly
        </button>
        <button onClick={() => setTerm("yearly")}
                className={`flex-1 py-1.5 rounded text-[11px] font-medium transition-all ${
                  term === "yearly" ? "bg-accent text-white shadow-sm" : "text-ink-500 hover:text-ink-300"
                }`}>
          Yearly{discount > 0 ? ` -${discount}%` : ""}
        </button>
      </div>
      {term === "yearly" && discount > 0 && plan.plan_type !== "msp" && plan.price_per_device > 0 && (
        <div className="text-ink-500">
          <span className="font-mono text-[10px]">
            <span className="text-signal">${(plan.price_per_device * (1 - discount / 100)).toFixed(2)}/device/mo</span>
          </span>
        </div>
      )}
      {term === "yearly" && discount > 0 && plan.plan_type === "msp" && (
        <div className="flex flex-wrap gap-2 text-ink-500">
          {Object.entries(plan.pricing_tiers || {}).slice(0, 4).map(([tier, price]: [string, any]) => (
            <span key={tier} className="font-mono text-[10px]">
              {tier} dev: <span className="text-signal">${(Number(price) * (1 - discount / 100)).toFixed(0)}</span>
            </span>
          ))}
        </div>
      )}
      <button onClick={() => onSelect(plan, term)} disabled={busy}
              className="w-full px-3 py-1.5 rounded-md bg-accent text-white text-[12px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
        {busy ? "Selecting…" : "Select Plan"}
      </button>
    </div>
  );
}

function BillingCard() {
  const [org, setOrg] = useState<OrganizationDetail | null>(null);
  const [planInfo, setPlanInfo] = useState<CustomerPlanInfo | null>(null);
  const [availablePlans, setAvailablePlans] = useState<PlanData[]>([]);
  const [freeLicense, setFreeLicense] = useState<FreeLicenseInfo | null>(null);
  // Purchase form state
  const [purCount, setPurCount] = useState(1);
  const [purTier, setPurTier] = useState("10");
  const [cart, setCart] = useState<{ count: number; tier?: string; price: number; subTerm: string }[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.getOrganization().then(setOrg).catch(() => {});
    api.currentPlan().then(setPlanInfo).catch(() => {});
    api.availablePlans().then(setAvailablePlans).catch(() => {});
    api.fetchLicenseBundles().then((r) => setFreeLicense(r.free_license ?? null)).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  const planName = planInfo?.plan_name || org?.plan || "None";
  const isFree = planName === "Free" || planName === "free";
  const planType = planInfo?.plan_type || "professional";
  // Inherit subscription term from selected plan
  const purTerm: "monthly" | "yearly" = (planInfo as any)?.subscription_term || "monthly";
  const currentPlan = availablePlans.find((p) => p.name === planName);
  const tiers = planInfo?.pricing_tiers || currentPlan?.pricing_tiers || {};
  const pricePerDevice = planInfo?.price_per_device ?? currentPlan?.price_per_device ?? 0;
  const mspTierKeys = planType === "msp" ? Object.keys(tiers).sort((a, b) => Number(a) - Number(b)) : [];
  const totalCost = planInfo?.monthly_cost || 0;

  // License allocations from plan info, keyed by subscription term:
  //   Professional: {"monthly": {"licenses": 5}}
  //   MSP:          {"monthly": {"10": 3}}   (tier -> purchased count)
  const allocs: Record<string, number> = {};
  const allocByTerm: Record<string, Record<string, number>> = { monthly: {}, yearly: {} };
  const allocRaw = planInfo?.license_allocations || {};
  const terms = (allocRaw as any).monthly !== undefined || (allocRaw as any).yearly !== undefined
    ? ["monthly", "yearly"] : null;

  function processAlloc(data: Record<string, any>, targetTerm: string) {
    for (const [k, v] of Object.entries(data)) {
      if (typeof v !== "number") continue;
      const tierMult = planType === "msp" ? (Number(k) || 1) : 1;
      const licenses = v * tierMult;
      allocs[k] = (allocs[k] || 0) + licenses;
      allocByTerm[targetTerm][k] = (allocByTerm[targetTerm][k] || 0) + licenses;
    }
  }

  if (terms) {
    for (const term of terms) {
      if ((allocRaw as any)[term]) processAlloc((allocRaw as any)[term] || {}, term);
    }
  } else {
    processAlloc(allocRaw, "monthly");
  }

  const totalLicenses = Object.values(allocs).reduce((a, b) => a + b, 0);
  const usedDevices = planInfo?.usage?.firewalls || 0;
  const yearlyDiscount = planInfo?.yearly_discount_pct || 20;
  const yearlyTotal = planInfo?.yearly_total || 0;
  const displayCost = purTerm === "yearly" && yearlyTotal > 0 ? yearlyTotal : totalCost;
  const displayPeriod = purTerm === "yearly" && yearlyTotal > 0 ? "/yr" : "/mo";

  async function selectPlan(plan: PlanData, term: "monthly" | "yearly") {
    setErr(null); setMsg(null); setBusy(true);
    try {
      const info = await api.updateOrgPlan({ plan_id: plan.id, subscription_term: term });
      setPlanInfo(info); setMsg(`Upgraded to ${plan.name} (${term}).`);
      setPurTier(mspTierKeys[0] || "10");
    } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
    finally { setBusy(false); }
  }

  function addToCart() {
    const key = `${purTerm}-${planType === "msp" ? purTier : "flat"}`;
    setCart((c) => {
      const existing = c.findIndex((item) =>
        `${item.subTerm}-${planType === "msp" ? item.tier : "flat"}` === key);
      if (existing >= 0) {
        const updated = [...c];
        updated[existing] = { ...updated[existing], count: updated[existing].count + purCount };
        return updated;
      }
      const basePrice = planType === "msp" ? Number((tiers as any)?.[purTier] || 0) : pricePerDevice;
      // Yearly discount applied to monthly-equivalent price
      const effectivePrice = purTerm === "yearly"
        ? basePrice * (1 - yearlyDiscount / 100)
        : basePrice;
      return [...c, { count: purCount, tier: planType === "msp" ? purTier : undefined, price: effectivePrice, subTerm: purTerm }];
    });
    setPurCount(1);
  }

  function removeFromCart(idx: number) {
    setCart((c) => c.filter((_, i) => i !== idx));
  }

  async function purchaseCart() {
    setErr(null); setMsg(null); setBusy(true);
    try {
      for (const item of cart) {
        const body: any = { count: item.count, subscription_term: item.subTerm };
        if (planType === "msp") body.tier = item.tier;
        const info = await api.purchaseLicenses(body);
        setPlanInfo(info);
      }
      setCart([]);
      setMsg(`Purchased ${cart.reduce((s, i) => s + i.count, 0)} licenses across ${cart.length} bundle(s).`);
    } catch (e) { setErr(e instanceof Error ? e.message : "Purchase failed"); }
    finally { setBusy(false); }
  }

  return (
    <Panel title="Plan & billing" eyebrow="Subscription">
      {err && <p className="text-sev-high text-[12px] mb-2">{err}</p>}
      {msg && <p className="text-signal text-[12px] mb-2">{msg}</p>}

      {/* License Details Card */}
      <div className="mb-4 p-4 rounded-lg bg-base-800/50 border border-base-500 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-ink-100 font-semibold text-sm">{planName}</span>
              {currentPlan?.is_testing && (
                <span className="badge text-[9px] ml-1" style={{ color: "#f5c451", borderColor: "#f5c45155", background: "#f5c45114" }}>TEST</span>
              )}
              {!isFree && (
                <span className="badge text-[9px] capitalize"
                      style={{ color: purTerm === "yearly" ? "#c084fc" : "#4f8cff",
                               borderColor: purTerm === "yearly" ? "#c084fc55" : "#4f8cff55",
                               background: purTerm === "yearly" ? "#c084fc14" : "#4f8cff14" }}>
                  {purTerm === "yearly" ? "Yearly" : "Monthly"}
                </span>
              )}
              {!isFree && yearlyDiscount > 0 && purTerm === "yearly" && (
                <span className="font-mono text-[9px] text-signal">-{yearlyDiscount}%</span>
              )}
            </div>
            <div className="font-mono text-[10px] text-ink-500 mt-0.5">
              {isFree
                ? (freeLicense
                    ? `Free Monthly license · ${freeLicense.remaining} of ${freeLicense.total} available`
                    : "1 device included")
                : `${planInfo?.device_count || 0} licenses`}
              {isFree && freeLicense && (
                <span className="block mt-0.5">
                  Start {freeLicense.start_date ? freeLicense.start_date.slice(0, 10) : "—"}
                  {" · "}Expires {freeLicense.expiry_date ? freeLicense.expiry_date.slice(0, 10) : "—"}
                  {freeLicense.expired && <span className="text-sev-high"> (expired)</span>}
                </span>
              )}
              {planInfo?.usage?.firewalls != null && planInfo.usage.firewalls > 0 && <span> · {planInfo.usage.firewalls} registered</span>}
            </div>
          </div>
          {displayCost > 0 && (
            <div className="text-right">
              <div className="font-display font-bold text-lg text-accent">${displayCost.toFixed(2)}<span className="text-[12px] font-normal text-ink-500">{displayPeriod}</span></div>
            </div>
          )}
          {isFree && <span className="font-mono text-[12px] text-ink-500">Free</span>}
        </div>

        {/* License Utilization */}
        {!isFree && totalLicenses > 0 && (
          <div className="space-y-2 border-t border-base-500 pt-3">
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">License Utilization</div>
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="text-ink-300">Total Licenses</span>
                <span className="text-ink-100 font-mono">{usedDevices} / {totalLicenses} Used</span>
              </div>
              <div className="h-1.5 rounded-full bg-base-700 overflow-hidden">
                <div className="h-full rounded-full" style={{
                  width: `${totalLicenses > 0 ? (usedDevices / totalLicenses) * 100 : 0}%`,
                  background: usedDevices >= totalLicenses ? "#ff4d4d" : "#39d98a",
                }} />
              </div>
            </div>
            {Object.values(allocByTerm.yearly || {} as Record<string, number>).reduce((a, b) => a + b, 0) > 0 &&
             Object.values(allocByTerm.monthly || {} as Record<string, number>).reduce((a, b) => a + b, 0) > 0 && (
              <div className="flex gap-3 mt-1 text-[10px]">
                <span className="text-ink-500 font-mono">Monthly: {Object.values(allocByTerm.monthly || {})
                  .reduce((a: number, b: number) => a + b, 0)}</span>
                <span className="text-[#c084fc] font-mono">Yearly: {Object.values(allocByTerm.yearly || {})
                  .reduce((a: number, b: number) => a + b, 0)} (-{yearlyDiscount}%)</span>
              </div>
            )}
          </div>
        )}

        {isFree && (
          <div className="text-ink-500 text-[12px] font-mono border-t border-base-500 pt-3">
            {usedDevices > 0 ? `${usedDevices} device(s) registered` : "No devices"}
          </div>
        )}
      </div>

      {/* Purchase History */}
      {!isFree && planInfo && (planInfo.purchase_history?.length ?? 0) > 0 && (
        <div className="mb-4 p-4 rounded-lg bg-base-800/30 border border-base-500">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-3">License Purchase History</div>
          <PurchaseHistory purchases={planInfo.purchase_history} />
        </div>
      )}

      {/* Purchase licenses (non-Free only) */}
      {!isFree && (
        <div className="mb-4 p-4 rounded-lg bg-base-800/30 border border-base-500">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-3">
            Purchase Licenses · <span className="text-ink-300">{purTerm === "yearly" ? "Yearly" : "Monthly"} term{yearlyDiscount > 0 && purTerm === "yearly" ? ` (-${yearlyDiscount}%)` : ""}</span>
          </div>
          <div className="grid sm:grid-cols-3 gap-3 items-end">
            {planType === "msp" && mspTierKeys.length > 0 && (
              <label className="block">
                <span className="font-mono text-[10px] text-ink-500">Tier</span>
                <select value={purTier} onChange={(e) => setPurTier(e.target.value)}
                        className="mt-1 w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent">
                  {mspTierKeys.map((t) => (
                    <option key={t} value={t}>{t} devices{Number((tiers as any)?.[t]) > 0 ? ` — $${(tiers as any)[t]}/mo` : ""}</option>
                  ))}
                </select>
              </label>
            )}
            {planType !== "msp" && pricePerDevice > 0 && (
              <div className="font-mono text-[10px] text-ink-500 self-center">
                ${pricePerDevice}/device/mo
              </div>
            )}
            <label className="block">
              <span className="font-mono text-[10px] text-ink-500">Count</span>
              <input type="number" min={1} value={purCount} onChange={(e) => setPurCount(Math.max(1, Number(e.target.value)))}
                     className="mt-1 w-full bg-base-900 border border-base-500 rounded-lg px-3 py-2 text-[13px] text-ink-100 focus:outline-none focus:border-accent" />
            </label>
            <div className="flex items-end gap-2">
              <button onClick={addToCart} disabled={busy}
                      className="px-4 py-2 rounded-lg border border-accent/40 text-accent text-[13px] font-medium hover:bg-accent/10 transition-all whitespace-nowrap">
                + Add to Cart
              </button>
            </div>
          </div>
          {/* Cart */}
          {cart.length > 0 && (
            <div className="mt-3 p-3 rounded bg-base-900/50 border border-base-500 space-y-2">
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">Purchase Cart</div>
              {cart.map((item, i) => (
                <div key={i} className="flex items-center justify-between text-[12px]">
                  <span className="text-ink-300">
                    <span className={`font-mono text-[9px] mr-1 ${item.subTerm === "yearly" ? "text-[#c084fc]" : ""}`}>
                      {item.subTerm === "yearly" ? "YR" : "MO"}
                    </span>
                    {item.count}× license{item.count !== 1 ? "s" : ""}{item.tier ? ` (Tier ${item.tier})` : ""}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-ink-100">${(item.price * item.count).toFixed(2)}/mo</span>
                    <button onClick={() => removeFromCart(i)}
                            className="text-ink-500 hover:text-sev-high text-xs">×</button>
                  </div>
                </div>
              ))}
              <div className="flex items-center justify-between border-t border-base-500 pt-2">
                <span className="text-ink-100 font-semibold text-[13px]">
                  Total: ${cart.reduce((s, i) => s + i.price * i.count, 0).toFixed(2)}/mo
                </span>
                <button onClick={purchaseCart} disabled={busy}
                        className="px-4 py-2 rounded-lg bg-accent text-white text-[13px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
                  {busy ? "Processing…" : "Purchase All"}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Features */}
      {planInfo && (
        <div className="mb-4">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-1">Features</div>
          <div className="flex flex-wrap gap-1">
            {Object.entries(planInfo.features || {}).filter(([, v]) => v).map(([k]) => (
              <span key={k} className="badge text-[9px]" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>
                {k.replace(/_/g, " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Available plans */}
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500 mb-2">Available Plans</div>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {availablePlans.filter((p) => p.is_visible).map((p) => {
          const active = planName === p.name;
          const discount = p.yearly_discount_pct || 20;
          return (
            <div key={p.id} className={`p-3 rounded-lg border transition-all flex flex-col ${
              active ? "border-accent/50 bg-accent/5" : "border-base-500 bg-base-800/30 hover:border-base-400"
            }`}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-ink-100 font-semibold text-[13px]">{p.name}</span>
                {active && <span className="badge text-[9px]" style={{ color: "#39d98a", borderColor: "#39d98a55", background: "#39d98a14" }}>Current</span>}
              </div>
              <div className="font-mono text-[10px] text-ink-500 line-clamp-2 mb-2">{p.description || "—"}</div>
              {/* Pricing details — flex-grow pushes buttons to bottom */}
              <div className="flex-1">
              {p.plan_type === "msp" ? (
                <div className="flex flex-wrap gap-2 mb-2">
                  {Object.entries(p.pricing_tiers || {}).map(([tier, price]: [string, any]) => (
                    <span key={tier} className="font-mono text-[10px] text-ink-500">
                      {tier} dev: <span className="text-ink-300">${price}/mo</span>
                    </span>
                  ))}
                </div>
              ) : (
                p.price_per_device > 0 && (
                  <div className="mb-2">
                    <span className="font-mono text-[10px] text-ink-500">
                      <span className="text-ink-300">${p.price_per_device}/device/mo</span>
                    </span>
                  </div>
                )
              )}
              </div>{/* end flex-1 */}
              {/* Term selection + select button (two-step) — Free plan has no term */}
              {!active && p.name !== "Free" && (
                <PlanSelectCard plan={p} discount={discount}
                                busy={busy} onSelect={selectPlan} />
              )}
              {!active && p.name === "Free" && (
                <button onClick={() => selectPlan(p, "monthly")} disabled={busy}
                        className="w-full px-3 py-1.5 rounded-md bg-accent text-white text-[12px] font-semibold hover:brightness-110 disabled:opacity-40 transition-all">
                  {busy ? "Selecting…" : "Select Free"}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function SSOCard() {
  const [cfg, setCfg] = useState<SSOConfig | null>(null);
  const [secret, setSecret] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(() => {
    api.getSsoConfig().then(setCfg).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load SSO config"));
  }, []);
  useEffect(() => { load(); }, [load]);

  async function save() {
    if (!cfg) return;
    setErr(null); setMsg(null);
    try {
      const payload: any = { ...cfg };
      if (secret) payload.oidc_client_secret = secret;
      const updated = await api.putSsoConfig(payload);
      setCfg(updated);
      setSecret("");
      setMsg("Saved.");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Save failed");
    }
  }

  function set<K extends keyof SSOConfig>(k: K, v: SSOConfig[K]) {
    setCfg((c) => (c ? { ...c, [k]: v } : c));
  }

  if (!cfg) return <Panel title="Single sign-on"><p className="font-mono text-ink-500 text-sm animate-pulse">Loading…</p></Panel>;

  return (
    <Panel title="Single sign-on" eyebrow="SAML / OIDC">
      {err && <p className="text-sev-high text-[12px] mb-2">{err}</p>}
      {msg && <p className="text-signal text-[12px] mb-2">{msg}</p>}
      <div className="space-y-3">
        <label className="flex items-center justify-between py-1 cursor-pointer">
          <span className="text-[13px] text-ink-300">Enabled</span>
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => set("enabled", e.target.checked)} />
        </label>
        <Field label="Protocol">
          <select value={cfg.protocol} onChange={(e) => set("protocol", e.target.value as "oidc" | "saml")}
                  className={inputCls}>
            <option value="oidc">OIDC</option>
            <option value="saml">SAML 2.0</option>
          </select>
        </Field>

        {cfg.protocol === "oidc" ? (
          <>
            <Field label="Discovery URL (Okta / Entra ID / Google)">
              <input value={cfg.oidc_discovery_url} onChange={(e) => set("oidc_discovery_url", e.target.value)}
                     placeholder="https://idp/.well-known/openid-configuration" className={inputCls} />
            </Field>
            <Field label="Client ID">
              <input value={cfg.oidc_client_id} onChange={(e) => set("oidc_client_id", e.target.value)} className={inputCls} />
            </Field>
            <Field label={`Client secret ${cfg.has_client_secret ? "(set — leave blank to keep)" : ""}`}>
              <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} className={inputCls} />
            </Field>
          </>
        ) : (
          <>
            <Field label="IdP entity ID">
              <input value={cfg.saml_idp_entity_id} onChange={(e) => set("saml_idp_entity_id", e.target.value)} className={inputCls} />
            </Field>
            <Field label="IdP SSO URL">
              <input value={cfg.saml_idp_sso_url} onChange={(e) => set("saml_idp_sso_url", e.target.value)} className={inputCls} />
            </Field>
            <Field label="IdP x509 certificate">
              <textarea value={cfg.saml_idp_x509_cert} onChange={(e) => set("saml_idp_x509_cert", e.target.value)}
                        rows={3} className={`${inputCls} font-mono text-[11px]`} />
            </Field>
            <p className="font-mono text-[11px] text-ink-500">
              Note: SAML signature validation is not enforced in this build — use OIDC for production.
            </p>
          </>
        )}

        <Field label="Groups → role mapping (JSON)">
          <textarea
            value={JSON.stringify(cfg.group_role_map, null, 0)}
            onChange={(e) => {
              try { set("group_role_map", JSON.parse(e.target.value)); } catch { /* ignore */ }
            }}
            rows={2} className={`${inputCls} font-mono text-[12px]`}
            placeholder='{"fw-admins": "admin", "auditors": "viewer"}' />
        </Field>
        <Field label="Default role">
          <select value={cfg.default_role} onChange={(e) => set("default_role", e.target.value)} className={inputCls}>
            {["owner", "admin", "analyst", "msp_operator", "viewer"].map((r) => <option key={r}>{r}</option>)}
          </select>
        </Field>

        <button onClick={save}
                className="px-3 py-2 rounded-panel bg-accent text-white text-[13px] font-semibold hover:opacity-90">
          Save SSO configuration
        </button>
      </div>
    </Panel>
  );
}

function PsirtCard() {
  const [logs, setLogs] = useState<PsirtRefresh[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api.psirtChangelog().then(setLogs).catch((e) =>
      setErr(e instanceof Error ? e.message : "Failed to load changelog"));
  }, []);
  useEffect(() => { load(); }, [load]);

  async function refresh() {
    setBusy(true); setErr(null);
    try { await api.psirtRefresh(); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Refresh failed"); }
    finally { setBusy(false); }
  }

  return (
    <Panel title="PSIRT advisories" eyebrow="Threat intelligence"
           right={<button onClick={refresh} disabled={busy}
                          className="px-3 py-1.5 rounded-panel border border-base-500 text-ink-300 text-[12px] hover:border-accent hover:text-accent disabled:opacity-50">
             {busy ? "Refreshing…" : "Refresh now"}
           </button>}>
      {err && <p className="text-sev-high text-[12px] mb-2">{err}</p>}
      {logs.length === 0 ? (
        <p className="text-ink-500 text-sm">No refresh history yet.</p>
      ) : (
        <ul className="divide-y divide-base-500">
          {logs.map((l) => (
            <li key={l.id} className="flex items-center justify-between gap-3 py-2 text-[13px]">
              <span className="font-mono text-[11px]" style={{ color: l.changed ? "#f5c451" : "#6b7689" }}>
                {l.changed ? "changed" : "no change"}
              </span>
              <span className="text-ink-300">{l.advisory_count} advisories · {l.affected_devices} affected</span>
              <span className="text-ink-500">{l.source}</span>
              <span className="font-mono text-[11px] text-ink-500">{fmtDate(l.ran_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function PurchaseHistory({ purchases }: { purchases: LicensePurchase[] }) {
  const totalLicenses = purchases.reduce((s, p) => s + p.total_devices, 0);
  return (
    <div className="space-y-1.5">
      <div className="font-mono text-[10px] text-ink-500 mb-1">
        {purchases.length} purchase{purchases.length !== 1 ? "s" : ""} · {totalLicenses} licenses total
      </div>
      {purchases.map((p) => (
        <div key={p.id} className="flex items-center justify-between text-[11px] py-1.5 px-3 rounded bg-base-900/50 border border-base-500">
          <div>
            <span className="text-ink-300">
              {p.total_devices} license{p.total_devices !== 1 ? "s" : ""}
              {p.tier ? <span className="text-ink-500 ml-1">(Tier {p.tier} × {p.count})</span> : ` × ${p.count}`}
            </span>
            <span className={`ml-2 font-mono text-[9px] ${p.subscription_term === "yearly" ? "text-[#c084fc]" : "text-ink-500"}`}>
              {p.subscription_term === "yearly" ? "YR" : "MO"}
            </span>
          </div>
          <div className="text-right font-mono text-ink-500">
            <div>Purchased: {p.purchased_at ? new Date(p.purchased_at).toLocaleDateString() : "—"}</div>
            <div>Expires: {p.expires_at ? new Date(p.expires_at).toLocaleDateString() : "—"}</div>
          </div>
        </div>
      ))}
    </div>
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