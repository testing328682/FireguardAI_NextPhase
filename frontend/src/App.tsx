import { useEffect, useRef, useState } from "react";
import { api, isAuthed } from "./lib/api";
import type { Analysis, Customer, User } from "./lib/types";
import { Login, Logo } from "./components/Login";
import { AnalysisView } from "./components/AnalysisView";
import { Dashboard } from "./components/Dashboard";
import { FindingsExplorer } from "./components/FindingsExplorer";
import { FindingDetailView } from "./components/FindingDetail";
import { Profile } from "./components/Profile";
import { Rules } from "./components/Rules";
import { RuleDetail } from "./components/RuleDetail";
import { Compliance } from "./components/Compliance";
import { Integrations } from "./components/Integrations";
import { ApiTokens } from "./components/ApiTokens";
import { Devices } from "./components/Devices";
import { DeviceDetailView } from "./components/DeviceDetail";
import { Customers } from "./components/Customers";
import { CustomerDetailView } from "./components/CustomerDetail";
import { Organization } from "./components/Organization";
import { Trends } from "./components/Trends";
import { CelBuilder } from "./components/CelBuilder";
import { ProductConfig } from "./components/ProductConfig";
import { Platform } from "./components/Platform";
import { TsrTester } from "./components/TsrTester";
import { SecurityAnalytics } from "./components/SecurityAnalytics";
import { AdvancedDashboard } from "./components/AdvancedDashboard";
import { ApiFlowConfigPage } from "./components/ApiFlowConfig";
import { PlanManager } from "./components/PlanManager";
import { ModalHost } from "./components/Modal";
import { Icon, type IconName } from "./components/icons";
import { useHashRoute, navigate, matchRoute, currentPath } from "./lib/router";
import { toggleTheme, getTheme } from "./lib/theme";
import demoAnalysis from "./demo-analysis.json";

type Mode = "loading" | "login" | "app" | "demo";
interface NavItem { path: string; label: string; icon: IconName; mspOnly?: boolean }
interface NavGroup { title: string; items: NavItem[] }

const NAV_GROUPS: NavGroup[] = [
  { title: "Overview", items: [
    { path: "/dashboard", label: "Dashboard", icon: "dashboard" },
    { path: "/advanced-dashboard", label: "Advanced Dashboard", icon: "dashboard" },
    { path: "/analytics", label: "Trends", icon: "trends" },
  ] },
  { title: "Assets", items: [
    { path: "/devices", label: "Devices", icon: "devices" },
  ] },
  { title: "MSP", items: [
    { path: "/customers", label: "Customers", icon: "customers", mspOnly: true },
  ] },
  { title: "Security", items: [
    { path: "/findings", label: "Findings", icon: "findings" },
    { path: "/security-analytics", label: "Security Analytics", icon: "findings" },
    { path: "/rules", label: "Rules", icon: "rules" },
    { path: "/compliance", label: "Compliance", icon: "compliance" },
  ] },
  { title: "Connect", items: [
    { path: "/integrations", label: "Integrations", icon: "integrations" },
  ] },
  { title: "Settings", items: [
    { path: "/settings/profile", label: "Profile", icon: "findings" },
    { path: "/settings/organization", label: "Organization", icon: "customers" },
    { path: "/settings/api-tokens", label: "API Tokens", icon: "integrations" },
  ] },
];

const PROFILE_LINKS = [
  { path: "/settings/profile", label: "My profile" },
  { path: "/settings/organization", label: "Organization" },
  { path: "/settings/api-tokens", label: "API tokens" },
];

const TITLES: Record<string, string> = {
  "/dashboard": "Dashboard", "/analytics": "Security Trends", "/devices": "Devices",
  "/customers": "Customers",
  "/customers/": "Customer", "/findings": "Findings", "/security-analytics": "Security Analytics", "/rules": "Detection Rules",
  "/compliance": "Compliance", "/integrations": "Integrations", "/platform": "Platform Operations",
  "/plans": "Plan Management", "/tsr-tester": "TSR Analysis Tester",
  "/api-config": "API TSR Parser Config",
  "/settings/profile": "Settings", "/settings/organization": "Settings", "/settings/api-tokens": "Settings",
};

export default function App() {
  const [mode, setMode] = useState<Mode>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [isMsp, setIsMsp] = useState(false);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [navOpen, setNavOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [theme, setTheme] = useState(getTheme());
  const route = useHashRoute();

  useEffect(() => {
    (async () => {
      const hash = window.location.hash;
      if (hash.startsWith("#/sso?")) {
        const params = new URLSearchParams(hash.split("?")[1]);
        const access = params.get("access");
        const refresh = params.get("refresh");
        if (access && refresh) {
          api.applySsoTokens(access, refresh);
          window.location.hash = "/dashboard";
        }
      }
      if (!isAuthed()) { setMode("login"); return; }
      try {
        const u = await api.me();
        setUser(u);
        await loadContext();
        if (!currentPath() || currentPath() === "/") navigate("/dashboard");
        setMode("app");
      } catch {
        setMode("login");
      }
    })();
  }, []);

  async function loadContext() {
    try {
      const cs = await api.listCustomers();
      setCustomers(cs.length ? cs : [await api.createCustomer("My Organization")]);
    } catch { setCustomers([]); }
    try { setIsMsp((await api.getOrganization()).is_msp); } catch { /* ignore */ }
  }

  function enterDemo() {
    setAnalysis(demoAnalysis as unknown as Analysis);
    setAnalysisId(null);
    setMode("demo");
  }

  function signOut() {
    api.logout();
    setUser(null);
    setAnalysis(null);
    setMode("login");
  }

  function go(path: string) { navigate(path); setNavOpen(false); }

  if (mode === "loading") {
    return (
      <div className="min-h-full grid place-items-center">
        <span className="font-mono text-ink-500 text-sm animate-pulse">Loading…</span>
      </div>
    );
  }

  if (mode === "login") {
    return (
      <Login
        onAuthed={async (u) => { setUser(u); await loadContext(); navigate(u.is_superadmin ? "/platform" : "/dashboard"); setMode("app"); }}
        onDemo={enterDemo}
      />
    );
  }

  // ---- demo: minimal shell ----
  if (mode === "demo") {
    return (
      <div className="min-h-full flex flex-col">
        <TopBar title="Sample analysis" onMenu={null} theme={theme}
                onToggleTheme={() => setTheme(toggleTheme())}
                right={<button onClick={signOut} className="font-mono text-[12px] text-ink-300 hover:text-accent">Exit sample</button>} />
        <main className="flex-1 w-full max-w-[1500px] mx-auto px-6 py-6">
          <AnalysisView analysis={analysis!} analysisId={analysisId} demo />
        </main>
      </div>
    );
  }

  // ---- authenticated app: sidebar shell ----
  // Superadmins get a dedicated operator view; regular users see the full tenant nav.
  const isSuperadmin = user?.is_superadmin ?? false;
  const groups: NavGroup[] = isSuperadmin
    ? [
        { title: "Operator", items: [
          { path: "/platform", label: "Platform", icon: "platform" },
          { path: "/plans", label: "Plans", icon: "integrations" },
          { path: "/rules", label: "Rules", icon: "rules" },
          { path: "/builder", label: "Rule Builder", icon: "rules" },
          { path: "/tsr-tester", label: "TSR Tester", icon: "devices" },
          { path: "/api-config", label: "API TSR Parser Config", icon: "integrations" },
          { path: "/config", label: "Product Config", icon: "platform" },
        ]},
        { title: "MSP", items: [
          { path: "/customers", label: "Customers", icon: "customers" },
        ]},
        { title: "Settings", items: [
          { path: "/settings/organization", label: "Organization", icon: "customers" },
          { path: "/settings/profile", label: "My profile", icon: "findings" },
        ]},
      ]
    : NAV_GROUPS.map((g) => ({
        ...g, items: g.items.filter((it) => !it.mspOnly || isMsp),
      }));
  const title = TITLES[route.split("?")[0]] || (route.startsWith("/findings") ? "Finding"
    : route.startsWith("/rules") ? "Rule"
    : route.startsWith("/devices/") ? "Device" : "FirewallGuard AI");

  const sidebar = (
    <SidebarNav groups={groups} route={route} onNavigate={go} />
  );

  return (
    <ModalHost>
      <div className="min-h-full flex">
        {/* Desktop sidebar */}
        <aside className="hidden lg:flex flex-col w-60 shrink-0 border-r border-base-500 bg-base-800/50 sticky top-0 h-screen">
          {sidebar}
        </aside>

        {/* Mobile drawer */}
        {navOpen && (
          <div className="lg:hidden fixed inset-0 z-30 flex">
            <div className="w-64 bg-base-800 border-r border-base-500 h-full overflow-y-auto">{sidebar}</div>
            <div className="flex-1 bg-black/50" onClick={() => setNavOpen(false)} />
          </div>
        )}

        <div className="flex-1 flex flex-col min-w-0">
          <TopBar
            title={title}
            onMenu={() => setNavOpen(true)}
            theme={theme}
            onToggleTheme={() => setTheme(toggleTheme())}
            right={
              <ProfileMenu user={user} open={profileOpen} setOpen={setProfileOpen}
                           theme={theme} onToggleTheme={() => setTheme(toggleTheme())} onSignOut={signOut} />
            }
          />
          <main className="flex-1 w-full max-w-[1600px] mx-auto px-5 sm:px-6 py-6 space-y-5">
            <Routed route={route} user={user!} customers={customers}
                    onUserChange={setUser}
                    onAnalysis={(id, a) => { setAnalysisId(id); setAnalysis(a); }} />
          </main>
        </div>
      </div>
    </ModalHost>
  );
}

function SidebarNav({ groups, route, onNavigate }:
  { groups: NavGroup[]; route: string; onNavigate: (p: string) => void }) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2.5 px-5 h-16 border-b border-base-500 bg-gradient-to-r from-base-800 to-transparent">
        <Logo />
        <span className="font-display font-bold text-ink-100 tracking-tight">
          FirewallGuard<span className="text-accent"> AI</span>
        </span>
        {groups.some(g => g.title === "Operator") && (
          <span className="badge ml-auto" style={{ color: "#c084fc", borderColor: "#c084fc55", background: "#c084fc14" }}>OPERATOR</span>
        )}
      </div>
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
        {groups.map((g) => (
          <div key={g.title}>
            <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-500 px-3 mb-1.5">{g.title}</div>
            <div className="space-y-0.5">
              {g.items.map((it) => {
                const IconCmp = Icon[it.icon];
                const active = route === it.path || route.startsWith(it.path + "/") ||
                  (it.path === "/findings" && route.startsWith("/findings")) ||
                  (it.path === "/rules" && route.startsWith("/rules"));
                return (
                  <button key={it.path} onClick={() => onNavigate(it.path)}
                          className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] transition-all duration-200 relative ${
                            active
                              ? "bg-accent/10 text-accent font-semibold shadow-[inset_0_0_0_1px_rgba(79,140,255,0.2)]"
                              : "text-ink-300 hover:bg-base-700/60 hover:text-ink-100"
                          }`}>
                    {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-accent shadow-[0_0_6px_rgba(79,140,255,0.5)]" />}
                    <span className={active ? "text-accent" : "text-ink-500"}><IconCmp /></span>
                    {it.label}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-base-500 font-mono text-[10px] text-ink-500">
        Continuous SonicWall posture analysis
      </div>
    </div>
  );
}

function TopBar({ title, onMenu, theme, onToggleTheme, right }:
  { title: string; onMenu: (() => void) | null; theme: string;
    onToggleTheme: () => void; right: React.ReactNode }) {
  return (
    <header className="sticky top-0 z-20 h-16 border-b border-base-500 bg-base-900/80 backdrop-blur flex items-center gap-3 px-5 sm:px-6">
      {onMenu && (
        <button onClick={onMenu} aria-label="Menu"
                className="lg:hidden w-9 h-9 grid place-items-center rounded-panel border border-base-500 text-ink-300">
          <Icon.menu />
        </button>
      )}
      <h1 className="font-display font-semibold text-ink-100 text-[17px] flex-1 truncate">{title}</h1>
      <button onClick={onToggleTheme} aria-label="Toggle theme"
              title={theme === "dark" ? "Switch to light" : "Switch to dark"}
              className="w-9 h-9 grid place-items-center rounded-panel border border-base-500 text-ink-300 hover:text-accent hover:border-accent transition-colors">
        {theme === "dark" ? <Icon.sun /> : <Icon.moon />}
      </button>
      {right}
    </header>
  );
}

function ProfileMenu({ user, open, setOpen, theme, onToggleTheme, onSignOut }:
  { user: User | null; open: boolean; setOpen: (b: boolean) => void; theme: string;
    onToggleTheme: () => void; onSignOut: () => void }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open, setOpen]);

  return (
    <div ref={containerRef} className="relative">
      <button onClick={() => setOpen(!open)}
              className="flex items-center gap-2 rounded-panel border border-base-500 pl-1.5 pr-2 py-1 hover:border-accent transition-colors">
        <span className="w-7 h-7 grid place-items-center rounded-full bg-gradient-to-br from-accent to-signal text-white text-[12px] font-semibold">
          {(user?.full_name || user?.email || "?").slice(0, 1).toUpperCase()}
        </span>
        <span className="font-mono text-[12px] text-ink-300 hidden sm:inline max-w-[150px] truncate">
          {user?.full_name || user?.email}
        </span>
        <span className="text-ink-500 text-[10px]">▾</span>
      </button>
      {open && (
        <div className="absolute right-0 mt-1.5 w-60 z-50 bg-base-800 border border-base-500 rounded-panel shadow-panel py-1.5">
          <div className="px-3 py-2 border-b border-base-500">
            <div className="text-ink-100 text-[13px] truncate">{user?.full_name || "—"}</div>
            <div className="font-mono text-[11px] text-ink-500 truncate">{user?.email}</div>
            <div className="font-mono text-[10px] text-ink-500 mt-0.5 capitalize">
              {user?.role}{user?.is_superadmin ? " · operator" : ""}
            </div>
          </div>
          {PROFILE_LINKS.map((l) => (
            <button key={l.path} onClick={() => { navigate(l.path); setOpen(false); }}
                    className="w-full text-left px-3 py-2 text-[13px] text-ink-300 hover:bg-accent/10 hover:text-accent">
              {l.label}
            </button>
          ))}
          <div className="border-t border-base-500 mt-1 pt-1">
            <button onClick={onToggleTheme}
                    className="w-full text-left px-3 py-2 text-[13px] text-ink-300 hover:bg-accent/10 hover:text-accent">
              {theme === "dark" ? "Light theme" : "Dark theme"}
            </button>
            <button onClick={onSignOut}
                    className="w-full flex items-center gap-2 text-left px-3 py-2 text-[13px] text-sev-high hover:bg-sev-high/10">
              <Icon.logout /> Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Routed({ route, user, customers, onUserChange, onAnalysis }: {
  route: string;
  user: User;
  customers: Customer[];
  onUserChange: (u: User) => void;
  onAnalysis: (id: string | null, a: Analysis) => void;
}) {
  void onAnalysis;
  const path = route.split("?")[0];

  const findingMatch = matchRoute("/findings/:id", path);
  if (findingMatch) return <FindingDetailView id={findingMatch.id} />;
  if (path === "/findings") return <FindingsExplorer />;
  const saFindingMatch = matchRoute("/security-analytics/finding/:id", path);
  if (saFindingMatch) return <FindingDetailView id={saFindingMatch.id} backBase="/security-analytics/device-findings" />;
  if (path === "/security-analytics/device-findings") return <FindingsExplorer backRoute="/security-analytics" />;
  if (path === "/security-analytics") return <SecurityAnalytics />;

  const ruleMatch = matchRoute("/rules/:id", path);
  if (ruleMatch) return <RuleDetail id={ruleMatch.id} user={user} />;
  if (path === "/rules") return <Rules user={user} />;
  if (path === "/compliance") return <Compliance />;
  if (path === "/analytics") return <Trends />;
  if (path === "/advanced-dashboard") return <AdvancedDashboard />;
  if (path === "/platform") return <Platform />;
  if (path === "/plans") return <PlanManager />;
  if (path === "/builder") return <CelBuilder user={user} />;
  if (path === "/tsr-tester") return user?.is_superadmin ? <TsrTester /> : <Dashboard />;
  if (path === "/api-config") return user?.is_superadmin ? <ApiFlowConfigPage /> : <Dashboard />;
  if (path === "/config") return <ProductConfig />;
  if (path === "/integrations") return <Integrations />;
  // Devices is where firewalls are added (API or manual TSR upload).
  const deviceMatch = matchRoute("/devices/:id", path);
  if (deviceMatch) return <DeviceDetailView id={deviceMatch.id} customers={customers} />;
  if (path === "/devices" || path === "/analyze") return <Devices customers={customers} />;
  if (path === "/customers") return <Customers />;
  if (path.startsWith("/customers/")) return <CustomerDetailView id={path.split("/")[2]} />;
  if (path.startsWith("/settings")) {
    return <SettingsLayout route={path} user={user} onUserChange={onUserChange} />;
  }
  return user?.is_superadmin ? <Platform /> : <Dashboard />;
}

function SettingsLayout({ route, user, onUserChange }:
  { route: string; user: User; onUserChange: (u: User) => void }) {
  const tabs = [
    { path: "/settings/profile", label: "Profile" },
    { path: "/settings/organization", label: "Organization" },
    { path: "/settings/api-tokens", label: "API Tokens" },
  ];
  return (
    <div className="space-y-4">
      <div className="flex gap-1 border-b border-base-500">
        {tabs.map((t) => (
          <button key={t.path} onClick={() => navigate(t.path)}
                  className={`px-3 py-2 text-[13px] border-b-2 -mb-px ${
                    route === t.path ? "border-accent text-accent" : "border-transparent text-ink-300 hover:text-ink-100"
                  }`}>
            {t.label}
          </button>
        ))}
      </div>
      {route === "/settings/api-tokens" ? <ApiTokens />
        : route === "/settings/organization" ? <Organization />
        : <Profile user={user} onUserChange={onUserChange} />}
    </div>
  );
}
