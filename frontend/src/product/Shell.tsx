import { Suspense, useEffect, useRef, useState } from "react";
import {
  Link,
  NavLink,
  Outlet,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  Activity,
  Bell,
  Blocks,
  Boxes,
  Building2,
  Bug,
  ChevronDown,
  ChevronRight,
  ChevronsLeft,
  CircleHelp,
  Cloud,
  Container,
  Database,
  FileCheck2,
  FileCode2,
  FileText,
  Fingerprint,
  LayoutDashboard,
  ListChecks,
  LogOut,
  MapPin,
  Network,
  Radar,
  Search,
  Share2,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Wrench,
  X,
} from "lucide-react";
import { assets, tenants } from "./data";
import { useProduct, type Role } from "./store";
import { serviceAllowsAsset, serviceAllowsPath } from "./services";
import { Badge, Overlay } from "./ui";
import { useAccountScope } from "../lib/accountScope";
import { api } from "../lib/api";
import AWS from "react-aws-icons/dist/aws/logo/AWS";
import "./product.css";
import "./shell-premium.css";

const AWSLogo = ((AWS as unknown as { default?: typeof AWS }).default ?? AWS);

const groups = [
  {
    label: "Overview",
    items: [{ path: "/", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Cloud security",
    items: [
      { path: "/security-graph", label: "Security Graph", icon: Share2 },
      { path: "/accounts", label: "Cloud Accounts", icon: Cloud },
      { path: "/inventory", label: "Inventory", icon: Boxes },
      { path: "/findings", label: "Issues", icon: ShieldAlert },
      { path: "/attack-paths", label: "Attack Paths", icon: Network },
      {
        path: "/cloud-configuration",
        label: "Cloud Configuration",
        icon: SlidersHorizontal,
      },
      { path: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
      { path: "/kubernetes", label: "Kubernetes Security", icon: Container },
      { path: "/data", label: "Data Security", icon: Database },
      { path: "/identities", label: "Identity & Access", icon: Fingerprint },
      { path: "/workloads", label: "Workload Security", icon: Blocks },
      { path: "/threats", label: "Threat Detection", icon: Radar },
    ],
  },
  {
    label: "Developer security",
    items: [
      { path: "/code-security", label: "Code Security", icon: FileCode2 },
      { path: "/iac", label: "IaC Scanner", icon: FileCode2 },
    ],
  },
  {
    label: "Governance",
    items: [
      { path: "/compliance", label: "Compliance", icon: ShieldCheck },
      { path: "/policies", label: "Policies", icon: ListChecks },
      { path: "/exceptions", label: "Exceptions", icon: FileCheck2 },
    ],
  },
  {
    label: "Operations",
    items: [
      { path: "/remediation", label: "Remediation", icon: Wrench },
      { path: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    label: "Administration",
    items: [
      { path: "/integrations", label: "Integrations", icon: Blocks },
      { path: "/audit-logs", label: "Audit Logs", icon: Activity },
      { path: "/settings", label: "Settings", icon: Settings2 },
    ],
  },
];
const connectedPaths = new Set([
  "/",
  "/security-graph",
  "/accounts",
  "/inventory",
  "/findings",
  "/attack-paths",
  "/cloud-configuration",
  "/vulnerabilities",
  "/kubernetes",
  "/data",
  "/identities",
  "/threats",
  "/code-security",
  "/iac",
  "/compliance",
  "/settings",
]);
export function Shell() {
  const {
    demo,
    setDemo,
    tenant,
    tenantId,
    setTenantId,
    tenantAccounts,
    service,
    subscribedServices,
    scope,
    setScope,
    role,
    setRole,
    workspace,
    toast,
    notify,
    inScope,
  } = useProduct();
  const {
    accountId,
    setAccountId,
    provider,
    setProvider,
    region,
    setRegion,
  } = useAccountScope();
  const [liveAccounts, setLiveAccounts] = useState<
    { id: number; name: string; provider: "aws" | "azure" | "gcp" }[]
  >([]);
  const [liveError, setLiveError] = useState(false);
  const [liveLoading, setLiveLoading] = useState(true);
  const [liveRegions, setLiveRegions] = useState<string[]>([]);
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("cs.sidebar") === "collapsed",
  );
  const [panel, setPanel] = useState("");
  const [query, setQuery] = useState("");
  const location = useLocation();
  const navigate = useNavigate();
  const searchRef = useRef<HTMLInputElement>(null);
  const workspaceServices =
    !demo || subscribedServices.length === 4 ? ["CNAPP"] : subscribedServices;
  const visibleGroups = demo
    ? groups
        .map((group) => ({
          ...group,
          items: group.items.filter((item) =>
            serviceAllowsPath(service, item.path, subscribedServices),
          ),
        }))
        .filter((group) => group.items.length > 0)
    : groups
        .map((group) => ({
          ...group,
          items: group.items.filter((item) => connectedPaths.has(item.path)),
        }))
        .filter((group) => group.items.length > 0);
  const activeGroup = visibleGroups.find((g) =>
    g.items.some((i) =>
      i.path === "/"
        ? location.pathname === "/"
        : location.pathname.startsWith(i.path),
    ),
  );
  const active = activeGroup?.items.find((i) =>
    i.path === "/"
      ? location.pathname === "/"
      : location.pathname.startsWith(i.path),
  );
  function changeEnvironment(nextDemo: boolean) {
    if (nextDemo === demo) return;
    setDemo(nextDemo);
    // Detail-only demo routes do not have an equivalent connected-data page.
    if (!nextDemo && !connectedPaths.has(location.pathname)) navigate("/");
  }
  function changeTenant(nextTenantId: string) {
    if (nextTenantId === tenantId) return;
    setTenantId(nextTenantId);
    setPanel("");
    navigate("/");
  }
  useEffect(() => {
    if (!demo) {
      let cancelled = false;
      setLiveLoading(true);
      api
        .accounts()
        .then((result) => {
          if (!cancelled) {
            setLiveAccounts(
              result.items.filter((a) => a.is_active && a.onboarding_status !== "awaiting_stack").map((a) => ({
                id: a.id,
                name: a.name || a.account_identifier,
                provider: a.provider as "aws" | "azure" | "gcp",
              })),
            );
            setLiveError(false);
          }
        })
        .catch(() => {
          if (!cancelled) {
            setLiveError(true);
            setLiveAccounts([]);
          }
        })
        .finally(() => {
          if (!cancelled) setLiveLoading(false);
        });
      return () => {
        cancelled = true;
      };
    }
  }, [demo, location.pathname]);
  useEffect(() => {
    if (demo) {
      if (provider !== "aws") setProvider("aws");
      const selected = tenantAccounts.find((account) => account.id === scope);
      const fallback = tenantAccounts.find(
        (account) => !workspace.disconnected.includes(account.id),
      );
      if (!selected || workspace.disconnected.includes(selected.id)) {
        if (fallback) setScope(fallback.id);
        return;
      }
      if (!selected.regions.includes(region)) setRegion(selected.regions[0]);
      return;
    }
    if (!liveAccounts.length) return;
    const connectedProviders = Array.from(
      new Set(liveAccounts.map((account) => account.provider)),
    );
    const nextProvider = connectedProviders.includes(provider)
      ? provider
      : connectedProviders[0];
    if (nextProvider !== provider) {
      setProvider(nextProvider);
      return;
    }
    const matchingAccounts = liveAccounts.filter(
      (account) => account.provider === nextProvider,
    );
    if (!matchingAccounts.some((account) => account.id === accountId)) {
      setAccountId(matchingAccounts[0]?.id ?? null);
    }
  }, [
    accountId,
    demo,
    liveAccounts,
    provider,
    region,
    scope,
    setAccountId,
    setProvider,
    setRegion,
    setScope,
    tenantAccounts,
    workspace.disconnected,
  ]);
  useEffect(() => {
    if (demo || accountId === null) {
      setLiveRegions([]);
      return;
    }
    let cancelled = false;
    api
      .accountRegions(accountId)
      .then((result) => {
        if (cancelled) return;
        const available = result.regions
          .filter((item) => !item.excluded && item.region !== "global")
          .map((item) => item.region);
        const next = available.length ? available : ["us-east-1"];
        setLiveRegions(next);
        if (!next.includes(region)) setRegion(next[0]);
      })
      .catch(() => {
        if (!cancelled) {
          setLiveRegions([region || "us-east-1"]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accountId, demo, region, setRegion]);
  useEffect(() => {
    setPanel("");
    setQuery("");
    document.title = `${active?.label || "Workspace"} · Odineyes`;
  }, [location.pathname, active?.label]);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setPanel("search");
        setTimeout(() => searchRef.current?.focus(), 0);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  const searchResults = [
    ...assets
      .filter(
        (a) =>
          inScope(a.account, a.region) &&
          serviceAllowsAsset(service, a, subscribedServices),
      )
      .map((a) => ({
        type: "Asset",
        label: a.name,
        detail: a.arn,
        path: `/inventory/${a.id}`,
      })),
    ...workspace.findings
      .filter((f) =>
        assets.some(
              (a) =>
                a.id === f.asset &&
                inScope(a.account, a.region) &&
                serviceAllowsAsset(service, a, subscribedServices),
        ),
      )
      .map((f) => ({
        type: "Finding",
        label: f.title,
        detail: f.id,
        path: `/findings/${f.id}`,
      })),
    ...tenantAccounts
      .filter((a) => inScope(a.id))
      .map((a) => ({
        type: "Account",
        label: a.name,
        detail: a.number,
        path: `/accounts/${a.id}`,
      })),
    ...(serviceAllowsPath(service, "/policies", subscribedServices)
      ? Array.from(
          new Map(workspace.findings.map((f) => [f.policy, f])).values(),
        ).map((f) => ({
          type: "Policy",
          label: f.policy,
          detail: f.title,
          path: `/policies/${f.policy}`,
        }))
      : []),
  ]
    .filter((r) =>
      `${r.label} ${r.detail}`.toLowerCase().includes(query.toLowerCase()),
    )
    .slice(0, 12);
  return (
    <div className={`cs-app cs-premium ${demo ? "is-demo" : "is-live"} ${collapsed ? "is-collapsed" : ""}`}>
      <a href="#cs-main" className="cs-skip">
        Skip to content
      </a>
      <aside className="cs-sidebar">
        <Link className="cs-brand" to="/" aria-label="Odineyes home">
          <span className="cs-brand-icon">
            <Shield size={22} strokeWidth={2} />
            <span />
          </span>
          <strong>
            Odineyes<span className="cs-brand-dot">.</span>
          </strong>
        </Link>
        <button
          className="cs-organization"
          onClick={() => setPanel(demo ? "tenant" : "profile")}
          title={demo ? "Switch tenant" : "Workspace settings"}
        >
          <span className="cs-org-avatar">{demo ? tenant.initials : "CS"}</span>
          <span>
            <strong>{demo ? tenant.name : "Connected workspace"}</strong>
            <small>{demo ? "Demo workspace" : "Live cloud workspace"}</small>
          </span>
          <ChevronDown size={14} />
        </button>
        <nav aria-label="Main navigation" className="cs-nav">
          {visibleGroups.map((group) => (
            <div className="cs-nav-group" key={group.label}>
              <div className="cs-nav-label">{group.label}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === "/"}
                  title={item.label}
                  aria-label={item.label}
                  className={({ isActive }) =>
                    `cs-nav-item ${isActive ? "active" : ""}`
                  }
                >
                  <item.icon size={17} />
                  <span>{item.label}</span>
                  {demo && item.path === "/findings" && (
                    <small>
                      {
                        workspace.findings.filter(
                          (f) =>
                            ["Open", "Reopened"].includes(f.status) &&
                            assets.some(
                              (a) =>
                                a.id === f.asset &&
                                inScope(a.account, a.region) &&
                                serviceAllowsAsset(
                                  service,
                                  a,
                                  subscribedServices,
                                ),
                            ),
                        ).length
                      }
                    </small>
                  )}
                  {item.path === "/workloads" && <em>NEW</em>}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="cs-sidebar-bottom">
          <div className={`cs-connection ${!demo && (liveError || !liveAccounts.length) ? "is-pending" : ""}`}>
            <span className="cs-status-dot" />
            <span>
              {demo ? "Demo environment" : liveError ? "API unavailable" : liveLoading ? "Connecting to API" : liveAccounts.length ? "Connected workspace" : "Connect your cloud"}
              <small>
                {demo ? "Isolated sample workspace" : liveError ? "Review connection settings" : liveAccounts.length ? `${liveAccounts.length} cloud ${liveAccounts.length === 1 ? "account" : "accounts"}` : "Waiting for a connector"}
              </small>
            </span>
          </div>
          <button
            className="cs-collapse"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            onClick={() => {
              setCollapsed(!collapsed);
              localStorage.setItem(
                "cs.sidebar",
                !collapsed ? "collapsed" : "expanded",
              );
            }}
          >
            <ChevronsLeft size={17} />
            <span>Collapse sidebar</span>
          </button>
        </div>
      </aside>
      <div className="cs-workspace">
        <header className="cs-topbar">
          <div className="cs-breadcrumb">
            <span>{activeGroup?.label || "Cloud security"}</span>
            <ChevronRight size={13} />
            <strong>{active?.label || "Investigation"}</strong>
            {location.pathname.split("/").length > 2 && (
              <>
                <ChevronRight size={13} />
                <span>Details</span>
              </>
            )}
          </div>
          <div className="cs-topbar-tools">
            {demo && (
              <label className="cs-tenant-switch">
                <Building2 size={15} aria-hidden="true" />
                <span className="sr-only">Tenant</span>
                <select
                  aria-label="Demo tenant"
                  value={tenantId}
                  onChange={(event) => changeTenant(event.target.value)}
                >
                  {tenants.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="cs-environment-switch" role="group" aria-label="Data environment">
              <button
                type="button"
                className={demo ? "is-active" : ""}
                aria-pressed={demo}
                onClick={() => changeEnvironment(true)}
              >
                Demo
              </button>
              <button
                type="button"
                className={!demo ? "is-active" : ""}
                aria-pressed={!demo}
                onClick={() => changeEnvironment(false)}
              >
                Live data
              </button>
            </div>
            <button
              className="cs-search-trigger"
              aria-label="Search workspace"
              onClick={() => setPanel("search")}
            >
              <Search size={16} />
              <span>Search anything...</span>
              <kbd>⌘ K</kbd>
            </button>
            <div className="cs-top-divider" />
            {demo && (
              <button
                className="cs-icon notification"
                aria-label="Notifications"
                onClick={() => setPanel("notifications")}
              >
                <Bell size={18} />
                <i />
              </button>
            )}
            <button
              className="cs-icon"
              aria-label="Help"
              onClick={() => setPanel("help")}
            >
              <CircleHelp size={18} />
            </button>
            <button
              className="cs-user-avatar"
              aria-label="User profile"
              onClick={() => setPanel("profile")}
            >
              {demo ? "PM" : "CS"}
            </button>
          </div>
        </header>
        <div className="cs-scopebar" role="group" aria-label="Cloud scope">
            <span className="cs-scope-caption">Cloud scope</span>
            <label className="cs-provider-switch">
              <span className="cs-provider-mark">
                {provider === "aws" ? <AWSLogo size={18} /> : provider.toUpperCase()}
              </span>
              <select
                aria-label="Cloud provider"
                value={provider}
                disabled={!demo && !liveAccounts.length}
                onChange={(event) => {
                  const next = event.target.value as
                    | "aws"
                    | "azure"
                    | "gcp";
                  setProvider(next);
                  if (!demo) {
                    const nextAccount = liveAccounts.find(
                      (account) => account.provider === next,
                    );
                    setAccountId(nextAccount?.id ?? null);
                  }
                }}
              >
                {!demo && !liveAccounts.length && <option value={provider}>Cloud provider</option>}
                {(demo
                  ? ["aws"]
                  : Array.from(
                      new Set(liveAccounts.map((account) => account.provider)),
                    )
                ).map((connectedProvider) => (
                  <option key={connectedProvider} value={connectedProvider}>
                    {connectedProvider === "aws"
                      ? "AWS"
                      : connectedProvider === "azure"
                        ? "Azure"
                        : "Google Cloud"}
                  </option>
                ))}
              </select>
            </label>
            <label className="cs-scope">
              <Cloud size={15} />
              <select
                aria-label="Cloud account"
                value={demo ? scope : (accountId ?? liveAccounts[0]?.id ?? "")}
                disabled={!demo && !liveAccounts.length}
                onChange={(e) =>
                  demo
                    ? setScope(e.target.value)
                    : setAccountId(
                        e.target.value ? Number(e.target.value) : null,
                      )
                }
              >
                {!demo && !liveAccounts.length && <option value="">No connected accounts</option>}
                {demo ? (
                  tenantAccounts
                    .filter((a) => !workspace.disconnected.includes(a.id))
                    .map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name}
                      </option>
                    ))
                ) : (
                  liveAccounts
                    .filter((account) => account.provider === provider)
                    .map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name}
                      </option>
                    ))
                )}
              </select>
            </label>
            <label className="cs-scope cs-region-switch">
              <MapPin size={15} />
              <select
                aria-label="Server region"
                value={region}
                disabled={!demo && !liveAccounts.length}
                onChange={(event) => setRegion(event.target.value)}
              >
                {(demo
                  ? tenantAccounts.find((account) => account.id === scope)?.regions ||
                    ["ap-south-1"]
                  : liveRegions.length
                    ? liveRegions
                    : [region]
                ).map((serverRegion) => (
                  <option key={serverRegion} value={serverRegion}>
                    {serverRegion}
                  </option>
                ))}
              </select>
            </label>
            <button
              className={`cs-freshness ${!demo && (liveError || !liveAccounts.length) ? "is-pending" : ""}`}
              onClick={() => navigate("/accounts")}
              title={
                demo
                  ? "Demo evidence captured September 6, 2026 at 08:48 UTC"
                  : "Inspect account scan freshness"
              }
            >
              <span className="cs-status-dot" />
              {demo
                ? "Demo snapshot"
                : liveError
                  ? "API unavailable"
                  : liveLoading
                    ? "Connecting…"
                    : liveAccounts.length
                      ? "View scan status"
                      : "Connect an account"}
            </button>
        </div>
        <main id="cs-main" className="cs-main">
          <Suspense
            fallback={
              <div
                className="cs-route-loading"
                role="status"
                aria-label="Loading workspace"
              >
                <span />
                <span />
                <span />
              </div>
            }
          >
            <Outlet />
          </Suspense>
        </main>
        <footer className="cs-footer">
          <span>
            <Shield size={12} /> Odineyes{" "}
            {demo ? "· Demo workspace" : "· Connected workspace"}
          </span>
          {demo && <span>Evidence snapshot · Sep 6, 2026, 08:48 UTC</span>}
        </footer>
      </div>
      {toast && (
        <div role="status" className="cs-toast">
          <ShieldCheck size={18} />
          {toast}
          <button aria-label="Dismiss notification" onClick={() => notify("")}>
            <X size={14} />
          </button>
        </div>
      )}
      {panel === "search" && (
        <Overlay title="Search workspace" onClose={() => setPanel("")}>
          <label className="cs-search large">
            <Search size={18} />
            <input
              ref={searchRef}
              autoFocus
              placeholder="Search assets, findings, policies, accounts..."
              aria-label="Global search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          {demo ? (
            <div className="cs-search-results">
              {searchResults.map((r) => (
                <Link key={r.path} to={r.path} onClick={() => setPanel("")}>
                  <Badge>{r.type}</Badge>
                  <span>
                    <strong>{r.label}</strong>
                    <small>{r.detail}</small>
                  </span>
                  <ChevronRight size={16} />
                </Link>
              ))}
              {searchResults.length === 0 && (
                <p>No results in current cloud scope.</p>
              )}
            </div>
          ) : (
            <div className="cs-search-results">
              <Link
                to={`/inventory?q=${encodeURIComponent(query)}`}
                onClick={() => setPanel("")}
              >
                Search connected inventory
                <ChevronRight size={16} />
              </Link>
              <Link
                to={`/findings?q=${encodeURIComponent(query)}`}
                onClick={() => setPanel("")}
              >
                Search connected findings
                <ChevronRight size={16} />
              </Link>
            </div>
          )}
        </Overlay>
      )}
      {panel === "profile" && (
        <Overlay title="Workspace & profile" onClose={() => setPanel("")}>
          <div className="cs-profile">
            <span className="cs-user-avatar">{demo ? "PM" : "CS"}</span>
            <div>
              <h3>{demo ? "Priya Mehta" : "Connected workspace"}</h3>
              <p>
                {demo
                  ? `Security Operations · ${tenant.name}`
                  : "Live data"}
              </p>
            </div>
          </div>
          <fieldset className="cs-environment-field">
            <legend>Workspace data</legend>
            <div className="cs-environment-switch" role="group" aria-label="Workspace data environment">
              <button type="button" className={demo ? "is-active" : ""} aria-pressed={demo}
                onClick={() => changeEnvironment(true)}>Demo</button>
              <button type="button" className={!demo ? "is-active" : ""} aria-pressed={!demo}
                onClick={() => changeEnvironment(false)}>Live data</button>
            </div>
            <p className="cs-muted">
              {demo
                ? "Sample data only. Demo actions never call the connected API."
                : "Connected API data. Actions affect only the selected live workspace."}
            </p>
          </fieldset>
          {!demo && (
            <section className="cs-workspace-services" aria-labelledby="live-workspace-services-title">
              <span id="live-workspace-services-title">Workspace services</span>
              <div className="cs-tenant-service-badges"><em>CNAPP</em></div>
            </section>
          )}
          {demo && (
            <>
              <label className="cs-field">
                <span>Tenant</span>
                <select value={tenantId} onChange={(event) => changeTenant(event.target.value)}>
                  {tenants.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
                </select>
              </label>
              <section className="cs-workspace-services" aria-labelledby="workspace-services-title">
                <span id="workspace-services-title">Workspace services</span>
                <div className="cs-tenant-service-badges">
                  {workspaceServices.map((item) => <em key={item}>{item}</em>)}
                </div>
              </section>
              <label className="cs-field">
                <span>Preview role</span>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as Role)}
                >
                  {["Administrator", "Security Analyst", "Read Only"].map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </select>
              </label>
            </>
          )}
          {demo && (
            <p className="cs-muted">
              Demo role changes preview action permissions. Production authorization must be enforced by your identity provider and API.
            </p>
          )}
          <button
            className="cs-button"
            onClick={() => {
              setPanel("");
              navigate("/settings");
            }}
          >
            <SlidersHorizontal size={16} />
            Workspace settings
          </button>
        </Overlay>
      )}
      {panel === "tenant" && (
        <Overlay title="Switch demo tenant" onClose={() => setPanel("")}>
          <div className="cs-tenant-list" aria-label="Demo tenants">
            {tenants.map((item) => (
              <button
                key={item.id}
                type="button"
                className={item.id === tenantId ? "is-active" : ""}
                aria-pressed={item.id === tenantId}
                onClick={() => changeTenant(item.id)}
              >
                <span className="cs-org-avatar">{item.initials}</span>
                <span>
                  <strong>{item.name}</strong>
                  <small>{item.accountIds.length} AWS accounts · {item.plan}</small>
                  <span className="cs-tenant-service-badges" aria-label={`${item.name} subscribed services`}>
                    {(item.services.length === 4 ? ["CNAPP"] : item.services).map((itemService) => (
                      <em key={itemService}>{itemService}</em>
                    ))}
                  </span>
                </span>
                {item.id === tenantId && <ShieldCheck size={17} aria-label="Current tenant" />}
              </button>
            ))}
          </div>
        </Overlay>
      )}
      {panel === "notifications" && (
        <Overlay title="Notifications" drawer onClose={() => setPanel("")}>
          <div className="cs-search-results">
            {[
              [
                "Coverage needs attention",
                `${tenantAccounts[0]?.name || "Account"} · Review collection coverage`,
                `/accounts/${tenantAccounts[0]?.id || scope}`,
              ],
              [
                "Critical risk confirmed",
                "Public workload can access sensitive data",
                "/attack-paths",
              ],
              [
                "Tenant boundary active",
                `${tenant.name} · ${workspaceServices.join(", ")} workspace`,
                "/",
              ],
            ].filter(([, , path]) => serviceAllowsPath(service, path, subscribedServices)).map(([title, detail, path]) => (
              <Link key={title} to={path} onClick={() => setPanel("")}>
                <Bell size={17} />
                <span>
                  <strong>{title}</strong>
                  <small>
                    {demo
                      ? detail
                      : "Preview notification · Connect notification service"}
                  </small>
                </span>
                <ChevronRight size={16} />
              </Link>
            ))}
          </div>
        </Overlay>
      )}
      {panel === "help" && (
        <Overlay title="Investigation guide" onClose={() => setPanel("")}>
          <ol className="cs-help-list">
            <li>Connect cloud accounts and verify collection coverage.</li>
            <li>Prioritize contextual findings and inspect source evidence.</li>
            <li>Trace verified relationships through an attack path.</li>
            <li>Review remediation impact, approval, and rollback.</li>
            <li>Wait for fresh evidence before verifying resolution.</li>
          </ol>
          <p className="cs-muted">
            Workload Security uses the research document’s agentless inspection
            model. Unverified network reachability remains a collection gap.
          </p>
          <Link
            className="cs-button primary"
            to="/accounts"
            onClick={() => setPanel("")}
          >
            <LogOut size={15} />
            Open cloud accounts
          </Link>
        </Overlay>
      )}
    </div>
  );
}
