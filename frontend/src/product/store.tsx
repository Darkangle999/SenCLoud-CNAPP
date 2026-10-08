import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  accounts,
  assets,
  initialFindings,
  tenants,
  type Account,
  type Finding,
  type SecurityService,
  type Tenant,
} from "./data";
import { useAccountScope } from "../lib/accountScope";
import type { CnappService } from "./services";

export type Role = "Administrator" | "Security Analyst" | "Read Only";
export type { CnappService } from "./services";
export type Exception = {
  id: string;
  finding: string;
  reason: string;
  scope: string;
  justification: string;
  control: string;
  evidence: string;
  expiry: string;
  approver: string;
  status: string;
};
export type Remediation = {
  id: string;
  finding: string;
  status:
    | "Review"
    | "Approved"
    | "Pending Verification"
    | "Verified Resolved"
    | "Still Open"
    | "Unknown"
    | "Reopened";
  created: string;
};
export type Audit = {
  id: string;
  time: string;
  actor: string;
  action: string;
  object: string;
  previous: string;
  next: string;
  result: string;
};
export type Workspace = {
  findings: Finding[];
  exceptions: Exception[];
  remediations: Remediation[];
  audit: Audit[];
  settings: Record<string, string>;
  disconnected: string[];
};
const initial: Workspace = {
  findings: initialFindings,
  exceptions: [
    {
      id: "EX-021",
      finding: "CS-1043",
      reason: "Temporary vendor maintenance access",
      scope: "production-2",
      justification: "Vendor migration completes September 12.",
      control: "Source monitoring and daily access review",
      evidence: "CHG-2841",
      expiry: "2026-09-12",
      approver: "Priya Mehta",
      status: "Expiring Soon",
    },
  ],
  remediations: [
    {
      id: "REM-081",
      finding: "CS-1041",
      status: "Review",
      created: "2026-09-06T08:35:00Z",
    },
    {
      id: "REM-082",
      finding: "CS-1071",
      status: "Pending Verification",
      created: "2026-09-06T08:30:00Z",
    },
  ],
  audit: [
    {
      id: "AUD-01",
      time: "2026-09-06T08:48:00Z",
      actor: "Collection service",
      action: "Evaluation completed",
      object: "Production",
      previous: "Evaluating",
      next: "32 signals evaluated",
      result: "Success",
    },
  ],
  settings: {
    cadence: "Every 6 hours",
    expiry: "30 days",
    routing: "Platform Team",
    region: "ap-south-1",
    threshold: "Critical",
    session: "8 hours",
  },
  disconnected: [],
};
const workspaceForTenant = (source: Workspace, tenant: Tenant): Workspace => {
  const assetIds = new Set(
    assets
      .filter((asset) => tenant.accountIds.includes(asset.account))
      .map((asset) => asset.id),
  );
  const findingIds = new Set(
    source.findings
      .filter((finding) => assetIds.has(finding.asset))
      .map((finding) => finding.id),
  );
  return {
    ...source,
    findings: source.findings.filter((finding) => assetIds.has(finding.asset)),
    exceptions: source.exceptions.filter((item) => findingIds.has(item.finding)),
    remediations: source.remediations.filter((item) => findingIds.has(item.finding)),
    audit: [...source.audit],
    settings: { ...source.settings },
    disconnected: source.disconnected.filter((accountId) =>
      tenant.accountIds.includes(accountId),
    ),
  };
};
const initialTenantWorkspaces = () =>
  Object.fromEntries(
    tenants.map((tenant) => [tenant.id, workspaceForTenant(initial, tenant)]),
  ) as Record<string, Workspace>;
function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}
type Context = {
  demo: boolean;
  setDemo: (v: boolean) => void;
  tenant: Tenant;
  tenantId: string;
  setTenantId: (v: string) => void;
  tenantAccounts: Account[];
  inTenant: (account: string) => boolean;
  service: CnappService;
  subscribedServices: SecurityService[];
  scope: string;
  setScope: (v: string) => void;
  role: Role;
  setRole: (v: Role) => void;
  workspace: Workspace;
  update: (f: (state: Workspace) => Workspace) => void;
  notify: (v: string) => void;
  toast: string;
  log: (action: string, object: string, previous: string, next: string) => void;
  canManage: boolean;
  canAct: boolean;
  inScope: (account: string, resourceRegion?: string) => boolean;
};
const Ctx = createContext<Context>(null!);
function defaultDemoMode(): boolean {
  const configured = import.meta.env.VITE_DEFAULT_ENVIRONMENT?.toLowerCase();
  if (configured === "demo") return true;
  // The production UI is backed by the current Odineyes API by default. The
  // isolated product demo remains available only when explicitly requested.
  return false;
}

export function ProductProvider({ children }: { children: ReactNode }) {
  const { region } = useAccountScope();
  const [savedDemo, setSavedDemo] = useState(() =>
    read("cs.product.demo", defaultDemoMode()),
  );
  const demo = savedDemo;
  const setDemo = (value: boolean) => {
    setSavedDemo(value);
  };
  const [tenantId, setSavedTenantId] = useState(() => {
    const saved = read("cs.product.tenant", tenants[0].id);
    return tenants.some((tenant) => tenant.id === saved) ? saved : tenants[0].id;
  });
  const tenant = tenants.find((item) => item.id === tenantId) || tenants[0];
  const tenantAccounts = accounts.filter((account) =>
    tenant.accountIds.includes(account.id),
  );
  const subscribedServices = tenant.services;
  const service: CnappService = "CNAPP";
  const [scope, setScope] = useState(() => {
    const saved = read("cs.product.scope", "production");
    return tenant.accountIds.includes(saved)
      ? saved
      : tenant.accountIds[0];
  });
  const [role, setRole] = useState<Role>(() =>
    read("cs.product.role", "Administrator"),
  );
  const [tenantWorkspaces, setTenantWorkspaces] = useState<Record<string, Workspace>>(() => {
    const saved = read<Record<string, Workspace> | null>("cs.product.tenants.v1", null);
    const seeded = initialTenantWorkspaces();
    if (saved) {
      return Object.fromEntries(
        tenants.map((item) => [
          item.id,
          saved[item.id]?.findings ? saved[item.id] : seeded[item.id],
        ]),
      );
    }
    const legacy = read<Workspace>("cs.product.v1", initial);
    const source = legacy.findings && legacy.remediations && legacy.disconnected ? legacy : initial;
    return Object.fromEntries(
      tenants.map((item) => [item.id, workspaceForTenant(source, item)]),
    );
  });
  const workspace = tenantWorkspaces[tenant.id] || initialTenantWorkspaces()[tenant.id];
  const update = (change: (state: Workspace) => Workspace) =>
    setTenantWorkspaces((current) => ({
      ...current,
      [tenant.id]: change(current[tenant.id] || initialTenantWorkspaces()[tenant.id]),
    }));
  const setTenantId = (nextTenantId: string) => {
    const nextTenant = tenants.find((item) => item.id === nextTenantId);
    if (!nextTenant || nextTenant.id === tenant.id) return;
    setSavedTenantId(nextTenant.id);
    setScope(nextTenant.accountIds[0]);
  };
  const [toast, notify] = useState("");
  useEffect(() => {
    try {
      localStorage.setItem("cs.product.tenants.v1", JSON.stringify(tenantWorkspaces));
      localStorage.setItem("cs.product.demo", JSON.stringify(demo));
      localStorage.setItem("cs.product.tenant", JSON.stringify(tenantId));
      localStorage.setItem("cs.product.scope", JSON.stringify(scope));
      localStorage.setItem("cs.product.role", JSON.stringify(role));
    } catch {
      /* Preferences remain usable in memory. */
    }
  }, [tenantWorkspaces, demo, tenantId, scope, role]);
  useEffect(() => {
    if (toast) {
      const timer = window.setTimeout(() => notify(""), 5000);
      return () => clearTimeout(timer);
    }
  }, [toast]);
  const log = (
    action: string,
    object: string,
    previous: string,
    next: string,
  ) =>
    update((s) => ({
      ...s,
      audit: [
        {
          id: crypto.randomUUID(),
          time: new Date().toISOString(),
          actor: role,
          action,
          object,
          previous,
          next,
          result: "Success · Demo",
        },
        ...s.audit,
      ],
    }));
  const inScope = (account: string, resourceRegion?: string) =>
    tenant.accountIds.includes(account) &&
    !workspace.disconnected.includes(account) &&
    scope === account &&
    (!resourceRegion || resourceRegion === "Global" || resourceRegion === region);
  return (
    <Ctx.Provider
      value={{
        demo,
        setDemo,
        tenant,
        tenantId,
        setTenantId,
        tenantAccounts,
        inTenant: (account) => tenant.accountIds.includes(account),
        service,
        subscribedServices,
        scope,
        setScope,
        role,
        setRole,
        workspace,
        update,
        notify,
        toast,
        log,
        canManage: role === "Administrator",
        canAct: role !== "Read Only",
        inScope,
      }}
    >
      {children}
    </Ctx.Provider>
  );
}
export const useProduct = () => useContext(Ctx);
