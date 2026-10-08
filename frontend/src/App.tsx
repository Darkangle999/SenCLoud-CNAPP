import { lazy, Suspense } from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";

import { Shell } from "./product/Shell";
import { ProductProvider, useProduct } from "./product/store";
import { serviceAllowsPath } from "./product/services";
import { Identities, IdentityDetail } from "./product/Identities";
import {
  Accounts as ProductAccounts,
  AccountDetail,
  Inventory as ProductInventory,
  AssetDetail,
  Findings as ProductFindings,
  FindingDetail,
  AttackPaths as ProductAttackPaths,
  AttackPathDetail,
} from "./product/Investigations";
import {
  Compliance as ProductCompliance,
  Policies,
  Exceptions,
  Reports,
} from "./product/Governance";
import {
  Remediations,
  Workloads,
  IacSecurity,
  Integrations,
  AuditLogs,
  Settings as ProductSettings,
} from "./product/Operations";
import "./product/product.css";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { AccountScopeProvider } from "./lib/accountScope";
import { RealtimeProvider } from "./lib/realtime";
import { ThemeProvider } from "./theme";
const ProductDashboard = lazy(() =>
  import("./product/Dashboard").then((module) => ({
    default: module.Dashboard,
  })),
);
const ConnectedDashboard = lazy(() =>
  import("./product/ConnectedDashboard").then((module) => ({
    default: module.ConnectedDashboard,
  })),
);
const SecurityGraphWorkspace = lazy(() =>
  import("./product/Cnapp").then((module) => ({
    default: module.SecurityGraphWorkspace,
  })),
);
const CloudConfiguration = lazy(() =>
  import("./product/Cnapp").then((module) => ({
    default: module.CloudConfiguration,
  })),
);
const VulnerabilitiesHub = lazy(() =>
  import("./product/Cnapp").then((module) => ({
    default: module.VulnerabilitiesHub,
  })),
);
const KubernetesSecurity = lazy(() =>
  import("./product/Cnapp").then((module) => ({
    default: module.KubernetesSecurity,
  })),
);
const DataSecurityHub = lazy(() =>
  import("./product/Cnapp").then((module) => ({
    default: module.DataSecurityHub,
  })),
);
const ThreatDetectionHub = lazy(() =>
  import("./product/Cnapp").then((module) => ({
    default: module.ThreatDetectionHub,
  })),
);
const CodeSecurityHub = lazy(() =>
  import("./product/Cnapp").then((module) => ({
    default: module.CodeSecurityHub,
  })),
);
const Accounts = lazy(() =>
  import("./pages/Accounts").then((module) => ({ default: module.Accounts })),
);
const AssetDetails = lazy(() =>
  import("./pages/AssetDetails").then((module) => ({
    default: module.AssetDetails,
  })),
);
const AttackPaths = lazy(() =>
  import("./pages/AttackPaths").then((module) => ({
    default: module.AttackPaths,
  })),
);
const Compliance = lazy(() =>
  import("./pages/Compliance").then((module) => ({
    default: module.Compliance,
  })),
);
const CveDatabase = lazy(() =>
  import("./pages/CveDatabase").then((module) => ({
    default: module.CveDatabase,
  })),
);
const Data = lazy(() =>
  import("./pages/Data").then((module) => ({ default: module.Data })),
);
const Findings = lazy(() =>
  import("./pages/Findings").then((module) => ({ default: module.Findings })),
);
const Iac = lazy(() =>
  import("./pages/Iac").then((module) => ({ default: module.Iac })),
);
const Identity = lazy(() =>
  import("./pages/Identity").then((module) => ({ default: module.Identity })),
);
const IdentityDetails = lazy(() =>
  import("./pages/IdentityDetails").then((module) => ({
    default: module.IdentityDetails,
  })),
);
const Inventory = lazy(() =>
  import("./pages/Inventory").then((module) => ({ default: module.Inventory })),
);
const Geography = lazy(() =>
  import("./pages/Geography").then((module) => ({ default: module.Geography })),
);
const Settings = lazy(() =>
  import("./pages/Settings").then((module) => ({ default: module.Settings })),
);
const Threats = lazy(() =>
  import("./pages/Threats").then((module) => ({ default: module.Threats })),
);
const Vulnerabilities = lazy(() =>
  import("./pages/Vulnerabilities").then((module) => ({
    default: module.Vulnerabilities,
  })),
);

export default function App() {
  return (
    <ThemeProvider>
      <AccountScopeProvider>
        <ProductProvider>
          <RealtimeMode>
            <ErrorBoundary>
              <BrowserRouter>
                <Suspense fallback={<WorkspaceLoading />}>
                  <AppRoutes />
                </Suspense>
              </BrowserRouter>
            </ErrorBoundary>
          </RealtimeMode>
        </ProductProvider>
      </AccountScopeProvider>
    </ThemeProvider>
  );
}

function WorkspaceLoading() {
  return (
    <main className="product-loading" aria-busy="true" aria-label="Loading workspace">
      Loading workspace…
    </main>
  );
}

function RealtimeMode({ children }: { children: React.ReactNode }) {
  const { demo } = useProduct();
  return demo ? (
    <>{children}</>
  ) : (
    <RealtimeProvider>{children}</RealtimeProvider>
  );
}

function AppRoutes() {
  const { pathname } = useLocation();
  const { demo, service, subscribedServices } = useProduct();
  const preview = (_title: string, element: React.ReactNode) =>
    demo ? element : <Navigate to="/" replace />;
  if (demo && !serviceAllowsPath(service, pathname, subscribedServices)) {
    return <Navigate to="/" replace />;
  }
  return (
    <Routes>
      <Route
        element={
          <ErrorBoundary resetKey={pathname}>
            <Shell />
          </ErrorBoundary>
        }
      >
        <Route index element={demo ? <ProductDashboard /> : <ConnectedDashboard />} />
        <Route
          path="/security-graph"
          element={
            demo ? <SecurityGraphWorkspace /> : <AttackPaths />
          }
        />
        <Route
          path="/architecture"
          element={<Navigate to="/security-graph" replace />}
        />
        <Route
          path="/accounts"
          element={demo ? <ProductAccounts /> : <Accounts />}
        />
        <Route
          path="/accounts/:accountId"
          element={preview("Cloud account", <AccountDetail />)}
        />
        <Route
          path="/inventory"
          element={demo ? <ProductInventory /> : <Inventory />}
        />
        <Route
          path="/inventory/:assetId"
          element={demo ? <AssetDetail /> : <AssetDetails />}
        />
        {/* Geography needs the /api/inventory/geo contract, which has not yet
            landed in the current backend. Keep the branch's demo experience,
            but never expose a broken live route. */}
        <Route
          path="/geography"
          element={demo ? <Geography /> : <Navigate to="/inventory" replace />}
        />
        <Route
          path="/identity"
          element={<Navigate to="/identities" replace />}
        />
        <Route
          path="/identity/:identityId"
          element={<Navigate to="/identities/:identityId" replace />}
        />
        <Route
          path="/identities"
          element={demo ? <Identities /> : <Identity />}
        />
        <Route
          path="/identities/:identityId"
          element={demo ? <IdentityDetail /> : <IdentityDetails />}
        />
        <Route path="/data" element={demo ? <DataSecurityHub /> : <Data />} />
        <Route
          path="/findings"
          element={demo ? <ProductFindings /> : <Findings />}
        />
        <Route
          path="/findings/:findingId"
          element={preview("Finding investigation", <FindingDetail />)}
        />
        <Route
          path="/attack-paths"
          element={demo ? <ProductAttackPaths /> : <AttackPaths />}
        />
        <Route
          path="/attack-paths/:pathId"
          element={preview("Attack path investigation", <AttackPathDetail />)}
        />
        <Route
          path="/cloud-configuration"
          element={demo ? <CloudConfiguration /> : <Findings />}
        />
        <Route
          path="/workloads"
          element={preview("Workload Security", <Workloads />)}
        />
        <Route
          path="/kubernetes"
          element={demo ? <KubernetesSecurity /> : <Inventory />}
        />
        <Route path="/ebpf" element={<Navigate to="/workloads" replace />} />
        <Route
          path="/threats"
          element={demo ? <ThreatDetectionHub /> : <Threats />}
        />
        <Route
          path="/vulnerabilities"
          element={demo ? <VulnerabilitiesHub /> : <Vulnerabilities />}
        />
        <Route path="/cve-database" element={<CveDatabase />} />
        <Route
          path="/code-security"
          element={demo ? <CodeSecurityHub /> : <Iac />}
        />
        <Route path="/iac" element={demo ? <IacSecurity /> : <Iac />} />
        <Route
          path="/compliance"
          element={demo ? <ProductCompliance /> : <Compliance />}
        />
        <Route
          path="/compliance/:frameworkId"
          element={preview("Compliance controls", <ProductCompliance />)}
        />
        <Route
          path="/policies"
          element={preview("Policy Catalog", <Policies />)}
        />
        <Route
          path="/policies/:policyId"
          element={preview("Policy detail", <Policies />)}
        />
        <Route
          path="/exceptions"
          element={preview("Exceptions", <Exceptions />)}
        />
        <Route
          path="/remediation"
          element={preview("Remediation", <Remediations />)}
        />
        <Route path="/reports" element={preview("Reports", <Reports />)} />
        <Route
          path="/integrations"
          element={preview("Integrations", <Integrations />)}
        />
        <Route
          path="/audit-logs"
          element={preview("Audit Logs", <AuditLogs />)}
        />
        <Route
          path="/settings"
          element={demo ? <ProductSettings /> : <Settings />}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
