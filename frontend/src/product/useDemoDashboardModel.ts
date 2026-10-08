import { useAccountScope } from "../lib/accountScope";
import {
  accounts,
  assets,
  attackPaths,
  isActive,
  observedAt,
  type Asset,
  type Finding,
  type SecurityService,
  type Tenant,
} from "./data";
import type {
  DashboardDomain,
  DashboardGraphEdge,
  DashboardGraphNode,
  DashboardModel,
  DashboardSeverity,
} from "./dashboard-model";
import { serviceAllowsAsset } from "./services";
import { useProduct } from "./store";

const severityWeight: Record<DashboardSeverity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

const scenarios: Record<string, string> = {
  acme: "Enterprise cloud security: connect public exposure, sensitive data, identity access, and workload risk.",
  northstar: "Healthcare security: prioritize patient data exposure, cloud configuration, and excessive identity access.",
  meridian: "Retail security: investigate internet-facing infrastructure and workload configuration risk.",
  atlas: "Financial data security: review sensitive stores and the identities that can access them.",
};

type DemoDashboardInput = {
  tenant: Tenant;
  accountId: string;
  region: string;
  findings: Finding[];
  disconnected: string[];
};

/** A pure adapter keeps tenant isolation and evidence calculations reviewable. */
export function buildDemoDashboardModel({
  tenant,
  accountId,
  region,
  findings,
  disconnected,
}: DemoDashboardInput): DashboardModel {
  const services = [...tenant.services];
  const account = accounts.find(
    (item) => item.id === accountId && tenant.accountIds.includes(item.id),
  );
  const connected = Boolean(account && !disconnected.includes(accountId));
  const scopedAssets = assets.filter(
    (asset) =>
      connected &&
      asset.account === accountId &&
      (asset.region === region || asset.region === "Global") &&
      serviceAllowsAsset("CNAPP", asset, services),
  );
  const assetsById = new Map(scopedAssets.map((asset) => [asset.id, asset]));
  const evidence = [
    ...new Map(
      findings
        .filter((finding) => assetsById.has(finding.asset))
        .map((finding) => [finding.id, finding]),
    ).values(),
  ];
  const active = evidence.filter(isActive).sort(
    (left, right) =>
      severityWeight[right.severity] - severityWeight[left.severity] ||
      right.score - left.score ||
      left.id.localeCompare(right.id),
  );
  const coverage = connected ? account!.coverage : null;
  const score = evidence.length
    ? Math.max(
        0,
        Math.round(
          100 -
            (active.reduce(
              (total, finding) => total + severityWeight[finding.severity],
              0,
            ) /
              (evidence.length * 4)) *
              100,
        ),
      )
    : null;
  const serviceForAsset = (asset: Asset): SecurityService => {
    const domain =
      asset.category === "Data"
        ? "DSPM"
        : asset.category === "Identity"
          ? "CIEM"
          : asset.category === "Compute"
            ? "CWPP"
            : "CSPM";
    return services.includes(domain) ? domain : "CSPM";
  };
  const domains: DashboardDomain[] = services.map((service) => {
    const domainAssets = scopedAssets.filter((asset) =>
      serviceAllowsAsset(service, asset, [service]),
    );
    const domainIds = new Set(domainAssets.map((asset) => asset.id));
    const domainFindings = active.filter((finding) => domainIds.has(finding.asset));
    const domainEvidence = evidence.filter((finding) => domainIds.has(finding.asset));
    const detail = `${domainFindings.length} active configuration finding${domainFindings.length === 1 ? "" : "s"}`;
    const state = !domainAssets.length
      ? "empty"
      : !domainEvidence.length || coverage !== 100
        ? "partial"
        : "ready";
    if (service === "CSPM") {
      return {
        service,
        label: "Public resources",
        value: domainAssets.length
          ? domainAssets.filter((asset) => asset.exposure === "Public").length
          : null,
        detail,
        secondary: `${domainAssets.length} resources in posture scope`,
        href: "/cloud-configuration",
        status: state,
      };
    }
    if (service === "DSPM") {
      return {
        service,
        label: "Sensitive data stores",
        value: domainAssets.length
          ? domainAssets.filter((asset) => asset.sensitivity !== "Not classified").length
          : null,
        detail,
        secondary: `${domainAssets.filter((asset) => asset.exposure === "Public").length} public stores · ${domainAssets.length} stores in scope`,
        href: "/data",
        status: state,
      };
    }
    if (service === "CIEM") {
      return {
        service,
        label: "Cloud identities",
        value: domainAssets.length || null,
        detail: `${domainFindings.length} active access finding${domainFindings.length === 1 ? "" : "s"}`,
        secondary: `${domainFindings.filter((finding) => /wildcard|privilege/i.test(finding.title)).length} excessive-permission findings`,
        href: "/identities",
        status: state,
      };
    }
    return {
      service,
      label: "Workloads in scope",
      value: domainAssets.length || null,
      detail,
      secondary: `${domainAssets.filter((asset) => asset.exposure === "Public").length} public workloads · configuration evidence`,
      href: "/workloads",
      status: state,
    };
  });

  const graphNodes = new Map<string, DashboardGraphNode>();
  const graphEdges = new Map<string, DashboardGraphEdge>();
  const modeledPaths = attackPaths.filter(
    (path) => connected && path.account === accountId,
  );
  const graphNodeForAsset = (asset: Asset): DashboardGraphNode => ({
    id: asset.id,
    label: asset.name,
    kind: asset.type,
    detail: `${asset.exposure} · ${asset.sensitivity} · ${asset.region}`,
    href: `/inventory/${asset.id}`,
  });
  let verifiedPaths = 0;
  for (const path of modeledPaths) {
    // Resolve each original position separately. Filtering first would invent
    // edges between resources that were never adjacent in the source path.
    const pathNodes = path.nodes.map((node) => {
      if (node.state !== "Verified") return undefined;
      if (node.type === "External" && node.name === "Internet") {
        return {
          id: "internet",
          label: "Internet",
          kind: "External",
          detail: node.observed,
        } satisfies DashboardGraphNode;
      }
      const asset = scopedAssets.find((item) => item.name === node.name);
      return asset ? graphNodeForAsset(asset) : undefined;
    });
    if (path.state === "Verified" && pathNodes.every(Boolean)) verifiedPaths += 1;
    for (let index = 0; index < pathNodes.length - 1; index += 1) {
      const source = pathNodes[index];
      const target = pathNodes[index + 1];
      if (!source || !target) continue;
      graphNodes.set(source.id, source);
      graphNodes.set(target.id, target);
      const edge = {
        source: source.id,
        target: target.id,
        label: path.nodes[index].relationship,
      };
      graphEdges.set(`${edge.source}:${edge.target}:${edge.label}`, edge);
    }
  }
  for (const asset of scopedAssets) {
    if (!graphNodes.has(asset.id)) graphNodes.set(asset.id, graphNodeForAsset(asset));
  }
  const distribution = new Map<string, number>();
  for (const asset of scopedAssets) {
    distribution.set(asset.category, (distribution.get(asset.category) || 0) + 1);
  }

  return {
    mode: "demo",
    workspace: tenant.name,
    scopeLabel: `${account?.name || "No account selected"} · ${region}`,
    scenario: scenarios[tenant.id],
    services,
    status: !scopedAssets.length ? "empty" : coverage === 100 ? "ready" : "partial",
    errors: [],
    snapshot: observedAt,
    score,
    scoreLabel: "Demo posture index",
    scoreDetail: evidence.length
      ? `Severity-weighted active findings across ${evidence.length} evaluated findings. Each finding is counted once; missing evidence is not scored as healthy.`
      : "No evaluated findings in this scope. A posture score is not available.",
    metrics: [
      {
        label: "Assets in scope",
        value: scopedAssets.length,
        detail: `${connected ? 1 : 0} demo account · ${distribution.size} resource categories`,
        href: "/inventory",
      },
      {
        label: "Active findings",
        value: active.length,
        detail: `${active.filter((finding) => severityWeight[finding.severity] >= 3).length} critical or high priority`,
        href: "/findings",
      },
      {
        label: "Public assets",
        value: scopedAssets.filter((asset) => asset.exposure === "Public").length,
        detail: "Public exposure recorded in this demo snapshot",
        href: "/inventory?exposure=Public",
      },
    ],
    domains,
    findings: active.map((finding) => {
      const asset = assetsById.get(finding.asset)!;
      return {
        id: finding.id,
        title: finding.title,
        resource: asset.name,
        severity: finding.severity,
        score: finding.score,
        service: serviceForAsset(asset),
        href: `/findings/${encodeURIComponent(finding.id)}`,
        context: `${asset.exposure} · ${finding.owner} · ${finding.status}`,
      };
    }),
    findingsTotal: active.length,
    severity: (Object.keys(severityWeight) as DashboardSeverity[]).map((label) => ({
      label,
      count: active.filter((finding) => finding.severity === label).length,
    })),
    distribution: [...distribution].map(([label, count]) => ({ label, count })),
    graph: {
      nodes: [...graphNodes.values()],
      edges: [...graphEdges.values()],
      totalNodes: graphNodes.size,
      totalEdges: graphEdges.size,
      paths: verifiedPaths,
      status: !scopedAssets.length ? "empty" : graphEdges.size ? "ready" : "partial",
      detail: graphEdges.size
        ? "Only verified, adjacent relationships from the modeled demo paths are shown within this account, region, and service scope."
        : "Inventory resources are shown without connections. No verified relationships are modeled for this scope.",
    },
    coverage: [
      {
        label: "Account collection",
        value: coverage === null ? "No connected demo account" : `${coverage}% of modeled account collection`,
        status: coverage === null ? "empty" : coverage === 100 ? "ready" : "partial",
      },
      ...domains.map((domain) => ({
        label: `${domain.service} evidence`,
        value: domain.status === "empty" ? "No resources in this scope" : domain.detail,
        status: domain.status,
      })),
    ],
  };
}

export function useDemoDashboardModel(): DashboardModel {
  const { tenant, scope, workspace } = useProduct();
  const { region } = useAccountScope();
  return buildDemoDashboardModel({
    tenant,
    accountId: scope,
    region,
    findings: workspace.findings,
    disconnected: workspace.disconnected,
  });
}
