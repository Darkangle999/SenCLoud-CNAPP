import { useEffect, useState } from "react";
import { useApi } from "../hooks/useApi";
import { useAccountScope } from "../lib/accountScope";
import { api, type ApiError } from "../lib/api";
import type { SecurityGraph } from "../types";
import type { DashboardModel, DashboardSeverity, EvidenceStatus } from "./dashboard-model";

const services = ["CSPM", "DSPM", "CIEM", "CWPP"] as const;
const severities: DashboardSeverity[] = ["Critical", "High", "Medium", "Low"];
type Source = { data: unknown; error: ApiError | null; loading: boolean };

// Revoked, disconnected, or unavailable account coordinates must never expose
// previously loaded evidence, even during a same-workspace refresh.
function useScopedEvidence<T>(fn: () => Promise<T>, deps: unknown[], options: { enabled: boolean }) {
  const source = useApi(fn, deps, options);
  return options.enabled ? source : { ...source, data: null, error: null, loading: false };
}

function evidence(source: Source, enabled: boolean, count?: number): EvidenceStatus {
  if (!enabled) return "empty";
  if (source.error) return "error";
  if (source.loading || source.data === null) return "loading";
  return count === 0 ? "empty" : "ready";
}

function graphPreview(data: SecurityGraph | null): Pick<DashboardModel["graph"], "nodes" | "edges"> {
  if (!data) return { nodes: [], edges: [] };
  const existing = new Map(data.nodes.map((node) => [node.id, node]));
  const selected = new Set<string>();
  const route = [...data.paths].sort((a, b) =>
    severities.findIndex((severity) => severity.toLowerCase() === a.severity)
    - severities.findIndex((severity) => severity.toLowerCase() === b.severity)
    || a.length - b.length,
  )[0];
  for (const id of route?.nodes ?? []) {
    if (existing.has(id) && selected.size < 7) selected.add(id);
  }
  // Fill the preview with actual connected evidence, never decorative edges.
  for (const edge of data.edges) {
    if (selected.size >= 7) break;
    if (!existing.has(edge.source) || !existing.has(edge.target)) continue;
    const needed = Number(!selected.has(edge.source)) + Number(!selected.has(edge.target));
    if (selected.size + needed > 7) continue;
    selected.add(edge.source);
    selected.add(edge.target);
  }
  for (const node of data.nodes) {
    if (selected.size >= 7) break;
    selected.add(node.id);
  }
  return {
    nodes: [...selected].map((id) => {
      const node = existing.get(id)!;
      return {
        id,
        label: node.name,
        kind: node.kind,
        detail: node.asset_type ?? node.kind.replace(/_/g, " "),
        href: "/security-graph",
      };
    }),
    edges: data.edges.filter((edge) => selected.has(edge.source) && selected.has(edge.target))
      .map((edge) => ({ source: edge.source, target: edge.target, label: edge.type.replace(/_/g, " ") })),
  };
}

/** One validated connected account, using aggregate APIs rather than page sizes. */
export function useConnectedDashboardModel() {
  const { accountId, provider, region } = useAccountScope();
  const accounts = useApi(() => api.accounts());
  const account = accounts.data?.items.find((item) =>
    item.id === accountId && item.is_active && item.provider === provider
    && item.onboarding_status !== "awaiting_stack",
  );
  const enabled = Boolean(account);
  const id = account?.id;
  const options = { enabled };
  const inventory = useScopedEvidence(() => api.inventorySummary(id, provider), [id, provider], options);
  const resources = useScopedEvidence(() => api.inventoryResources({ account_id: id, provider, page_size: 1 }), [id, provider], options);
  const findings = useScopedEvidence(() => api.findingsSummary(id, provider), [id, provider], options);
  const priority = useScopedEvidence(() => api.findingResources({ account_id: id, provider, status: "open", sort: "severity", page_size: 8 }), [id, provider], options);
  const identities = useScopedEvidence(() => api.identityResources({ account_id: id, provider, page_size: 1 }), [id, provider], options);
  const data = useScopedEvidence(() => api.dataSecurityResources({ account_id: id, provider, page_size: 1 }), [id, provider], options);
  const vulnerabilities = useScopedEvidence(() => api.vulnerabilitiesSummary(id), [id], options);
  const agents = useScopedEvidence(() => api.runtimeAgents(id), [id], options);
  const compliance = useScopedEvidence(() => api.complianceCurrent(id, provider), [id, provider], options);
  const graph = useScopedEvidence(() => api.graph({ provider, account: account?.account_identifier }), [id, provider, account?.account_identifier], options);
  const [submitting, setSubmitting] = useState(false);
  const [queuedAfter, setQueuedAfter] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [scanQueuedAt, setScanQueuedAt] = useState<number | null>(null);
  const latest = account?.latest_scan;
  const activeScan = latest?.status === "queued" || latest?.status === "running";
  const scanning = submitting || activeScan || queuedAfter !== null;

  const sources = [
    ["Inventory", inventory], ["Resource distribution", resources], ["CSPM findings", findings],
    ["Priority findings", priority], ["CIEM", identities],
    ["DSPM", data], ["CWPP", vulnerabilities], ["Runtime sensors", agents],
    ["Compliance", compliance], ["Security graph", graph],
  ] as const;

  function refreshEvidence() {
    accounts.refetch();
    if (enabled) sources.forEach(([, source]) => source.refetch());
  }

  useEffect(() => {
    if (!enabled || (!activeScan && queuedAfter === null)) return;
    const timer = window.setInterval(refreshEvidence, 6000);
    return () => window.clearInterval(timer);
    // Source callbacks remain bound to this account; this component remounts
    // when account/provider/region changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, activeScan, queuedAfter]);

  useEffect(() => {
    if (queuedAfter === null) return;
    if (latest && latest.id > queuedAfter && (latest.status === "completed" || latest.status === "failed")) {
      setQueuedAfter(null);
      setMessage(latest.status === "completed" ? "Inventory scan completed. Connected evidence refreshed." : "Inventory scan failed. Review connector permissions and scan details.");
    } else if (scanQueuedAt && Date.now() - scanQueuedAt > 120000 && !activeScan) {
      setQueuedAfter(null);
      setMessage("Scan was queued, but progress has not been reported. Check the connector's scan status.");
    }
  }, [latest, queuedAfter, scanQueuedAt, activeScan]);

  async function runScan() {
    if (!account || scanning) return;
    setSubmitting(true);
    setMessage(null);
    try {
      const result = await api.scanAccount(account.id, region);
      setQueuedAfter(result.last_job_id);
      setScanQueuedAt(Date.now());
      setMessage(`Inventory scan queued for ${account.name ?? account.account_identifier}. Evidence refreshes as collection completes.`);
      refreshEvidence();
    } catch {
      setMessage("Could not queue the inventory scan. Review connector access and retry.");
    } finally {
      setSubmitting(false);
    }
  }

  const errors = sources.filter(([, source]) => source.error)
    .map(([name, source]) => `${name}: ${source.error?.status ? `HTTP ${source.error.status}` : "request unavailable"}. Refresh to retry.`);
  if (accounts.error) errors.unshift("Connected accounts could not be loaded. Refresh to retry.");
  const hasEvidence = sources.some(([, source]) => source.data !== null);
  const loading = accounts.loading || (enabled && sources.some(([, source]) => source.loading || (!source.data && !source.error)));
  const status: EvidenceStatus = errors.length ? (hasEvidence ? "partial" : "error")
    : loading ? "loading" : !enabled || inventory.data?.total_assets === 0 ? "empty" : "ready";
  const snapshots = compliance.data?.items ?? [];
  const assessedSnapshots = snapshots.filter((snapshot) => snapshot.total > snapshot.not_assessed);
  const score = assessedSnapshots.length
    ? Math.round(assessedSnapshots.reduce((sum, snapshot) => sum + snapshot.score, 0) / assessedSnapshots.length)
    : null;
  const classification = data.data?.totals;
  const identity = identities.data?.totals;
  const cv = vulnerabilities.data;
  const graphStatus = evidence(graph, enabled, graph.data?.nodes.length);
  const graphAnalysis = graph.data?.analysis;
  const model: DashboardModel = {
    mode: "live",
    workspace: account?.name ?? account?.account_identifier ?? "Connected workspace",
    scopeLabel: `${provider.toUpperCase()} · ${account?.account_identifier ?? "Select a connected account"} · All regions + global services`,
    scenario: enabled
      ? `Account-wide evidence across CSPM, DSPM, CIEM and CWPP. Scan request region: ${region}.`
      : "Connect a cloud account and complete its first scan to populate this workspace.",
    services: [...services],
    status,
    errors,
    snapshot: latest?.completed_at ?? null,
    score,
    scoreLabel: "Compliance posture",
    scoreDetail: score === null
      ? "Awaiting assessed compliance snapshots. Missing evidence is not a passing score."
      : `Mean of ${assessedSnapshots.length} assessed framework scores for this account; this is a compliance measure, not a CNAPP-wide score.`,
    metrics: [
      { label: "Assets in scope", value: inventory.data?.total_assets ?? null, detail: "Active inventory · all regions", href: "/inventory" },
      { label: "Active findings", value: findings.data?.open ?? null, detail: "Configuration findings · account-wide", href: "/findings" },
      { label: "Public assets", value: inventory.data?.public_assets ?? null, detail: "Public configuration · reachability may vary", href: "/inventory?exposure=public" },
    ],
    domains: [
      {
        service: "CSPM", label: "Configuration findings", value: findings.data?.open ?? null,
        detail: "Open posture findings across this account", href: "/cloud-configuration",
        status: evidence(findings, enabled, findings.data?.open),
        secondary: findings.data ? `${findings.data.by_severity.critical ?? 0} critical · ${findings.data.by_severity.high ?? 0} high` : "Awaiting posture evidence",
      },
      {
        service: "DSPM", label: "Sensitive data stores", value: classification?.sensitive ?? null,
        detail: "Stores classified high or critical", href: "/data",
        status: classification && classification.stores > classification.classified ? "partial" : evidence(data, enabled, classification?.stores),
        secondary: classification ? `${classification.classified} / ${classification.stores} classified · ${classification.public} public` : "Awaiting classification evidence",
      },
      {
        service: "CIEM", label: "Privileged identities", value: identity?.admins ?? null,
        detail: "Admin access within analyzed policy layers", href: "/identities",
        status: identity?.incomplete_evaluations ? "partial" : evidence(identities, enabled, identity?.principals),
        secondary: identity ? `${identity.principals} principals · ${identity.incomplete_evaluations} incomplete evaluations` : "Awaiting identity evidence",
      },
      {
        service: "CWPP", label: "Vulnerability findings", value: cv?.open ?? null,
        detail: "Persisted open package vulnerabilities", href: "/vulnerabilities",
        status: evidence(vulnerabilities, enabled, cv?.open),
        secondary: cv ? `${cv.affected_assets} affected assets · ${cv.kev} KEV findings${cv.open === 0 ? " · scan coverage unverified" : ""}` : "Awaiting workload evidence",
      },
    ],
    findings: (priority.data?.items ?? []).map((finding) => ({
      id: String(finding.id), title: finding.verdict.title, resource: finding.resource.name,
      severity: (finding.posture.severity === "info" ? "Low" : `${finding.posture.severity[0].toUpperCase()}${finding.posture.severity.slice(1)}`) as DashboardSeverity,
      score: finding.posture.risk_score,
      service: "CSPM",
      href: `/findings?rule=${encodeURIComponent(finding.verdict.rule_id)}`,
      context: `${finding.resource.service} · ${finding.posture.exposure} · configuration evidence`,
    })),
    findingsTotal: findings.data?.open ?? null,
    severity: severities.map((severity) => ({
      label: severity,
      count: (findings.data?.by_severity[severity.toLowerCase()] ?? 0)
        + (severity === "Low" ? findings.data?.by_severity.info ?? 0 : 0),
    })),
    distribution: (resources.data?.facets.categories ?? []).map((category) => ({ label: category.label, count: category.count })),
    graph: {
      ...graphPreview(graph.data),
      totalNodes: graph.data?.nodes.length ?? null,
      totalEdges: graph.data?.edges.length ?? null,
      paths: graph.data?.paths.length ?? null,
      status: graphStatus === "ready" && graphAnalysis?.status !== "ready" ? "partial" : graphStatus,
      detail: graphAnalysis
        ? `${graphAnalysis.message} ${graphAnalysis.limitations.join(" ")}`
        : enabled ? "Collecting account-scoped resource and identity relationships." : "Connect an account to model its security relationships.",
    },
    coverage: [
      { label: "Inventory", value: inventory.data ? `${inventory.data.total_assets} active resources` : "Awaiting collection", status: evidence(inventory, enabled, inventory.data?.total_assets) },
      { label: "Data classification", value: classification ? `${classification.classified} / ${classification.stores} stores classified` : "Awaiting DSPM evidence", status: classification && classification.classified < classification.stores ? "partial" : evidence(data, enabled, classification?.stores) },
      { label: "Identity evaluation", value: identity ? `${identity.principals - identity.incomplete_evaluations} / ${identity.principals} complete` : "Awaiting CIEM evidence", status: identity?.incomplete_evaluations ? "partial" : evidence(identities, enabled, identity?.principals) },
      { label: "Runtime sensors", value: agents.data ? `${agents.data.by_status.online ?? 0} / ${agents.data.total} hosts online` : "Awaiting sensor evidence", status: agents.data?.total && (agents.data.by_status.online ?? 0) < agents.data.total ? "partial" : evidence(agents, enabled, agents.data?.total) },
      { label: "Compliance", value: compliance.data ? `${assessedSnapshots.length} assessed frameworks` : "Awaiting compliance evidence", status: evidence(compliance, enabled, assessedSnapshots.length) },
    ],
  };
  return { model, onRefresh: refreshEvidence, onScan: runScan, scanning, message, canScan: enabled };
}
