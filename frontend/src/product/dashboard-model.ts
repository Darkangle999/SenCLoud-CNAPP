import type { SecurityService } from "./data";

export type DashboardSeverity = "Critical" | "High" | "Medium" | "Low";
export type EvidenceStatus = "ready" | "loading" | "empty" | "error" | "partial";

export interface DashboardMetric {
  label: string;
  value: number | null;
  detail: string;
  href: string;
}

export interface DashboardDomain extends DashboardMetric {
  service: SecurityService;
  status: EvidenceStatus;
  secondary: string;
}

export interface DashboardFinding {
  id: string;
  title: string;
  resource: string;
  severity: DashboardSeverity;
  score: number;
  service: SecurityService;
  href: string;
  context: string;
}

export interface DashboardGraphNode {
  id: string;
  label: string;
  kind: string;
  detail: string;
  href?: string;
}

export interface DashboardGraphEdge {
  source: string;
  target: string;
  label: string;
}

/** Presentation contract shared by isolated demo evidence and connected APIs. */
export interface DashboardModel {
  mode: "demo" | "live";
  workspace: string;
  scopeLabel: string;
  scenario?: string;
  services: SecurityService[];
  status: EvidenceStatus;
  errors: string[];
  snapshot: string | null;
  score: number | null;
  scoreLabel: string;
  scoreDetail: string;
  metrics: DashboardMetric[];
  domains: DashboardDomain[];
  findings: DashboardFinding[];
  findingsTotal: number | null;
  severity: Array<{ label: DashboardSeverity; count: number }>;
  distribution: Array<{ label: string; count: number }>;
  graph: {
    nodes: DashboardGraphNode[];
    edges: DashboardGraphEdge[];
    totalNodes: number | null;
    totalEdges: number | null;
    paths: number | null;
    status: EvidenceStatus;
    detail: string;
  };
  coverage: Array<{ label: string; value: string; status: EvidenceStatus }>;
}
