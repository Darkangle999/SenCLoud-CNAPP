import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  ArrowUpRight,
  Cloud,
  Code2,
  Container,
  Database,
  ExternalLink,
  FileCode2,
  Fingerprint,
  GitBranch,
  Globe2,
  KeyRound,
  PackageCheck,
  Search,
  Server,
  ShieldAlert,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
} from "react-simple-maps";
import { GraphCanvas } from "../components/GraphCanvas";
import { useTheme } from "../theme";
import type { AttackRoute, GraphEdge, GraphKind, GraphNode, Severity as GraphSeverity } from "../types";
import { accounts, assets, attackPaths } from "./data";
import { useProduct } from "./store";
import {
  Badge,
  Empty,
  Filters,
  Head,
  Notice,
  Overlay,
  Panel,
  Table,
  useFilters,
} from "./ui";

const GEO_URL = "/geo/countries-110m.json";
const regionCoordinates: Record<string, [number, number]> = {
  "us-east-1": [-78.8, 38],
  "eu-west-1": [-6.2, 53],
  "ap-south-1": [72.9, 19.1],
  "ap-southeast-1": [103.8, 1.3],
};

function useChartPalette() {
  const { theme } = useTheme();
  return useMemo(
    () =>
      theme === "dark"
        ? {
            text: "#9db4c2",
            grid: "#213746",
            surface: "#0e1e29",
            accent: "#8dd9f7",
            blue: "#65bfea",
            critical: "#ff5f6d",
            high: "#ff9f5a",
            medium: "#f2cb61",
            low: "#6ebbd9",
            green: "#55d6a5",
          }
        : {
            text: "#617580",
            grid: "#d9e8ee",
            surface: "#ffffff",
            accent: "#187ba3",
            blue: "#3598c1",
            critical: "#c93445",
            high: "#dc6d2c",
            medium: "#ba8c16",
            low: "#487c9c",
            green: "#19805e",
          },
    [theme],
  );
}

function ChartTip() {
  const palette = useChartPalette();
  return (
    <Tooltip
      contentStyle={{
        background: palette.surface,
        border: `1px solid ${palette.grid}`,
        borderRadius: 8,
        color: palette.text,
        fontSize: 11,
      }}
    />
  );
}

export function CloudWorldMap({ dataMode = false }: { dataMode?: boolean }) {
  const { inScope } = useProduct();
  const palette = useChartPalette();
  const markers = Object.entries(
    assets
      .filter((asset) => inScope(asset.account, asset.region))
      .reduce(
        (sum, asset) => {
          if (asset.region !== "Global") {
            const current = sum[asset.region] || { total: 0, exposed: 0 };
            current.total += 1;
            current.exposed += asset.exposure === "Public" ? 1 : 0;
            sum[asset.region] = current;
          }
          return sum;
        },
        {} as Record<string, { total: number; exposed: number }>,
      ),
  );
  return (
    <div className="cs-world-map">
      <ComposableMap
        width={860}
        height={330}
        projection="geoEqualEarth"
        projectionConfig={{ scale: 145 }}
        aria-label={
          dataMode
            ? "Sensitive data residency map"
            : "Global asset exposure map"
        }
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map((geography) => (
              <Geography
                key={geography.rKey}
                geography={geography}
                fill={palette.grid}
                stroke={palette.surface}
                strokeWidth={0.5}
              />
            ))
          }
        </Geographies>
        {markers.map(([region, count]) => {
          const position = regionCoordinates[region];
          if (!position) return null;
          const risk = dataMode
            ? assets.filter(
                (asset) =>
                  asset.region === region &&
                  asset.sensitivity !== "Not classified",
              ).length
            : count.exposed;
          return (
            <Marker key={region} coordinates={position}>
              <circle
                r={7 + Math.sqrt(count.total) * 2.2}
                fill={risk ? palette.critical : palette.accent}
                fillOpacity={0.2}
                stroke={risk ? palette.critical : palette.accent}
                strokeWidth={1.2}
              />
              <circle r={2.5} fill={risk ? palette.critical : palette.accent} />
              <title>{`${region}: ${count.total} assets, ${risk} ${dataMode ? "sensitive" : "public"}`}</title>
            </Marker>
          );
        })}
      </ComposableMap>
      <div className="cs-map-legend">
        <span>
          <i className="critical" />
          {dataMode ? "Sensitive data" : "Public exposure"}
        </span>
        <span>
          <i />
          Observed region
        </span>
        <small>Marker size represents resource volume</small>
      </div>
    </div>
  );
}

// Demo security graph is derived from the scoped account's modeled attack
// paths, so the relation graph always matches the assets in scope instead of
// rendering one hardcoded chain.
const PATH_NODE_KIND: Record<string, GraphKind> = {
  External: "internet",
  "Load balancer": "compute",
  "Security group": "security_group",
  "EC2 instance": "compute",
  "IAM role": "role",
  "IAM user": "user",
  "Sensitive S3": "bucket",
  "S3 bucket": "bucket",
  Database: "database",
};

const DEMO_RISK: Record<string, number> = {
  Critical: 95,
  High: 80,
  Medium: 55,
  Low: 25,
};

function demoEdgeType(source: GraphKind, target: GraphKind): GraphEdge["type"] {
  if (source === "internet") return "EXPOSED_TO";
  if (target === "security_group") return "USES_SECURITY_GROUP";
  if (target === "role" || target === "user") return "CAN_ASSUME";
  return "CAN_ACCESS";
}

interface DemoGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  routes: AttackRoute[];
}

function buildDemoGraph(accountId: string): DemoGraph {
  const scopedAssets = assets.filter((asset) => asset.account === accountId);
  const scopedPaths = attackPaths.filter((path) => path.account === accountId);
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const routes: AttackRoute[] = [];

  const nodeIdFor = (name: string) => {
    if (name === "Internet") return "internet";
    const asset = scopedAssets.find((item) => item.name === name);
    return asset ? asset.id : name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  };

  for (const path of scopedPaths) {
    const ids: string[] = [];
    for (const hop of path.nodes) {
      const id = nodeIdFor(hop.name);
      ids.push(id);
      if (!nodes.has(id)) {
        const asset = scopedAssets.find((item) => item.id === id);
        nodes.set(id, {
          id,
          kind: PATH_NODE_KIND[hop.type] ?? "compute",
          name: hop.name,
          asset_type: hop.type,
          region: asset?.region,
          is_public: hop.type === "External" || asset?.exposure === "Public",
          risk_score: asset ? (DEMO_RISK[asset.risk] ?? 40) : path.score,
          properties: hop.observed ? { observed: hop.observed } : {},
        });
      }
    }
    for (let index = 0; index < ids.length - 1; index += 1) {
      const source = nodes.get(ids[index])!;
      const target = nodes.get(ids[index + 1])!;
      const type = demoEdgeType(source.kind, target.kind);
      edges.set(`${source.id}->${target.id}:${type}`, {
        source: source.id,
        target: target.id,
        type,
      });
    }
    const findingId = `finding-${path.id}`;
    nodes.set(findingId, {
      id: findingId,
      kind: "finding",
      name: path.name,
      severity: path.severity.toLowerCase() as GraphSeverity,
      risk_score: path.score,
      issue_type: "attack_path",
    });
    edges.set(`${ids[ids.length - 1]}->${findingId}`, {
      source: ids[ids.length - 1],
      target: findingId,
      type: "HAS_FINDING",
    });
    routes.push({
      id: path.id,
      nodes: [...ids, findingId],
      length: ids.length - 1,
      entry: nodes.get(ids[0])!.kind,
      target: path.nodes[path.nodes.length - 1].name,
      target_kind: nodes.get(ids[ids.length - 1])!.kind,
      severity: path.severity.toLowerCase() as GraphSeverity,
    });
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()], routes };
}

export function SecurityGraphWorkspace() {
  const { scope, setScope, tenantAccounts } = useProduct();
  const [query, setQuery] = useState("");
  const [node, setNode] = useState<GraphNode | null>(null);
  const graph = useMemo(() => buildDemoGraph(scope), [scope]);
  const term = query.trim().toLowerCase();
  const routes = term
    ? graph.routes.filter(
        (route) =>
          route.target.toLowerCase().includes(term) ||
          route.id.toLowerCase().includes(term) ||
          route.severity.toLowerCase().includes(term),
      )
    : graph.routes;
  const visibleNode = node
    ? graph.nodes.find((item) => item.id === node.id) || null
    : null;
  return (
    <div className="cs-page cs-domain-page">
      <Head title="Security Graph" />
      <div className="cs-graph-query">
        <Search size={17} />
        <input
          aria-label="Security graph query"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Find public workloads that can access sensitive data..."
        />
        <kbd>{routes.length} paths</kbd>
      </div>
      <div className="cs-query-templates">
        <span>Saved queries</span>
        {[
          "Public compute with admin role",
          "Cross-account access to sensitive data",
          "Internet to critical vulnerability",
        ].map((template) => (
          <button key={template} onClick={() => setQuery(template)}>
            {template}
          </button>
        ))}
      </div>
      <Panel className="cs-security-graph-panel">
        {graph.nodes.length ? (
          <GraphCanvas
            nodes={graph.nodes}
            edges={graph.edges}
            paths={routes}
            accounts={tenantAccounts.map((account) => ({
              account_identifier: account.number,
              name: account.name,
            }))}
            account={
              tenantAccounts.find((account) => account.id === scope)?.number || ""
            }
            onAccountChange={(number) => {
              const next = tenantAccounts.find(
                (account) => account.number === number,
              );
              if (next) setScope(next.id);
            }}
            onSelect={setNode}
          />
        ) : (
          <Empty
            title="No attack paths"
            text="No attack-path relationships are modeled for this account scope."
          />
        )}
      </Panel>
      {visibleNode && (
        <Overlay drawer title={visibleNode.name} onClose={() => setNode(null)}>
          <GraphNodeDetail node={visibleNode} />
        </Overlay>
      )}
    </div>
  );
}

function GraphNodeDetail({ node }: { node: GraphNode }) {
  const { scope } = useProduct();
  return (
    <div className="cs-drawer-stack">
      <div className="cs-kv-grid">
        <div>
          <span>Risk score</span>
          <strong>{node.risk_score ?? "Unknown"}</strong>
        </div>
        <div>
          <span>Exposure</span>
          <strong>{node.is_public ? "Public" : "Private"}</strong>
        </div>
        <div>
          <span>Resource type</span>
          <strong>{node.asset_type || node.kind}</strong>
        </div>
        <div>
          <span>Region</span>
          <strong>{node.region || "Global"}</strong>
        </div>
      </div>
      <Panel title="Security Graph position">
        <div className="cs-mini-path">
          <Globe2 size={17} />
          <i />
          <Server size={17} />
          <i />
          <KeyRound size={17} />
          <i />
          <Database size={17} />
        </div>
      </Panel>
      <Panel title="Observed risk">
        <Notice>
          Relationship and risk data come from current evidence. Missing
          authorization layers remain Unknown.
        </Notice>
      </Panel>
      <Link
        className="cs-button primary"
        to={`/attack-paths/${attackPaths.find((path) => path.account === scope)?.id || ""}`}
      >
        Open attack path <ArrowUpRight size={14} />
      </Link>
    </div>
  );
}

const vulnerabilitySeed = [
  {
    account: "production",
    id: "CVE-2026-21894",
    score: 9.8,
    epss: 0.94,
    pkg: "openssl",
    version: "3.0.2",
    fixed: "3.0.15",
    resource: "payments-api:2026.09.04",
    layer: "RUN apt-get install openssl",
    severity: "Critical",
    assets: 18,
  },
  {
    account: "development",
    id: "CVE-2025-9086",
    score: 8.8,
    epss: 0.72,
    pkg: "libxml2",
    version: "2.9.13",
    fixed: "2.12.9",
    resource: "checkout-worker:stable",
    layer: "COPY requirements.txt",
    severity: "High",
    assets: 11,
  },
  {
    account: "security",
    id: "CVE-2026-11721",
    score: 7.5,
    epss: 0.31,
    pkg: "curl",
    version: "7.81.0",
    fixed: "8.10.1",
    resource: "reporting-api:v42",
    layer: "FROM ubuntu:22.04",
    severity: "High",
    assets: 7,
  },
  {
    account: "production",
    id: "CVE-2024-5535",
    score: 6.5,
    epss: 0.09,
    pkg: "node",
    version: "20.11.0",
    fixed: "20.18.1",
    resource: "web-portal:1.24",
    layer: "FROM node:20-alpine",
    severity: "Medium",
    assets: 4,
  },
  {
    account: "shared-services",
    id: "CVE-2025-10231",
    score: 3.7,
    epss: 0.02,
    pkg: "zlib",
    version: "1.2.11",
    fixed: "",
    resource: "audit-exporter:8",
    layer: "RUN apk add zlib",
    severity: "Low",
    assets: 2,
  },
];
const vulnerabilityAccounts = new Set(
  vulnerabilitySeed.map((item) => item.account),
);
const vulnerabilities = [
  ...vulnerabilitySeed,
  ...accounts
    .filter((account) => !vulnerabilityAccounts.has(account.id))
    .map((account, index) => ({
      account: account.id,
      id: `CVE-2026-${31041 + index}`,
      score: index % 2 ? 8.2 : 9.1,
      epss: index % 2 ? 0.46 : 0.78,
      pkg: index % 2 ? "glibc" : "openssl",
      version: index % 2 ? "2.35" : "3.0.2",
      fixed: index % 2 ? "2.39" : "3.0.15",
      resource:
        assets.find(
          (asset) => asset.account === account.id && asset.category === "Compute",
        )?.name || `${account.id}-workload`,
      layer: index % 2 ? "FROM ubuntu:22.04" : "RUN apt-get install openssl",
      severity: index % 2 ? "High" : "Critical",
      assets: 3 + index,
    })),
];

export function VulnerabilitiesHub() {
  const { inScope } = useProduct();
  const palette = useChartPalette();
  const filters = useFilters();
  const [selected, setSelected] = useState<
    (typeof vulnerabilities)[number] | null
  >(null);
  const scopedVulnerabilities = vulnerabilities.filter((item) => inScope(item.account));
  const rows = scopedVulnerabilities.filter(
    (item) =>
      !filters.params.get("severity") ||
      filters.params.get("severity")?.split(",").includes(item.severity),
  );
  const severity = ["Critical", "High", "Medium", "Low"].map((name) => ({
    name,
    value: scopedVulnerabilities.filter((item) => item.severity === name).length,
  }));
  const affectedAssets = scopedVulnerabilities.reduce((total, item) => total + item.assets, 0);
  return (
    <div className="cs-page cs-domain-page">
      <Head title="Vulnerabilities">
        <button className="cs-button primary">
          <PackageCheck size={15} />
          Scan workloads
        </button>
      </Head>
      <div className="cs-domain-summary">
        <DomainStat
          label="Open CVEs"
          value={String(scopedVulnerabilities.length)}
          tone="critical"
        />
        <DomainStat
          label="Known exploited"
          value={String(scopedVulnerabilities.filter((item) => item.epss >= 0.7).length)}
          tone="critical"
        />
        <DomainStat
          label="Fix available"
          value={`${Math.round((scopedVulnerabilities.filter((item) => item.fixed).length / Math.max(scopedVulnerabilities.length, 1)) * 100)}%`}
        />
        <DomainStat label="Affected assets" value={String(affectedAssets)} />
      </div>
      <div className="cs-visual-grid">
        <Panel title="Exploitability matrix">
          <div className="cs-cnapp-chart">
            <ResponsiveContainer width="100%" height={240}>
              <ScatterChart
                margin={{ top: 15, right: 25, bottom: 12, left: -12 }}
              >
                <CartesianGrid stroke={palette.grid} />
                <XAxis
                  type="number"
                  dataKey="score"
                  name="CVSS"
                  domain={[0, 10]}
                  tick={{ fill: palette.text, fontSize: 10 }}
                />
                <YAxis
                  type="number"
                  dataKey="epss"
                  name="EPSS"
                  domain={[0, 1]}
                  tick={{ fill: palette.text, fontSize: 10 }}
                />
                <ZAxis type="number" dataKey="assets" range={[60, 420]} />
                <ChartTip />
                <Scatter data={scopedVulnerabilities} fill={palette.critical} />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Severity and fix coverage">
          <div className="cs-split-donuts">
            <MiniDonut data={severity} />
            <MiniDonut
              data={[
                { name: "Fixable", value: 259 },
                { name: "No fix", value: 25 },
              ]}
              colors={[palette.green, palette.medium]}
            />
          </div>
        </Panel>
      </div>
      <Panel>
        <Filters
          filters={filters}
          placeholder="Search CVE, package, image..."
          fields={{
            severity: ["Critical", "High", "Medium", "Low"],
            fix: ["Available", "No fix"],
            source: ["Host", "Container image"],
          }}
        />
        <Table
          headers={[
            "CVE",
            "CVSS",
            "EPSS",
            "Package",
            "Affected resource",
            "Assets",
            "Fix",
            "Severity",
            "",
          ]}
          count={rows.length}
        >
          {rows.map((item) => (
            <tr key={item.id} onClick={() => setSelected(item)}>
              <td>
                <button
                  className="cs-resource-button"
                  onClick={() => setSelected(item)}
                >
                  <strong>{item.id}</strong>
                </button>
              </td>
              <td>
                <b className="cs-risk-score critical">{item.score}</b>
              </td>
              <td>{Math.round(item.epss * 100)}%</td>
              <td>
                <strong>{item.pkg}</strong>
                <span className="cs-cell-sub">{item.version}</span>
              </td>
              <td>{item.resource}</td>
              <td>{item.assets}</td>
              <td>
                <Badge kind={item.fixed ? "Healthy" : "Unknown"}>
                  {item.fixed || "No fix"}
                </Badge>
              </td>
              <td>
                <Badge kind={item.severity}>{item.severity}</Badge>
              </td>
              <td>
                <button
                  className="cs-icon"
                  aria-label={`Inspect ${item.id}`}
                  onClick={() => setSelected(item)}
                >
                  <ArrowUpRight size={14} />
                </button>
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {selected && scopedVulnerabilities.includes(selected) && (
        <Overlay drawer title={selected.id} onClose={() => setSelected(null)}>
          <div className="cs-drawer-stack">
            <div className="cs-kv-grid">
              <div>
                <span>CVSS</span>
                <strong>{selected.score}</strong>
              </div>
              <div>
                <span>EPSS</span>
                <strong>{Math.round(selected.epss * 100)}%</strong>
              </div>
              <div>
                <span>Package</span>
                <strong>
                  {selected.pkg} {selected.version}
                </strong>
              </div>
              <div>
                <span>Fixed version</span>
                <strong>{selected.fixed || "Unavailable"}</strong>
              </div>
            </div>
            <Panel title="Container layer">
              <code className="cs-code-block">{selected.layer}</code>
            </Panel>
            <Panel title="Security Graph">
              <div className="cs-mini-path">
                <Container size={17} />
                <i />
                <PackageCheck size={17} />
                <i />
                <ShieldAlert size={17} />
              </div>
            </Panel>
            <button className="cs-button primary">Create remediation</button>
          </div>
        </Overlay>
      )}
    </div>
  );
}

function MiniDonut({
  data,
  colors,
}: {
  data: { name: string; value: number }[];
  colors?: string[];
}) {
  const palette = useChartPalette();
  const total = data.reduce((sum, item) => sum + item.value, 0);
  const fills = colors || [
    palette.critical,
    palette.high,
    palette.medium,
    palette.low,
  ];
  return (
    <div className="cs-mini-donut">
      <ResponsiveContainer width="100%" height={165}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            innerRadius={43}
            outerRadius={63}
            paddingAngle={2}
            strokeWidth={0}
          >
            {data.map((item, index) => (
              <Cell key={item.name} fill={fills[index % fills.length]} />
            ))}
          </Pie>
          <ChartTip />
        </PieChart>
      </ResponsiveContainer>
      <strong>{total}</strong>
      <div>
        {data.map((item, index) => (
          <span key={item.name}>
            <i style={{ background: fills[index % fills.length] }} />
            {item.name} <b>{item.value}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

function DomainStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <div className={`cs-domain-stat ${tone || ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function CloudConfiguration() {
  const { workspace, inScope } = useProduct();
  const palette = useChartPalette();
  const filters = useFilters();
  const [selected, setSelected] = useState<
    (typeof workspace.findings)[number] | null
  >(null);
  const rows = workspace.findings
    .filter((f) => assets.some((a) => a.id === f.asset && inScope(a.account, a.region)))
    .filter(
      (f) =>
        !filters.params.get("severity") ||
        filters.params.get("severity")?.split(",").includes(f.severity),
    );
  const categories = [
    { name: "IAM", value: 9 },
    { name: "Network", value: 7 },
    { name: "Storage", value: 6 },
    { name: "Encryption", value: 4 },
    { name: "Logging", value: 3 },
  ];
  return (
    <div className="cs-page cs-domain-page">
      <Head title="Cloud Configuration">
        <button className="cs-button primary">
          <ShieldAlert size={15} />
          Evaluate configuration
        </button>
      </Head>
      <div className="cs-domain-summary">
        <DomainStat
          label="Misconfigurations"
          value={String(rows.length)}
          tone="critical"
        />
        <DomainStat
          label="Failed controls · 5 frameworks"
          value="18"
        />
        <DomainStat label="Auto-remediated · 30d" value="23" />
        <DomainStat label="Manual review" value="8" />
      </div>
      <div className="cs-visual-grid">
        <Panel title="Misconfigurations by category">
          <div className="cs-cnapp-chart">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={categories}
                layout="vertical"
                margin={{ left: 12, right: 25 }}
              >
                <CartesianGrid stroke={palette.grid} horizontal={false} />
                <XAxis
                  type="number"
                  tick={{ fill: palette.text, fontSize: 10 }}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={75}
                  tick={{ fill: palette.text, fontSize: 10 }}
                />
                <ChartTip />
                <Bar
                  dataKey="value"
                  fill={palette.accent}
                  radius={[0, 4, 4, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Cloud and framework coverage">
          <div className="cs-cloud-comparison">
            {[
              ["AWS", 29, 82],
              ["Azure", 12, 88],
              ["Google Cloud", 7, 79],
            ].map(([name, issues, score]) => (
              <div key={name}>
                <span className="cs-cloud-glyph">
                  <Cloud size={15} />
                </span>
                <span>
                  <strong>{name}</strong>
                  <small>{issues} issues</small>
                </span>
                <div className="cs-progress">
                  <i style={{ width: `${score}%` }} />
                </div>
                <b>{score}%</b>
              </div>
            ))}
          </div>
        </Panel>
      </div>
      <Panel>
        <Filters
          filters={filters}
          placeholder="Search rules, resources, frameworks..."
          fields={{
            severity: ["Critical", "High", "Medium", "Low"],
            category: ["IAM", "Network", "Storage", "Encryption", "Logging"],
            cloud: ["AWS", "Azure", "Google Cloud"],
          }}
        />
        <Table
          headers={[
            "Rule",
            "Resource",
            "Severity",
            "Cloud",
            "Framework",
            "Owner",
            "Status",
            "",
          ]}
          count={rows.length}
        >
          {rows.map((f) => {
            const asset = assets.find((a) => a.id === f.asset)!;
            return (
              <tr key={f.id} onClick={() => setSelected(f)}>
                <td>
                  <button
                    className="cs-resource-button"
                    onClick={() => setSelected(f)}
                  >
                    <strong>{f.title}</strong>
                    <span className="cs-cell-sub">{f.policy}</span>
                  </button>
                </td>
                <td>
                  <Link to={`/inventory/${asset.id}`}>{asset.name}</Link>
                </td>
                <td>
                  <Badge kind={f.severity}>{f.severity}</Badge>
                </td>
                <td>AWS</td>
                <td>CIS · NIST</td>
                <td>{f.owner}</td>
                <td>
                  <Badge>{f.status}</Badge>
                </td>
                <td>
                  <ArrowUpRight size={14} />
                </td>
              </tr>
            );
          })}
        </Table>
      </Panel>
      {selected && (
        <Overlay
          drawer
          title={selected.title}
          onClose={() => setSelected(null)}
        >
          <div className="cs-drawer-stack">
            <Badge kind={selected.severity}>{selected.severity}</Badge>
            <Panel title="Observed state">
              <code className="cs-code-block">{selected.observed}</code>
            </Panel>
            <Panel title="Required state">
              <code className="cs-code-block">{selected.required}</code>
            </Panel>
            <Panel title="Security Graph">
              <div className="cs-mini-path">
                <Globe2 size={17} />
                <i />
                <Cloud size={17} />
                <i />
                <ShieldAlert size={17} />
              </div>
            </Panel>
            <Link className="cs-button primary" to={`/findings/${selected.id}`}>
              Full investigation
            </Link>
          </div>
        </Overlay>
      )}
    </div>
  );
}

const clusterSeed = [
  {
    account: "production",
    name: "payments-prod-eks",
    cloud: "AWS",
    version: "1.32",
    nodes: 18,
    pods: 246,
    issues: 14,
    risk: "Critical",
    owner: "Platform Team",
  },
  {
    account: "development",
    name: "analytics-dev-gke",
    cloud: "Google Cloud",
    version: "1.31",
    nodes: 12,
    pods: 184,
    issues: 7,
    risk: "High",
    owner: "Data Engineering",
  },
  {
    account: "shared-services",
    name: "shared-services-aks",
    cloud: "Azure",
    version: "1.31",
    nodes: 8,
    pods: 96,
    issues: 3,
    risk: "Medium",
    owner: "Cloud Operations",
  },
  {
    account: "security",
    name: "security-platform-eks",
    cloud: "AWS",
    version: "1.32",
    nodes: 6,
    pods: 74,
    issues: 2,
    risk: "Low",
    owner: "Security Team",
  },
];
const clusterAccounts = new Set(clusterSeed.map((item) => item.account));
const clusters = [
  ...clusterSeed,
  ...accounts
    .filter((account) => !clusterAccounts.has(account.id))
    .map((account, index) => ({
      account: account.id,
      name: `${account.id}-eks`,
      cloud: "AWS",
      version: index % 2 ? "1.31" : "1.32",
      nodes: 6 + index * 2,
      pods: 72 + index * 18,
      issues: 2 + index * 2,
      risk: index % 2 ? "High" : "Medium",
      owner: index % 2 ? "Platform Team" : "Security Team",
    })),
];

export function KubernetesSecurity() {
  const { inScope, scope } = useProduct();
  const palette = useChartPalette();
  const [selected, setSelected] = useState<(typeof clusters)[number] | null>(
    null,
  );
  const workloadName =
    scope === "production"
      ? "payments"
      : scope === "development"
        ? "analytics"
        : scope === "security"
          ? "security-platform"
          : scope.replace(/[^a-z0-9]+/g, "-");
  const topologyNodes: GraphNode[] = [
    {
      id: "ingress",
      kind: "internet",
      name: "Public ingress",
      is_public: true,
      risk_score: 82,
    },
    {
      id: "service",
      kind: "compute",
      name: `${workloadName}-service`,
      asset_type: "Kubernetes service",
      risk_score: 84,
    },
    {
      id: "pod",
      kind: "compute",
      name: `${workloadName}-api-7d9c`,
      asset_type: "Pod",
      risk_score: 92,
    },
    {
      id: "sa",
      kind: "role",
      name: workloadName,
      asset_type: "Service account",
      risk_score: 94,
      properties: { has_admin: true },
    },
    {
      id: "secret",
      kind: "database",
      name: `${workloadName}-db-secret`,
      asset_type: "Kubernetes secret",
      risk_score: 96,
    },
  ];
  const topologyEdges: GraphEdge[] = [
    { source: "ingress", target: "service", type: "EXPOSED_TO" },
    { source: "service", target: "pod", type: "EXPOSED_TO" },
    { source: "pod", target: "sa", type: "CAN_ASSUME" },
    { source: "sa", target: "secret", type: "CAN_ACCESS" },
  ];
  const topologyPaths: AttackRoute[] = [
    {
      id: "k8s-path",
      nodes: topologyNodes.map((n) => n.id),
      length: 5,
      entry: "internet",
      target: `${workloadName}-db-secret`,
      target_kind: "database",
      severity: "critical",
    },
  ];
  const scopedClusters = clusters.filter((cluster) => inScope(cluster.account));
  const visibleCluster = selected && scopedClusters.includes(selected) ? selected : null;
  return (
    <div className="cs-page cs-domain-page">
      <Head title="Kubernetes Security">
        <button className="cs-button primary">
          <Container size={15} />
          Scan clusters
        </button>
      </Head>
      <div className="cs-domain-summary">
        <DomainStat label="Clusters" value={String(scopedClusters.length)} />
        <DomainStat
          label="Critical issues"
          value={String(scopedClusters.filter((cluster) => cluster.risk === "Critical").length)}
          tone="critical"
        />
        <DomainStat
          label="Overprivileged SAs"
          value={String(scopedClusters.reduce((sum, cluster) => sum + Math.ceil(cluster.issues / 2), 0))}
        />
        <DomainStat label="PSS restricted compliance" value={scopedClusters.length ? "78%" : "N/A"} />
      </div>
      <div className="cs-k8s-layout">
        <Panel title="Cluster topology">
          <div className="cs-embedded-graph">
            <GraphCanvas
              nodes={topologyNodes}
              edges={topologyEdges}
              paths={topologyPaths}
              accounts={[]}
              account="all"
              onAccountChange={() => undefined}
            />
          </div>
        </Panel>
        <Panel title="Runtime vs build-time">
          <div className="cs-cnapp-chart">
            <ResponsiveContainer width="100%" height={245}>
              <BarChart
                data={[
                  { name: "Critical", runtime: 4, build: 2 },
                  { name: "High", runtime: 8, build: 11 },
                  { name: "Medium", runtime: 12, build: 17 },
                  { name: "Low", runtime: 6, build: 14 },
                ]}
              >
                <CartesianGrid stroke={palette.grid} vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={{ fill: palette.text, fontSize: 10 }}
                />
                <YAxis tick={{ fill: palette.text, fontSize: 10 }} />
                <ChartTip />
                <Bar dataKey="runtime" stackId="a" fill={palette.critical} />
                <Bar dataKey="build" stackId="a" fill={palette.blue} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="cs-chart-legend">
            <span>
              <i style={{ background: palette.critical }} />
              Runtime
            </span>
            <span>
              <i style={{ background: palette.blue }} />
              Build-time
            </span>
          </div>
        </Panel>
      </div>
      <Panel title="Clusters">
        <Table
          headers={[
            "Cluster",
            "Cloud",
            "Version",
            "Nodes",
            "Pods",
            "Issues",
            "Risk",
            "Owner",
            "",
          ]}
          count={scopedClusters.length}
        >
          {scopedClusters.map((cluster) => (
            <tr key={cluster.name} onClick={() => setSelected(cluster)}>
              <td>
                <button
                  className="cs-resource-button"
                  onClick={() => setSelected(cluster)}
                >
                  <span className="cs-resource">
                    <span className="cs-resource-icon compute">
                      <Container size={16} />
                    </span>
                    <strong>{cluster.name}</strong>
                  </span>
                </button>
              </td>
              <td>{cluster.cloud}</td>
              <td>{cluster.version}</td>
              <td>{cluster.nodes}</td>
              <td>{cluster.pods}</td>
              <td>{cluster.issues}</td>
              <td>
                <Badge kind={cluster.risk}>{cluster.risk}</Badge>
              </td>
              <td>{cluster.owner}</td>
              <td>
                <ArrowUpRight size={14} />
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {visibleCluster && (
        <Overlay drawer title={visibleCluster.name} onClose={() => setSelected(null)}>
          <div className="cs-drawer-stack">
            <div className="cs-kv-grid">
              <div>
                <span>Cloud</span>
                <strong>{visibleCluster.cloud}</strong>
              </div>
              <div>
                <span>Kubernetes</span>
                <strong>{visibleCluster.version}</strong>
              </div>
              <div>
                <span>Nodes</span>
                <strong>{visibleCluster.nodes}</strong>
              </div>
              <div>
                <span>Pods</span>
                <strong>{visibleCluster.pods}</strong>
              </div>
            </div>
            <Panel title="RBAC risk">
              <Notice>
                3 service accounts can read secrets across namespaces. One
                relationship is inferred from incomplete admission evidence.
              </Notice>
            </Panel>
            <Panel title="Security Graph">
              <div className="cs-mini-path">
                <Globe2 size={17} />
                <i />
                <Container size={17} />
                <i />
                <KeyRound size={17} />
              </div>
            </Panel>
          </div>
        </Overlay>
      )}
    </div>
  );
}

const dataStoreSeed = [
  {
    account: "production",
    name: "customer-data-prod",
    type: "S3 bucket",
    class: "PII · PCI",
    exposure: "Public",
    encryption: "SSE-KMS",
    records: "18.4M",
    risk: "Critical",
    owner: "Platform Team",
  },
  {
    account: "production",
    name: "analytics-db-dev",
    type: "RDS PostgreSQL",
    class: "PII",
    exposure: "VPC",
    encryption: "Enabled",
    records: "7.2M",
    risk: "High",
    owner: "Data Engineering",
  },
  {
    account: "development",
    name: "payment-events-dev",
    type: "DynamoDB",
    class: "PCI",
    exposure: "Private",
    encryption: "Enabled",
    records: "3.8M",
    risk: "Medium",
    owner: "Payments Team",
  },
  {
    account: "shared-services",
    name: "audit-archive-shared",
    type: "S3 bucket",
    class: "Security logs",
    exposure: "Private",
    encryption: "SSE-S3",
    records: "980K",
    risk: "Low",
    owner: "Security Team",
  },
  {
    account: "security",
    name: "threat-intel-archive-security",
    type: "S3 bucket",
    class: "Secrets",
    exposure: "Private",
    encryption: "SSE-KMS",
    records: "1.2M",
    risk: "Low",
    owner: "Security Team",
  },
];
const dataStoreAccounts = new Set(dataStoreSeed.map((item) => item.account));
const dataStores = [
  ...dataStoreSeed,
  ...accounts
    .filter((account) => !dataStoreAccounts.has(account.id))
    .flatMap((account, index) =>
      assets
        .filter(
          (asset) => asset.account === account.id && asset.category === "Data",
        )
        .slice(0, 2)
        .map((asset, assetIndex) => ({
          account: account.id,
          name: asset.name,
          type: asset.type,
          class: assetIndex ? "Confidential" : index % 2 ? "PCI" : "PII",
          exposure: asset.exposure === "Public" ? "Public" : "Private",
          encryption: assetIndex ? "Enabled" : "SSE-KMS",
          records: `${2 + index * 3 + assetIndex * 2}.${assetIndex + 1}M`,
          risk: asset.risk,
          owner: asset.owner,
        })),
    ),
];

export function DataSecurityHub() {
  const { inScope, scope } = useProduct();
  const palette = useChartPalette();
  const [selected, setSelected] = useState<(typeof dataStores)[number] | null>(
    null,
  );
  const scopedStores = dataStores.filter((store) => inScope(store.account));
  const visibleStore = selected && scopedStores.includes(selected) ? selected : null;
  const classifications = ["PII", "PCI", "PHI", "Secrets"].map((name) => ({
    name,
    value: scopedStores.filter((store) => store.class.includes(name)).length,
  }));
  return (
    <div className="cs-page cs-domain-page">
      <Head title="Data Security">
        <button className="cs-button">
          <Database size={15} />
          Classification policy
        </button>
      </Head>
      <div className="cs-domain-summary">
        <DomainStat label="Data stores" value={String(scopedStores.length)} />
        <DomainStat label="Sensitive" value={String(scopedStores.filter((store) => store.class !== "Unclassified").length)} />
        <DomainStat
          label="Public sensitive"
          value={String(scopedStores.filter((store) => store.exposure === "Public").length)}
          tone="critical"
        />
        <DomainStat label="Unclassified" value={String(scopedStores.filter((store) => store.class === "Unclassified").length)} />
      </div>
      <div className="cs-visual-grid cs-data-visual">
        <Panel title="Data classification">
          <MiniDonut
            data={classifications}
            colors={[
              palette.critical,
              palette.high,
              palette.medium,
              palette.blue,
              palette.text,
            ]}
          />
        </Panel>
        <Panel title="Geographic data residency">
          <CloudWorldMap dataMode />
        </Panel>
      </div>
      <Panel title="Sensitive data exposure">
        <Table
          headers={[
            "Data store",
            "Type",
            "Classification",
            "Exposure",
            "Encryption",
            "Estimated records",
            "Risk",
            "Owner",
            "",
          ]}
          count={scopedStores.length}
        >
          {scopedStores.map((store) => (
            <tr key={store.name} onClick={() => setSelected(store)}>
              <td>
                <button
                  className="cs-resource-button"
                  onClick={() => setSelected(store)}
                >
                  <strong>{store.name}</strong>
                </button>
              </td>
              <td>{store.type}</td>
              <td>
                <Badge>{store.class}</Badge>
              </td>
              <td>
                <Badge
                  kind={store.exposure === "Public" ? "Critical" : "Healthy"}
                >
                  {store.exposure}
                </Badge>
              </td>
              <td>{store.encryption}</td>
              <td>{store.records}</td>
              <td>
                <Badge kind={store.risk}>{store.risk}</Badge>
              </td>
              <td>{store.owner}</td>
              <td>
                <ArrowUpRight size={14} />
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {visibleStore && (
        <Overlay drawer title={visibleStore.name} onClose={() => setSelected(null)}>
          <div className="cs-drawer-stack">
            <div className="cs-kv-grid">
              <div>
                <span>Classification</span>
                <strong>{visibleStore.class}</strong>
              </div>
              <div>
                <span>Exposure</span>
                <strong>{visibleStore.exposure}</strong>
              </div>
              <div>
                <span>Encryption</span>
                <strong>{visibleStore.encryption}</strong>
              </div>
              <div>
                <span>Records</span>
                <strong>{visibleStore.records}</strong>
              </div>
            </div>
            <Panel title="Security Graph">
              <div className="cs-mini-path">
                <Globe2 size={17} />
                <i />
                <Fingerprint size={17} />
                <i />
                <Database size={17} />
              </div>
            </Panel>
            <Link
              className="cs-button primary"
              to={`/attack-paths/${attackPaths.find((path) => path.account === scope)?.id || ""}`}
            >
              View exposure path
            </Link>
          </div>
        </Overlay>
      )}
    </div>
  );
}

const detections = [
  {
    account: "production",
    time: "08:43:21",
    title: "Credential access followed by unusual S3 enumeration",
    technique: "T1530",
    resource: "payments-api-prod",
    severity: "Critical",
    count: 7,
  },
  {
    account: "production",
    time: "08:31:04",
    title: "Role assumed from new external account",
    technique: "T1078.004",
    resource: "application-role-prod",
    severity: "High",
    count: 3,
  },
  {
    account: "production",
    time: "08:18:39",
    title: "Container executed interactive shell",
    technique: "T1059.004",
    resource: "checkout-worker-7d9c",
    severity: "High",
    count: 1,
  },
  {
    account: "production",
    time: "07:56:12",
    title: "Unusual outbound connection to new ASN",
    technique: "T1041",
    resource: "analytics-worker-prod",
    severity: "Medium",
    count: 12,
  },
  ...accounts
    .filter((account) => account.id !== "production")
    .map((account, index) => ({
      account: account.id,
      time: `${String(7 + index).padStart(2, "0")}:2${index}:10`,
      title: index % 2
        ? "Unusual role assumption from external identity"
        : "Workload contacted a newly observed destination",
      technique: index % 2 ? "T1078.004" : "T1041",
      resource:
        assets.find(
          (asset) => asset.account === account.id && asset.category === "Compute",
        )?.name || account.id,
      severity: index % 3 === 0 ? "High" : "Medium",
      count: 1 + index,
    })),
];

export function ThreatDetectionHub() {
  const { inScope } = useProduct();
  const palette = useChartPalette();
  const [range, setRange] = useState("24H");
  const [selected, setSelected] = useState<(typeof detections)[number] | null>(
    null,
  );
  const scopedDetections = detections.filter((item) => inScope(item.account));
  const trend = Array.from({ length: 12 }, (_, i) => ({
    time: `${String(i * 2).padStart(2, "0")}:00`,
    alerts: [3, 4, 2, 7, 4, 6, 10, 8, 13, 7, 5, 9][i],
  }));
  return (
    <div className="cs-page cs-domain-page">
      <Head title="Threat Detection">
        <div className="cs-segment">
          {["24H", "7D", "30D"].map((item) => (
            <button
              className={range === item ? "active" : ""}
              onClick={() => setRange(item)}
              key={item}
            >
              {item}
            </button>
          ))}
        </div>
      </Head>
      <div className="cs-domain-summary">
        <DomainStat
          label="Open alerts"
          value={String(scopedDetections.reduce((sum, item) => sum + item.count, 0))}
          tone="critical"
        />
        <DomainStat label="Assets involved" value={String(scopedDetections.length)} />
        <DomainStat label="MITRE techniques" value="17" />
        <DomainStat label="Mean triage" value="18m" />
      </div>
      <div className="cs-threat-grid">
        <Panel title="Alert activity">
          <div className="cs-cnapp-chart">
            <ResponsiveContainer width="100%" height={205}>
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1">
                    <stop
                      offset="0"
                      stopColor={palette.critical}
                      stopOpacity={0.35}
                    />
                    <stop
                      offset="1"
                      stopColor={palette.critical}
                      stopOpacity={0}
                    />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={palette.grid} vertical={false} />
                <XAxis
                  dataKey="time"
                  tick={{ fill: palette.text, fontSize: 10 }}
                />
                <YAxis tick={{ fill: palette.text, fontSize: 10 }} />
                <ChartTip />
                <Area
                  dataKey="alerts"
                  stroke={palette.critical}
                  fill="url(#threatFill)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="MITRE ATT&CK coverage">
          <div className="cs-mitre-grid">
            {[
              "Initial Access",
              "Execution",
              "Persistence",
              "Privilege Esc.",
              "Defense Evasion",
              "Credential Access",
              "Discovery",
              "Lateral Movement",
              "Collection",
              "Exfiltration",
            ].map((tactic, index) => (
              <div key={tactic}>
                <span>{tactic}</span>
                {[0, 1, 2, 3].map((cell) => (
                  <i
                    key={cell}
                    style={{
                      opacity: 0.2 + ((index + cell) % 5) * 0.18,
                      background: index < 3 ? palette.critical : palette.high,
                    }}
                    title={`${tactic} activity`}
                  />
                ))}
              </div>
            ))}
          </div>
        </Panel>
      </div>
      <Panel title="Live alert feed">
        <Table
          headers={[
            "Time",
            "Detection",
            "MITRE",
            "Resource",
            "Events",
            "Severity",
            "",
          ]}
          count={scopedDetections.length}
        >
          {scopedDetections.map((item) => (
            <tr key={item.time} onClick={() => setSelected(item)}>
              <td>
                <span className="cs-live-dot" />
                {item.time}
              </td>
              <td>
                <button
                  className="cs-resource-button"
                  onClick={() => setSelected(item)}
                >
                  <strong>{item.title}</strong>
                </button>
              </td>
              <td>
                <Badge>{item.technique}</Badge>
              </td>
              <td>{item.resource}</td>
              <td>{item.count}</td>
              <td>
                <Badge kind={item.severity}>{item.severity}</Badge>
              </td>
              <td>
                <ArrowUpRight size={14} />
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {selected && (
        <Overlay
          drawer
          title={selected.title}
          onClose={() => setSelected(null)}
        >
          <div className="cs-drawer-stack">
            <Badge kind={selected.severity}>{selected.severity}</Badge>
            <Panel title="Observed sequence">
              <div className="cs-timeline">
                <span>
                  <i />
                  08:41 · sts:AssumeRole
                </span>
                <span>
                  <i />
                  08:42 · s3:ListAllMyBuckets
                </span>
                <span>
                  <i />
                  08:43 · s3:GetObject burst
                </span>
              </div>
            </Panel>
            <Panel title="Anomaly graph">
              <div className="cs-mini-path">
                <Fingerprint size={17} />
                <i />
                <KeyRound size={17} />
                <i />
                <Database size={17} />
              </div>
            </Panel>
            <button className="cs-button primary">Start investigation</button>
          </div>
        </Overlay>
      )}
    </div>
  );
}

const repositories = [
  {
    name: "payments-platform",
    provider: "GitHub",
    branch: "main",
    iac: 9,
    secrets: 2,
    pipeline: "BLOCK",
    last: "6 min ago",
    owner: "Payments Team",
  },
  {
    name: "customer-data-infra",
    provider: "GitLab",
    branch: "production",
    iac: 4,
    secrets: 0,
    pipeline: "WARN",
    last: "18 min ago",
    owner: "Platform Team",
  },
  {
    name: "shared-services",
    provider: "GitHub",
    branch: "main",
    iac: 1,
    secrets: 0,
    pipeline: "PASS",
    last: "43 min ago",
    owner: "Cloud Operations",
  },
];

export function CodeSecurityHub() {
  const palette = useChartPalette();
  const [selected, setSelected] = useState<
    (typeof repositories)[number] | null
  >(null);
  const trend = Array.from({ length: 10 }, (_, i) => ({
    day: `Aug ${28 + i}`,
    opened: [8, 6, 7, 11, 9, 8, 6, 5, 4, 3][i],
    fixed: [2, 4, 3, 5, 7, 6, 9, 8, 7, 10][i],
  }));
  return (
    <div className="cs-page cs-domain-page">
      <Head title="Code Security">
        <button className="cs-button primary">
          <GitBranch size={15} />
          Connect repository
        </button>
      </Head>
      <div className="cs-domain-summary">
        <DomainStat label="Repositories" value="18" />
        <DomainStat
          label="IaC issues"
          value="47"
          tone="critical"
        />
        <DomainStat label="Secrets" value="6" tone="critical" />
        <DomainStat label="Blocked builds · 24h" value="4" />
      </div>
      <div className="cs-visual-grid">
        <Panel title="Pipeline risk trend">
          <div className="cs-cnapp-chart">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={trend}>
                <CartesianGrid stroke={palette.grid} vertical={false} />
                <XAxis
                  dataKey="day"
                  tick={{ fill: palette.text, fontSize: 10 }}
                />
                <YAxis tick={{ fill: palette.text, fontSize: 10 }} />
                <ChartTip />
                <Area
                  dataKey="opened"
                  stroke={palette.critical}
                  fill={palette.critical}
                  fillOpacity={0.1}
                />
                <Area
                  dataKey="fixed"
                  stroke={palette.green}
                  fill={palette.green}
                  fillOpacity={0.08}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Code-to-cloud traceability">
          <div className="cs-code-trace">
            <span>
              <GitBranch size={17} />
              <b>payments-platform</b>
              <small>main</small>
            </span>
            <i />
            <span>
              <FileCode2 size={17} />
              <b>modules/api/main.tf</b>
              <small>line 84</small>
            </span>
            <i />
            <span>
              <Cloud size={17} />
              <b>payments-api-prod</b>
              <small>ap-south-1</small>
            </span>
            <i />
            <span className="risk">
              <ShieldAlert size={17} />
              <b>4 issues</b>
              <small>1 critical</small>
            </span>
          </div>
        </Panel>
      </div>
      <Panel title="Repositories and pipelines">
        <Table
          headers={[
            "Repository",
            "Provider",
            "Branch",
            "IaC issues",
            "Secrets",
            "Pipeline",
            "Last scan",
            "Owner",
            "",
          ]}
          count={repositories.length}
        >
          {repositories.map((repo) => (
            <tr key={repo.name} onClick={() => setSelected(repo)}>
              <td>
                <button
                  className="cs-resource-button"
                  onClick={() => setSelected(repo)}
                >
                  <span className="cs-resource">
                    <span className="cs-resource-icon management">
                      <Code2 size={16} />
                    </span>
                    <strong>{repo.name}</strong>
                  </span>
                </button>
              </td>
              <td>{repo.provider}</td>
              <td>
                <code>{repo.branch}</code>
              </td>
              <td>{repo.iac}</td>
              <td>{repo.secrets}</td>
              <td>
                <Badge kind={repo.pipeline}>{repo.pipeline}</Badge>
              </td>
              <td>{repo.last}</td>
              <td>{repo.owner}</td>
              <td>
                <ArrowUpRight size={14} />
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {selected && (
        <Overlay drawer title={selected.name} onClose={() => setSelected(null)}>
          <div className="cs-drawer-stack">
            <div className="cs-kv-grid">
              <div>
                <span>Provider</span>
                <strong>{selected.provider}</strong>
              </div>
              <div>
                <span>Branch</span>
                <strong>{selected.branch}</strong>
              </div>
              <div>
                <span>IaC issues</span>
                <strong>{selected.iac}</strong>
              </div>
              <div>
                <span>Secrets</span>
                <strong>{selected.secrets}</strong>
              </div>
            </div>
            <Panel title="Code-to-cloud">
              <div className="cs-mini-path">
                <GitBranch size={17} />
                <i />
                <FileCode2 size={17} />
                <i />
                <Cloud size={17} />
              </div>
            </Panel>
            <Link className="cs-button primary" to="/iac">
              Open IaC results <ExternalLink size={14} />
            </Link>
          </div>
        </Overlay>
      )}
    </div>
  );
}

export function DomainUnavailable({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="cs-page">
      <Head title={title} />
      <Empty
        title="No evidence collected"
        text="Connect supported sources and run collection. Missing evidence remains Unknown."
      />
      {children}
    </div>
  );
}
