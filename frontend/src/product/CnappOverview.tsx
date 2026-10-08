import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, Box, Check,
  ChevronRight, CircleAlert, Cloud, Database, Fingerprint, Globe2,
  Layers3, Network, RefreshCw, ScanLine, ShieldCheck, ShieldAlert,
} from "lucide-react";
import { Pie, PieChart, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { Badge } from "./ui";
import { AwsResourceIcon } from "./AwsResourceIcon";
import type { DashboardModel, DashboardGraphNode } from "./dashboard-model";
import "./cnapp-overview.css";

const domainMeta = {
  CSPM: { title: "Cloud posture", icon: ShieldCheck, href: "/cloud-configuration" },
  DSPM: { title: "Data security", icon: Database, href: "/data" },
  CIEM: { title: "Identity & access", icon: Fingerprint, href: "/identities" },
  CWPP: { title: "Workload protection", icon: Box, href: "/vulnerabilities" },
};
const number = (value: number | null) => value === null ? "—" : value.toLocaleString();
const severityColor = (label: string) => `var(--ov-${label.toLowerCase()})`;
const statusText = {
  ready: "Evidence available", loading: "Collecting evidence", empty: "Awaiting evidence",
  error: "Source unavailable", partial: "Partial evidence",
};

function nodeIcon(kind: string) {
  if (/internet|external/i.test(kind)) return Globe2;
  if (/identity|role|user/i.test(kind)) return Fingerprint;
  if (/bucket|data|storage/i.test(kind)) return Database;
  if (/finding|issue|security/i.test(kind)) return ShieldAlert;
  return Box;
}

function GraphPreview({ graph }: { graph: DashboardModel["graph"] }) {
  const [selected, setSelected] = useState<string | null>(null);
  // This is a bounded view of observed entities, never a generated attack path.
  const nodes = graph.nodes.slice(0, 7);
  const positions = [[78, 160], [290, 65], [290, 245], [492, 158], [702, 65], [702, 245], [492, 285]];
  const placed = new Map(nodes.map((node, index) => [node.id, positions[index]]));
  const edges = graph.edges.filter((edge) => placed.has(edge.source) && placed.has(edge.target));
  const selectedNode = nodes.find((node) => node.id === selected);
  const inspect = (node: DashboardGraphNode) => setSelected(node.id);
  return (
    <section className="ov-card ov-graph" aria-label="Cloud security relationships">
      <div className="ov-card-head">
        <div><h2>Security graph</h2></div>
        <Link className="ov-text-link" to="/security-graph">Explore graph <ArrowUpRight size={15} /></Link>
      </div>
      <div className="ov-graph-stats">
        <span><strong>{number(graph.totalNodes)}</strong> entities</span>
        <span><strong>{number(graph.totalEdges)}</strong> relationships</span>
        <span><strong>{number(graph.paths)}</strong> attack paths</span>
      </div>
      {nodes.length ? (
        <div className="ov-network-canvas">
          <svg viewBox="0 0 800 360" aria-label="Observed cloud resource relationships" role="group">
            <defs>
              <pattern id="overview-grid" width="24" height="24" patternUnits="userSpaceOnUse">
                <circle cx="1" cy="1" r="1" fill="var(--ov-graph-dot)" />
              </pattern>
              <marker id="overview-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
                <path d="M0 0 L7 3.5 L0 7" fill="var(--ov-graph-edge)" />
              </marker>
            </defs>
            <rect width="800" height="360" fill="url(#overview-grid)" />
            {edges.map((edge, index) => {
              const [x1, y1] = placed.get(edge.source)!;
              const [x2, y2] = placed.get(edge.target)!;
              const connected = edge.source === selected || edge.target === selected;
              return (
                <g key={`${edge.source}-${edge.target}-${index}`} className={connected ? "is-selected" : ""}>
                  <path className="ov-network-edge" d={`M${x1} ${y1} C${(x1+x2)/2} ${y1}, ${(x1+x2)/2} ${y2}, ${x2} ${y2}`} markerEnd="url(#overview-arrow)" />
                  <title>{edge.label}</title>
                  {connected && <text className="ov-edge-label" x={(x1+x2)/2} y={(y1+y2)/2-8} textAnchor="middle">{edge.label.replace(/_/g, " ").slice(0, 24)}</text>}
                </g>
              );
            })}
            {nodes.map((node) => {
              const [x, y] = placed.get(node.id)!;
              const Icon = nodeIcon(node.kind);
              return (
                <foreignObject key={node.id} x={x-65} y={y-31} width="130" height="85">
                  <button className={`ov-network-node ${selected === node.id ? "is-selected" : ""}`} onClick={() => inspect(node)} aria-label={`Inspect ${node.label}`} aria-pressed={selected === node.id}>
                    <span>{/internet|external|finding|issue/i.test(node.kind) ? <Icon size={21} aria-hidden="true" /> : <AwsResourceIcon service={node.kind} type={node.detail} size={30} />}</span>
                    <strong title={node.label}>{node.label}</strong>
                    <small>{node.kind.replace(/_/g, " ")}</small>
                  </button>
                </foreignObject>
              );
            })}
          </svg>
        </div>
      ) : (
        <div className="ov-graph-empty">
          <div className="ov-empty-orbit"><Network size={32} /></div>
          <h3>{graph.status === "loading" ? "Loading graph…" : graph.status === "error" ? "Graph unavailable" : "No graph data"}</h3>
          <Link className="ov-text-link" to="/accounts">Manage cloud accounts <ArrowRight size={15} /></Link>
        </div>
      )}
      <div className="ov-graph-inspector" aria-live="polite">
        {selectedNode ? <><span className="ov-inspector-icon"><Layers3 size={16} /></span><div><strong>{selectedNode.label}</strong><small>{selectedNode.kind}</small></div>{selectedNode.href && <Link aria-label={`Open ${selectedNode.label}`} to={selectedNode.href}><ArrowUpRight size={17} /></Link>}</> : <><span className="ov-live-dot" /><div><strong>{statusText[graph.status]}</strong></div><span className="ov-subtle">{nodes.length} entities shown</span></>}
      </div>
    </section>
  );
}

export function CnappOverview({ model, onRefresh, onScan, scanning = false, message, canScan = false }: {
  model: DashboardModel;
  onRefresh?: () => void;
  onScan?: () => void;
  scanning?: boolean;
  message?: string | null;
  canScan?: boolean;
}) {
  const [priority, setPriority] = useState("all");
  const [exported, setExported] = useState(false);
  const severe = model.severity.filter((item) => ["Critical", "High"].includes(item.label)).reduce((total, item) => total + item.count, 0);
  const visibleFindings = model.findings.filter((finding) => priority === "all" || finding.severity === priority);
  const critical = model.severity.find((item) => item.label === "Critical")?.count ?? 0;
  const shownSeverities = model.severity.filter((item) => item.count > 0);
  const distributionTotal = model.distribution.reduce((sum, item) => sum + item.count, 0);
  const scoreTone = model.score === null ? "neutral" : model.score < 70 ? "warning" : "good";
  const icons = [Cloud, ShieldAlert, Globe2];
  function exportOverview() {
    const payload = { ...model, exportedAt: new Date().toISOString(), scope: model.scopeLabel };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `cloudsentinel-${model.mode}-overview.json`;
    link.click();
    URL.revokeObjectURL(url);
    setExported(true);
  }
  return (
    <div className="cs-page cs-dashboard ov-dashboard" aria-busy={model.status === "loading"}>
      <header className="ov-page-head">
        <div><h1>Security Posture</h1></div>
        <div className="ov-header-actions">
          <button className="ov-button" onClick={exportOverview}><ArrowDownToLine size={15} />{exported ? "Report exported" : "Export report"}</button>
          {onScan && canScan ? <button className="ov-button ov-button-primary" onClick={onScan} disabled={scanning}><ScanLine size={16} className={scanning ? "cs-spin" : ""} />{scanning ? "Scan in progress…" : "Run scan"}</button> : <Link className="ov-button ov-button-primary" to="/accounts"><Cloud size={16} />Connect cloud</Link>}
        </div>
      </header>

      <div className="ov-scope-bar">
        <div className="cs-dashboard-entitlements"><span className={`ov-mode ${model.mode}`}><span />{model.mode === "demo" ? "DEMO WORKSPACE" : "LIVE ENVIRONMENT"}</span><strong>{model.workspace}</strong>{(model.services.length === 4 ? ["CNAPP"] : model.services).map((service) => <Badge key={service}>{service}</Badge>)}</div>
        <div className="ov-scope-right"><span>{model.scopeLabel}</span>{onRefresh && <button onClick={onRefresh} className="ov-icon-button" aria-label="Refresh dashboard"><RefreshCw size={14} /></button>}</div>
      </div>
      {(message || exported) && <div className="ov-feedback" role="status">{message || "Overview exported with scope and evidence status."}</div>}
      {model.errors.length > 0 && <div className="ov-error" role="alert"><CircleAlert size={18} /><div><strong>Some evidence is unavailable</strong><p>{model.errors.join(" · ")}</p></div>{onRefresh && <button className="ov-button" onClick={onRefresh}>Retry</button>}</div>}

      <section className="ov-metrics" aria-label="Security overview">
        <article className={`ov-score-card ${scoreTone}`}>
          <div><span className="ov-metric-label">Security posture score</span><div className="ov-score-number">{number(model.score)}<small>/100</small></div><span className="ov-score-state"><span />{model.scoreLabel}</span></div>
          <svg className="ov-score-gauge" viewBox="0 0 100 100" role="img" aria-label={`Security posture score ${model.score ?? "unknown"} out of 100`}>
            <circle cx="50" cy="50" r="40" className="ov-gauge-track" /><circle cx="50" cy="50" r="40" className="ov-gauge-fill" strokeDasharray={`${(model.score ?? 0)*2.513} 251.3`} transform="rotate(-90 50 50)" />
            <ShieldCheck x="35" y="35" width="30" height="30" />
          </svg>
        </article>
        {model.metrics.map((metric, index) => {
          const Icon = icons[index % icons.length];
          return <Link className="ov-metric-card" to={metric.href} key={metric.label}><div><span className="ov-metric-label">{metric.label}</span><span className={`ov-metric-icon tone-${index}`}><Icon size={18} /></span></div><strong>{number(metric.value)}</strong><div className="ov-metric-bottom"><ArrowUpRight size={15} /></div></Link>;
        })}
      </section>

      <div className="ov-primary-grid">
        <GraphPreview key={`${model.mode}-${model.workspace}-${model.scopeLabel}`} graph={model.graph} />
        <section className="ov-card ov-priority-brief">
          <div className="ov-card-head"><h2>Priority risks</h2><span className="ov-brief-icon"><ShieldAlert size={20} /></span></div>
          <div className="ov-focus-number"><strong>{model.findingsTotal === null ? "—" : number(severe)}</strong><div><b>high-impact findings</b><span>{model.findingsTotal === null ? "Awaiting severity breakdown" : `${critical} critical · ${severe-critical} high severity`}</span></div></div>
          <div className="ov-focus-list">{model.findings.slice(0, 3).map((finding, index) => <Link key={finding.id} to={finding.href}><span className="ov-focus-index">0{index+1}</span><div><strong>{finding.title}</strong><small>{finding.resource}</small></div><ChevronRight size={16} /></Link>)}</div>
          {!model.findings.length && <div className="ov-calm-state"><ShieldCheck size={22} /><span>{model.findingsTotal === null ? "Awaiting finding evidence" : model.findingsTotal === 0 ? "No open findings" : "Priority details unavailable"}</span></div>}
          <Link className="ov-brief-link" to="/findings">Open risk center <ArrowRight size={16} /></Link>
        </section>
      </div>

      <section aria-labelledby="ov-domain-title" className="ov-domain-section">
        <div className="ov-section-heading"><h2 id="ov-domain-title">Security health</h2></div>
        <div className="ov-domain-grid">{model.domains.map((domain) => {
          const meta = domainMeta[domain.service];
          return <Link to={domain.href || meta.href} className={`ov-domain-card domain-${domain.service.toLowerCase()}`} key={domain.service}><div className="ov-domain-title"><span><meta.icon size={18} /></span><h3>{meta.title}</h3><ArrowUpRight size={15} /></div><div className="ov-domain-value"><strong>{number(domain.value)}</strong><span>{domain.label}</span></div><div className={`ov-source-state state-${domain.status}`}><span />{statusText[domain.status]}</div></Link>;
        })}</div>
      </section>

      <div className="ov-secondary-grid">
        <section className="ov-card ov-risk-chart"><div className="ov-card-head"><h2>Issues by severity</h2><span className="ov-subtle">Current scope</span></div><div className="ov-donut-layout"><div className="ov-donut"><ResponsiveContainer width="100%" height={180}><PieChart><Pie data={shownSeverities.length ? shownSeverities : [{ label: "empty", count: 1 }]} dataKey="count" nameKey="label" innerRadius={61} outerRadius={77} paddingAngle={shownSeverities.length ? 4 : 0} strokeWidth={0} isAnimationActive={false}>{(shownSeverities.length ? shownSeverities : [{ label: "empty" }]).map((item) => <Cell key={item.label} fill={item.label === "empty" ? "var(--ov-divider)" : severityColor(item.label)} />)}</Pie>{shownSeverities.length > 0 && <Tooltip contentStyle={{ background: "var(--ov-card)", borderColor: "var(--ov-divider)", borderRadius: 10, color: "var(--ov-text)" }} />}</PieChart></ResponsiveContainer><div className="ov-donut-total"><strong>{number(model.findingsTotal)}</strong><span>active findings</span></div></div><div className="ov-severity-legend">{model.severity.map((item) => <Link key={item.label} to={`/findings?severity=${model.mode === "demo" ? item.label : item.label.toLowerCase()}`}><span style={{ background: severityColor(item.label) }} />{item.label}<strong>{model.findingsTotal === null ? "—" : number(item.count)}</strong></Link>)}</div></div></section>
        <section className="ov-card ov-distribution"><div className="ov-card-head"><h2>Resource landscape</h2><Link className="ov-text-link" to="/inventory">Inventory <ArrowUpRight size={14} /></Link></div><div className="ov-distribution-body">{model.distribution.filter((item) => item.count > 0).slice(0, 6).map((item, index) => <div className="ov-distribution-row" key={item.label}><span>{item.label}</span><div><i className={`ov-category-${index}`} style={{ width: `${distributionTotal ? item.count/distributionTotal*100 : 0}%` }} /></div><strong>{number(item.count)}</strong></div>)}{!distributionTotal && <div className="ov-small-empty"><Layers3 size={24} /><p>Resource types appear after discovery.</p></div>}</div></section>
        <section className="ov-card ov-coverage"><div className="ov-card-head"><h2>Evidence coverage</h2><Activity size={17} /></div><div className="ov-coverage-list">{model.coverage.map((item) => <div key={item.label}><span className={`ov-coverage-icon state-${item.status}`}>{item.status === "ready" ? <Check size={13} /> : <CircleAlert size={13} />}</span><span>{item.label}</span><strong>{item.value}</strong></div>)}</div><Link className="ov-coverage-link" to="/accounts">Manage connections <ArrowRight size={14} /></Link></section>
      </div>

      <section className="ov-card ov-priority-table" aria-labelledby="ov-findings-title">
        <div className="ov-card-head"><h2 id="ov-findings-title">Priority findings</h2><label className="ov-filter"><ShieldAlert size={14} /><select aria-label="Priority severity" value={priority} onChange={(event) => setPriority(event.target.value)}><option value="all">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></label></div>
        <div className="ov-table-scroll"><table><thead><tr><th>Finding</th><th>Severity</th><th>Resource</th><th>Risk score</th><th><span className="sr-only">Investigation</span></th></tr></thead><tbody>{visibleFindings.slice(0, 6).map((finding) => <tr key={finding.id}><td><Link to={finding.href}>{finding.title}</Link><small>{finding.context}</small></td><td><Badge>{finding.severity}</Badge></td><td><span className="ov-resource-name"><Box size={13} />{finding.resource}</span></td><td><span className="ov-risk-value">{finding.score}<i><span style={{ width: `${Math.min(100, Math.max(0, finding.score))}%`, background: severityColor(finding.severity) }} /></i></span></td><td><Link aria-label={`Investigate ${finding.title}`} to={finding.href}><ArrowUpRight size={16} /></Link></td></tr>)}</tbody></table></div>
        {!visibleFindings.length && <div className="ov-table-empty"><ShieldCheck size={20} /><span>{model.status === "loading" ? "Loading findings…" : model.findingsTotal === null ? "Finding evidence is not available yet." : "No findings match this preview."}</span></div>}
        <div className="ov-table-footer"><span>{Math.min(6, visibleFindings.length)} shown · {number(model.findingsTotal)} active findings in scope</span><Link className="ov-text-link" to="/findings">View all findings <ArrowRight size={14} /></Link></div>
      </section>
      <div className="ov-evidence-footer"><span><ShieldCheck size={13} />{model.mode === "demo" ? "Isolated demo evidence" : "Connected cloud evidence"}</span><span>{model.snapshot ? `Snapshot · ${new Date(model.snapshot).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}` : "Awaiting first scan"}</span></div>
    </div>
  );
}
