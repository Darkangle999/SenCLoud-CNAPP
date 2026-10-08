import { useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, ArrowUpRight, Crosshair, FileText, GitBranch, Globe2, Maximize2, Minus, Plus, Search, ShieldAlert, X } from "lucide-react";
import { AwsResourceIcon } from "./AwsResourceIcon";
import { Badge, download } from "./ui";
import "./attack-path-workspace.css";

export interface PathEntity {
  id: string;
  name: string;
  type: string;
  service?: string;
  state: string;
  relationship?: string;
  evidence?: string;
  href?: string;
}

export interface PathRecord {
  id: string;
  title: string;
  severity: string;
  risk: number;
  confidence: number;
  state: string;
  account: string;
  nodes: PathEntity[];
  href?: string;
}

const stateLabel = (state: string) => state === "Missing" ? "Unverified" : state;
const severityLabel = (value: string) => value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();

export function PathEntityIcon({ node, size = 28 }: { node: PathEntity; size?: number }) {
  return /^(Internet|External)$/i.test(node.type)
    ? <Globe2 size={size} />
    : <AwsResourceIcon service={node.service || node.type} type={node.type} size={size} />;
}

export function AttackPathCanvas({ path }: { path: PathRecord }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [expanded, setExpanded] = useState(false);
  const drag = useRef<{ x: number; y: number; originX: number; originY: number } | null>(null);
  const svg = useRef<SVGSVGElement>(null);
  const marker = useId().replace(/:/g, "");
  const width = Math.max(760, path.nodes.length * 164 + 64);
  const positions = path.nodes.map((_, index) => ({
    x: path.nodes.length === 1 ? width / 2 : 86 + index * (width - 172) / (path.nodes.length - 1),
    y: index % 2 === 0 ? 140 : 210,
  }));
  const active = path.nodes.find((node) => node.id === selected);
  function fit() { setZoom(1); setPan({ x: 0, y: 0 }); }
  return (
    <section className={`ap-canvas-shell ${expanded ? "is-expanded" : ""}`} aria-label="Attack path graph" onKeyDown={(event) => { if (event.key === "Escape") setExpanded(false); }}>
      <div className="ap-graph-toolbar"><span><i className="ap-line-key" />Observed <i className="ap-line-key uncertain" />Unverified</span><div>
        <button aria-label="Zoom out" disabled={zoom <= .6} onClick={() => setZoom((value) => Math.max(.6, value - .2))}><Minus size={15} /></button>
        <output aria-label="Graph zoom">{Math.round(zoom * 100)}%</output>
        <button aria-label="Zoom in" disabled={zoom >= 2.4} onClick={() => setZoom((value) => Math.min(2.4, value + .2))}><Plus size={15} /></button>
        <button aria-label="Fit graph" onClick={fit}><Crosshair size={16} /></button>
        <button aria-label={expanded ? "Restore graph" : "Expand graph"} aria-pressed={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? <X size={16} /> : <Maximize2 size={16} />}</button>
      </div></div>
      <div className="ap-canvas">
        <svg ref={svg} viewBox={`0 0 ${width} 380`} aria-label={`${path.title} relationships`} role="group"
          onPointerDown={(event) => {
            if ((event.target as Element).closest("button")) return;
            drag.current = { x: event.clientX, y: event.clientY, originX: pan.x, originY: pan.y };
            event.currentTarget.setPointerCapture(event.pointerId);
          }}
          onPointerMove={(event) => {
            if (!drag.current || !svg.current) return;
            const factor = width / svg.current.getBoundingClientRect().width;
            setPan({ x: drag.current.originX + (event.clientX - drag.current.x) * factor, y: drag.current.originY + (event.clientY - drag.current.y) * factor });
          }}
          onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }}>
          <defs>
            <pattern id={`${marker}-dots`} width="22" height="22" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="var(--ap-dot)" /></pattern>
            <marker id={`${marker}-arrow`} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8" fill="var(--ap-edge)" /></marker>
          </defs>
          <rect width={width} height="380" fill={`url(#${marker}-dots)`} />
          <g transform={`translate(${pan.x + (1-zoom)*width/2} ${pan.y + (1-zoom)*190}) scale(${zoom})`}>
            {path.nodes.slice(0, -1).map((node, index) => {
              const target = path.nodes[index + 1];
              const start = positions[index]; const end = positions[index + 1];
              const verified = node.state === "Verified" && target.state === "Verified" && Boolean(node.relationship);
              return <g key={`${node.id}-${target.id}`} className={`ap-relationship ${verified ? "verified" : "uncertain"}`}>
                <path d={`M${start.x+29} ${start.y} C${(start.x+end.x)/2} ${start.y},${(start.x+end.x)/2} ${end.y},${end.x-35} ${end.y}`} markerEnd={`url(#${marker}-arrow)`} />
                <text x={(start.x+end.x)/2} y={(start.y+end.y)/2-18} textAnchor="middle">{(node.relationship || "Unverified").slice(0, 24)}<title>{node.relationship || "Relationship evidence unavailable"}</title></text>
              </g>;
            })}
            {path.nodes.map((node, index) => {
              const position = positions[index];
              return <g key={node.id}>
                <text className={`ap-stage ${index === path.nodes.length-1 ? "target" : ""}`} x={position.x} y={position.y-52} textAnchor="middle">{index === 0 ? "ENTRY POINT" : index === path.nodes.length-1 ? "TARGET" : ""}</text>
                <foreignObject x={position.x-79} y={position.y-32} width="158" height="126">
                  <button className={`ap-canvas-node ${selected === node.id ? "selected" : ""} ${index === path.nodes.length-1 ? "target" : ""}`} aria-label={`Inspect ${node.name}`} aria-pressed={selected === node.id} onClick={() => setSelected(node.id)}>
                    <span className="ap-node-icon"><PathEntityIcon node={node} size={34} /><i className={node.state === "Verified" ? "verified" : "uncertain"} /></span>
                    <strong title={node.name}>{node.name}</strong><small>{node.type}</small>
                  </button>
                </foreignObject>
              </g>;
            })}
          </g>
        </svg>
      </div>
      <div className="ap-inspector" aria-live="polite">
        {active ? <><span className="ap-inspector-icon"><PathEntityIcon node={active} size={27} /></span><div><strong>{active.name}</strong><span>{active.type}</span></div><Badge>{stateLabel(active.state)}</Badge>{active.href && <Link className="ap-node-link" to={active.href} aria-label={`Open ${active.name}`}><ArrowUpRight size={16} /></Link>}</> : <><GitBranch size={17} /><strong>{path.nodes.length} entities</strong><span>{Math.max(0, path.nodes.length-1)} relationships</span><Badge>{stateLabel(path.state)}</Badge></>}
      </div>
      {active?.evidence && <dl className="ap-observation"><dt>Observed evidence</dt><dd>{active.evidence}</dd></dl>}
    </section>
  );
}

export function AttackPathWorkspace({ paths, onInspect, mode = "demo", loading = false, error, actions }: {
  paths: PathRecord[];
  onInspect?: (path: PathRecord) => void;
  mode?: "demo" | "live";
  loading?: boolean;
  error?: string | null;
  actions?: React.ReactNode;
}) {
  const [view, setView] = useState("Graph");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const rows = paths.filter((path) => (severity === "all" || path.severity.toLowerCase() === severity) && `${path.id} ${path.title} ${path.nodes.map((node) => node.name).join(" ")}`.toLowerCase().includes(query.toLowerCase()));
  const selected = rows.find((path) => path.id === selectedId) || rows[0];
  return (
    <div className="cs-page ap-workspace" aria-busy={loading}>
      <header className="cs-head"><div><h1>Attack Paths</h1></div><div className="cs-actions"><button className="cs-button" onClick={() => download(`attack-paths-${mode}.json`, JSON.stringify({ mode, paths: rows }, null, 2), "application/json")}><FileText size={15} />Export</button>{actions}</div></header>
      <div className="ap-metrics">{[
        ["Open paths", paths.length], ["Critical", paths.filter((path) => path.severity.toLowerCase() === "critical").length],
        ["Affected resources", new Set(paths.flatMap((path) => path.nodes.filter((node) => !/^(Internet|External)$/i.test(node.type)).map((node) => node.id))).size],
        ["Unverified", paths.filter((path) => path.state !== "Verified").length],
      ].map(([label, value]) => <div key={label}><span>{label}</span><strong>{loading || error && !paths.length ? "—" : value}</strong></div>)}</div>
      <div className="ap-controls"><label className="ap-search"><Search size={15} /><input aria-label="Search attack paths" placeholder="Search attack paths" value={query} onChange={(event) => setQuery(event.target.value)} /></label><select aria-label="Attack path severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{severityLabel(value)}</option>)}</select><span className="ap-result-count">{rows.length} paths</span><div className="cs-segment">{["List", "Graph"].map((item) => <button key={item} className={view === item ? "active" : ""} aria-pressed={view === item} onClick={() => setView(item)}>{item === "List" ? <FileText size={14} /> : <GitBranch size={14} />}{item}</button>)}</div></div>
      {error && <div className="ap-error" role="alert"><ShieldAlert size={17} />{error}</div>}
      {!rows.length ? <div className="ap-empty"><GitBranch size={34} /><h2>{loading ? "Loading attack paths…" : error ? "Attack paths unavailable" : "No matching paths"}</h2></div> : view === "List" ? (
        <section className="ap-list-table"><table><thead><tr><th>Risk</th><th>Attack path</th><th>Target</th><th>Severity</th><th>Entities</th><th>Evidence</th><th /></tr></thead><tbody>{rows.map((path) => <tr key={path.id}><td><b className="ap-risk">{Math.round(path.risk)}</b></td><td><button className="ap-title-button" onClick={() => { setSelectedId(path.id); setView("Graph"); }}>{path.title}</button><small>{path.id}</small></td><td>{path.nodes[path.nodes.length-1]?.name}</td><td><Badge>{severityLabel(path.severity)}</Badge></td><td>{path.nodes.length}</td><td><Badge>{stateLabel(path.state)}</Badge></td><td>{path.href ? <Link to={path.href} aria-label={`Investigate ${path.id}`}><ArrowUpRight size={16} /></Link> : <button className="ap-icon-button" aria-label={`Investigate ${path.id}`} onClick={() => onInspect?.(path)}><ArrowUpRight size={16} /></button>}</td></tr>)}</tbody></table></section>
      ) : (
        <section className="ap-investigation"><aside className="ap-path-queue" aria-label="Attack path queue"><div className="ap-queue-head"><strong>Risk queue</strong><Badge>{mode === "demo" ? "Demo" : "Live"}</Badge></div>{rows.map((path) => <button key={path.id} className={`ap-path-option ${selected?.id === path.id ? "selected" : ""}`} aria-pressed={selected?.id === path.id} onClick={() => setSelectedId(path.id)}><span className="ap-option-head"><Badge>{severityLabel(path.severity)}</Badge><b>{Math.round(path.risk)}</b></span><strong>{path.title}</strong><span className="ap-option-icons">{path.nodes.slice(0, 4).map((node, index) => <span key={node.id}>{index > 0 && <ArrowRight size={11} />}<PathEntityIcon node={node} size={20} /></span>)}{path.nodes.length > 4 && <small>+{path.nodes.length-4}</small>}</span><span className="ap-option-meta"><span>{path.id}</span><span>{Math.round(path.confidence)}% confidence</span></span></button>)}</aside>
          {selected && <div className="ap-investigation-main"><div className="ap-selected-head"><div><span>{selected.id} · {selected.account}</span><h2>{selected.title}</h2><div><Badge>{severityLabel(selected.severity)}</Badge><Badge>{stateLabel(selected.state)}</Badge><span>{Math.round(selected.confidence)}% confidence</span></div></div>{selected.href ? <Link className="cs-button" to={selected.href}>Investigate <ArrowUpRight size={14} /></Link> : onInspect && <button className="cs-button" onClick={() => onInspect(selected)}>Evidence <ArrowUpRight size={14} /></button>}</div><AttackPathCanvas key={selected.id} path={selected} /></div>}
        </section>
      )}
    </div>
  );
}
