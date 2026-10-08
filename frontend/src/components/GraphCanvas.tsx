import * as dagre from '@dagrejs/dagre'
import { motion } from 'motion/react'
import {
  AlertTriangle,
  Crown,
  Database,
  ExternalLink,
  Globe,
  HardDrive,
  KeyRound,
  ListTree,
  Maximize2,
  Minus,
  Plus,
  Server,
  Shield,
  Users,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { NodeIcon } from '../lib/awsIcons'
import type { AttackRoute, GraphEdge, GraphKind, GraphNode, Severity } from '../types'

export const KIND_ICON: Record<GraphKind, typeof Globe> = {
  internet: Globe,
  external: Users,
  user: Users,
  compute: Server,
  security_group: Shield,
  role: KeyRound,
  bucket: HardDrive,
  database: Database,
  finding: AlertTriangle,
}

const KIND_LABEL: Record<GraphKind, string> = {
  internet: 'Internet',
  external: 'External principal',
  user: 'IAM user',
  compute: 'Compute',
  security_group: 'Security group',
  role: 'IAM role',
  bucket: 'S3 bucket',
  database: 'Database',
  finding: 'Finding',
}

export const KIND_COLOR: Record<GraphKind, string> = {
  internet: '#3b82f6',
  external: '#8b5cf6',
  user: '#a855f7',
  compute: '#2563eb',
  security_group: '#14b8a6',
  role: '#8b5cf6',
  bucket: '#10b981',
  database: '#f59e0b',
  finding: '#e24b4a',
}

export const SEV_COLOR: Record<string, string> = {
  critical: '#e24b4a',
  high: '#ef9f27',
  medium: '#3b82c4',
  low: '#1d9e75',
  info: '#8b95a5',
}

const EDGE_STYLE: Record<GraphEdge['type'], { color: string; verb: string }> = {
  EXPOSED_TO: { color: '#ef9f27', verb: 'exposed to' },
  USES_SECURITY_GROUP: { color: '#94a3b8', verb: 'uses' },
  CAN_ASSUME: { color: '#8b5cf6', verb: 'can assume' },
  CAN_ACCESS: { color: '#3b82f6', verb: 'can access' },
  CAN_MODIFY_AND_INVOKE: { color: '#e24b4a', verb: 'can modify and invoke' },
  CAN_IMPERSONATE_VIA_SERVICE: { color: '#a855f7', verb: 'can impersonate via service' },
  HAS_FINDING: { color: '#e24b4a', verb: 'has finding' },
}

const NODE_W = 140
const NODE_H = 72
const ICON_R = 24
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low']
const edgeKey = (source: string, target: string) => `${source}->${target}`

function nodeColor(node: GraphNode) {
  if (node.kind === 'finding') return SEV_COLOR[node.severity ?? 'high'] ?? KIND_COLOR.finding
  return KIND_COLOR[node.kind]
}

interface Placed extends GraphNode {
  x: number
  y: number
}

interface Routed {
  id: string
  src: string
  dst: string
  d: string
  mid: { x: number; y: number }
  color: string
  verb: string
}

function layout(nodes: GraphNode[], edges: GraphEdge[]) {
  const graph = new dagre.graphlib.Graph()
  graph.setGraph({ rankdir: 'LR', nodesep: 58, ranksep: 132, marginx: 52, marginy: 56 })
  graph.setDefaultEdgeLabel(() => ({}))
  const present = new Set(nodes.map((node) => node.id))
  nodes.forEach((node) => graph.setNode(node.id, { width: NODE_W, height: NODE_H }))
  edges.forEach((edge) => { if (present.has(edge.source) && present.has(edge.target)) graph.setEdge(edge.source, edge.target) })
  dagre.layout(graph)

  const placed: Placed[] = nodes.map((node) => {
    const position = graph.node(node.id)
    return { ...node, x: position.x, y: position.y }
  })
  const byId = new Map(placed.map((node) => [node.id, node]))
  const routed: Routed[] = []
  edges.forEach((edge, index) => {
    const source = byId.get(edge.source)
    const target = byId.get(edge.target)
    if (!source || !target) return
    const x1 = source.x + ICON_R
    const x2 = target.x - ICON_R
    const dx = Math.max(42, (x2 - x1) * 0.5)
    const style = EDGE_STYLE[edge.type]
    routed.push({
      id: `${edge.source}-${edge.target}-${index}`,
      src: edge.source,
      dst: edge.target,
      d: `M${x1},${source.y} C${x1 + dx},${source.y} ${x2 - dx},${target.y} ${x2},${target.y}`,
      mid: { x: (x1 + x2) / 2, y: (source.y + target.y) / 2 - 9 },
      color: edge.type === 'HAS_FINDING' ? nodeColor(target) : style.color,
      verb: edge.wildcard && edge.type === 'CAN_ASSUME' ? 'can assume (wildcard)' : style.verb,
    })
  })
  const { width = 0, height = 0 } = graph.graph()
  return { placed, routed, width, height }
}

export function GraphCanvas({
  nodes,
  edges,
  paths,
  accounts,
  account,
  onAccountChange,
  onSelect,
}: {
  nodes: GraphNode[]
  edges: GraphEdge[]
  paths: AttackRoute[]
  accounts: { account_identifier: string; name: string | null }[]
  account: string
  onAccountChange: (account: string) => void
  onSelect?: (node: GraphNode) => void
}) {
  const { placed, routed, width, height } = useMemo(() => layout(nodes, edges), [nodes, edges])
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all')
  const [hoverRoute, setHoverRoute] = useState<AttackRoute | null>(null)
  const [hoverNode, setHoverNode] = useState<string | null>(null)
  const [focusedRouteId, setFocusedRouteId] = useState('all')
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [pathListOpen, setPathListOpen] = useState(false)

  const activeRoutes = useMemo(() => filterSev === 'all' ? paths : paths.filter((path) => path.severity === filterSev), [paths, filterSev])
  const focusedRoute = activeRoutes.find((route) => route.id === focusedRouteId) ?? null

  useEffect(() => {
    if (focusedRouteId !== 'all' && !activeRoutes.some((route) => route.id === focusedRouteId)) setFocusedRouteId('all')
  }, [activeRoutes, focusedRouteId])

  useEffect(() => {
    if (!nodes.length) {
      setSelectedNodeId(null)
      return
    }
    if (!nodes.some((node) => node.id === selectedNodeId)) {
      setSelectedNodeId(nodes.find((node) => node.kind === 'finding')?.id ?? nodes[0].id)
    }
  }, [nodes, selectedNodeId])

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? null
  const selectedRelationships = useMemo(() => selectedNode ? edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id) : [], [edges, selectedNode])
  const nodeNames = useMemo(() => new Map(nodes.map((node) => [node.id, node.name])), [nodes])
  const selectedProperties = useMemo(() => Object.entries(selectedNode?.properties ?? {}).filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value)).slice(0, 7), [selectedNode])

  const hot = useMemo(() => {
    const routes = hoverRoute ? [hoverRoute] : focusedRoute ? [focusedRoute] : hoverNode ? activeRoutes.filter((route) => route.nodes.includes(hoverNode)) : filterSev !== 'all' ? activeRoutes : null
    if (!routes?.length) return null
    const routeNodes = new Set<string>()
    const routeEdges = new Set<string>()
    routes.forEach((route) => {
      route.nodes.forEach((node) => routeNodes.add(node))
      for (let index = 1; index < route.nodes.length; index += 1) routeEdges.add(edgeKey(route.nodes[index - 1], route.nodes[index]))
    })
    return { nodes: routeNodes, edges: routeEdges }
  }, [hoverRoute, focusedRoute, hoverNode, activeRoutes, filterSev])

  const counts = useMemo(() => {
    const entries = new Set(paths.map((path) => path.nodes[0]))
    const targets = new Set(paths.map((path) => path.nodes[path.nodes.length - 1]))
    const bySeverity: Record<string, number> = {}
    paths.forEach((path) => { bySeverity[path.severity] = (bySeverity[path.severity] ?? 0) + 1 })
    return { total: paths.length, entries: entries.size, targets: targets.size, bySeverity }
  }, [paths])
  const kindsPresent = useMemo(() => Array.from(new Set(nodes.map((node) => node.kind))), [nodes])

  const canvasRef = useRef<HTMLDivElement>(null)
  const drag = useRef<{ px: number; py: number; ox: number; oy: number } | null>(null)
  const [view, setView] = useState({ x: 0, y: 0, k: 1 })

  const fit = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas || !width || !height) return
    const scale = Math.min(canvas.clientWidth / width, canvas.clientHeight / height, 1.08) * 0.88
    setView({ x: (canvas.clientWidth - width * scale) / 2, y: (canvas.clientHeight - height * scale) / 2, k: scale })
  }, [width, height])

  useEffect(() => { fit() }, [fit])
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const handleWheel = (event: WheelEvent) => {
      event.preventDefault()
      const rect = canvas.getBoundingClientRect()
      const mx = event.clientX - rect.left
      const my = event.clientY - rect.top
      setView((current) => {
        const nextScale = Math.min(2.4, Math.max(0.2, current.k * (event.deltaY < 0 ? 1.12 : 1 / 1.12)))
        return { k: nextScale, x: mx - ((mx - current.x) / current.k) * nextScale, y: my - ((my - current.y) / current.k) * nextScale }
      })
    }
    canvas.addEventListener('wheel', handleWheel, { passive: false })
    return () => canvas.removeEventListener('wheel', handleWheel)
  }, [])

  function handlePointerDown(event: React.PointerEvent) {
    if ((event.target as HTMLElement).closest('.gc-node')) return
    drag.current = { px: event.clientX, py: event.clientY, ox: view.x, oy: view.y }
    ;(event.currentTarget as HTMLElement).setPointerCapture(event.pointerId)
  }
  function handlePointerMove(event: React.PointerEvent) {
    if (!drag.current) return
    const start = drag.current
    setView((current) => ({ ...current, x: start.ox + event.clientX - start.px, y: start.oy + event.clientY - start.py }))
  }
  function handlePointerUp() { drag.current = null }
  function zoom(factor: number) {
    const canvas = canvasRef.current
    if (!canvas) return
    const mx = canvas.clientWidth / 2
    const my = canvas.clientHeight / 2
    setView((current) => {
      const nextScale = Math.min(2.4, Math.max(0.2, current.k * factor))
      return { k: nextScale, x: mx - ((mx - current.x) / current.k) * nextScale, y: my - ((my - current.y) / current.k) * nextScale }
    })
  }
  function focusRoute(route: AttackRoute) {
    setFocusedRouteId(route.id)
    setSelectedNodeId(route.nodes[route.nodes.length - 1] ?? null)
  }

  const dimNode = (id: string) => hot ? !hot.nodes.has(id) : false
  const dimEdge = (source: string, target: string) => hot ? !hot.edges.has(edgeKey(source, target)) : false

  return (
    <div className="gc-wrap">
      <header className="gc-toolbar">
        <div className="gc-toolbar-title"><strong>Security graph</strong><span>{nodes.length} nodes · {edges.length} relationships</span></div>
        <label className="gc-route-picker"><span className="sr-only">Focus attack path</span><select value={focusedRouteId} onChange={(event) => { const id = event.target.value; setFocusedRouteId(id); const route = activeRoutes.find((item) => item.id === id); if (route) focusRoute(route) }}><option value="all">All observed paths</option>{activeRoutes.map((route) => <option key={route.id} value={route.id}>{route.severity} · {route.target} · {route.length} hops</option>)}</select></label>
        <div className="gc-chips">{(['all', ...SEV_ORDER] as const).map((severity) => <button key={severity} className={`gc-chip${filterSev === severity ? ' on' : ''}${severity !== 'all' ? ` sev-${severity}` : ''}`} onClick={() => setFilterSev(severity)}>{severity === 'all' ? 'All' : `${severity} ${counts.bySeverity[severity] ?? 0}`}</button>)}</div>
        <div className="gc-controls">
          {accounts.length ? <select className="gc-acct" value={account} onChange={(event) => onAccountChange(event.target.value)} aria-label="Account scope"><option value="all">All accounts ({accounts.length})</option>{accounts.map((item) => <option key={item.account_identifier} value={item.account_identifier}>{item.name || item.account_identifier}</option>)}</select> : null}
          <button onClick={() => setPathListOpen((open) => !open)} aria-label="Toggle attack path list" title="Attack path list"><ListTree size={15} /></button>
          <button onClick={() => zoom(1.2)} aria-label="Zoom in" title="Zoom in"><Plus size={15} /></button>
          <button onClick={() => zoom(1 / 1.2)} aria-label="Zoom out" title="Zoom out"><Minus size={15} /></button>
          <button onClick={fit} aria-label="Fit graph" title="Fit graph"><Maximize2 size={14} /></button>
        </div>
      </header>

      <div className="gc-counts"><strong>{counts.total}</strong> attack paths <span className="gc-dot crit" /> {counts.bySeverity.critical ?? 0} critical <span className="gc-dot high" /> {counts.bySeverity.high ?? 0} high <span className="gc-sep" /> {counts.entries} entries · {counts.targets} targets</div>

      {pathListOpen ? <aside className="gc-paths"><header>Observed attack paths · {activeRoutes.length}</header><div className="gc-paths-body">{activeRoutes.map((route) => <button key={route.id} className={`gc-path-row sev-${route.severity}${focusedRouteId === route.id ? ' selected' : ''}`} onClick={() => focusRoute(route)} onMouseEnter={() => setHoverRoute(route)} onMouseLeave={() => setHoverRoute(null)}><span className="gc-path-sev" style={{ background: SEV_COLOR[route.severity] }} /><span className="gc-path-flow"><NodeIcon node={{ kind: route.entry }} size={16} /><span className="gc-path-arrow">→</span><NodeIcon node={{ kind: route.target_kind }} size={16} /><span className="gc-path-target" title={route.target}>{route.target}</span></span><span className="gc-path-hops">{route.length} hops</span></button>)}{!activeRoutes.length ? <div className="gc-paths-empty">No paths at this severity.</div> : null}</div></aside> : null}

      <div ref={canvasRef} className="gc-pan" onPointerDown={handlePointerDown} onPointerMove={handlePointerMove} onPointerUp={handlePointerUp} onPointerLeave={handlePointerUp}>
        <div className="gc-stage" style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})`, width, height }}>
          <svg className="gc-edges" width={width} height={height} aria-hidden>
            <defs>{routed.map((route) => <marker key={`marker-${route.id}`} id={`arrow-${route.id}`} markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0,0 L8,4.5 L0,9 z" fill={route.color} /></marker>)}</defs>
            {routed.map((route, index) => <motion.path key={route.id} d={route.d} fill="none" stroke={route.color} strokeWidth={2} strokeLinecap="round" markerEnd={`url(#arrow-${route.id})`} initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: 1, opacity: dimEdge(route.src, route.dst) ? 0.07 : 0.82 }} transition={{ delay: Math.min(index * 0.008, 0.08), duration: 0.18, ease: 'easeOut' }} />)}
          </svg>
          {routed.filter((route) => route.verb).map((route) => <span key={`verb-${route.id}`} className="gc-verb" style={{ left: route.mid.x, top: route.mid.y, opacity: dimEdge(route.src, route.dst) ? 0.12 : 1 }}>{route.verb}</span>)}
          {placed.map((node, index) => {
            const color = nodeColor(node)
            const isFinding = node.kind === 'finding'
            const selected = node.id === selectedNodeId
            return <motion.button key={node.id} type="button" className={`gc-node${isFinding ? ' finding' : ''}${selected ? ' selected' : ''}`} style={{ left: node.x, top: node.y }} onClick={() => setSelectedNodeId(node.id)} onMouseEnter={() => setHoverNode(node.id)} onMouseLeave={() => setHoverNode(null)} initial={{ opacity: 0, scale: 0.88 }} animate={{ opacity: dimNode(node.id) ? 0.16 : 1, scale: 1 }} transition={{ delay: Math.min(index * 0.01, 0.1), duration: 0.16 }} title={node.id}><span className={`gc-icon${isFinding ? '' : ' aws'}`} style={{ color, borderColor: color, background: isFinding ? color : 'var(--surface)' }}><NodeIcon node={node} size={28} color={color} />{Boolean(node.properties?.has_admin) ? <Crown className="gc-crown" size={12} /> : null}{node.is_public && !isFinding ? <span className="gc-public" title="Internet exposed" /> : null}</span><span className="gc-label"><span className="gc-name" title={node.name}>{node.name}</span><span className="gc-kind">{KIND_LABEL[node.kind]}</span></span></motion.button>
          })}
        </div>
      </div>

      <div className="gc-legend">{kindsPresent.map((kind) => <span key={kind} className="gc-leg-item"><span className="gc-leg-ico" style={{ borderColor: KIND_COLOR[kind] }}><NodeIcon node={{ kind }} size={14} color={KIND_COLOR[kind]} /></span>{KIND_LABEL[kind]}</span>)}</div>

      {selectedNode ? <aside className="gc-inspector"><div className="gc-inspector-head"><span className="gc-node-type" style={{ color: nodeColor(selectedNode) }}><NodeIcon node={selectedNode} size={16} color={nodeColor(selectedNode)} />{KIND_LABEL[selectedNode.kind]}</span>{selectedNode.severity ? <span className={`sev-badge sev-${selectedNode.severity}`}><span className="dot" />{selectedNode.severity}</span> : null}</div><h2>{selectedNode.name}</h2><p className="mono gc-inspector-id">{selectedNode.resource_id ?? selectedNode.id}</p><div className="gc-inspector-stats"><div><span>Risk</span><strong>{Math.round(selectedNode.risk_score ?? 0)}</strong></div><div><span>Public</span><strong>{selectedNode.is_public ? 'Yes' : 'No'}</strong></div><div><span>Relations</span><strong>{selectedRelationships.length}</strong></div></div><dl className="gc-inspector-kv">{selectedNode.asset_type ? <div><dt>Asset type</dt><dd>{selectedNode.asset_type}</dd></div> : null}{selectedNode.region ? <div><dt>Region</dt><dd className="mono">{selectedNode.region}</dd></div> : null}{selectedNode.issue_type ? <div><dt>Issue type</dt><dd>{selectedNode.issue_type.replace(/_/g, ' ')}</dd></div> : null}{selectedProperties.map(([key, value]) => <div key={key}><dt>{key.replace(/_/g, ' ')}</dt><dd>{String(value)}</dd></div>)}</dl><section className="gc-inspector-section"><span className="label">Connected relationships</span>{selectedRelationships.length ? selectedRelationships.slice(0, 6).map((relationship, index) => { const outgoing = relationship.source === selectedNode.id; const peer = outgoing ? relationship.target : relationship.source; return <div className="gc-relationship" key={`${relationship.source}-${relationship.target}-${index}`}><span>{outgoing ? '→' : '←'} {relationship.type.replace(/_/g, ' ')}</span><strong title={peer}>{nodeNames.get(peer) ?? peer}</strong></div> }) : <p>No graph relationship is attached to this node.</p>}</section>{selectedNode.kind === 'finding' && onSelect ? <button className="btn primary gc-open-finding" onClick={() => onSelect(selectedNode)}>Open finding evidence <ExternalLink size={14} /></button> : null}</aside> : null}
    </div>
  )
}
