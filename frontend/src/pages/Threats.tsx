import { useMemo, useState } from 'react'
import { motion } from 'motion/react'
import { Box, GitBranch, ListTree, Terminal } from 'lucide-react'

import { Card, PageHead, SevBadge, SEVERITY_ORDER, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { num, relTime, shortId } from '../lib/format'
import type { RuntimeEvent, Severity } from '../types'

type Mode = 'timeline' | 'tree'

// One OS process (keyed by pid) and every runtime event observed on it.
interface ProcNode {
  pid: number
  comm: string
  command: string | null
  parent: string | null
  ppid: number | null
  container: string | null
  events: RuntimeEvent[]
  children: ProcNode[]
}

function sevRank(s: string): number {
  const i = SEVERITY_ORDER.indexOf(s as Severity)
  return i === -1 ? SEVERITY_ORDER.length : i
}

function worstSev(events: RuntimeEvent[]): string {
  return events.reduce((w, e) => (sevRank(e.severity) < sevRank(w) ? e.severity : w), 'info')
}

// Build a process forest from pid → ppid links across all events. Events that
// carry no pid are returned separately for a flat list.
function buildForest(events: RuntimeEvent[]): { roots: ProcNode[]; orphans: RuntimeEvent[] } {
  const byPid = new Map<number, ProcNode>()
  const orphans: RuntimeEvent[] = []

  for (const e of events) {
    if (e.pid == null) {
      orphans.push(e)
      continue
    }
    let n = byPid.get(e.pid)
    if (!n) {
      n = {
        pid: e.pid,
        comm: e.comm || e.process || e.event_type,
        command: e.command ?? null,
        parent: e.parent ?? null,
        ppid: e.ppid ?? null,
        container: e.container ?? e.workload ?? null,
        events: [],
        children: [],
      }
      byPid.set(e.pid, n)
    }
    n.events.push(e)
    if (e.comm) n.comm = e.comm
    if (e.command) n.command = e.command
    if (e.parent) n.parent = e.parent
    if (e.ppid != null) n.ppid = e.ppid
    if (e.container || e.workload) n.container = e.container ?? e.workload ?? n.container
  }

  // Link children to parents that we actually observed; roots are processes
  // whose parent pid was never itself seen (the lineage entry point).
  const roots: ProcNode[] = []
  for (const n of byPid.values()) {
    const parent = n.ppid != null ? byPid.get(n.ppid) : undefined
    if (parent && parent !== n) parent.children.push(n)
    else roots.push(n)
  }
  return { roots, orphans }
}

function EventChips({ events }: { events: RuntimeEvent[] }) {
  // Distinct event types on this process, each tagged with its severity.
  const seen = new Map<string, string>()
  for (const e of events) {
    const cur = seen.get(e.event_type)
    if (cur == null || sevRank(e.severity) < sevRank(cur)) seen.set(e.event_type, e.severity)
  }
  return (
    <span className="pnode-chips">
      {[...seen.entries()].map(([type, sev]) => (
        <span key={type} className={`ev-chip sev-${sev}`} title={`${type} · ${sev}`}>
          <span className="dot" style={{ background: 'currentColor' }} />
          {type}
        </span>
      ))}
    </span>
  )
}

function ProcRow({ node, depth }: { node: ProcNode; depth: number }) {
  const worst = worstSev(node.events)
  const dest = node.events.find((e) => e.dest)?.dest
  const last = node.events.reduce<RuntimeEvent | null>(
    (a, e) => (!a || (e.observed_at ?? '') > (a.observed_at ?? '') ? e : a),
    null,
  )
  // Total observations after burst-collapse — surfaces a recon/shell loop as ×N.
  const occ = node.events.reduce((n, e) => n + (e.count || 1), 0)
  return (
    <div className="pnode">
      <motion.div
        className={`pnode-row worst-${worst}`}
        initial={{ opacity: 0, x: -6 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.22, delay: Math.min(depth * 0.03, 0.3) }}
      >
        <span className="pnode-glyph">
          {node.children.length ? <GitBranch size={13} /> : <Terminal size={13} />}
        </span>
        <span className="pnode-comm" title={node.command ?? node.comm}>
          {node.command || node.comm}
        </span>
        <span className="pnode-meta">
          {[
            `pid ${node.pid}`,
            node.parent ? `← ${node.parent}` : null,
            node.container ? shortId(node.container) : null,
            dest ? `→ ${dest}` : null,
            occ > 1 ? `×${occ}` : null,
            last?.observed_at ? relTime(last.observed_at) : null,
          ]
            .filter(Boolean)
            .join(' · ')}
        </span>
        <EventChips events={node.events} />
      </motion.div>
      {node.children.length > 0 && (
        <div className="pnode-children">
          {node.children
            .sort((a, b) => sevRank(worstSev(a.events)) - sevRank(worstSev(b.events)))
            .map((c) => (
              <ProcRow key={c.pid} node={c} depth={depth + 1} />
            ))}
        </div>
      )}
    </div>
  )
}

export function Threats() {
  const [type, setType] = useState('all')
  const [mode, setMode] = useState<Mode>('timeline')
  const [hideNoise, setHideNoise] = useState(true)
  const { accountId } = useAccountScope()
  const summary = useApi(() => api.runtimeEventsSummary(accountId), [accountId])
  const events = useApi(
    () => api.runtimeEvents({ account_id: accountId ?? undefined, type: type === 'all' ? undefined : type, limit: 300 }),
    [accountId, type],
  )

  const typeOptions = useMemo(
    () => ['all', ...Object.keys(summary.data?.by_type ?? {}).sort()],
    [summary.data],
  )

  // Filter out benign system-auth reads (PAM/identity machinery) when hiding
  // noise — these are expected OS behavior, flagged benign by the sensor.
  const allItems = events.data?.items ?? []
  const noiseCount = allItems.filter((e) => e.benign).length
  const items = useMemo(
    () => (hideNoise ? allItems.filter((e) => !e.benign) : allItems),
    [allItems, hideNoise],
  )

  const forest = useMemo(() => buildForest(items), [items])
  const treeable = forest.roots.length > 0

  return (
    <div className="page">
      <PageHead
        crumb="threats"
        title="Threat detection"
        sub={
          summary.data
            ? `${num(summary.data.total)} runtime events observed`
            : 'Runtime signals from the eBPF sensor.'
        }
      />

      <div className="control-row reveal" style={{ ['--i' as string]: 1 }}>
        <select className="select" value={type} onChange={(e) => setType(e.target.value)} aria-label="event type filter">
          {typeOptions.map((t) => (
            <option key={t} value={t}>
              {t === 'all' ? 'type: all' : t}
            </option>
          ))}
        </select>
        <div className="seg-ctl" role="tablist" aria-label="view mode">
          <button
            role="tab"
            aria-selected={mode === 'timeline'}
            className={mode === 'timeline' ? 'on' : undefined}
            onClick={() => setMode('timeline')}
          >
            <ListTree size={12} style={{ verticalAlign: '-2px', marginRight: 5 }} />
            Timeline
          </button>
          <button
            role="tab"
            aria-selected={mode === 'tree'}
            className={mode === 'tree' ? 'on' : undefined}
            onClick={() => setMode('tree')}
          >
            <GitBranch size={12} style={{ verticalAlign: '-2px', marginRight: 5 }} />
            Process tree
          </button>
        </div>
        <label className="noise-toggle" title="Hide expected system-auth reads (PAM, identity, sudo config) flagged benign by the sensor">
          <input type="checkbox" checked={hideNoise} onChange={(e) => setHideNoise(e.target.checked)} />
          Hide noise{noiseCount ? ` (${num(noiseCount)})` : ''}
        </label>
      </div>

      <Card i={2} bodyPad={false}>
        <StateView
          loading={events.loading}
          error={events.error}
          empty={!!events.data && items.length === 0}
          emptyHint="No runtime events to show. Deploy the eBPF sensor (sensor/) — it POSTs to /api/internal/runtime-events. (If 'Hide noise' is on, only benign system-auth reads may be present.)"
        >
          {events.data && mode === 'timeline' ? (
            <div>
              {items.map((e) => (
                <div key={e.id} className={`frow sev-${e.severity}`}>
                  <span className="pill" style={{ flexShrink: 0 }}>{e.event_type}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="t">
                      {e.benign && <span className="benign-tag">benign</span>}
                      {e.command || e.process || e.summary || e.event_type}
                      {e.count > 1 && (
                        <span
                          className="pill tint"
                          style={{ marginLeft: 6, fontSize: 10 }}
                          title={`${e.count} occurrences collapsed (burst control)`}
                        >
                          ×{e.count}
                        </span>
                      )}
                    </div>
                    <div className="r" title={e.command ?? e.resource_id ?? e.workload ?? ''}>
                      {[
                        e.lineage || e.workload || null,
                        e.resource_id ? shortId(e.resource_id) : null,
                        e.pid ? `pid ${e.pid}` : null,
                        e.dest || null,
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </div>
                  </div>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', width: 72, textAlign: 'right', flexShrink: 0 }}>
                    {relTime(e.observed_at)}
                  </span>
                  <span style={{ width: 86, flexShrink: 0, textAlign: 'right' }}>
                    <SevBadge sev={e.severity} />
                  </span>
                </div>
              ))}
            </div>
          ) : null}

          {events.data && mode === 'tree' ? (
            treeable ? (
              <div className="ptree">
                {forest.roots
                  .sort((a, b) => sevRank(worstSev(a.events)) - sevRank(worstSev(b.events)))
                  .map((r) => (
                    <ProcRow key={r.pid} node={r} depth={0} />
                  ))}
                {forest.orphans.length > 0 && (
                  <div className="ptree-empty">
                    <Box size={12} style={{ verticalAlign: '-2px', marginRight: 6 }} />
                    {num(forest.orphans.length)} event(s) without process lineage — see Timeline.
                  </div>
                )}
              </div>
            ) : (
              <div className="ptree-empty">
                No process lineage to graph. These events carry no pid/parent
                — switch to Timeline. The eBPF sensor emits
                parent→child lineage that builds the tree.
              </div>
            )
          ) : null}
        </StateView>
      </Card>
    </div>
  )
}
