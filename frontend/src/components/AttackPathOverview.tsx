import { motion } from 'motion/react'
import { Link } from 'react-router-dom'
import { Fragment } from 'react'

import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { NodeIcon } from '../lib/awsIcons'
import type { GraphNode } from '../types'
import { Card, StateView } from './ui'
import { KIND_COLOR, SEV_COLOR } from './GraphCanvas'

const TOP = 6

// One enumerated route rendered as a compact, left-to-right animated flow of
// icon nodes with connectors that draw themselves in (motion).
function RouteFlow({ hops, severity, delay }: { hops: GraphNode[]; severity: string; delay: number }) {
  const color = SEV_COLOR[severity] ?? SEV_COLOR.high
  return (
    <motion.div
      className="apo-route"
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay, duration: 0.34, ease: 'easeOut' }}
    >
      <span className="apo-sev" style={{ background: color }} />
      <div className="apo-flow">
        {hops.map((h, i) => {
          const c = KIND_COLOR[h.kind] ?? color
          const last = i === hops.length - 1
          return (
            <Fragment key={`${h.id}-${i}`}>
              {i > 0 ? (
                <span className="apo-conn">
                  <motion.span
                    className="apo-line"
                    style={{ background: color }}
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: 1 }}
                    transition={{ delay: delay + 0.1 + i * 0.06, duration: 0.22, ease: 'easeOut' }}
                  />
                </span>
              ) : null}
              <span
                className="apo-node aws"
                style={{ borderColor: c, background: 'var(--surface)' }}
                title={`${h.kind}: ${h.name}`}
              >
                <NodeIcon node={h} size={18} color={c} />
              </span>
              {last ? (
                <span className="apo-target" title={h.name}>
                  {h.name}
                </span>
              ) : null}
            </Fragment>
          )
        })}
      </div>
    </motion.div>
  )
}

export function AttackPathOverview({ i }: { i?: number }) {
  // graph endpoint keys on account_identifier (string), scope holds the row id —
  // map it. null scope = 'all' (fleet). While a set scope is still resolving its
  // identifier, gate the fetch so we never briefly render another account's paths.
  const { accountId } = useAccountScope()
  const accounts = useApi(() => api.accounts())
  const acct =
    accountId == null
      ? 'all'
      : accounts.data?.items.find((a) => a.id === accountId)?.account_identifier
  const graph = useApi(() => api.graph({ account: acct }), [acct], { enabled: acct !== undefined })

  const paths = graph.data?.paths ?? []
  const byId = new Map((graph.data?.nodes ?? []).map((n) => [n.id, n]))
  const top = paths.slice(0, TOP)
  const crit = paths.filter((p) => p.severity === 'critical').length
  const high = paths.filter((p) => p.severity === 'high').length

  return (
    <Card
      title="Possible attack paths"
      i={i}
      bodyPad={false}
      right={
        paths.length ? (
          <Link to="/attack-paths" className="apo-link">
            view graph →
          </Link>
        ) : undefined
      }
    >
      <StateView
        loading={graph.loading}
        error={graph.error}
        empty={!!graph.data && paths.length === 0}
        emptyHint="No walkable attack paths. Run a scan, then evaluate from the Attack paths page."
      >
        {graph.data ? (
          <div>
            <div className="apo-counts">
              <span>
                <strong>{paths.length}</strong> routes attackers can walk
              </span>
              <span className="apo-pills">
                <span className="apo-pill" style={{ color: SEV_COLOR.critical }}>
                  ● {crit} critical
                </span>
                <span className="apo-pill" style={{ color: SEV_COLOR.high }}>
                  ● {high} high
                </span>
              </span>
            </div>
            <div className="apo-list">
              {top.map((p, idx) => {
                const hops = p.nodes.map((id) => byId.get(id)).filter(Boolean) as GraphNode[]
                if (hops.length < 2) return null
                return <RouteFlow key={p.id} hops={hops} severity={p.severity} delay={idx * 0.06} />
              })}
            </div>
            {paths.length > TOP ? (
              <Link to="/attack-paths" className="apo-more">
                +{paths.length - TOP} more paths in the full graph
              </Link>
            ) : null}
          </div>
        ) : null}
      </StateView>
    </Card>
  )
}
