import { ArrowRight, RefreshCw } from 'lucide-react'
import { useState } from 'react'

import { Drawer } from '../components/Drawer'
import { FlowChart } from '../components/FlowChart'
import { GraphCanvas } from '../components/GraphCanvas'
import { Card, PageHead, SevBadge, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api, ApiError } from '../lib/api'
import { num, relTime, shortId } from '../lib/format'
import type { AttackPathIssue, GraphNode, PathHop } from '../types'

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'] as const

const HOP_KIND_LABEL: Record<PathHop['kind'], string> = {
  internet: 'net',
  external: 'ext',
  compute: 'ec2',
  security_group: 'sg',
  role: 'iam',
  bucket: 's3',
  database: 'db',
}

function riskClass(score: number): string {
  if (score >= 80) return 'sev-critical'
  if (score >= 60) return 'sev-high'
  if (score >= 35) return 'sev-medium'
  return ''
}

function HopChain({ path }: { path: PathHop[] }) {
  return (
    <div className="hops">
      {path.map((h, i) => (
        <span key={`${h.id}-${i}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          {i > 0 ? (
            <span className="hop-arrow" aria-hidden>
              <ArrowRight size={11} />
            </span>
          ) : null}
          <span
            className={`hop${h.kind === 'internet' || h.kind === 'external' ? ' threat' : ''}`}
            title={h.id}
          >
            <span className="hk">{HOP_KIND_LABEL[h.kind] ?? h.kind}</span>
            {h.name}
          </span>
        </span>
      ))}
    </div>
  )
}

export function AttackPaths() {
  const [view, setView] = useState<'list' | 'graph'>('list')
  const [graphAccount, setGraphAccount] = useState('all')
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>('all')
  const [status, setStatus] = useState<'open' | 'resolved'>('open')
  const [selected, setSelected] = useState<AttackPathIssue | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const { accountId } = useAccountScope()
  const summary = useApi(() => api.issuesSummary(accountId), [accountId])
  const accounts = useApi(() => api.accounts())
  const scopedAccount = accounts.data?.items.find((account) => account.id === accountId)
  const requestedGraphAccount = view === 'graph' ? graphAccount : (scopedAccount?.account_identifier ?? 'all')
  const issues = useApi(
    () =>
      api.issues({
        account_id: accountId ?? undefined,
        status,
        severity: severity === 'all' ? undefined : severity,
      }),
    [accountId, status, severity],
  )
  // Graph mode pulls the whole graph (account-scoped or fleet-wide) + every open
  // issue (so a clicked finding node resolves to a full issue regardless of the
  // list's filters). Graph keeps its own account_identifier picker (graphAccount).
  const graph = useApi(
    () => api.graph({ account: requestedGraphAccount }),
    [requestedGraphAccount],
  )
  const openIssues = useApi(
    () => api.issues({ account_id: accountId ?? undefined, status: 'open' }),
    [accountId],
    { enabled: view === 'graph' },
  )

  function onGraphNode(node: GraphNode) {
    if (node.kind !== 'finding') return
    const match = openIssues.data?.items.find(
      (it) => it.issue_type === node.issue_type && it.resource_id === node.resource_id,
    )
    if (match) setSelected(match)
  }

  async function evaluate() {
    const roster = accounts.data?.items ?? []
    const targets = view === 'graph' && graphAccount !== 'all'
      ? roster.filter((account) => account.account_identifier === graphAccount)
      : accountId !== null
        ? roster.filter((account) => account.id === accountId)
        : roster
    if (!targets.length) return
    setEvaluating(true)
    try {
      const results = await Promise.all(
        targets.map((account) => api.evaluateIssues(account.provider, account.account_identifier)),
      )
      const r = results.reduce(
        (out, result) => ({
          new: out.new + result.new,
          reopened: out.reopened + result.reopened,
          resolved: out.resolved + result.resolved,
        }),
        { new: 0, reopened: 0, resolved: 0 },
      )
      setToast(`analyzed: ${r.new} new · ${r.reopened} reopened · ${r.resolved} resolved`)
      issues.refetch()
      summary.refetch()
      if (view === 'graph') {
        graph.refetch()
        openIssues.refetch()
      }
    } catch (e) {
      setToast(e instanceof ApiError ? e.message : String(e))
    } finally {
      setEvaluating(false)
      setTimeout(() => setToast(null), 4200)
    }
  }

  return (
    <div className={`page attack-paths-page${view === 'graph' ? ' graph-view' : ''}`}>
      <PageHead
        crumb="attack paths"
        title="Attack paths"
        sub={
          summary.data
            ? `${num(summary.data.open)} open paths · peak risk ${summary.data.max_risk}`
            : 'Correlated chains of misconfigurations an attacker can actually walk.'
        }
        actions={
          <button
            className="btn primary"
            onClick={evaluate}
            disabled={evaluating || !accounts.data?.items.length}
            title="Re-run the attack-path engine over persisted assets"
          >
            <RefreshCw style={evaluating ? { animation: 'spin 0.7s linear infinite' } : undefined} />
            {evaluating ? 'Analyzing…' : 'Analyze'}
          </button>
        }
      />

      <div className="control-row reveal" style={{ ['--i' as string]: 1 }}>
        <div className="seg-ctl" role="tablist" aria-label="view">
          {(['list', 'graph'] as const).map((v) => (
            <button key={v} className={view === v ? 'on' : ''} onClick={() => setView(v)}>
              {v}
            </button>
          ))}
        </div>
        {view === 'list' ? (
          <>
            <div className="seg-ctl" role="tablist" aria-label="status">
              {(['open', 'resolved'] as const).map((s) => (
                <button key={s} className={status === s ? 'on' : ''} onClick={() => setStatus(s)}>
                  {s}
                </button>
              ))}
            </div>
            <select
              className="select"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as never)}
              aria-label="severity filter"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s === 'all' ? 'severity: all' : s}
                </option>
              ))}
            </select>
          </>
        ) : (
          <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
            scroll to zoom · drag to pan · click a finding for detail
          </span>
        )}
      </div>

      {graph.data?.analysis ? (
        <section className={`graph-analysis ${graph.data.analysis.status} reveal`} style={{ ['--i' as string]: 1 }}>
          <div className="graph-analysis-copy">
            <span className="eyebrow">Analysis confidence</span>
            <strong>{graph.data.analysis.message}</strong>
            <span>
              {graph.data.analysis.metrics.assets} assets Â· {graph.data.analysis.metrics.attack_edges} traversable relationships Â· {graph.data.analysis.metrics.paths} paths
            </span>
          </div>
          <div className="graph-coverage" aria-label="attack path evidence coverage">
            {graph.data.analysis.coverage.map((signal) => (
              <span key={signal.key} className={`graph-coverage-chip ${signal.status}`} title={signal.detail}>
                <i />{signal.key.replace('_', ' ')} <b>{signal.observed}</b>
              </span>
            ))}
          </div>
          <details>
            <summary>Current analysis boundaries</summary>
            {graph.data.analysis.limitations.map((limitation) => <p key={limitation}>{limitation}</p>)}
          </details>
        </section>
      ) : null}

      {view === 'list' && issues.data && issues.data.items.some((i) => i.actively_exploited) ? (
        <div className="exploit-banner reveal" style={{ ['--i' as string]: 1 }}>
          <span className="live-dot" />
          {issues.data.items.filter((i) => i.actively_exploited).length} attack path(s) under
          active exploitation — runtime activity detected on a hop. The predicted path is being walked.
        </div>
      ) : null}

      {view === 'list' ? (
        <Card i={2} bodyPad={false}>
          <StateView
            loading={issues.loading}
            error={issues.error}
            empty={!!issues.data && issues.data.items.length === 0}
            emptyHint={
              status === 'open'
                ? (graph.data?.analysis.message ?? 'Attack-path evidence is still loading.')
                : 'Nothing resolved yet.'
            }
          >
            {issues.data ? (
              <div>
                {issues.data.items.map((i) => (
                  <div
                    key={i.id}
                    className={`frow sev-${i.severity}${i.status === 'resolved' ? ' resolved' : ''}${i.actively_exploited ? ' live' : ''}`}
                    onClick={() => setSelected(i)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && setSelected(i)}
                  >
                    <span className={`risk-num ${riskClass(i.risk_score)}`}>
                      {Math.round(i.risk_score)}
                    </span>
                    <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
                      <div className="t">
                        {i.actively_exploited && (
                          <span className="live-badge" title={
                            `Runtime activity on this path${i.last_exploit_at ? ` · ${relTime(i.last_exploit_at)}` : ''}` +
                            `${i.exploit_count ? ` · ${i.exploit_count} event(s)` : ''}`
                          }>
                            <span className="live-dot" />LIVE
                          </span>
                        )}
                        {i.title}
                        {i.confidence < 1 && (
                          <span
                            className="mono"
                            style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-3)' }}
                            title="Route confidence — how completely the path is evidenced (freshness × completeness)"
                          >
                            {Math.round(i.confidence * 100)}% conf
                          </span>
                        )}
                        {i.evidence_status && i.evidence_status !== 'confirmed' && (
                          <span
                            className="mono"
                            style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-3)' }}
                            title="Evidence quality is separate from impact and risk"
                          >
                            {i.evidence_status} evidence
                          </span>
                        )}
                      </div>
                      <HopChain path={i.path} />
                    </div>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', width: 72, textAlign: 'right', flexShrink: 0 }}>
                      {relTime(i.status === 'resolved' ? i.resolved_at : i.first_seen_at)}
                    </span>
                    <span style={{ width: 86, flexShrink: 0, textAlign: 'right' }}>
                      <SevBadge sev={i.severity} />
                    </span>
                  </div>
                ))}
              </div>
            ) : null}
          </StateView>
        </Card>
      ) : (
        <section className="graph-workspace-shell reveal" style={{ ['--i' as string]: 2 }}>
          <StateView
            loading={graph.loading}
            error={graph.error}
            empty={!!graph.data && graph.data.nodes.length === 0}
            emptyHint="No graph yet — register an account and run a scan, then Analyze."
          >
            {graph.data ? (
              <GraphCanvas
                nodes={graph.data.nodes}
                edges={graph.data.edges}
                paths={graph.data.paths}
                accounts={graph.data.accounts}
                account={graphAccount}
                onAccountChange={setGraphAccount}
                onSelect={onGraphNode}
              />
            ) : null}
          </StateView>
        </section>
      )}

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.title}
        subtitle={selected?.resource_id}
      >
        {selected ? (
          <>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className={`risk-num ${riskClass(selected.risk_score)}`} style={{ width: 'auto' }}>
                {Math.round(selected.risk_score)}
                <span className="of">/100</span>
              </span>
              <SevBadge sev={selected.severity} />
              <span className="pill">{selected.issue_type}</span>
              <span className="pill tint">{selected.status}</span>
              <span
                className="pill tint"
                title="Route confidence — how completely the path is evidenced (freshness × completeness)"
              >
                {Math.round(selected.confidence * 100)}% confidence
              </span>
              <span className="pill tint" title="Evidence quality is separate from impact and risk">
                {selected.evidence_status ?? 'confirmed'} evidence
              </span>
            </div>

            <div className="drawer-section">
              <span className="label">Attack path</span>
              <div className="flow-scroll">
                <FlowChart path={selected.path} severity={selected.severity} />
              </div>
            </div>

            <div className="drawer-section">
              <span className="label">Why this matters</span>
              <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6 }}>{selected.why}</p>
            </div>

            {selected.evidence && selected.evidence.length > 0 ? (
              <div className="drawer-section">
                <span className="label">Evidence</span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {selected.evidence.map((ev, i) => (
                    <div key={i} style={{ borderLeft: '2px solid var(--border)', paddingLeft: 8 }}>
                      <div className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>{ev.source}</div>
                      <div className="mono" style={{ fontSize: 11.5, lineHeight: 1.5, wordBreak: 'break-word' }}>{ev.observation}</div>
                      <div style={{ fontSize: 11.5, color: 'var(--text-2)', fontStyle: 'italic' }}>↳ {ev.effect}</div>
                    </div>
                  ))}
                </div>
                {selected.scoring ? (
                  <p className="mono" style={{ margin: '10px 0 0', fontSize: 11.5, lineHeight: 1.6, color: 'var(--text-2)' }}>
                    Σ {selected.scoring}
                  </p>
                ) : null}
              </div>
            ) : null}

            <div className="drawer-section">
              <span className="label">Remediation</span>
              <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6 }}>{selected.remediation}</p>
            </div>

            {Object.keys(selected.compliance).length > 0 ? (
              <div className="drawer-section">
                <span className="label">Compliance evidence</span>
                <dl className="kv">
                  {Object.entries(selected.compliance).map(([fw, controls]) => (
                    <div key={fw} style={{ display: 'contents' }}>
                      <dt>{fw}</dt>
                      <dd className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)' }}>
                        {controls.join(' · ')}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            ) : null}

            {selected.related.length > 0 ? (
              <div className="drawer-section">
                <span className="label">Affected resources</span>
                {selected.related.map((r) => (
                  <div key={r} className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)', padding: '3px 0', wordBreak: 'break-all' }} title={r}>
                    {shortId(r)}
                  </div>
                ))}
              </div>
            ) : null}

            <div className="drawer-section">
              <span className="label">Timeline</span>
              <dl className="kv">
                <dt>first seen</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>{selected.first_seen_at ?? '—'}</dd>
                <dt>last seen</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>{selected.last_seen_at ?? '—'}</dd>
                {selected.resolved_at ? (
                  <>
                    <dt>resolved</dt>
                    <dd className="mono" style={{ fontSize: 11.5 }}>{selected.resolved_at}</dd>
                  </>
                ) : null}
              </dl>
            </div>
          </>
        ) : null}
      </Drawer>

      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}
