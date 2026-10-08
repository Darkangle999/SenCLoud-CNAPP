import { ArrowDownRight, ArrowUpRight, Camera } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { Card, PageHead, Ring } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { num, relTime } from '../lib/format'
import type { CompliancePoint } from '../types'

// Tiny inline trend line for a framework's score history (0–100).
function Sparkline({ points }: { points: CompliancePoint[] }) {
  if (points.length < 2) return <span className="spark-empty">— need ≥2 snapshots —</span>
  const w = 160
  const h = 34
  const xs = points.map((_, i) => (i / (points.length - 1)) * w)
  const ys = points.map((p) => h - (p.score / 100) * h)
  const d = xs.map((x, i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ')
  const last = points[points.length - 1].score
  const first = points[0].score
  const up = last >= first
  return (
    <svg width={w} height={h} className="spark" aria-hidden>
      <path d={d} fill="none" stroke={up ? 'var(--ok)' : 'var(--sev-high)'} strokeWidth="1.5" />
      <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r="2.5" fill={up ? 'var(--ok)' : 'var(--sev-high)'} />
    </svg>
  )
}

// ── Continuous compliance: persisted snapshots, trend, drift ─────
function ContinuousCompliance() {
  const { accountId } = useAccountScope()
  const current = useApi(() => api.complianceCurrent(accountId), [accountId])
  const drift = useApi(() => api.complianceDrift({ limit: 50 }))
  const [fw, setFw] = useState<string | null>(null)
  const [snapping, setSnapping] = useState(false)

  const selected = fw ?? current.data?.items[0]?.framework ?? null
  const history = useApi(
    () => api.complianceHistory(selected as string),
    [selected],
    { enabled: !!selected },
  )

  async function snapshotNow() {
    setSnapping(true)
    try {
      await api.complianceSnapshot({ account_id: accountId ?? undefined })
      current.refetch()
      drift.refetch()
      history.refetch()
    } catch {
      /* surfaced by the live-scan error path; snapshot reuses that engine */
    } finally {
      setSnapping(false)
    }
  }

  const has = (current.data?.total ?? 0) > 0

  return (
    <Card
      title="Continuous compliance"
      i={1}
      right={
        <button className="btn" onClick={snapshotNow} disabled={snapping}>
          <Camera style={snapping ? { animation: 'spin 0.7s linear infinite' } : undefined} />
          {snapping ? 'Snapshotting…' : 'Snapshot now'}
        </button>
      }
    >
      {!has ? (
        <div className="statev">
          <span className="label">no snapshots yet</span>
          <div className="hint">
            “Snapshot now” persists a scored point, or set
            <code> ODINEYES_COMPLIANCE_INTERVAL_MIN</code> to score on an interval.
            History + drift (pass↔fail) build from these.
          </div>
        </div>
      ) : (
        <div className="cc-wrap">
          <div className="cc-frameworks">
            {current.data!.items.map((s) => (
              <button
                key={s.framework}
                className={`cc-fw${selected === s.framework ? ' on' : ''}`}
                onClick={() => setFw(s.framework)}
              >
                <div className="cc-fw-top">
                  <span className="cc-fw-name">{s.framework}</span>
                  <span className="cc-fw-score">{s.score}%</span>
                </div>
                <div className="cc-fw-sub">
                  {num(s.passing)}/{num(s.total)} · {relTime(s.captured_at)}
                  {s.origin ? (
                    <span
                      className="pill tint"
                      style={{ marginLeft: 6, fontSize: 10 }}
                      title={s.origin === 'steampipe' ? 'Scored by Steampipe/Powerpipe' : 'Scored by the in-tree Python fallback engine'}
                    >
                      {s.origin === 'steampipe' ? 'Powerpipe' : 'fallback'}
                    </span>
                  ) : null}
                </div>
                {selected === s.framework && history.data && (
                  <Sparkline points={history.data.points} />
                )}
              </button>
            ))}
          </div>

          <div className="cc-drift">
            <div className="cc-drift-head">
              <span className="label">Drift</span>
              {drift.data && (
                <span className="cc-drift-counts">
                  <span className="reg">{num(drift.data.regressions)} regressions</span>
                  {' · '}
                  <span className="rem">{num(drift.data.remediations)} remediations</span>
                </span>
              )}
            </div>
            {drift.data && drift.data.items.length > 0 ? (
              <div className="cc-drift-list">
                {drift.data.items.map((d, i) => (
                  <div key={i} className={`cc-drift-row ${d.direction}`}>
                    {d.direction === 'regression' ? <ArrowDownRight size={13} /> : <ArrowUpRight size={13} />}
                    <span className="mono cc-ctl">{d.framework} {d.control_id}</span>
                    <span className="cc-title">{d.control_title ?? ''}</span>
                    <span className="cc-trans mono">{d.from_state ?? '—'}→{d.to_state}</span>
                    <span className="cc-time mono">{relTime(d.detected_at)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="hint">No control transitions recorded yet (need ≥2 snapshots).</div>
            )}
          </div>
        </div>
      )}
    </Card>
  )
}

export function Compliance() {
  const { accountId } = useAccountScope()
  const report = useApi(() => api.complianceReport(accountId), [accountId])
  const [selectedFw, setSelectedFw] = useState<string | null>(null)
  const [failOnly, setFailOnly] = useState(true)

  useEffect(() => {
    if (report.data?.compliance && !selectedFw) {
      setSelectedFw(Object.keys(report.data.compliance)[0] ?? null)
    }
  }, [report.data?.compliance, selectedFw])

  const scan = report.data
  const framework = scan && selectedFw ? scan.compliance[selectedFw] : null
  const controls = useMemo(() => {
    if (!framework) return []
    const list = failOnly ? framework.controls.filter((c: any) => c.state === 'fail') : framework.controls
    const rank = { fail: 0, not_assessed: 1, pass: 2 }
    return [...list].sort((a, b) => rank[a.state as keyof typeof rank] - rank[b.state as keyof typeof rank] || a.id.localeCompare(b.id))
  }, [framework, failOnly])

  return (
    <div className="page">
      <PageHead
        crumb="compliance"
        title="Compliance"
        sub="Framework scores compiled instantly from the current database findings."
      />

      <ContinuousCompliance />

      {report.loading ? (
        <Card i={1}>
          <div className="statev" role="status">
            <div className="spinner" />
            <div className="hint mono" style={{ fontSize: 11.5 }}>
              Loading compliance report from database…
            </div>
          </div>
        </Card>
      ) : null}

      {report.error ? (
        <Card i={1}>
          <div className="statev">
            <div className="code">{report.error.message}</div>
            <div className="hint">Failed to load compliance report.</div>
          </div>
        </Card>
      ) : null}

      {scan ? (
        <>
          <div className="fw-grid" style={{ marginBottom: 12 }}>
            {Object.entries(scan.compliance).map(([key, fw], i) => (
              <button
                key={key}
                className={`card fw-card reveal${selectedFw === key ? ' on' : ''}`}
                style={{ ['--i' as string]: i + 1 }}
                onClick={() => setSelectedFw(key)}
              >
                <Ring pct={fw.score} />
                <div style={{ minWidth: 0 }}>
                  <div className="label">{fw.name}{fw.version ? ` ${fw.version}` : ''}</div>
                  <div className="pct">{fw.score}%</div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-3)' }}>
                    {num(fw.passing)}/{num(fw.total)} controls
                  </div>
                </div>
              </button>
            ))}
          </div>

          {framework ? (
            <Card
              title={`${framework.name} controls`}
              i={5}
              bodyPad={false}
              right={
                <div className="seg-ctl">
                  <button className={failOnly ? 'on' : ''} onClick={() => setFailOnly(true)}>
                    failing
                  </button>
                  <button className={!failOnly ? 'on' : ''} onClick={() => setFailOnly(false)}>
                    all
                  </button>
                </div>
              }
            >
              {controls.length === 0 ? (
                <div className="statev">
                  {framework.total === 0 ? (
                    <>
                      <span className="label">not assessed</span>
                      <div className="hint">No controls have been assessed yet. Please run a snapshot.</div>
                    </>
                  ) : (
                    <>
                      <span className="label">no failing controls</span>
                      <div className="hint">Every assessed control in this framework passes.</div>
                    </>
                  )}
                </div>
              ) : (
                <table className="tbl">
                  <thead>
                    <tr>
                      <th style={{ width: 90 }}>Control</th>
                      <th>Title</th>
                      <th style={{ width: 140 }}>Section</th>
                      <th style={{ width: 110 }}>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {controls.map((c) => (
                      <tr key={c.id} style={{ cursor: 'default' }}>
                        <td className="mono">{c.id}</td>
                        <td>{c.title}</td>
                        <td className="mono" style={{ color: 'var(--text-3)' }}>{c.section}</td>
                        <td>
                          <span className={`ctl-state ${c.state}`}>{c.state.replace('_', ' ')}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          ) : null}
        </>
      ) : null}
    </div>
  )
}
