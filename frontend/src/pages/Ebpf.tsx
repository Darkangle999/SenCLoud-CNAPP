import { useMemo, useState } from 'react'

import { Card, PageHead, StatCard, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { num, relTime, shortId } from '../lib/format'
import type { Agent, AgentStatus } from '../types'

// Liveness status → label + dot colour. A supported host with no sensor is a real
// coverage blind spot (loud); an unsupported OS (eBPF is Linux-only) is muted.
const STATUS: Record<AgentStatus, { label: string; dot: string }> = {
  online: { label: 'online', dot: 'sev-low' },
  stale: { label: 'stale', dot: 'sev-high' },
  no_sensor: { label: 'no sensor', dot: 'sev-critical' },
  unsupported: { label: 'unsupported', dot: 'hollow' },
}

const OS_LABEL: Record<string, string> = {
  linux: 'Linux', windows: 'Windows', unknown: 'Unknown',
}

function StatusBadge({ s }: { s: AgentStatus }) {
  const cfg = STATUS[s]
  return (
    <span className="sev-badge" style={{ color: 'var(--text-2)', gap: 6 }}>
      <span className={`dot ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

export function Ebpf() {
  const [os, setOs] = useState('all')
  const { accountId } = useAccountScope()
  const agents = useApi(() => api.runtimeAgents(accountId), [accountId])
  const findings = useApi(
    () => api.runtimeFindings({ account_id: accountId ?? undefined, limit: 200 }),
    [accountId],
  )

  const osOptions = useMemo(
    () => ['all', ...Object.keys(agents.data?.by_os ?? {}).sort()],
    [agents.data],
  )

  // Group the (OS-filtered) agents by OS platform for the categorized view.
  const groups = useMemo(() => {
    const items = (agents.data?.items ?? []).filter((a) => os === 'all' || a.os === os)
    const by: Record<string, Agent[]> = {}
    for (const a of items) (by[a.os] ??= []).push(a)
    return Object.entries(by).sort((a, b) => b[1].length - a[1].length)
  }, [agents.data, os])

  const st = agents.data?.by_status ?? {}

  return (
    <div className="page">
      <PageHead
        crumb="runtime"
        title="eBPF Sensors"
        sub="Kernel-level runtime agents by OS platform, with deployment coverage and detection findings. eBPF runs on Linux only."
      />

      <div className="grid-stats" style={{ marginBottom: 12 }}>
        <StatCard i={1} label="Online" value={agents.data ? num(st.online ?? 0) : null} sub="reporting recently" />
        <StatCard i={2} label="Stale" value={agents.data ? num(st.stale ?? 0) : null} sub="no recent events" />
        <StatCard i={3} label="No sensor" value={agents.data ? num(st.no_sensor ?? 0) : null} sub="Linux host, not deployed" crit={(st.no_sensor ?? 0) > 0} />
        <StatCard i={4} label="Unsupported" value={agents.data ? num(st.unsupported ?? 0) : null} sub="non-Linux OS" />
      </div>

      <div className="control-row reveal" style={{ ['--i' as string]: 1 }}>
        <select
          className="select"
          value={os}
          onChange={(e) => setOs(e.target.value)}
          aria-label="OS platform filter"
        >
          {osOptions.map((o) => (
            <option key={o} value={o}>
              {o === 'all' ? 'platform: all' : OS_LABEL[o] ?? o}
            </option>
          ))}
        </select>
      </div>

      <Card title="Agents by platform" i={2} bodyPad={false}>
        <StateView
          loading={agents.loading}
          error={agents.error}
          empty={!!agents.data && groups.length === 0}
          emptyHint="No hosts found. Run an inventory scan to discover EC2 hosts, or deploy the sensor to start reporting runtime events."
        >
          {groups.map(([osKey, list]) => (
            <div key={osKey} style={{ borderTop: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px 2px' }}>
                <span style={{ fontSize: 11, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--text-3)' }}>
                  {OS_LABEL[osKey] ?? osKey}
                </span>
                <span className="pill tint">{num(list.length)}</span>
                {osKey !== 'linux' && osKey !== 'unknown' ? (
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>eBPF unsupported</span>
                ) : null}
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>OS</th>
                    <th>Region</th>
                    <th>Status</th>
                    <th style={{ textAlign: 'right' }}>Events</th>
                    <th style={{ textAlign: 'right' }}>Findings</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((a) => (
                    <tr key={a.host} style={{ cursor: 'default' }}>
                      <td className="cell-name" title={a.resource_id}>{a.name ?? a.host}</td>
                      <td className="mono" title={a.os_detail}>{a.os_detail}</td>
                      <td className="mono">{a.region ?? '—'}</td>
                      <td><StatusBadge s={a.status} /></td>
                      <td className="num" style={{ textAlign: 'right' }}>{a.events ? num(a.events) : '—'}</td>
                      <td
                        className="num"
                        style={{ textAlign: 'right', color: a.findings ? 'var(--sev-high)' : 'var(--text-3)' }}
                      >
                        {a.findings ? num(a.findings) : '—'}
                      </td>
                      <td className="mono">{a.last_seen ? relTime(a.last_seen) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </StateView>
      </Card>

      <div style={{ marginTop: 12 }}>
        <Card title="Runtime detection findings" i={3} bodyPad={false}>
          <StateView
            loading={findings.loading}
            error={findings.error}
            empty={!!findings.data && findings.data.items.length === 0}
            emptyHint="No runtime findings yet. The sensor raises these when a detection rule fires on a host."
          >
            <table className="tbl">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Host</th>
                  <th>Process</th>
                  <th>Technique</th>
                  <th>Seen</th>
                </tr>
              </thead>
              <tbody>
                {(findings.data?.items ?? []).map((e) => (
                  <tr key={e.id} style={{ cursor: 'default' }}>
                    <td className="cell-name" title={e.rule_id ?? ''}>{e.rule_name ?? e.rule_id ?? e.event_type}</td>
                    <td>
                      <span className="sev-badge" style={{ color: 'var(--text-2)' }}>
                        <span className={`dot sev-${e.severity}`} />
                        {e.severity}
                      </span>
                    </td>
                    <td className="mono" title={e.resource_id ?? ''}>{e.resource_id ? shortId(e.resource_id) : '—'}</td>
                    <td className="mono" title={e.command ?? e.process ?? ''}>{e.command || e.process || '—'}</td>
                    <td className="mono">{[e.tactic, e.technique].filter(Boolean).join(' · ') || '—'}</td>
                    <td className="mono">{e.observed_at ? relTime(e.observed_at) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </StateView>
        </Card>
      </div>
    </div>
  )
}
