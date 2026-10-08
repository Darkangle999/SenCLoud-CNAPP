import { RefreshCw, Wrench } from 'lucide-react'
import { useMemo, useState } from 'react'

import { Drawer } from '../components/Drawer'
import { Card, PageHead, SevBadge, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api, ApiError } from '../lib/api'
import { num, relTime, shortId } from '../lib/format'
import type { Vulnerability, VulnerabilityComponent } from '../types'

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'] as const

function componentGroups(rows: Vulnerability[]): VulnerabilityComponent[] {
  const groups = new Map<string, VulnerabilityComponent>()
  rows.forEach((row) => {
    const key = `${row.package}\u0000${row.installed_version ?? ''}\u0000${row.package_type ?? ''}`
    const group = groups.get(key) ?? {
      package: row.package,
      installed_version: row.installed_version,
      package_type: row.package_type,
      fixed_versions: [],
      paths: [],
      targets: [],
      scanner_sources: [],
      vulnerability_count: 0,
      fixable_count: 0,
      by_severity: {},
    }
    group.vulnerability_count += 1
    group.by_severity[row.severity] = (group.by_severity[row.severity] ?? 0) + 1
    if (row.fixed_version) {
      group.fixable_count += 1
      if (!group.fixed_versions.includes(row.fixed_version)) group.fixed_versions.push(row.fixed_version)
    }
    if (row.package_path && !group.paths.includes(row.package_path)) group.paths.push(row.package_path)
    if (row.target && !group.targets.includes(row.target)) group.targets.push(row.target)
    if (!group.scanner_sources.includes(row.scanner_source)) group.scanner_sources.push(row.scanner_source)
    groups.set(key, group)
  })
  return [...groups.values()].sort((a, b) => (
    (b.by_severity.critical ?? 0) - (a.by_severity.critical ?? 0)
    || (b.by_severity.high ?? 0) - (a.by_severity.high ?? 0)
    || b.vulnerability_count - a.vulnerability_count
  ))
}

export function Vulnerabilities() {
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>('all')
  const [status, setStatus] = useState<'open' | 'resolved'>('open')
  const [selected, setSelected] = useState<Vulnerability | null>(null)
  const [scanning, setScanning] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const { accountId } = useAccountScope()
  const summary = useApi(() => api.vulnerabilitiesSummary(accountId), [accountId])
  const accounts = useApi(() => api.accounts())
  const vulns = useApi(
    () => api.vulnerabilities({ account_id: accountId ?? undefined, status, severity: severity === 'all' ? undefined : severity }),
    [accountId, status, severity],
  )
  const components = useMemo(() => componentGroups(vulns.data?.items ?? []), [vulns.data])

  async function scan() {
    const account = accounts.data?.items[0]
    if (!account) return
    setScanning(true)
    try {
      const r = await api.scanVulnerabilities(account.provider, account.account_identifier)
      setToast(
        `scanned ${r.instances_scanned} instances (${r.ssm_managed} SSM-managed) · ${r.new} new CVEs`,
      )
      vulns.refetch()
      summary.refetch()
    } catch (e) {
      setToast(e instanceof ApiError ? e.message : String(e))
    } finally {
      setScanning(false)
      setTimeout(() => setToast(null), 5200)
    }
  }

  async function scanImages() {
    const account = accounts.data?.items[0]
    if (!account) return
    setScanning(true)
    try {
      const r = await api.scanContainerImages(account.provider, account.account_identifier)
      setToast(
        `scanned ${r.images_scanned}/${r.images_discovered} ECR images · ${r.new} new CVEs`,
      )
      vulns.refetch()
      summary.refetch()
    } catch (e) {
      setToast(e instanceof ApiError ? e.message : String(e))
    } finally {
      setScanning(false)
      setTimeout(() => setToast(null), 5200)
    }
  }

  return (
    <div className="page">
      <PageHead
        crumb="vulnerabilities"
        title="Vulnerabilities"
        sub={
          summary.data
            ? `${num(summary.data.open)} open CVEs · ${num(summary.data.affected_assets)} affected workloads`
              + ` · ${num(summary.data.kev ?? 0)} KEV · ${num(summary.data.high_epss ?? 0)} high-EPSS`
            : 'Package CVEs on workloads (SSM package inventory → OSV), weighted by EPSS + CISA KEV.'
        }
        actions={
          <>
            <button
              className="btn"
              onClick={scanImages}
              disabled={scanning || !accounts.data?.items.length}
              title="Scan ECR container images with Trivy → CVE match"
            >
              <RefreshCw style={scanning ? { animation: 'spin 0.7s linear infinite' } : undefined} />
              {scanning ? 'Scanning…' : 'Scan images'}
            </button>
            <button
              className="btn primary"
              onClick={scan}
              disabled={scanning || !accounts.data?.items.length}
              title="SSM package inventory of EC2 → OSV match"
            >
              <RefreshCw style={scanning ? { animation: 'spin 0.7s linear infinite' } : undefined} />
              {scanning ? 'Scanning…' : 'Scan workloads'}
            </button>
          </>
        }
      />

      <div className="control-row reveal" style={{ ['--i' as string]: 1 }}>
        <div className="seg-ctl" role="tablist" aria-label="status">
          {(['open', 'resolved'] as const).map((s) => (
            <button key={s} className={status === s ? 'on' : ''} onClick={() => setStatus(s)}>
              {s}
            </button>
          ))}
        </div>
        <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value as never)} aria-label="severity filter">
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s === 'all' ? 'severity: all' : s}
            </option>
          ))}
        </select>
      </div>

      {components.length ? (
        <Card
          title="Remediation by affected component"
          right={<span className="label">{num(components.length)} components</span>}
          i={2}
          bodyPad={false}
        >
          <div className="asset-table-wrap">
            <table className="tbl asset-component-table">
              <thead>
                <tr>
                  <th>Component name</th>
                  <th>Version</th>
                  <th>Fixed version</th>
                  <th>Vulnerabilities</th>
                  <th>File path / target</th>
                  <th>Remediation</th>
                </tr>
              </thead>
              <tbody>
                {components.map((component) => (
                  <tr key={`${component.package}:${component.installed_version}:${component.package_type}`}>
                    <td>
                      <strong>{component.package}</strong>
                      <small>{component.package_type ?? 'package'} - {component.scanner_sources.join(', ')}</small>
                    </td>
                    <td className="mono">{component.installed_version ?? '-'}</td>
                    <td className="mono">{component.fixed_versions.join(', ') || '-'}</td>
                    <td>
                      <div className="asset-severity-counts">
                        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
                          component.by_severity[sev]
                            ? <span className={`sev-${sev}`} key={sev}>{component.by_severity[sev]} {sev[0].toUpperCase()}</span>
                            : null
                        ))}
                      </div>
                    </td>
                    <td className="asset-path-cell" title={[...component.paths, ...component.targets].join('\n')}>
                      {component.paths[0] ?? component.targets[0] ?? '-'}
                    </td>
                    <td>
                      {component.fixable_count
                        ? <span className="asset-fix"><Wrench size={13} /> Upgrade</span>
                        : <span className="hint">Vendor fix pending</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}

      <Card title={`${status === 'open' ? 'Unresolved' : 'Resolved'} vulnerabilities`} i={3} bodyPad={false}>
        <StateView
          loading={vulns.loading}
          error={vulns.error}
          empty={!!vulns.data && vulns.data.items.length === 0}
          emptyHint={
            status === 'open'
              ? 'No CVEs. Vulnerabilities only appear for SSM-managed, Online EC2 — hit “Scan workloads”.'
              : 'Nothing resolved yet.'
          }
        >
          {vulns.data ? (
            <div>
              {vulns.data.items.map((v) => (
                <div
                  key={v.id}
                  className={`frow sev-${v.severity}${v.status === 'resolved' ? ' resolved' : ''}`}
                  onClick={() => setSelected(v)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => e.key === 'Enter' && setSelected(v)}
                >
                  <span className="pill" style={{ flexShrink: 0 }}>{v.cve_id}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="t">
                      {v.kev && <span className="kev-badge" title="CISA Known Exploited Vulnerability — confirmed exploited in the wild">KEV</span>}
                      {v.package}
                      {v.installed_version ? ` @ ${v.installed_version}` : ''}
                    </div>
                    <div className="r" title={v.resource_id}>{shortId(v.resource_id)}</div>
                  </div>
                  {v.epss != null ? (
                    <span className={`mono epss${v.epss >= 0.5 ? ' hot' : ''}`} style={{ fontSize: 11, flexShrink: 0 }}
                      title={`EPSS — exploitation probability${v.epss_percentile != null ? ` · ${Math.round(v.epss_percentile * 100)}th pct` : ''}`}>
                      EPSS {(v.epss * 100).toFixed(v.epss >= 0.1 ? 0 : 1)}%
                    </span>
                  ) : null}
                  {v.cvss != null ? (
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', flexShrink: 0 }}>
                      CVSS {v.cvss}
                    </span>
                  ) : null}
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', width: 72, textAlign: 'right', flexShrink: 0 }}>
                    {relTime(v.status === 'resolved' ? v.resolved_at : v.first_seen_at)}
                  </span>
                  <span style={{ width: 86, flexShrink: 0, textAlign: 'right' }}>
                    <SevBadge sev={v.severity} />
                  </span>
                </div>
              ))}
            </div>
          ) : null}
        </StateView>
      </Card>

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.cve_id}
        subtitle={selected?.resource_id}
      >
        {selected ? (
          <>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <SevBadge sev={selected.severity} />
              <span className="pill">{selected.package}</span>
              <span className="pill tint">{selected.status}</span>
            </div>
            <div className="drawer-section">
              <span className="label">Details</span>
              <dl className="kv">
                <dt>installed</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>{selected.installed_version ?? '—'}</dd>
                <dt>fixed in</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>{selected.fixed_version ?? '—'}</dd>
                <dt>CVSS</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>{selected.cvss ?? '—'}</dd>
                <dt>EPSS</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>
                  {selected.epss != null
                    ? `${(selected.epss * 100).toFixed(2)}%${selected.epss_percentile != null ? ` (${Math.round(selected.epss_percentile * 100)}th pct)` : ''}`
                    : '—'}
                </dd>
                <dt>KEV</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>
                  {selected.kev ? 'yes — exploited in the wild' : 'no'}
                </dd>
              </dl>
            </div>
            {selected.summary ? (
              <div className="drawer-section">
                <span className="label">Summary</span>
                <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6 }}>{selected.summary}</p>
              </div>
            ) : null}
            <div className="drawer-section">
              <span className="label">Remediation</span>
              <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6 }}>
                {selected.fixed_version
                  ? `Upgrade ${selected.package} to ${selected.fixed_version} or later.`
                  : `Patch ${selected.package} to a fixed release; subscribe to the vendor advisory for ${selected.cve_id}.`}
              </p>
            </div>

            {selected.cve_id.startsWith('CVE-') ? (
              <div className="drawer-section">
                <span className="label">CVE references</span>
                <div className="cve-refs">
                  <a href={`https://nvd.nist.gov/vuln/detail/${selected.cve_id}`} target="_blank" rel="noreferrer">
                    NVD — full CVSS vector, CWE, references ↗
                  </a>
                  <a href={`https://www.cve.org/CVERecord?id=${selected.cve_id}`} target="_blank" rel="noreferrer">
                    CVE.org record ↗
                  </a>
                  <a href={`https://osv.dev/vulnerability/${selected.cve_id}`} target="_blank" rel="noreferrer">
                    OSV — affected ranges &amp; advisories ↗
                  </a>
                </div>
              </div>
            ) : null}
            <div className="drawer-section">
              <span className="label">Timeline</span>
              <dl className="kv">
                <dt>first seen</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>{selected.first_seen_at ?? '—'}</dd>
                <dt>last seen</dt>
                <dd className="mono" style={{ fontSize: 11.5 }}>{selected.last_seen_at ?? '—'}</dd>
              </dl>
            </div>
          </>
        ) : null}
      </Drawer>

      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}
