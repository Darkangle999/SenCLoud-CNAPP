import {
  Activity,
  ArrowLeft,
  Braces,
  Bug,
  Cloud,
  Download,
  ExternalLink,
  FileWarning,
  Globe2,
  KeyRound,
  Network,
  PackageCheck,
  ScanSearch,
  Server,
  ShieldAlert,
  ShieldCheck,
  Tags,
  Wrench,
} from 'lucide-react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useMemo, useState } from 'react'

import { Card, SevBadge, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { api, ApiError } from '../lib/api'
import { num, relTime, shortId, shortType } from '../lib/format'
import type {
  AssetDetail,
  AssetFinding,
  InternetReachability,
  RelatedResource,
  Vulnerability,
  VulnerabilityComponent,
} from '../types'

const TABS = [
  ['overview', 'Overview', ShieldCheck],
  ['findings', 'Findings', FileWarning],
  ['vulnerabilities', 'Vulnerability', Bug],
  ['relationships', 'Relationships', Network],
  ['configuration', 'Configuration', Braces],
  ['activity', 'Activity', Activity],
] as const

type AssetTab = (typeof TABS)[number][0]

function saveJson(name: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = name
  anchor.click()
  URL.revokeObjectURL(url)
}

function primitiveProperties(asset: AssetDetail) {
  return Object.entries(asset.properties ?? {})
    .filter(([, value]) => value === null || ['string', 'number', 'boolean'].includes(typeof value))
}

function isAdministrator(asset: AssetDetail) {
  const entries = Object.entries(asset.properties ?? {})
  return entries.some(([key, value]) => (
    /(admin|administrator|is_admin|has_admin)/i.test(key) && value === true
  ))
}

function scalar(value: unknown) {
  if (value === null || value === undefined || value === '') return '-'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function CoverageBanner({ asset }: { asset: AssetDetail }) {
  const coverage = asset.vulnerability_posture.coverage
  const completed = coverage.status === 'completed' || coverage.status === 'legacy_evidence'
  const countBasis = coverage.evidence.count_basis
  const countLabel = countBasis === 'vulnerable_components'
    ? 'vulnerable components reported'
    : 'packages inspected'
  return (
    <div className={`asset-coverage ${completed ? 'complete' : coverage.status}`}>
      <span className="asset-coverage-icon">
        {completed ? <PackageCheck size={18} /> : <ScanSearch size={18} />}
      </span>
      <div>
        <strong>
          {coverage.status === 'completed'
            ? `${coverage.scanner} scan completed`
            : coverage.status === 'legacy_evidence'
              ? 'Imported vulnerability evidence'
              : coverage.status.replace(/_/g, ' ')}
        </strong>
        <p>
          {coverage.scanned_at
            ? `${relTime(coverage.scanned_at)} - ${num(coverage.package_count ?? 0)} ${countLabel}`
            : coverage.reason}
        </p>
      </div>
      <span className="asset-coverage-count">
        <b>{num(asset.vulnerability_posture.summary.open)}</b>
        open CVEs
      </span>
    </div>
  )
}

const REACHABILITY_COPY: Record<
  InternetReachability['status'],
  { label: string; tone: string; headline: string; detail: string }
> = {
  reachable: {
    label: 'Reachable from the internet',
    tone: 'critical',
    headline: 'A packet path from 0.0.0.0/0 was proven',
    detail: 'Security group, route, internet gateway and network ACL all permit the path.',
  },
  blocked: {
    label: 'Blocked by a network control',
    tone: 'ok',
    headline: 'A public endpoint is configured, but the path does not complete',
    detail: 'This is proof from collected evidence, not an absence of data.',
  },
  unverified: {
    label: 'Unverified - evidence missing',
    tone: 'medium',
    headline: 'The path could not be proven or ruled out',
    detail: 'Missing evidence is a scanner coverage gap. It is not proof that the database is safe.',
  },
  not_applicable: {
    label: 'No public endpoint',
    tone: 'ok',
    headline: 'The resource does not configure a public endpoint',
    detail: 'There is no world-facing path to evaluate.',
  },
}

/**
 * Renders the reachability verdict. `blocked` and `unverified` must never look
 * the same: one means a control is doing its job, the other means we could not
 * see. Showing both as "nothing here" is how a real exposure gets missed.
 */
function ReachabilityPanel({ reachability }: { reachability: InternetReachability }) {
  const copy = REACHABILITY_COPY[reachability.status]
  const { evidence, missing, blockers } = reachability
  const Icon = reachability.status === 'reachable'
    ? ShieldAlert
    : reachability.status === 'unverified' ? ScanSearch : ShieldCheck
  return (
    <div className={`asset-reachability ${reachability.status}`}>
      <div className="asset-reachability-head">
        <span className="asset-reachability-icon"><Icon size={18} /></span>
        <div>
          <strong>{copy.label}</strong>
          <p>{copy.headline}. {copy.detail}</p>
        </div>
      </div>

      {missing.length ? (
        <div className="asset-reachability-block gap">
          <span className="asset-section-label"><ScanSearch size={13} /> Evidence not collected</span>
          <ul>{missing.map((item) => <li key={item}>{item}</li>)}</ul>
          <p className="asset-reachability-hint">
            Grant the scanner role the matching read permissions, then re-scan to get a verdict.
          </p>
        </div>
      ) : null}

      {blockers.length ? (
        <div className="asset-reachability-block">
          <span className="asset-section-label"><ShieldCheck size={13} /> Controls stopping the path</span>
          <ul>{blockers.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      ) : null}

      {evidence.length ? (
        <details className="asset-reachability-evidence">
          <summary>{evidence.length} pieces of evidence</summary>
          <ol>
            {evidence.map((item, index) => (
              <li key={`${item.source}-${index}`}>
                <code>{item.source}</code>
                <span className="mono">{item.observation}</span>
                <em>{item.effect}</em>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </div>
  )
}

function exposureInsight(asset: AssetDetail) {
  const status = asset.internet_reachability?.status
  if (status === 'reachable') return { value: 'Reachable', label: 'network exposure (proven)', tone: 'critical' }
  if (status === 'blocked') return { value: 'Blocked', label: 'network exposure (proven)', tone: 'ok' }
  if (status === 'unverified') return { value: 'Unverified', label: 'network exposure (no evidence)', tone: 'medium' }
  return {
    value: asset.is_public ? 'Public' : 'Private',
    label: 'network exposure',
    tone: asset.is_public ? 'high' : 'ok',
  }
}

function InsightSummary({ asset }: { asset: AssetDetail }) {
  const vulnerability = asset.vulnerability_posture.summary
  const criticalHigh = (vulnerability.by_severity.critical ?? 0) + (vulnerability.by_severity.high ?? 0)
  const exposure = exposureInsight(asset)
  const insights = [
    {
      icon: FileWarning,
      value: asset.findings.length,
      label: 'configuration findings',
      tone: asset.findings.length ? 'high' : 'ok',
    },
    {
      icon: Bug,
      value: criticalHigh,
      label: 'critical and high vulnerabilities',
      tone: criticalHigh ? 'critical' : 'ok',
    },
    {
      icon: KeyRound,
      value: isAdministrator(asset) ? 'Admin' : 'No admin',
      label: 'effective privilege',
      tone: isAdministrator(asset) ? 'critical' : 'ok',
    },
    // A proven verdict outranks the raw flag: a database whose security group
    // is closed is not "Public" just because PubliclyAccessible is set.
    {
      icon: Globe2,
      value: exposure.value,
      label: exposure.label,
      tone: exposure.tone,
    },
    {
      icon: Network,
      value: asset.attack_paths.length,
      label: 'correlated attack paths',
      tone: asset.attack_paths.length ? 'high' : 'ok',
    },
    {
      icon: ShieldCheck,
      value: asset.encryption_enabled === false ? 'Disabled' : asset.encryption_enabled ? 'Enabled' : 'N/A',
      label: 'encryption at rest',
      tone: asset.encryption_enabled === false ? 'medium' : 'ok',
    },
  ]
  return (
    <Card title="Insights summary" i={1}>
      <div className="asset-insights">
        {insights.map(({ icon: Icon, value, label, tone }) => (
          <div key={label} className={`asset-insight ${tone}`}>
            <Icon size={16} />
            <b>{value}</b>
            <span>{label}</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

function Overview({ asset }: { asset: AssetDetail }) {
  const facts = primitiveProperties(asset)
  const reachability = asset.internet_reachability
  return (
    <div className="asset-tab-stack">
      <InsightSummary asset={asset} />
      <div className="asset-overview-grid">
        <Card title="Properties" i={2}>
          {Object.keys(asset.tags ?? {}).length ? (
            <div className="asset-tag-block">
              <span className="asset-section-label"><Tags size={14} /> Tags</span>
              <div className="inventory-tags">
                {Object.entries(asset.tags).map(([key, value]) => (
                  <span className="pill" key={key}>{key}: {scalar(value)}</span>
                ))}
              </div>
            </div>
          ) : null}
          <dl className="asset-property-grid">
            <dt>Name</dt><dd>{asset.name ?? shortId(asset.resource_id)}</dd>
            <dt>Provider ID</dt><dd className="mono">{asset.resource_id}</dd>
            <dt>Cloud platform</dt><dd>{asset.cloud_provider.toUpperCase()}</dd>
            <dt>Native type</dt><dd>{shortType(asset.asset_type)}</dd>
            <dt>Account</dt><dd>{asset.account?.name ?? asset.account?.identifier ?? asset.account_id}</dd>
            <dt>Region</dt><dd>{asset.region}</dd>
            <dt>Status</dt><dd>{asset.is_active ? 'Active' : 'Inactive'}</dd>
            <dt>Created</dt><dd>{asset.resource_created_at ? new Date(asset.resource_created_at).toLocaleString() : '-'}</dd>
            {facts.slice(0, 14).map(([key, value]) => (
              <div className="asset-property-pair" key={key}>
                <dt>{key.replace(/_/g, ' ')}</dt>
                <dd className="mono" title={scalar(value)}>{scalar(value)}</dd>
              </div>
            ))}
          </dl>
          <div className="asset-observed">
            <span>First seen <b>{relTime(asset.first_seen_at)}</b></span>
            <span>Last observed <b>{relTime(asset.last_scanned_at)}</b></span>
          </div>
        </Card>
        <div className="asset-side-stack">
          <Card title="Network insights" i={3}>
            {reachability && reachability.status !== 'not_applicable'
              ? <ReachabilityPanel reachability={reachability} />
              : null}
            <dl className="asset-mini-kv">
              {reachability && reachability.status !== 'not_applicable' ? null : (
                <>
                  {/* No packet-path verdict for this type. Report the config flag
                      in config language — never 'Verified', which is reachability
                      proof this asset does not have. */}
                  <dt>Internet exposure</dt>
                  <dd className={asset.is_public ? 'danger-text' : 'ok-text'}>{asset.is_public ? 'Public (configured)' : 'Private'}</dd>
                </>
              )}
              <dt>Scope</dt><dd>{asset.network_exposure}</dd>
              <dt>Relationships</dt><dd>{asset.relationships.length}</dd>
            </dl>
          </Card>
          <Card title="Workload coverage" i={4}>
            <CoverageBanner asset={asset} />
          </Card>
          <Card title="Risk context" i={5}>
            <dl className="asset-mini-kv">
              <dt>Risk score</dt><dd className="num">{Math.round(asset.risk_score)}/100</dd>
              <dt>Open findings</dt><dd>{asset.findings.length}</dd>
              <dt>Attack paths</dt><dd>{asset.attack_paths.length}</dd>
              <dt>Known exploited CVEs</dt><dd>{asset.vulnerability_posture.summary.kev}</dd>
            </dl>
          </Card>
        </div>
      </div>
    </div>
  )
}

function ComponentTable({ components }: { components: VulnerabilityComponent[] }) {
  return (
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
                  {(['critical', 'high', 'medium', 'low'] as const).map((severity) => (
                    component.by_severity[severity]
                      ? <span key={severity} className={`sev-${severity}`}>{component.by_severity[severity]} {severity[0].toUpperCase()}</span>
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
  )
}

function VulnerabilityRows({ rows }: { rows: Vulnerability[] }) {
  return (
    <div className="asset-table-wrap">
      <table className="tbl asset-cve-table">
        <thead>
          <tr>
            <th>Finding</th>
            <th>Component</th>
            <th>Severity</th>
            <th>CVSS / exploit</th>
            <th>Fix version</th>
            <th>Detection method</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>
                <a
                  href={row.nvd_url ?? `https://nvd.nist.gov/vuln/detail/${row.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="asset-cve-link"
                >
                  <Bug size={14} /> {row.cve_id}
                </a>
                {row.kev ? <span className="kev-badge">KEV</span> : null}
              </td>
              <td><strong>{row.package}</strong><small>{row.installed_version ?? '-'}</small></td>
              <td><SevBadge sev={row.severity} /></td>
              <td className="mono">
                {row.cvss ?? '-'}
                {row.epss != null ? <small>EPSS {(row.epss * 100).toFixed(1)}%</small> : null}
              </td>
              <td className="mono">{row.fixed_version ?? '-'}</td>
              <td><span className="pill">{row.scanner_source}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function VulnerabilitiesTab({ asset }: { asset: AssetDetail }) {
  const posture = asset.vulnerability_posture
  return (
    <div className="asset-tab-stack">
      <CoverageBanner asset={asset} />
      {posture.components.length ? (
        <>
          <Card
            title="Remediation by component"
            right={<span className="label">{num(posture.summary.affected_components)} affected components</span>}
            i={1}
            bodyPad={false}
          >
            <ComponentTable components={posture.components} />
          </Card>
          <Card
            title="Unresolved vulnerabilities"
            right={<span className="label">{num(posture.summary.fixable)} fixable</span>}
            i={2}
            bodyPad={false}
          >
            <VulnerabilityRows rows={posture.items} />
          </Card>
        </>
      ) : (
        <div className="asset-empty">
          <ScanSearch size={28} />
          <strong>
            {posture.coverage.status === 'completed'
              ? 'No vulnerabilities detected in the completed scan'
              : 'No workload vulnerability evidence yet'}
          </strong>
          <p>{posture.coverage.reason ?? 'The scanner completed without open CVEs.'}</p>
          <Link className="btn primary" to="/vulnerabilities">Open vulnerability operations</Link>
        </div>
      )}
    </div>
  )
}

function FindingsTab({ findings }: { findings: AssetFinding[] }) {
  if (!findings.length) {
    return (
      <div className="asset-empty">
        <ShieldCheck size={28} />
        <strong>No open configuration findings</strong>
        <p>This resource has no currently-open posture rule violations.</p>
      </div>
    )
  }
  return (
    <div className="asset-finding-list">
      {findings.map((finding) => (
        <Card key={finding.id} i={1}>
          <div className="asset-finding-head">
            <div><span className="mono">{finding.rule_id}</span><h3>{finding.title}</h3></div>
            <SevBadge sev={finding.severity} />
          </div>
          <p>{finding.why}</p>
          <div className="asset-remediation"><Wrench size={15} /><span>{finding.remediation}</span></div>
        </Card>
      ))}
    </div>
  )
}

function ConfigurationTab({ asset }: { asset: AssetDetail }) {
  return (
    <div className="asset-tab-stack">
      <Card title="Normalized security properties" i={1} bodyPad={false}>
        <div className="asset-table-wrap">
          <table className="tbl asset-config-table">
            <thead><tr><th>Property</th><th>Observed value</th></tr></thead>
            <tbody>
              {Object.entries(asset.properties ?? {}).map(([key, value]) => (
                <tr key={key}><td>{key.replace(/_/g, ' ')}</td><td className="mono">{scalar(value)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <details className="asset-json-panel">
        <summary>Normalized resource JSON</summary>
        <pre className="json">{JSON.stringify(asset.normalized, null, 2)}</pre>
      </details>
      <details className="asset-json-panel">
        <summary>Raw cloud API response</summary>
        <pre className="json">{JSON.stringify(asset.raw, null, 2)}</pre>
      </details>
    </div>
  )
}

function ActivityTab({ asset }: { asset: AssetDetail }) {
  if (!asset.events.length) {
    return <div className="asset-empty"><Activity size={28} /><strong>No recorded changes</strong></div>
  }
  return (
    <div className="asset-timeline">
      {asset.events.map((event, index) => (
        <div className="asset-event" key={`${event.changed_at}:${index}`}>
          <span className="asset-event-dot" />
          <div><strong>{event.event_type.replace(/_/g, ' ')}</strong><span>{event.changed_at ? new Date(event.changed_at).toLocaleString() : '-'}</span></div>
        </div>
      ))}
    </div>
  )
}

const REL_LABELS: Record<string, string> = {
  BELONGS_TO: 'Cloud account',
  USES_SECURITY_GROUP: 'Network Security Group',
  USES_INSTANCE_PROFILE: 'Instance profile',
  EXECUTES_AS: 'Execution role',
  MEMBER_OF: 'IAM group membership',
  BOUNDED_BY: 'Permissions boundary',
}

function relLabel(type: string) {
  return REL_LABELS[type] ?? type.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())
}

// Wiz-style related-resources view: each relationship kind is one card whose
// rows are the resolved target assets (or the raw id when it points outside the
// scanned inventory — an account, a boundary policy, a foreign resource).
function RelationshipsTab({ asset }: { asset: AssetDetail }) {
  const groups = useMemo(() => {
    const map = new Map<string, RelatedResource[]>()
    for (const rel of asset.related_resources ?? []) {
      const list = map.get(rel.type) ?? []
      list.push(rel)
      map.set(rel.type, list)
    }
    return [...map.entries()]
  }, [asset.related_resources])

  if (!groups.length) {
    return (
      <div className="asset-empty">
        <Network size={28} />
        <strong>No related resources</strong>
        <p>No relationships were collected for this asset.</p>
      </div>
    )
  }
  return (
    <div className="asset-tab-stack">
      {groups.map(([type, rels], index) => (
        <Card
          key={type}
          title={relLabel(type)}
          right={<span className="label">{rels.length}</span>}
          i={index + 1}
          bodyPad={false}
        >
          <div className="asset-table-wrap">
            <table className="tbl">
              <thead>
                <tr><th>Resource</th><th>Type</th><th>Region</th><th>Status</th><th>External ID</th></tr>
              </thead>
              <tbody>
                {rels.map((rel) => (
                  <tr key={`${type}:${rel.target_id}`}>
                    <td>
                      {rel.asset ? (
                        <Link to={`/inventory/${rel.asset.id}`} className="asset-cve-link">
                          <Cloud size={14} /> {rel.asset.name}
                        </Link>
                      ) : (
                        <span className="inventory-resource">
                          <span className="inventory-resource-icon"><Globe2 size={15} /></span>
                          <span className="mono">{shortId(rel.target_id)}</span>
                        </span>
                      )}
                    </td>
                    <td>{rel.asset ? shortType(rel.asset.asset_type) : 'External / unresolved'}</td>
                    <td>{rel.asset?.region ?? '-'}</td>
                    <td>
                      {rel.asset
                        ? <span className={rel.asset.is_active ? 'ok-text' : 'hint'}>{rel.asset.is_active ? 'Active' : 'Inactive'}</span>
                        : <span className="hint">Not in inventory</span>}
                    </td>
                    <td className="mono" title={rel.target_id}>{shortId(rel.target_id)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ))}
    </div>
  )
}

export function AssetDetails() {
  const { assetId } = useParams()
  const [params, setParams] = useSearchParams()
  const requestedTab = params.get('tab') as AssetTab | null
  const tab: AssetTab = TABS.some(([key]) => key === requestedTab) ? requestedTab! : 'overview'
  const id = Number(assetId)
  const detail = useApi(
    () => (
      Number.isFinite(id)
        ? api.asset(id)
        : Promise.reject(new ApiError('GET', `/api/inventory/assets/${assetId}`, 400, 'Invalid asset id'))
    ),
    [id],
  )
  const [sbomBusy, setSbomBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const asset = detail.data
  const resourceLabel = useMemo(
    () => asset?.name ?? (asset ? shortId(asset.resource_id) : 'Resource'),
    [asset],
  )

  async function downloadSbom() {
    if (!asset) return
    setSbomBusy(true)
    try {
      const result = await api.generateImageSbom(asset.resource_id, asset.region)
      if (!result.generated) {
        setNotice(result.skipped_reason || 'SBOM generation was skipped.')
        return
      }
      saveJson(`${shortId(asset.resource_id)}.cdx.json`, result.sbom)
      setNotice(`CycloneDX SBOM downloaded with ${result.component_count} components.`)
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error))
    } finally {
      setSbomBusy(false)
      setTimeout(() => setNotice(null), 5200)
    }
  }

  return (
    <div className="page asset-details-page">
      <StateView loading={detail.loading} error={detail.error} empty={!detail.loading && !detail.error && !asset}>
        {asset ? (
          <>
            <Link to="/inventory" className="asset-back"><ArrowLeft size={14} /> Cloud inventory</Link>
            <header className="asset-hero">
              <div className="asset-hero-identity">
                <span className="asset-hero-icon"><Server size={22} /></span>
                <div>
                  <span className="crumb">{asset.cloud_provider.toUpperCase()} / {shortType(asset.asset_type)}</span>
                  <h1>{resourceLabel}</h1>
                  <p className="mono" title={asset.resource_id}>{asset.resource_id}</p>
                </div>
              </div>
              <div className="asset-actions">
                {asset.cloud_console_url ? (
                  <a className="btn" href={asset.cloud_console_url} target="_blank" rel="noreferrer">
                    <Cloud size={14} /> Open in AWS <ExternalLink size={12} />
                  </a>
                ) : null}
                <button className="btn" onClick={() => saveJson(`${shortId(asset.resource_id)}.json`, asset)}>
                  <Braces size={14} /> JSON
                </button>
                <button
                  className="btn"
                  onClick={downloadSbom}
                  disabled={sbomBusy || asset.vulnerability_posture.coverage.scanner !== 'trivy'}
                  title={asset.vulnerability_posture.coverage.scanner === 'trivy' ? 'Generate a CycloneDX SBOM with Trivy' : 'SBOM is available for Trivy-scanned container images'}
                >
                  <Download size={14} /> {sbomBusy ? 'Generating...' : 'Download SBOM'}
                </button>
              </div>
            </header>

            <nav className="asset-tabs" aria-label="resource detail sections" role="tablist">
              {TABS.map(([key, label, Icon]) => (
                <button
                  key={key}
                  role="tab"
                  aria-selected={tab === key}
                  className={tab === key ? 'active' : ''}
                  onClick={() => setParams(key === 'overview' ? {} : { tab: key })}
                >
                  <Icon size={15} /> {label}
                  {key === 'findings' && asset.findings.length ? <b>{asset.findings.length}</b> : null}
                  {key === 'vulnerabilities' && asset.vulnerability_posture.summary.open ? <b>{asset.vulnerability_posture.summary.open}</b> : null}
                  {key === 'relationships' && asset.related_resources?.length ? <b>{asset.related_resources.length}</b> : null}
                </button>
              ))}
            </nav>

            <main className="asset-tab-content">
              {tab === 'overview' ? <Overview asset={asset} /> : null}
              {tab === 'findings' ? <FindingsTab findings={asset.findings} /> : null}
              {tab === 'vulnerabilities' ? <VulnerabilitiesTab asset={asset} /> : null}
              {tab === 'relationships' ? <RelationshipsTab asset={asset} /> : null}
              {tab === 'configuration' ? <ConfigurationTab asset={asset} /> : null}
              {tab === 'activity' ? <ActivityTab asset={asset} /> : null}
            </main>
          </>
        ) : null}
      </StateView>
      {notice ? <div className="toast">{notice}</div> : null}
    </div>
  )
}
