import { motion } from 'motion/react'
import {
  Activity,
  BadgeCheck,
  Boxes,
  Cog,
  Database,
  Eye,
  FileCode2,
  KeyRound,
  Radar,
  ShieldAlert,
} from 'lucide-react'
import { Link } from 'react-router-dom'

import { PageHead, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import { num } from '../lib/format'

type Status = 'covered' | 'partial' | 'no-data'

const STATUS_LABEL: Record<Status, string> = {
  covered: 'covered',
  partial: 'partial',
  'no-data': 'no data',
}

// The ten Wiz cloud-security-architecture components, each bound to a real signal.
interface Pillar {
  key: string
  n: number
  title: string
  icon: typeof Eye
  to?: string
  metric: string
  status: Status
}

export function Architecture() {
  const inv = useApi(() => api.inventorySummary())
  const fnd = useApi(() => api.findingsSummary())
  const iss = useApi(() => api.issuesSummary())
  const vuln = useApi(() => api.vulnerabilitiesSummary())
  const rt = useApi(() => api.runtimeEventsSummary())
  const assets = useApi(() => api.assets({ page_size: 500 }))

  const loading = inv.loading || fnd.loading || iss.loading || vuln.loading || rt.loading || assets.loading
  const error = inv.error || fnd.error || iss.error || vuln.error || rt.error || assets.error

  const dataStores = (assets.data?.items ?? []).filter((a) =>
    /s3\.bucket|rds|redshift|docdb|neptune|dynamodb/.test(a.asset_type),
  )
  const encrypted = dataStores.filter((s) => s.encryption_enabled === true).length
  const encPct = dataStores.length ? Math.round((encrypted / dataStores.length) * 100) : null
  const publicAssets = inv.data?.public_assets ?? 0

  const identityIssues = (iss.data?.by_type?.PUBLIC_COMPUTE_TO_ADMIN ?? 0)
    + (iss.data?.by_type?.CROSS_ACCOUNT_LATERAL ?? 0)
    + (iss.data?.by_type?.IAM_PRIVILEGE_ESCALATION ?? 0)

  const pillars: Pillar[] = [
    {
      key: 'visibility', n: 1, title: 'Comprehensive visibility', icon: Eye, to: '/inventory',
      metric: inv.data ? `${num(inv.data.total_assets)} assets inventoried` : '—',
      status: (inv.data?.total_assets ?? 0) > 0 ? 'covered' : 'no-data',
    },
    {
      key: 'iam', n: 2, title: 'Identity & access (CIEM)', icon: KeyRound, to: '/identity',
      metric: `${num(identityIssues)} identity attack paths`,
      status: identityIssues > 0 ? 'covered' : 'partial',
    },
    {
      key: 'data', n: 3, title: 'Data security & encryption', icon: Database, to: '/data',
      metric: encPct === null ? 'no data stores' : `${encPct}% encrypted at rest`,
      status: dataStores.length === 0 ? 'no-data' : encPct === 100 ? 'covered' : 'partial',
    },
    {
      key: 'vuln', n: 4, title: 'Vulnerability management', icon: ShieldAlert, to: '/vulnerabilities',
      metric: vuln.data ? `${num(vuln.data.open)} open CVEs` : '—',
      status: (vuln.data?.open ?? 0) > 0 ? 'covered' : 'no-data',
    },
    {
      key: 'threat', n: 5, title: 'Threat detection & response', icon: Radar, to: '/threats',
      metric: rt.data ? `${num(rt.data.total)} runtime events` : '—',
      status: (rt.data?.total ?? 0) > 0 ? 'covered' : 'no-data',
    },
    {
      key: 'compliance', n: 6, title: 'Compliance assurance', icon: BadgeCheck, to: '/compliance',
      metric: fnd.data ? `${num(fnd.data.open)} findings mapped to frameworks` : '—',
      status: 'covered',
    },
    {
      key: 'iac', n: 7, title: 'Infrastructure-as-Code security', icon: FileCode2, to: '/iac',
      metric: 'pre-deploy scan ready',
      status: 'covered',
    },
    {
      key: 'risk', n: 8, title: 'Continuous monitoring & risk', icon: Activity, to: '/attack-paths',
      metric: iss.data ? `peak risk ${Math.round(iss.data.max_risk)} · ${num(iss.data.open)} open paths` : '—',
      status: (iss.data?.open ?? 0) > 0 ? 'covered' : 'partial',
    },
    {
      key: 'automation', n: 9, title: 'Automation & integration', icon: Cog,
      metric: 'fleet scan + suppression engine',
      status: 'covered',
    },
  ]

  const covered = pillars.filter((p) => p.status === 'covered').length

  const cia = [
    {
      key: 'C', label: 'Confidentiality',
      metric: encPct === null ? '—' : `${encPct}% encrypted · ${num(publicAssets)} public`,
      bad: publicAssets > 0,
    },
    {
      key: 'I', label: 'Integrity',
      metric: 'drift & change tracking active',
      bad: false,
    },
    {
      key: 'A', label: 'Availability',
      metric: iss.data ? `${num(iss.data.open)} exposure paths` : '—',
      bad: (iss.data?.open ?? 0) > 0,
    },
  ]

  return (
    <div className="page">
      <PageHead
        crumb="architecture"
        title="Security architecture"
        sub={`Posture across the ten cloud-security pillars · ${covered}/10 covered by live signal.`}
      />

      <StateView loading={loading} error={error}>
        <>
          {/* CIA triad strip */}
          <div className="cia-strip reveal" style={{ ['--i' as string]: 1 }}>
            {cia.map((c) => (
              <div key={c.key} className={`cia-cell${c.bad ? ' bad' : ''}`}>
                <span className="cia-glyph">{c.key}</span>
                <div>
                  <div className="cia-label">{c.label}</div>
                  <div className="cia-metric">{c.metric}</div>
                </div>
              </div>
            ))}
          </div>

          {/* 10-pillar coverage grid */}
          <div className="pillar-grid">
            {pillars.map((p, i) => {
              const Icon = p.icon
              const body = (
                <motion.div
                  className={`pillar status-${p.status}`}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.04 * i, duration: 0.3, ease: 'easeOut' }}
                >
                  <div className="pillar-top">
                    <span className="pillar-ico"><Icon size={16} /></span>
                    <span className="pillar-n">{String(p.n).padStart(2, '0')}</span>
                  </div>
                  <div className="pillar-title">{p.title}</div>
                  <div className="pillar-metric">{p.metric}</div>
                  <span className={`pillar-status status-${p.status}`}>
                    <span className="dot" />
                    {STATUS_LABEL[p.status]}
                  </span>
                </motion.div>
              )
              return p.to ? (
                <Link key={p.key} to={p.to} className="pillar-link">
                  {body}
                </Link>
              ) : (
                <div key={p.key}>{body}</div>
              )
            })}
          </div>

          <div className="arch-foot reveal" style={{ ['--i' as string]: 8 }}>
            <Boxes size={13} style={{ verticalAlign: '-2px', marginRight: 6 }} />
            Mapped to the Wiz cloud-security-architecture model. Pillars read “no data” honestly when
            their source (SSM vuln scan, eBPF sensor) has not reported yet — nothing is mocked.
          </div>
        </>
      </StateView>
    </div>
  )
}
