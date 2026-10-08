import {
  ArrowRight,
  BadgeCheck,
  Boxes,
  CloudCog,
  FileCode2,
  Radar,
  Route,
  ShieldAlert,
  Wrench,
} from 'lucide-react'
import { motion, useReducedMotion } from 'motion/react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { api } from '../lib/api'
import { num, shortType } from '../lib/format'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { PERSONAS, usePersona } from '../lib/persona'
import type { Persona } from '../lib/persona'
import { AttackPathOverview } from '../components/AttackPathOverview'
import { ScoreColumns, SeverityDonut, TrendArea } from '../components/charts'
import { BarList, Card, PageHead, StatCard, StateView } from '../components/ui'
import type { InventorySummary, PillarStatus } from '../types'

const ROLE_CONTENT: Record<Persona, {
  summary: string
  primary: { to: string; label: string }
  secondary: { to: string; label: string }
  actions: Array<{ to: string; title: string; detail: string; icon: typeof ShieldAlert }>
}> = {
  executive: {
    summary: 'Focus on material exposure, accountable ownership and whether risk is moving in the right direction.',
    primary: { to: '/attack-paths', label: 'Review material risk' },
    secondary: { to: '/compliance', label: 'View assurance posture' },
    actions: [
      { to: '/attack-paths', title: 'Review attack paths', detail: 'See the routes that can lead to account or data compromise.', icon: Route },
      { to: '/compliance', title: 'Assess assurance', detail: 'Track control posture, drift and evidence coverage.', icon: BadgeCheck },
      { to: '/architecture', title: 'Understand exposure', detail: 'See how cloud, identity, data and runtime risk connect.', icon: Radar },
    ],
  },
  analyst: {
    summary: 'Start with the highest-confidence signal, validate its evidence and follow the full attacker route.',
    primary: { to: '/findings', label: 'Start triage' },
    secondary: { to: '/attack-paths', label: 'Open attack paths' },
    actions: [
      { to: '/findings', title: 'Triage new findings', detail: 'Validate severity, evidence and affected resources.', icon: ShieldAlert },
      { to: '/attack-paths', title: 'Trace blast radius', detail: 'Follow exposure from entry point to identity and data.', icon: Route },
      { to: '/threats', title: 'Check runtime activity', detail: 'Review active workload signals and suspicious behavior.', icon: Radar },
    ],
  },
  engineer: {
    summary: 'Turn prioritized risk into concrete cloud changes, then verify that the finding closes after a scan.',
    primary: { to: '/findings', label: 'Open remediation queue' },
    secondary: { to: '/iac', label: 'Validate infrastructure code' },
    actions: [
      { to: '/findings', title: 'Fix assigned risk', detail: 'Use resource evidence and remediation guidance to close exposure.', icon: Wrench },
      { to: '/identity', title: 'Reduce permissions', detail: 'Inspect admin, trust and privilege-escalation conditions.', icon: CloudCog },
      { to: '/iac', title: 'Prevent regression', detail: 'Check Terraform or CloudFormation before deployment.', icon: FileCode2 },
    ],
  },
  grc: {
    summary: 'Understand assessed coverage, investigate failed controls and keep unassessed scope visible for audit.',
    primary: { to: '/compliance', label: 'Review controls' },
    secondary: { to: '/findings', label: 'Trace failed evidence' },
    actions: [
      { to: '/compliance', title: 'Review control posture', detail: 'Inspect passed, failed and not-assessed controls.', icon: BadgeCheck },
      { to: '/findings', title: 'Trace control evidence', detail: 'Connect technical findings to frameworks and remediation.', icon: ShieldAlert },
      { to: '/accounts', title: 'Confirm scope', detail: 'Verify every required account is connected and reporting.', icon: Boxes },
    ],
  },
}

function GuidedWorkflow({ accounts, assets, findings }: { accounts: number; assets: number; findings: number }) {
  const steps = [
    { label: 'Connect', detail: 'Cloud account', done: accounts > 0, to: '/accounts' },
    { label: 'Discover', detail: 'Assets & context', done: assets > 0, to: '/inventory' },
    { label: 'Prioritize', detail: 'Material risk', done: assets > 0, to: '/findings' },
    { label: 'Act', detail: 'Fix or decide', done: findings === 0 && assets > 0, to: '/findings' },
    { label: 'Verify', detail: 'Re-scan & report', done: findings === 0 && assets > 0, to: '/compliance' },
  ]
  const firstIncomplete = steps.findIndex((step) => !step.done)
  const active = firstIncomplete === -1 ? steps.length - 1 : firstIncomplete

  return (
    <section className="journey" aria-label="Security posture workflow">
      <div className="journey-head">
        <div>
          <span className="label">Operating workflow</span>
          <h2>From cloud connection to verified remediation</h2>
        </div>
        <span className="journey-status">Step {Math.min(active + 1, steps.length)} of {steps.length}</span>
      </div>
      <div className="journey-steps">
        {steps.map((step, index) => (
          <Link
            key={step.label}
            to={step.to}
            className={`journey-step${step.done ? ' done' : ''}${index === active ? ' current' : ''}`}
            aria-current={index === active ? 'step' : undefined}
          >
            <span className="journey-index">{step.done ? '✓' : index + 1}</span>
            <span><strong>{step.label}</strong><small>{step.detail}</small></span>
          </Link>
        ))}
      </div>
    </section>
  )
}

// Per-region service breakdown: real regions are expandable to their asset-type
// (service) counts; account-wide "global" assets (IAM, …) are split into their
// own section rather than masquerading as a region.
function RegionBreakdown({ data }: { data: InventorySummary }) {
  const [open, setOpen] = useState<string | null>(null)
  const byRegionType = data.by_region_type ?? {}
  const total = (m: Record<string, number>) => Object.values(m).reduce((a, b) => a + b, 0)

  const regions = Object.entries(byRegionType)
    .filter(([r]) => r !== 'global')
    .sort((a, b) => total(b[1]) - total(a[1]))
  const global = byRegionType['global']

  const services = (m: Record<string, number>) =>
    Object.entries(m).sort((a, b) => b[1] - a[1])

  return (
    <>
      <div style={{ borderTop: '1px solid var(--border)' }}>
        <div style={{ padding: '8px 16px 2px', fontSize: 11, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--text-3)' }}>
          Regions ({regions.length})
        </div>
        {regions.map(([region, svc]) => {
          const isOpen = open === region
          return (
            <div key={region} style={{ borderTop: '1px solid var(--hairline)' }}>
              <button
                onClick={() => setOpen(isOpen ? null : region)}
                aria-expanded={isOpen}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                  padding: '7px 16px', background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--text-1)', font: 'inherit', textAlign: 'left',
                }}
              >
                <span className="mono" style={{ width: 12, color: 'var(--text-3)' }}>{isOpen ? '▾' : '▸'}</span>
                <span className="mono" style={{ flex: 1 }}>{region}</span>
                <span className="num">{num(total(svc))}</span>
              </button>
              {isOpen ? (
                <div style={{ padding: '2px 16px 8px 40px' }}>
                  {services(svc).map(([t, n]) => (
                    <div key={t} style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 0', fontSize: 12 }}>
                      <span className="mono" style={{ color: 'var(--text-2)' }}>{shortType(t)}</span>
                      <span className="num">{num(n)}</span>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          )
        })}
      </div>

      {global && Object.keys(global).length > 0 ? (
        <div style={{ borderTop: '1px solid var(--border)' }}>
          <div style={{ padding: '8px 16px 2px', fontSize: 11, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--text-3)' }}>
            Global services <span style={{ textTransform: 'none', color: 'var(--text-3)' }}>· account-wide, no region</span>
          </div>
          <BarList entries={services(global).map(([t, n]) => [shortType(t), n])} />
        </div>
      ) : null}
    </>
  )
}

// Coverage status → dot color. Absent/degraded draw the eye on purpose: the
// whole point is making "no data" visible instead of an empty table.
const COV_DOT: Record<PillarStatus, string> = {
  healthy: 'sev-low',
  degraded: 'sev-high',
  absent: 'sev-critical',
  not_applicable: 'hollow',
}

export function Dashboard() {
  const { accountId } = useAccountScope()
  const { persona } = usePersona()
  const reduceMotion = useReducedMotion()
  const inv = useApi(() => api.inventorySummary(accountId), [accountId])
  const fnd = useApi(() => api.findingsSummary(accountId), [accountId])
  const accounts = useApi(() => api.accounts())
  const cov = useApi(() => api.coverage(accountId), [accountId])
  const comp = useApi(() => api.complianceCurrent(accountId), [accountId])
  // Trend the highest-signal framework (first = best-scored snapshot set).
  const topFw = comp.data?.items?.[0]?.framework
  const hist = useApi(() => api.complianceHistory(topFw!), [topFw], { enabled: !!topFw })

  const critical = fnd.data?.active_threat_by_severity?.critical ?? 0
  const profile = PERSONAS[persona]
  const roleContent = ROLE_CONTENT[persona]
  const accountCount = accounts.data?.items.filter((account) => account.is_active).length ?? 0
  const assetCount = inv.data?.total_assets ?? 0
  const findingCount = fnd.data?.active_threats ?? 0

  return (
    <div className="page">
      <PageHead
        crumb="overview"
        title={`${profile.label} workspace`}
        sub="One operating view from cloud visibility to a verified security decision."
      />

      <motion.section
        className="command-brief"
        initial={reduceMotion ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.18, ease: 'easeOut' }}
      >
        <div className="brief-copy">
          <span className="brief-kicker"><Radar size={14} aria-hidden /> Today’s security brief</span>
          <h2>
            {fnd.loading
              ? 'Building a prioritized view of your cloud posture'
              : critical > 0
                ? `${num(critical)} critical finding${critical === 1 ? '' : 's'} need a decision`
                : 'No critical posture findings in the current scope'}
          </h2>
          <p>{roleContent.summary}</p>
          <div className="brief-actions">
            <Link className="btn primary" to={roleContent.primary.to}>
              {roleContent.primary.label}<ArrowRight size={14} aria-hidden />
            </Link>
            <Link className="btn" to={roleContent.secondary.to}>{roleContent.secondary.label}</Link>
          </div>
        </div>
        <div className="brief-signal" aria-label="Current risk summary">
          <span className="label">Decision signal</span>
          <strong className={critical > 0 ? 'risk' : ''}>{fnd.loading ? '—' : num(critical)}</strong>
          <span>{critical > 0 ? 'critical risks' : 'critical risks open'}</span>
          <div className="brief-signal-meta">
            <span><b>{num(accountCount)}</b> accounts</span>
            <span><b>{num(assetCount)}</b> assets</span>
          </div>
        </div>
      </motion.section>

      <GuidedWorkflow accounts={accountCount} assets={assetCount} findings={findingCount} />

      <div className="grid-stats" style={{ marginBottom: 12 }}>
        <StatCard i={1} label="Assets" value={inv.data ? num(inv.data.total_assets) : null} sub="active in inventory" />
        <StatCard i={2} label="Public assets" value={inv.data ? num(inv.data.public_assets) : null} sub="internet-reachable" />
        <StatCard i={3} label="Active threats" value={fnd.data ? num(fnd.data.active_threats) : null} sub={fnd.data ? `${num(fnd.data.network_hygiene)} hygiene warnings` : undefined} />
        <StatCard i={4} label="Critical" value={fnd.data ? num(critical) : null} sub="open, highest severity" crit={critical > 0} />
      </div>

      <section className="next-actions" aria-labelledby="next-actions-title">
        <div className="section-heading">
          <div>
            <span className="label">Role-guided actions</span>
            <h2 id="next-actions-title">What to do next</h2>
          </div>
          <span>{profile.focus}</span>
        </div>
        <div className="action-grid">
          {roleContent.actions.map((action, index) => (
            <motion.div
              key={action.to}
              whileHover={reduceMotion ? undefined : { y: -2 }}
              whileTap={reduceMotion ? undefined : { scale: 0.99 }}
              transition={{ duration: 0.16, ease: 'easeOut' }}
            >
              <Link to={action.to} className={`action-card${index === 0 ? ' recommended' : ''}`}>
                <span className="action-icon"><action.icon size={17} aria-hidden /></span>
                <span className="action-copy">
                  {index === 0 ? <span className="action-recommended">Recommended</span> : null}
                  <strong>{action.title}</strong>
                  <small>{action.detail}</small>
                </span>
                <ArrowRight className="action-arrow" size={15} aria-hidden />
              </Link>
            </motion.div>
          ))}
        </div>
      </section>

      <div style={{ marginBottom: 12 }}>
        <Card
          title={`Source coverage${cov.data ? ` · ${cov.data.healthy}/${cov.data.total} healthy` : ''}`}
          i={5}
          bodyPad={false}
        >
          <StateView loading={cov.loading} error={cov.error}>
            {cov.data ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, padding: '12px 16px' }}>
                {cov.data.pillars.map((p) => (
                  <span
                    key={p.pillar}
                    className="sev-badge"
                    title={p.detail}
                    style={{ color: 'var(--text-2)', gap: 6 }}
                  >
                    <span className={`dot ${COV_DOT[p.status]}`} />
                    <span style={{ textTransform: 'capitalize' }}>{p.pillar}</span>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
                      {p.status.replace('_', ' ')}
                    </span>
                  </span>
                ))}
              </div>
            ) : null}
          </StateView>
        </Card>
      </div>

      <div className="grid-2" style={{ marginBottom: 12 }}>
        <Card title="Active threats by severity" i={6}>
          <StateView loading={fnd.loading} error={fnd.error}>
            {fnd.data ? <SeverityDonut bySeverity={fnd.data.active_threat_by_severity} /> : null}
          </StateView>
        </Card>

        <Card title={`Compliance trend${topFw ? ` · ${topFw}` : ''}`} i={7}>
          <StateView
            loading={comp.loading || hist.loading}
            error={comp.error ?? hist.error}
            empty={!!comp.data && comp.data.items.length === 0}
            emptyHint="No compliance snapshots yet. Capture one from the Compliance page."
          >
            {hist.data ? <TrendArea points={hist.data.points} /> : null}
          </StateView>
        </Card>
      </div>

      <div style={{ marginBottom: 12 }}>
        <Card title="Compliance posture" i={8}>
          <StateView
            loading={comp.loading}
            error={comp.error}
            empty={!!comp.data && comp.data.items.length === 0}
            emptyHint="No frameworks scored yet. Run a scan from the Compliance page."
          >
            {comp.data ? (
              <ScoreColumns data={comp.data.items.map((f) => ({ name: f.framework, score: f.score }))} />
            ) : null}
          </StateView>
        </Card>
      </div>

      <div style={{ marginBottom: 12 }}>
        <AttackPathOverview i={9} />
      </div>

      <div style={{ marginBottom: 12 }}>
        <Card title="Network hygiene · preventative controls" i={8} bodyPad={false}>
          <StateView
            loading={fnd.loading}
            error={fnd.error}
            empty={!!fnd.data && Object.keys(fnd.data.network_hygiene_by_rule).length === 0}
            emptyHint="No actionable network hygiene drift. Empty defaults and declared public zones stay out of this queue."
          >
            {fnd.data ? (
              <BarList entries={Object.entries(fnd.data.network_hygiene_by_rule).sort((a, b) => b[1] - a[1])} />
            ) : null}
          </StateView>
        </Card>
      </div>

      <div className="grid-2" style={{ marginBottom: 12 }}>
        <Card title="Active threats by rule" i={8} bodyPad={false}>
          <StateView
            loading={fnd.loading}
            error={fnd.error}
            empty={!!fnd.data && Object.keys(fnd.data.active_threat_by_rule).length === 0}
            emptyHint="No active threats. Preventative drift remains visible in Network hygiene."
          >
            {fnd.data ? (
              <BarList entries={Object.entries(fnd.data.active_threat_by_rule).sort((a, b) => b[1] - a[1])} />
            ) : null}
          </StateView>
        </Card>

        <Card title="Inventory composition" i={9} bodyPad={false}>
          <StateView
            loading={inv.loading}
            error={inv.error}
            empty={!!inv.data && inv.data.total_assets === 0}
            emptyHint="Inventory is empty. Run scripts/scan_inventory.py against an account."
          >
            {inv.data ? (
              <>
                <BarList entries={Object.entries(inv.data.by_type).sort((a, b) => b[1] - a[1])} />
                <div
                  style={{
                    display: 'flex',
                    gap: 18,
                    padding: '10px 16px',
                    borderTop: '1px solid var(--border)',
                  }}
                >
                  {(['public', 'vpc', 'private'] as const).map((k) => (
                    <span key={k} className="sev-badge" style={{ color: 'var(--text-2)' }}>
                      <span className={`dot ${k === 'public' ? 'sev-critical' : k === 'vpc' ? 'sev-low' : 'hollow'}`} />
                      {k} <span className="num">{num(inv.data!.by_exposure[k] ?? 0)}</span>
                    </span>
                  ))}
                </div>
                {/* Per-region spread — the shadow-IT lens: a region holding a
                    handful of assets you didn't expect stands out here. Expand a
                    region to see which services run in it; global (account-wide)
                    assets are split out below so they don't read as a region. */}
                <RegionBreakdown data={inv.data} />
              </>
            ) : null}
          </StateView>
        </Card>
      </div>

      <Card title="Connected accounts" i={10} bodyPad={false}>
        <StateView
          loading={accounts.loading}
          error={accounts.error}
          empty={!!accounts.data && accounts.data.items.length === 0}
          emptyHint="No accounts registered yet."
        >
          {accounts.data ? (
            <table className="tbl">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Account</th>
                  <th>Name</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {accounts.data.items.map((a) => (
                  <tr key={a.id} style={{ cursor: 'default' }}>
                    <td className="mono" style={{ textTransform: 'uppercase' }}>{a.provider}</td>
                    <td className="mono">{a.account_identifier}</td>
                    <td>{a.name ?? '—'}</td>
                    <td>
                      <span className="pill tint">{a.is_active ? 'active' : 'inactive'}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </StateView>
      </Card>
    </div>
  )
}
