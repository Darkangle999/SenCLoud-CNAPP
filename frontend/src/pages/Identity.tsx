import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  Fingerprint,
  KeyRound,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  UsersRound,
} from 'lucide-react'
import { useDeferredValue, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { Card, PageHead, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { num, relTime } from '../lib/format'
import type { IdentityPrincipal } from '../types'

const PAGE_SIZE = 40

function privilegeLabel(principal: IdentityPrincipal) {
  if (principal.privilege.admin_grant && !principal.privilege.boundary_restricts_admin) return 'Unbounded admin grant'
  if (principal.privilege.admin_grant) return 'Admin grant bounded'
  if (principal.privilege.effective_privilege_escalation_actions.length) return 'Privilege escalation path'
  return 'Standard privilege'
}

function trustLabel(principal: IdentityPrincipal) {
  return principal.trust.onboarding_verified ? 'Odineyes verified' : principal.trust.level
}

function identityProblems(principal: IdentityPrincipal) {
  const issues: Array<{ level: 'critical' | 'high' | 'medium'; title: string; detail: string }> = []
  if (principal.privilege.admin_grant && !principal.privilege.boundary_restricts_admin) issues.push({ level: 'critical', title: 'Unbounded administrative access', detail: principal.privilege.admin_reason || 'The evaluated policy layers grant effective administrator access.' })
  if (principal.authentication.console_enabled && !principal.authentication.mfa_enabled) issues.push({ level: 'high', title: 'Human console access has no MFA', detail: 'A stolen password could be sufficient for account access.' })
  if (principal.trust.external && !principal.trust.onboarding_verified) issues.push({ level: 'high', title: 'External trust requires review', detail: `${principal.trust.principals.length} external principal${principal.trust.principals.length === 1 ? '' : 's'} can participate in the trust relationship.` })
  if (!principal.authorization.effective_access_complete) issues.push({ level: 'medium', title: 'Effective access is incomplete', detail: principal.authorization.unevaluated_policy_layers.length ? `Not evaluated: ${principal.authorization.unevaluated_policy_layers.join(', ')}.` : 'One or more authorization layers could not be fully evaluated.' })
  return issues
}

export function Identity() {
  const [principalType, setPrincipalType] = useState('all')
  const [trust, setTrust] = useState('all')
  const [risk, setRisk] = useState('all')
  const [sort, setSort] = useState('risk')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const deferredSearch = useDeferredValue(search.trim())
  const navigate = useNavigate()

  const { accountId } = useAccountScope()
  const principals = useApi(
    () => api.identityResources({
      account_id: accountId ?? undefined,
      q: deferredSearch || undefined,
      principal_type: principalType === 'all' ? undefined : principalType,
      trust: trust === 'all' ? undefined : trust,
      min_risk: risk === 'all' ? undefined : Number(risk),
      sort,
      direction: sort === 'name' ? 'asc' : 'desc',
      page,
      page_size: PAGE_SIZE,
    }),
    [accountId, deferredSearch, principalType, trust, risk, sort, page],
  )
  const data = principals.data

  useEffect(() => {
    const items = data?.items ?? []
    if (!items.length) {
      setSelectedId(null)
      return
    }
    if (!items.some((item) => item.id === selectedId)) setSelectedId(items[0].id)
  }, [data?.items, selectedId])

  const selected = data?.items.find((principal) => principal.id === selectedId) ?? null
  const problems = useMemo(() => selected ? identityProblems(selected) : [], [selected])
  const activeFilters = principalType !== 'all' || trust !== 'all' || risk !== 'all' || !!search
  const resetSelection = () => setSelectedId(null)

  return (
    <div className="page security-model-page identity-page">
      <PageHead crumb="identity" title="Identity explorer" sub="Search a principal, understand effective privilege and trust, then follow the evidence into a full CIEM investigation." />

      <section className="inventory-kpis" aria-label="Identity posture totals">
        <div className="inventory-kpi"><Fingerprint size={18} /><span>Principals</span><strong>{data ? num(data.totals.principals) : '—'}</strong></div>
        <div className="inventory-kpi danger"><ShieldAlert size={18} /><span>Admin grants</span><strong>{data ? num(data.totals.admin_grants) : '—'}</strong></div>
        <div className="inventory-kpi warning"><KeyRound size={18} /><span>MFA gaps</span><strong>{data ? num(data.totals.mfa_gaps) : '—'}</strong></div>
        <div className="inventory-kpi"><UsersRound size={18} /><span>External trust</span><strong>{data ? num(data.totals.external_trust) : '—'}</strong></div>
      </section>

      <Card i={2} bodyPad={false}>
        <nav className="inventory-categories" aria-label="Principal types">
          <button className={principalType === 'all' ? 'active' : ''} onClick={() => { setPrincipalType('all'); setPage(1); resetSelection() }}><UsersRound size={16} /><span>All principals</span><b>{data?.totals.principals ?? 0}</b></button>
          {(data?.facets.principal_types ?? []).map((facet) => <button key={facet.value} className={principalType === facet.value ? 'active' : ''} onClick={() => { setPrincipalType(facet.value); setPage(1); resetSelection() }}><UserCheck size={16} /><span>{facet.label}s</span><b>{facet.count}</b></button>)}
        </nav>

        <div className="inventory-controls identity-controls">
          <label className="inventory-search"><Search size={16} /><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); resetSelection() }} placeholder="Search credential, principal, ARN, or type" aria-label="Search identities" /></label>
          <select value={trust} onChange={(event) => { setTrust(event.target.value); setPage(1); resetSelection() }} aria-label="Trust filter"><option value="all">Any trust</option>{(data?.facets.trust_levels ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}</select>
          <select value={risk} onChange={(event) => { setRisk(event.target.value); setPage(1); resetSelection() }} aria-label="Risk filter"><option value="all">Any risk</option><option value="80">Critical · 80+</option><option value="60">High · 60+</option><option value="40">Medium · 40+</option></select>
          <select value={sort} onChange={(event) => { setSort(event.target.value); setPage(1) }} aria-label="Sort identities"><option value="risk">Sort: risk</option><option value="findings">Sort: findings</option><option value="last_scanned">Sort: last scanned</option><option value="name">Sort: name</option></select>
          {activeFilters ? <button className="btn" onClick={() => { setPrincipalType('all'); setTrust('all'); setRisk('all'); setSearch(''); setPage(1); resetSelection() }}>Clear</button> : null}
        </div>

        <StateView loading={principals.loading} error={principals.error} empty={!!data && data.items.length === 0} emptyHint={activeFilters ? 'No principals match current filters.' : 'No identity principals are available. Run an account scan first.'}>
          <div className="identity-workspace">
            <div className="identity-master" aria-label="Identity principals">
              {(data?.items ?? []).map((principal) => (
                <button key={principal.id} type="button" className={`identity-master-row${selected?.id === principal.id ? ' selected' : ''}`} onClick={() => setSelectedId(principal.id)}>
                  <div className="identity-row-badges">
                    <span className="pill tint">{principal.identity.principal_type}</span>
                    {principal.privilege.admin_grant ? <span className="pill model-elevated">admin</span> : null}
                    {principal.trust.external && !principal.trust.onboarding_verified ? <span className="pill identity-external">external trust</span> : null}
                  </div>
                  <strong>{principal.identity.name}</strong>
                  <span className="mono" title={principal.identity.resource_id}>{principal.identity.resource_id}</span>
                  <div className="identity-row-foot"><small>{principal.identity.account_name ?? principal.identity.account_id}</small><b className={principal.posture.severity}>{Math.round(principal.posture.risk_score)}</b></div>
                </button>
              ))}
            </div>

            {selected ? (
              <section className="identity-inspector" aria-label={`${selected.identity.name} identity analysis`}>
                <div className="identity-inspector-head">
                  <div><span className="label">Principal analysis</span><h2>{selected.identity.name}</h2><p className="mono">{selected.identity.resource_id}</p></div>
                  <button className="btn" onClick={() => navigate(`/identity/${selected.id}`)}>Full investigation <ArrowUpRight size={14} /></button>
                </div>

                <div className="identity-signal-grid">
                  <div className={selected.authentication.console_enabled && !selected.authentication.mfa_enabled ? 'bad' : ''}><ShieldCheck size={16} /><span>MFA</span><strong>{selected.authentication.console_enabled ? selected.authentication.mfa_enabled ? 'Enabled' : 'Missing' : 'Not applicable'}</strong></div>
                  <div className={selected.privilege.admin_grant && !selected.privilege.boundary_restricts_admin ? 'bad' : ''}><KeyRound size={16} /><span>Privilege</span><strong>{privilegeLabel(selected)}</strong></div>
                  <div><Activity size={16} /><span>Activity</span><strong>{selected.lifecycle.last_used_days === null ? 'Never / unknown' : `${selected.lifecycle.last_used_days}d ago`}</strong></div>
                  <div className={selected.trust.external && !selected.trust.onboarding_verified ? 'bad' : ''}><UsersRound size={16} /><span>Trust</span><strong>{trustLabel(selected)}</strong></div>
                </div>

                {problems.length ? <div className="identity-alerts"><span className="label">What requires attention</span>{problems.map((problem) => <article key={problem.title} className={`identity-alert ${problem.level}`}><ShieldAlert size={16} /><div><strong>{problem.title}</strong><p>{problem.detail}</p></div></article>)}</div> : <div className="identity-clean"><CheckCircle2 size={18} /><div><strong>No high-confidence identity problem in the evaluated data</strong><p>Continue to review usage and policy drift because this is a point-in-time assessment.</p></div></div>}

                <div className="identity-evidence-grid">
                  <section><span className="label">Effective access</span><dl className="explorer-kv"><div><dt>Policy sources</dt><dd>{selected.authorization.policy_sources}</dd></div><div><dt>Allow statements</dt><dd>{selected.authorization.allow_statements}</dd></div><div><dt>Explicit denies</dt><dd>{selected.authorization.explicit_denies}</dd></div><div><dt>Conditional statements</dt><dd>{selected.authorization.conditional_statements}</dd></div><div><dt>Wildcard actions</dt><dd>{selected.authorization.wildcard_action_statements}</dd></div><div><dt>Evaluation</dt><dd>{selected.authorization.effective_access_complete ? 'Complete' : 'Partial'}</dd></div></dl></section>
                  <section><span className="label">Trust relationships</span><div className="identity-trust-list">{selected.trust.principals.length ? selected.trust.principals.map((principal) => <span className="mono" key={principal}>{principal}</span>) : <p>No assumable principal was observed.</p>}</div><span className="label identity-escalation-label">Escalation actions</span><div className="identity-trust-list">{selected.privilege.effective_privilege_escalation_actions.length ? selected.privilege.effective_privilege_escalation_actions.map((action) => <span className="mono" key={action}>{action}</span>) : <p>None detected after boundary evaluation.</p>}</div></section>
                </div>

                <section className="identity-review"><span className="label">Investigation checklist</span>{['Confirm business owner and expected access', 'Review trust conditions and external principals', 'Remove unused grants or apply a boundary', 'Re-scan and verify the access path is broken'].map((item) => <div key={item}><CheckCircle2 size={15} /><span>{item}</span></div>)}</section>
                <div className="identity-scan-note">Last scanned {relTime(selected.lifecycle.last_scanned_at)} · {selected.posture.open_findings} open findings · {selected.posture.attack_paths} attack paths</div>
              </section>
            ) : null}
          </div>
        </StateView>

        {data && data.pagination.pages > 1 ? <div className="pager"><span className="mono">Page {data.pagination.page} of {data.pagination.pages} · {num(data.pagination.total)} principals</span><div className="pager-actions"><button className="btn" disabled={page <= 1} onClick={() => { setPage((value) => value - 1); resetSelection() }}>Previous</button><button className="btn" disabled={page >= data.pagination.pages} onClick={() => { setPage((value) => value + 1); resetSelection() }}>Next</button></div></div> : null}
      </Card>
    </div>
  )
}
