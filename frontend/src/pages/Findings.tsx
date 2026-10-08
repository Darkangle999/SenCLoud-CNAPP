import { Download, EyeOff, Network, RefreshCw, Search, ShieldAlert, ShieldCheck, Siren, Sparkles } from 'lucide-react'
import { useDeferredValue, useEffect, useMemo, useState } from 'react'

import { Drawer } from '../components/Drawer'
import { Card, PageHead, SevBadge, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api, ApiError } from '../lib/api'
import { num, relTime } from '../lib/format'
import { REALTIME_EVENT } from '../lib/realtime'
import type { ModeledFinding, Severity } from '../types'

const PAGE_SIZE = 40

export function Findings() {
  const [status, setStatus] = useState<'open' | 'suppressed' | 'resolved'>('open')
  const [signal, setSignal] = useState<'all' | 'active_threat' | 'network_hygiene'>('active_threat')
  const [severity, setSeverity] = useState<'all' | Severity>('all')
  const [category, setCategory] = useState('all')
  const [rule, setRule] = useState('all')
  const [service, setService] = useState('all')
  const [sort, setSort] = useState('risk')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<ModeledFinding | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const deferredSearch = useDeferredValue(search.trim())

  const { accountId } = useAccountScope()
  const accounts = useApi(() => api.accounts())
  const findings = useApi(
    () => api.findingResources({
      account_id: accountId ?? undefined,
      q: deferredSearch || undefined,
      status,
      severity: severity === 'all' ? undefined : severity,
      category: category === 'all' ? undefined : category,
      rule: rule === 'all' ? undefined : rule,
      service: service === 'all' ? undefined : service,
      signal: signal === 'all' ? undefined : signal,
      sort,
      direction: sort === 'title' ? 'asc' : 'desc',
      page,
      page_size: PAGE_SIZE,
    }),
    [accountId, deferredSearch, status, signal, severity, category, rule, service, sort, page],
  )

  useEffect(() => {
    const onRealtime = (event: Event) => {
      const detail = (event as CustomEvent).detail
      if (detail?.type === 'security_mutation') {
        setToast(detail.alert?.title || 'Security-relevant cloud change detected')
      }
      if (detail?.type === 'reconciliation_complete') findings.refetch()
      window.setTimeout(() => setToast(null), 4200)
    }
    window.addEventListener(REALTIME_EVENT, onRealtime)
    return () => window.removeEventListener(REALTIME_EVENT, onRealtime)
  }, [findings.refetch])

  const data = findings.data
  const lastSeen = useMemo(() => {
    const values = (data?.items ?? []).map((item) => item.lifecycle.last_seen_at).filter(Boolean) as string[]
    values.sort()
    return values.length ? values[values.length - 1] : null
  }, [data])
  const stale = lastSeen ? Date.now() - Date.parse(lastSeen) > 86_400_000 : false
  const activeFilters = severity !== 'all' || category !== 'all' || rule !== 'all' || service !== 'all' || !!search

  async function evaluate() {
    const account = accounts.data?.items.find((item) => item.id === accountId) ?? accounts.data?.items[0]
    if (!account) return
    setEvaluating(true)
    try {
      const result = await api.evaluate(account.provider, account.account_identifier)
      setToast(`Evaluated · ${result.new} new · ${result.reopened} reopened · ${result.suppressed ?? 0} suppressed · ${result.resolved} resolved`)
      findings.refetch()
    } catch (error) {
      setToast(error instanceof ApiError ? error.message : String(error))
    } finally {
      setEvaluating(false)
      setTimeout(() => setToast(null), 4200)
    }
  }

  return (
    <div className="page security-model-page">
      <PageHead
        crumb="findings"
        title="Security findings"
        sub={data ? `${num(data.totals.active_threats)} active threats · ${num(data.totals.network_hygiene)} hygiene warnings` : 'Prioritized rule verdicts with resource and business context.'}
        actions={
          <>
            <a className="btn" href={api.findingsExportUrl({ account_id: accountId ?? undefined, status, signal: signal === 'all' ? undefined : signal, severity: severity === 'all' ? undefined : severity, rule: rule === 'all' ? undefined : rule, format: 'csv' })}>
              <Download size={13} /> Export CSV
            </a>
            <button className="btn primary" onClick={evaluate} disabled={evaluating || !accounts.data?.items.length}>
              <RefreshCw style={evaluating ? { animation: 'spin .7s linear infinite' } : undefined} />
              {evaluating ? 'Evaluating…' : 'Re-evaluate'}
            </button>
          </>
        }
      />

      <section className="inventory-kpis">
        <div className="inventory-kpi"><ShieldAlert size={18} /><span>Active threats</span><strong>{data ? num(data.totals.active_threats) : '—'}</strong></div>
        <div className="inventory-kpi"><Network size={18} /><span>Network hygiene</span><strong>{data ? num(data.totals.network_hygiene) : '—'}</strong></div>
        <div className="inventory-kpi danger"><Siren size={18} /><span>Critical</span><strong>{data ? num(data.totals.critical) : '—'}</strong></div>
        <div className="inventory-kpi warning"><Sparkles size={18} /><span>Elevated context</span><strong>{data ? num(data.totals.elevated) : '—'}</strong></div>
        <div className="inventory-kpi"><EyeOff size={18} /><span>Suppressed noise</span><strong>{data ? num(data.totals.suppressed) : '—'}</strong></div>
        <div className="inventory-kpi"><ShieldCheck size={18} /><span>Resolved</span><strong>{data ? num(data.totals.resolved) : '—'}</strong></div>
      </section>

      <Card i={2} bodyPad={false}>
        <nav className="inventory-categories">
          {(['active_threat', 'network_hygiene', 'all'] as const).map((value) => (
            <button key={value} className={signal === value ? 'active' : ''} onClick={() => { setSignal(value); setPage(1) }}>
              <span>{value === 'active_threat' ? 'Active threats' : value === 'network_hygiene' ? 'Network hygiene' : 'All signals'}</span>
              <b>{value === 'active_threat' ? data?.totals.active_threats ?? 0 : value === 'network_hygiene' ? data?.totals.network_hygiene ?? 0 : data?.totals.open ?? 0}</b>
            </button>
          ))}
        </nav>
        <nav className="inventory-categories">
          {(['open', 'suppressed', 'resolved'] as const).map((value) => (
            <button key={value} className={status === value ? 'active' : ''} onClick={() => { setStatus(value); setPage(1) }}>
              <span>{value === 'open' ? 'Open' : value === 'suppressed' ? 'Suppressed' : 'Resolved'}</span>
              <b>{value === 'open' ? data?.totals.open ?? 0 : value === 'suppressed' ? data?.totals.suppressed ?? 0 : data?.totals.resolved ?? 0}</b>
            </button>
          ))}
          {(data?.facets.categories ?? []).map((facet) => (
            <button key={facet.value} className={category === facet.value ? 'active' : ''} onClick={() => { setCategory(category === facet.value ? 'all' : facet.value); setPage(1) }}>
              <span>{facet.label}</span><b>{facet.count}</b>
            </button>
          ))}
        </nav>

        <div className="inventory-controls findings-controls">
          <label className="inventory-search"><Search size={16} /><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} placeholder="Search verdict, rule, resource, or type" /></label>
          <select value={severity} onChange={(event) => { setSeverity(event.target.value as typeof severity); setPage(1) }}>
            <option value="all">All severities</option>
            {(data?.facets.severities ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}
          </select>
          <select value={rule} onChange={(event) => { setRule(event.target.value); setPage(1) }}>
            <option value="all">All rules</option>
            {(data?.facets.rules ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}
          </select>
          <select value={service} onChange={(event) => { setService(event.target.value); setPage(1) }}>
            <option value="all">All services</option>
            {(data?.facets.services ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}
          </select>
          <select value={sort} onChange={(event) => { setSort(event.target.value); setPage(1) }}>
            <option value="risk">Sort: contextual risk</option><option value="severity">Sort: severity</option><option value="last_seen">Sort: last seen</option><option value="title">Sort: title</option>
          </select>
          {activeFilters ? <button className="btn" onClick={() => { setSeverity('all'); setCategory('all'); setRule('all'); setService('all'); setSearch(''); setPage(1) }}>Clear</button> : null}
        </div>

        {status === 'open' && stale ? <div className="model-alert">Findings last confirmed {relTime(lastSeen)}. Re-scan inventory before treating status as current.</div> : null}

        <StateView loading={findings.loading} error={findings.error} empty={!!data && data.items.length === 0} emptyHint={status === 'open' ? 'No open findings match current filters.' : status === 'suppressed' ? 'No findings were suppressed by tuning.' : 'No resolved findings match current filters.'}>
          <div className="inventory-table-wrap">
            <table className="tbl inventory-table findings-table">
              <thead><tr><th>Verdict</th><th>Resource</th><th>Context</th><th>Risk</th><th>Status</th><th>Last observed</th></tr></thead>
              <tbody>
                {(data?.items ?? []).map((finding) => (
                  <tr key={finding.id} onClick={() => setSelected(finding)}>
                    <td><strong className="model-primary">{finding.verdict.title}</strong><small>{finding.verdict.rule_id} · {finding.verdict.signal === 'network_hygiene' ? 'network hygiene' : finding.verdict.category}</small></td>
                    <td><strong className="model-primary">{finding.resource.name}</strong><small title={finding.resource.resource_id}>{finding.resource.service.toUpperCase()} · {finding.resource.asset_type}</small></td>
                    <td><span className="sev-badge"><span className={`dot ${finding.posture.exposure === 'public' ? 'sev-critical' : 'sev-low'}`} />{finding.posture.exposure}</span><small>{finding.posture.data_sensitivity ? `${finding.posture.data_sensitivity.label} data` : finding.resource.account_name}</small></td>
                    <td><div className="model-risk"><b className={finding.posture.severity}>{Math.round(finding.posture.risk_score)}</b><SevBadge sev={finding.posture.severity} /></div></td>
                    <td>{finding.posture.elevated ? <span className="pill model-elevated">Elevated</span> : <span className="pill tint">{finding.posture.status}</span>}</td>
                    <td className="mono inventory-seen">{relTime(finding.lifecycle.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </StateView>

        {data && data.pagination.pages > 1 ? <div className="pager"><span className="mono">Page {data.pagination.page} of {data.pagination.pages} · {num(data.pagination.total)} findings</span><div className="pager-actions"><button className="btn" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button><button className="btn" disabled={page >= data.pagination.pages} onClick={() => setPage((value) => value + 1)}>Next</button></div></div> : null}
      </Card>

      <Drawer open={selected !== null} onClose={() => setSelected(null)} title={selected?.verdict.title} subtitle={selected?.resource.resource_id}>
        {selected ? <>
          <div className="model-drawer-header"><SevBadge sev={selected.posture.severity} /><span className="pill">{selected.verdict.rule_id}</span><span className="pill tint">{selected.verdict.signal === 'network_hygiene' ? 'preventative hygiene' : 'active threat'}</span><span className="pill tint">risk {Math.round(selected.posture.risk_score)}</span></div>
          <div className="drawer-section"><span className="label">Affected resource</span><dl className="kv"><dt>Name</dt><dd>{selected.resource.name}</dd><dt>Service</dt><dd className="mono">{selected.resource.service}</dd><dt>Type</dt><dd className="mono">{selected.resource.asset_type}</dd><dt>Exposure</dt><dd>{selected.posture.exposure}</dd></dl></div>
          <div className="drawer-section"><span className="label">Why this matters</span><p className="model-copy">{selected.evidence.why}</p></div>
          {selected.evidence.suppressed_by ? <div className="drawer-section"><span className="label">Suppression evidence</span><dl className="kv"><dt>Layer</dt><dd className="mono">{selected.evidence.suppressed_by}</dd><dt>Reason</dt><dd>{selected.evidence.suppressed_why ?? 'No reason recorded'}</dd></dl></div> : null}
          <div className="drawer-section"><span className="label">Remediation</span><p className="model-copy">{selected.remediation.guidance}</p>{selected.remediation.cli ? <button className="model-command mono" onClick={() => { navigator.clipboard?.writeText(selected.remediation.cli ?? ''); setToast('Command copied'); setTimeout(() => setToast(null), 1800) }}>$ {selected.remediation.cli}</button> : null}</div>
          {Object.keys(selected.evidence.compliance).length ? <div className="drawer-section"><span className="label">Compliance mapping</span><dl className="kv">{Object.entries(selected.evidence.compliance).map(([framework, controls]) => <div key={framework} className="inventory-fact"><dt>{framework}</dt><dd className="mono">{controls.join(' · ')}</dd></div>)}</dl></div> : null}
          <div className="drawer-section"><span className="label">Lifecycle</span><dl className="kv"><dt>First seen</dt><dd className="mono">{selected.lifecycle.first_seen_at ?? '—'}</dd><dt>Last seen</dt><dd className="mono">{selected.lifecycle.last_seen_at ?? '—'}</dd>{selected.lifecycle.resolved_at ? <><dt>Resolved</dt><dd className="mono">{selected.lifecycle.resolved_at}</dd></> : null}</dl></div>
        </> : null}
      </Drawer>
      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}
