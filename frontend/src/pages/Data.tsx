import { Database, FileSearch, Globe2, LockKeyhole, RefreshCw, Search, ShieldAlert } from 'lucide-react'
import { useDeferredValue, useState } from 'react'

import { Drawer } from '../components/Drawer'
import { Card, PageHead, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { num, relTime } from '../lib/format'
import type { DataSecurityStore } from '../types'

const PAGE_SIZE = 40

export function Data() {
  const [service, setService] = useState('all')
  const [label, setLabel] = useState('all')
  const [region, setRegion] = useState('all')
  const [exposure, setExposure] = useState('all')
  const [risk, setRisk] = useState('all')
  const [sort, setSort] = useState('risk')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<DataSecurityStore | null>(null)
  const deferredSearch = useDeferredValue(search.trim())

  const { accountId } = useAccountScope()
  const stores = useApi(
    () => api.dataSecurityResources({
      account_id: accountId ?? undefined,
      q: deferredSearch || undefined,
      service: service === 'all' ? undefined : service,
      label: label === 'all' ? undefined : label,
      region: region === 'all' ? undefined : region,
      exposure: exposure === 'all' ? undefined : exposure,
      min_risk: risk === 'all' ? undefined : Number(risk),
      sort,
      direction: sort === 'name' ? 'asc' : 'desc',
      page,
      page_size: PAGE_SIZE,
    }),
    [accountId, deferredSearch, service, label, region, exposure, risk, sort, page],
  )
  const data = stores.data
  const activeFilters = service !== 'all' || label !== 'all' || region !== 'all' || exposure !== 'all' || risk !== 'all' || !!search

  return (
    <div className="page security-model-page">
      <PageHead
        crumb="data"
        title="Data security"
        sub={data ? `${num(data.totals.stores)} data stores · ${num(data.totals.classified)} classified` : 'DSPM context across classification, exposure, encryption, and risk.'}
        actions={<button className="btn" onClick={stores.refetch} disabled={stores.loading}><RefreshCw style={stores.loading ? { animation: 'spin .7s linear infinite' } : undefined} />Refresh</button>}
      />

      <section className="inventory-kpis">
        <div className="inventory-kpi"><Database size={18} /><span>Data stores</span><strong>{data ? num(data.totals.stores) : '—'}</strong></div>
        <div className="inventory-kpi"><FileSearch size={18} /><span>Classified</span><strong>{data ? num(data.totals.classified) : '—'}</strong></div>
        <div className="inventory-kpi danger"><Globe2 size={18} /><span>Public exposure</span><strong>{data ? num(data.totals.public) : '—'}</strong></div>
        <div className="inventory-kpi warning"><LockKeyhole size={18} /><span>Unencrypted</span><strong>{data ? num(data.totals.unencrypted) : '—'}</strong></div>
      </section>

      <Card i={2} bodyPad={false}>
        <nav className="inventory-categories">
          <button className={label === 'all' ? 'active' : ''} onClick={() => { setLabel('all'); setPage(1) }}><Database size={16} /><span>All stores</span><b>{data?.totals.stores ?? 0}</b></button>
          {(data?.facets.labels ?? []).map((facet) => (
            <button key={facet.value} className={label === facet.value ? 'active' : ''} onClick={() => { setLabel(facet.value); setPage(1) }}><ShieldAlert size={16} /><span>{facet.label}</span><b>{facet.count}</b></button>
          ))}
        </nav>

        <div className="inventory-controls data-controls">
          <label className="inventory-search"><Search size={16} /><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} placeholder="Search store name, ARN, service, or type" /></label>
          <select value={service} onChange={(event) => { setService(event.target.value); setPage(1) }}><option value="all">All services</option>{(data?.facets.services ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}</select>
          <select value={region} onChange={(event) => { setRegion(event.target.value); setPage(1) }}><option value="all">All regions</option>{(data?.facets.regions ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}</select>
          <select value={exposure} onChange={(event) => { setExposure(event.target.value); setPage(1) }}><option value="all">Any exposure</option><option value="public">Public</option><option value="vpc">VPC scoped</option><option value="private">Private</option></select>
          <select value={risk} onChange={(event) => { setRisk(event.target.value); setPage(1) }}><option value="all">Any risk</option><option value="80">Critical · 80+</option><option value="60">High · 60+</option><option value="40">Medium · 40+</option></select>
          <select value={sort} onChange={(event) => { setSort(event.target.value); setPage(1) }}><option value="risk">Sort: risk</option><option value="sensitivity">Sort: sensitivity</option><option value="last_seen">Sort: last seen</option><option value="name">Sort: name</option></select>
          {activeFilters ? <button className="btn" onClick={() => { setService('all'); setLabel('all'); setRegion('all'); setExposure('all'); setRisk('all'); setSearch(''); setPage(1) }}>Clear</button> : null}
        </div>

        <StateView loading={stores.loading} error={stores.error} empty={!!data && data.items.length === 0} emptyHint={activeFilters ? 'No data stores match current filters.' : 'No data stores in inventory. Run an account scan.'}>
          <div className="inventory-table-wrap">
            <table className="tbl inventory-table data-security-table">
              <thead><tr><th>Data store</th><th>Classification</th><th>Protection</th><th>Data evidence</th><th>Risk</th><th>Last observed</th></tr></thead>
              <tbody>{(data?.items ?? []).map((store) => (
                <tr key={store.id} onClick={() => setSelected(store)}>
                  <td><div className="inventory-resource"><span className="inventory-resource-icon data"><Database size={17} /></span><span><strong>{store.identity.name}</strong><small title={store.identity.resource_id}>{store.identity.service.toUpperCase()} · {store.identity.store_type} · {store.identity.region}</small></span></div></td>
                  <td><span className={`pill ${store.classification.label === 'critical' || store.classification.label === 'high' ? 'model-elevated' : 'tint'}`}>{store.classification.label}</span><small>{store.classification.status} · sensitivity {Math.round(store.classification.sensitivity_score * (store.classification.sensitivity_score <= 1 ? 100 : 1))}</small></td>
                  <td><span className="sev-badge"><span className={`dot ${store.protection.public ? 'sev-critical' : 'sev-low'}`} />{store.protection.exposure}</span><small>Encryption: {store.protection.encryption}</small></td>
                  <td><strong className="model-primary">{num(store.classification.records_estimated)} records</strong><small>{num(store.classification.objects_sampled)} objects sampled · {store.classification.data_types.length} data types</small></td>
                  <td><div className="model-risk"><b className={store.risk.severity}>{Math.round(store.risk.score)}</b><span><strong>{store.risk.open_findings}</strong><small> findings</small></span></div></td>
                  <td className="mono inventory-seen">{relTime(store.lifecycle.last_seen_at)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </StateView>

        {data && data.pagination.pages > 1 ? <div className="pager"><span className="mono">Page {data.pagination.page} of {data.pagination.pages} · {num(data.pagination.total)} stores</span><div className="pager-actions"><button className="btn" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button><button className="btn" disabled={page >= data.pagination.pages} onClick={() => setPage((value) => value + 1)}>Next</button></div></div> : null}
      </Card>

      <Drawer open={selected !== null} onClose={() => setSelected(null)} title={selected?.identity.name} subtitle={selected?.identity.resource_id}>
        {selected ? <>
          <div className="model-drawer-header"><span className={`pill ${selected.classification.label === 'critical' || selected.classification.label === 'high' ? 'model-elevated' : 'tint'}`}>{selected.classification.label}</span><span className="pill tint">risk {Math.round(selected.risk.score)}</span><span className="pill tint">{selected.identity.store_type}</span></div>
          <div className="drawer-section"><span className="label">Store identity</span><dl className="kv"><dt>Service</dt><dd>{selected.identity.service}</dd><dt>Type</dt><dd className="mono">{selected.identity.asset_type}</dd><dt>Region</dt><dd>{selected.identity.region}</dd><dt>Account</dt><dd>{selected.identity.account_name ?? selected.identity.account_id}</dd></dl></div>
          <div className="drawer-section"><span className="label">Classification</span><dl className="kv"><dt>Status</dt><dd>{selected.classification.status}</dd><dt>Label</dt><dd>{selected.classification.label}</dd><dt>Sensitivity</dt><dd>{selected.classification.sensitivity_score}</dd><dt>Records estimated</dt><dd>{num(selected.classification.records_estimated)}</dd><dt>Objects sampled</dt><dd>{num(selected.classification.objects_sampled)}</dd></dl>{selected.classification.data_types.length ? <div className="inventory-tags">{selected.classification.data_types.map((value) => <span key={value} className="pill">{value}</span>)}</div> : null}</div>
          <div className="drawer-section"><span className="label">Protection</span><dl className="kv"><dt>Exposure</dt><dd>{selected.protection.exposure}</dd><dt>Encryption</dt><dd>{selected.protection.encryption}</dd><dt>Public</dt><dd>{selected.protection.public ? 'Yes' : 'No'}</dd><dt>Open findings</dt><dd>{selected.risk.open_findings}</dd></dl>{selected.protection.posture_findings.map((finding) => <div key={finding} className="inventory-relationship"><b>POSTURE</b><span>{finding}</span></div>)}</div>
          {selected.classification.taxonomies.length || selected.classification.frameworks.length ? <div className="drawer-section"><span className="label">Governance mapping</span><div className="inventory-tags">{[...selected.classification.taxonomies, ...selected.classification.frameworks].map((value) => <span key={value} className="pill tint">{value}</span>)}</div></div> : null}
          <div className="drawer-section"><span className="label">Lifecycle</span><dl className="kv"><dt>First seen</dt><dd className="mono">{selected.lifecycle.first_seen_at ?? '—'}</dd><dt>Last seen</dt><dd className="mono">{selected.lifecycle.last_seen_at ?? '—'}</dd></dl></div>
        </> : null}
      </Drawer>
    </div>
  )
}
