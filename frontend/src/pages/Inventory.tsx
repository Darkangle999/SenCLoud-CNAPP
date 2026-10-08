import { useDeferredValue, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowUpRight,
  Boxes,
  Cloud,
  Database,
  Globe2,
  KeyRound,
  Network,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react'
import { motion } from 'motion/react'

import { Card, PageHead, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { num, relTime } from '../lib/format'
import type { InventoryCategory, InventoryResource } from '../types'

const PAGE_SIZE = 40

const categoryMeta: Record<string, { label: string; icon: typeof Boxes }> = {
  identity: { label: 'Identity', icon: KeyRound },
  compute: { label: 'Compute', icon: Server },
  network: { label: 'Network', icon: Network },
  data: { label: 'Data', icon: Database },
  security: { label: 'Security', icon: ShieldCheck },
  management: { label: 'Management', icon: Cloud },
  other: { label: 'Other', icon: Boxes },
}

function postureLabel(resource: InventoryResource) {
  if (resource.posture.is_public) return 'Public'
  if (resource.posture.encryption.status === 'disabled') return 'Unencrypted'
  if (resource.posture.exposure === 'vpc') return 'VPC scoped'
  return 'Private'
}

export function Inventory() {
  const [category, setCategory] = useState<'all' | InventoryCategory>('all')
  const [service, setService] = useState('all')
  const [region, setRegion] = useState('all')
  const [exposure, setExposure] = useState('all')
  const [risk, setRisk] = useState('all')
  const [sort, setSort] = useState('risk')
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const deferredSearch = useDeferredValue(search.trim())
  const navigate = useNavigate()

  const { accountId } = useAccountScope()
  const resources = useApi(
    () =>
      api.inventoryResources({
        account_id: accountId ?? undefined,
        q: deferredSearch || undefined,
        category: category === 'all' ? undefined : category,
        service: service === 'all' ? undefined : service,
        region: region === 'all' ? undefined : region,
        exposure: exposure === 'all' ? undefined : exposure,
        min_risk: risk === 'all' ? undefined : Number(risk),
        sort,
        direction: sort === 'name' ? 'asc' : 'desc',
        page,
        page_size: PAGE_SIZE,
      }),
    [accountId, deferredSearch, category, service, region, exposure, risk, sort, page],
  )

  const data = resources.data
  const selected = data?.items.find((resource) => resource.id === selectedId) ?? null
  const activeFilters = category !== 'all' || service !== 'all' || region !== 'all' || exposure !== 'all' || risk !== 'all' || !!search
  const clearFilters = () => {
    setCategory('all')
    setService('all')
    setRegion('all')
    setExposure('all')
    setRisk('all')
    setSearch('')
    setPage(1)
    setSelectedId(null)
  }

  return (
    <div className="page inventory-page">
      <PageHead
        crumb="inventory"
        title="Cloud inventory"
        sub="Search every discovered resource, then inspect ownership, exposure, encryption, and risk in context."
      />

      <section className="inventory-kpis" aria-label="Inventory totals">
        <div className="inventory-kpi"><Boxes size={18} /><span>Active resources</span><strong>{data ? num(data.totals.assets) : '—'}</strong></div>
        <div className="inventory-kpi danger"><Globe2 size={18} /><span>Public exposure</span><strong>{data ? num(data.totals.public) : '—'}</strong></div>
        <div className="inventory-kpi warning"><ShieldAlert size={18} /><span>Elevated risk</span><strong>{data ? num(data.totals.elevated_risk) : '—'}</strong></div>
        <div className="inventory-kpi"><Search size={18} /><span>Current result</span><strong>{data ? num(data.totals.filtered) : '—'}</strong></div>
      </section>

      <Card i={2} bodyPad={false}>
        <nav className="inventory-categories" aria-label="Resource categories">
          <button className={category === 'all' ? 'active' : ''} onClick={() => { setCategory('all'); setPage(1); setSelectedId(null) }}>
            <Boxes size={16} /><span>All</span><b>{data?.totals.assets ?? 0}</b>
          </button>
          {(data?.facets.categories ?? []).map((facet) => {
            const meta = categoryMeta[facet.value] ?? categoryMeta.other
            const Icon = meta.icon
            return (
              <button key={facet.value} className={category === facet.value ? 'active' : ''} onClick={() => { setCategory(facet.value as InventoryCategory); setPage(1); setSelectedId(null) }}>
                <Icon size={16} /><span>{meta.label}</span><b>{facet.count}</b>
              </button>
            )
          })}
        </nav>

        <div className="inventory-controls">
          <label className="inventory-search">
            <Search size={16} />
            <input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); setSelectedId(null) }} placeholder="Search ARN, name, resource ID, or type" aria-label="Search inventory" />
          </label>
          <select value={service} onChange={(event) => { setService(event.target.value); setPage(1); setSelectedId(null) }} aria-label="Service filter">
            <option value="all">All services</option>
            {(data?.facets.services ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}
          </select>
          <select value={region} onChange={(event) => { setRegion(event.target.value); setPage(1); setSelectedId(null) }} aria-label="Region filter">
            <option value="all">All regions</option>
            {(data?.facets.regions ?? []).map((facet) => <option key={facet.value} value={facet.value}>{facet.label} · {facet.count}</option>)}
          </select>
          <select value={exposure} onChange={(event) => { setExposure(event.target.value); setPage(1); setSelectedId(null) }} aria-label="Exposure filter">
            <option value="all">Any exposure</option><option value="public">Public</option><option value="vpc">VPC scoped</option><option value="private">Private</option>
          </select>
          <select value={risk} onChange={(event) => { setRisk(event.target.value); setPage(1); setSelectedId(null) }} aria-label="Risk filter">
            <option value="all">Any risk</option><option value="80">Critical · 80+</option><option value="60">High · 60+</option><option value="40">Medium · 40+</option>
          </select>
          <select value={sort} onChange={(event) => { setSort(event.target.value); setPage(1) }} aria-label="Sort resources">
            <option value="risk">Sort: risk</option><option value="last_scanned">Sort: last scanned</option><option value="name">Sort: name</option><option value="type">Sort: type</option><option value="region">Sort: region</option>
          </select>
          {activeFilters ? <button className="btn" onClick={clearFilters}>Clear</button> : null}
        </div>

        <StateView loading={resources.loading} error={resources.error} empty={!!data && data.items.length === 0} emptyHint={activeFilters ? 'No resources match current filters.' : 'No resources yet. Connect an account and run its first scan.'}>
          <div className={`explorer-split inventory-explorer${selected ? ' has-selection' : ''}`}>
            <div className="explorer-list inventory-table-wrap">
              <table className="tbl inventory-table">
                <thead><tr><th>Resource</th><th>Type</th><th>Region</th><th>Exposure</th><th>Owner</th></tr></thead>
                <tbody>
                  {(data?.items ?? []).map((resource, index) => {
                    const meta = categoryMeta[resource.identity.category] ?? categoryMeta.other
                    const Icon = meta.icon
                    return (
                      <motion.tr
                        key={resource.id}
                        initial={{ opacity: 0, y: 4 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: Math.min(index * 0.012, 0.12), duration: 0.16 }}
                        className={selected?.id === resource.id ? 'selected' : ''}
                        onClick={() => setSelectedId(resource.id)}
                        onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedId(resource.id) } }}
                        tabIndex={0}
                      >
                        <td><div className="inventory-resource"><span className={`inventory-resource-icon ${resource.identity.category}`}><Icon size={17} /></span><span><strong>{resource.identity.name}</strong><small title={resource.identity.resource_id}>{resource.identity.resource_id}</small></span></div></td>
                        <td><strong className="inventory-service">{resource.identity.service.toUpperCase()}</strong><small className="inventory-kind">{meta.label} · {resource.identity.kind.replace(/_/g, ' ')}</small></td>
                        <td><span className="inventory-scope">{resource.scope.region}</span></td>
                        <td><span className="sev-badge"><span className={`dot ${resource.posture.is_public ? 'sev-critical' : 'sev-low'}`} />{postureLabel(resource)}</span></td>
                        <td><strong className="model-primary">{resource.identity.account_name ?? `Account ${resource.identity.account_id}`}</strong></td>
                      </motion.tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {selected ? (
              <aside className="explorer-inspector" aria-label={`${selected.identity.name} details`}>
                <div className="explorer-inspector-head">
                  <div><span className="label">Selected resource</span><h2>{selected.identity.name}</h2><p className="mono" title={selected.identity.resource_id}>{selected.identity.resource_id}</p></div>
                  <button className="icon-btn" onClick={() => setSelectedId(null)} aria-label="Close resource details"><X size={16} /></button>
                </div>
                <div className="insight-summary">
                  <div><span>Risk</span><strong className={selected.posture.risk.severity}>{Math.round(selected.posture.risk.score)}</strong></div>
                  <div><span>Findings</span><strong>{selected.posture.findings.total}</strong></div>
                  <div><span>Relations</span><strong>{selected.metadata.relationship_count}</strong></div>
                </div>
                <dl className="explorer-kv">
                  <div><dt>Type</dt><dd>{selected.identity.kind.replace(/_/g, ' ')}</dd></div>
                  <div><dt>Service</dt><dd className="mono">{selected.identity.service}</dd></div>
                  <div><dt>Account</dt><dd>{selected.identity.account_name ?? selected.identity.account_id}</dd></div>
                  <div><dt>Region</dt><dd className="mono">{selected.scope.region}</dd></div>
                  <div><dt>Exposure</dt><dd className={selected.posture.is_public ? 'critical' : ''}>{postureLabel(selected)}</dd></div>
                  <div><dt>Encryption</dt><dd>{selected.posture.encryption.status.replace('_', ' ')}</dd></div>
                  <div><dt>First seen</dt><dd>{relTime(selected.lifecycle.first_seen_at)}</dd></div>
                  <div><dt>Last observed</dt><dd>{relTime(selected.lifecycle.last_scanned_at)}</dd></div>
                </dl>
                {Object.keys(selected.metadata.tags).length ? <div className="explorer-tags"><span className="label">Tags</span><div>{Object.entries(selected.metadata.tags).slice(0, 10).map(([key, value]) => <span className="mono" key={key}>{key}={String(value)}</span>)}</div></div> : null}
                <button className="btn primary explorer-open" onClick={() => navigate(`/inventory/${selected.id}`)}>Open full asset <ArrowUpRight size={14} /></button>
              </aside>
            ) : null}
          </div>
        </StateView>

        {data && data.pagination.pages > 1 ? <div className="pager"><span className="mono">Page {data.pagination.page} of {data.pagination.pages} · {num(data.pagination.total)} resources</span><div className="pager-actions"><button className="btn" disabled={page <= 1} onClick={() => { setPage((value) => value - 1); setSelectedId(null) }}>Previous</button><button className="btn" disabled={page >= data.pagination.pages} onClick={() => { setPage((value) => value + 1); setSelectedId(null) }}>Next</button></div></div> : null}
      </Card>
    </div>
  )
}
