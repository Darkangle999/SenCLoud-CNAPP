import { ChevronLeft, ChevronRight, Download, Search } from 'lucide-react'
import { useState } from 'react'

import { Drawer } from '../components/Drawer'
import { Card, PageHead, SevBadge, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { api, ApiError } from '../lib/api'
import { num, relTime } from '../lib/format'

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'] as const

export function CveDatabase() {
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>('all')
  const [input, setInput] = useState('') // search box value
  const [keyword, setKeyword] = useState('') // applied (on submit) — avoids refetch per keystroke
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<string | null>(null)
  const [syncing, setSyncing] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const summary = useApi(() => api.cveCatalogSummary())
  const catalog = useApi(
    () =>
      api.cveCatalog({
        page,
        page_size: 50,
        severity: severity === 'all' ? undefined : severity,
        q: keyword || undefined,
      }),
    [page, severity, keyword],
  )
  const detail = useApi(() => api.cve(selected as string), [selected], { enabled: selected !== null })

  function applySearch(e: React.FormEvent) {
    e.preventDefault()
    setPage(1)
    setKeyword(input.trim())
  }

  async function sync() {
    setSyncing(true)
    try {
      const r = await api.ingestCveCatalog({ incremental: true, days: 7 })
      setToast(`synced ${num(r.ingested)} CVEs modified in the last ${r.days ?? 7}d`)
      catalog.refetch()
      summary.refetch()
    } catch (e) {
      setToast(e instanceof ApiError ? e.message : String(e))
    } finally {
      setSyncing(false)
      setTimeout(() => setToast(null), 6000)
    }
  }

  const data = catalog.data
  return (
    <div className="page">
      <PageHead
        crumb="cve database"
        title="CVE Database"
        sub={
          summary.data
            ? `${num(summary.data.total)} CVEs in catalog`
              + ` · ${num(summary.data.by_severity?.critical ?? 0)} critical`
              + ` · ${num(summary.data.by_severity?.high ?? 0)} high`
            : 'Full NVD CVE dictionary — browse and search every published CVE.'
        }
        actions={
          <button
            className="btn"
            onClick={sync}
            disabled={syncing}
            title="Pull CVEs modified in the last 7 days from the NVD 2.0 API"
          >
            <Download style={syncing ? { animation: 'spin 0.7s linear infinite' } : undefined} />
            {syncing ? 'Syncing…' : 'Sync recent'}
          </button>
        }
      />

      <div className="control-row reveal" style={{ ['--i' as string]: 1 }}>
        <form onSubmit={applySearch} style={{ display: 'flex', gap: 8, flex: 1, minWidth: 0 }}>
          <div style={{ position: 'relative', flex: 1, minWidth: 0 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
            <input
              className="input"
              style={{ width: '100%', paddingLeft: 30 }}
              placeholder="Search CVE id or description… (press Enter)"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              aria-label="search CVEs"
            />
          </div>
          <button className="btn" type="submit">Search</button>
        </form>
        <select
          className="select"
          value={severity}
          onChange={(e) => {
            setPage(1)
            setSeverity(e.target.value as never)
          }}
          aria-label="severity filter"
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s === 'all' ? 'severity: all' : s}
            </option>
          ))}
        </select>
      </div>

      <Card i={2} bodyPad={false}>
        <StateView
          loading={catalog.loading}
          error={catalog.error}
          empty={!!data && data.items.length === 0}
          emptyHint={
            keyword || severity !== 'all'
              ? 'No CVEs match. Try a broader search.'
              : 'Catalog is empty. Bulk-load it: POST /api/inventory/cve-catalog/ingest with a directory of NVD feed files, or hit “Sync recent”.'
          }
        >
          {data ? (
            <div>
              {data.items.map((c) => (
                <div
                  key={c.cve_id}
                  className={`frow sev-${c.severity ?? 'info'}`}
                  onClick={() => setSelected(c.cve_id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => e.key === 'Enter' && setSelected(c.cve_id)}
                >
                  <span className="pill" style={{ flexShrink: 0 }}>{c.cve_id}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="t" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {c.description ?? '—'}
                    </div>
                  </div>
                  {c.cvss_score != null ? (
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', flexShrink: 0 }}>
                      CVSS {c.cvss_score}
                      {c.cvss_version ? ` v${c.cvss_version}` : ''}
                    </span>
                  ) : null}
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', width: 72, textAlign: 'right', flexShrink: 0 }}>
                    {relTime(c.last_modified)}
                  </span>
                  <span style={{ width: 86, flexShrink: 0, textAlign: 'right' }}>
                    <SevBadge sev={c.severity ?? 'info'} />
                  </span>
                </div>
              ))}
            </div>
          ) : null}
        </StateView>
      </Card>

      {data && data.pages > 1 ? (
        <div className="control-row" style={{ justifyContent: 'flex-end', gap: 12 }}>
          <span className="mono" style={{ fontSize: 12, color: 'var(--text-3)' }}>
            page {data.page} of {num(data.pages)} · {num(data.total)} total
          </span>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="btn" disabled={data.page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} aria-label="previous page">
              <ChevronLeft size={14} />
            </button>
            <button className="btn" disabled={data.page >= data.pages} onClick={() => setPage((p) => p + 1)} aria-label="next page">
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      ) : null}

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ?? undefined}
        subtitle={detail.data?.cvss_version ? `CVSS v${detail.data.cvss_version}` : undefined}
      >
        <StateView loading={detail.loading} error={detail.error} empty={false}>
          {detail.data ? (
            <>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <SevBadge sev={detail.data.severity ?? 'info'} />
                {detail.data.cvss_score != null ? (
                  <span className="pill">CVSS {detail.data.cvss_score}</span>
                ) : null}
                {(detail.data.cwes ?? []).map((cwe) => (
                  <span key={cwe} className="pill tint">{cwe}</span>
                ))}
              </div>
              {detail.data.description ? (
                <div className="drawer-section">
                  <span className="label">Description</span>
                  <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6 }}>{detail.data.description}</p>
                </div>
              ) : null}
              <div className="drawer-section">
                <span className="label">Details</span>
                <dl className="kv">
                  <dt>vector</dt>
                  <dd className="mono" style={{ fontSize: 11.5 }}>{detail.data.cvss_vector ?? '—'}</dd>
                  <dt>published</dt>
                  <dd className="mono" style={{ fontSize: 11.5 }}>{detail.data.published ?? '—'}</dd>
                  <dt>modified</dt>
                  <dd className="mono" style={{ fontSize: 11.5 }}>{detail.data.last_modified ?? '—'}</dd>
                </dl>
              </div>
              <div className="drawer-section">
                <span className="label">References</span>
                <div className="cve-refs">
                  <a href={`https://nvd.nist.gov/vuln/detail/${detail.data.cve_id}`} target="_blank" rel="noreferrer">
                    NVD record ↗
                  </a>
                  {(detail.data.refs ?? []).slice(0, 12).map((r) => (
                    <a key={r} href={r} target="_blank" rel="noreferrer">{r}</a>
                  ))}
                </div>
              </div>
            </>
          ) : null}
        </StateView>
      </Drawer>

      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}
