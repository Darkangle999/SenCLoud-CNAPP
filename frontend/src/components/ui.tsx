import type { ReactNode } from 'react'

import type { ApiError } from '../lib/api'
import { num } from '../lib/format'
import type { Severity } from '../types'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

// ── page chrome ────────────────────────────────────────────────

export function PageHead({
  crumb,
  title,
  sub,
  actions,
}: {
  crumb: string
  title: string
  sub?: string
  actions?: ReactNode
}) {
  return (
    <header className="page-head reveal" data-section={crumb} style={{ ['--i' as string]: 0 }}>
      <div>
        <h1>{title}</h1>
        {sub ? <div className="page-sub">{sub}</div> : null}
      </div>
      {actions ? <div style={{ display: 'flex', gap: 8 }}>{actions}</div> : null}
    </header>
  )
}

// ── status primitives ──────────────────────────────────────────

type Kind = 'ok' | 'warn' | 'fail' | 'neutral'

const KIND_COLOR: Record<Kind, string> = {
  ok: 'var(--sev-low)',
  warn: 'var(--sev-medium)',
  fail: 'var(--sev-high)',
  neutral: 'var(--text-3)',
}

export function Pill({ kind = 'neutral', children }: { kind?: Kind; children: ReactNode }) {
  return (
    <span className="pill" style={{ color: KIND_COLOR[kind] }}>
      <span className="dot" style={{ background: KIND_COLOR[kind] }} />
      {children}
    </span>
  )
}

export function Banner({ kind = 'neutral', children }: { kind?: Kind; children: ReactNode }) {
  return (
    <div
      className="hint"
      style={{
        borderLeft: `2px solid ${KIND_COLOR[kind]}`,
        background: 'var(--surface-2)',
        borderRadius: 4,
        padding: '8px 10px',
        margin: '8px 0',
        color: kind === 'neutral' ? undefined : KIND_COLOR[kind],
      }}
    >
      {children}
    </div>
  )
}

/** Preflight results. `info` and `warn` are deliberately distinct from `fail`:
 *  only a fail means a launch link would not resolve. */
export function CheckList({
  checks,
}: {
  checks: { name: string; status: string; detail?: string }[]
}) {
  const kindOf = (status: string): Kind =>
    status === 'pass' ? 'ok' : status === 'fail' ? 'fail' : status === 'warn' ? 'warn' : 'neutral'
  return (
    <div style={{ display: 'grid', gap: 6, marginTop: 8 }}>
      {checks.map((c) => (
        <div key={c.name} style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
          <Pill kind={kindOf(c.status)}>{c.status}</Pill>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12.5 }}>{c.name}</div>
            {c.detail ? (
              <div className="hint mono" style={{ fontSize: 11, wordBreak: 'break-word' }}>
                {c.detail}
              </div>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  )
}

export function KeyValues({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv" style={{ marginTop: 10 }}>
      {rows.map(([term, value]) => (
        <div key={term} style={{ display: 'contents' }}>
          <dt>{term}</dt>
          <dd className="mono" style={{ fontSize: 11.5 }}>{value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function CopyButton({ text, label = 'copy' }: { text: string; label?: string }) {
  return (
    <button className="btn" onClick={() => void navigator.clipboard?.writeText(text)}>
      {label}
    </button>
  )
}

// ── honest tri-state ───────────────────────────────────────────

export function StateView({
  loading,
  error,
  empty,
  emptyHint,
  children,
}: {
  loading: boolean
  error: ApiError | null
  empty?: boolean
  emptyHint?: string
  children: ReactNode
}) {
  if (loading) {
    return (
      <div className="statev statev-loading" role="status" aria-label="Loading content">
        <span className="sr-only">Loading</span>
        <SkeletonRows n={6} />
      </div>
    )
  }
  if (error) {
    return (
      <div className="statev">
        <div className="code">{error.message}</div>
        {error.detail ? <div className="hint">{error.detail}</div> : null}
        <div className="hint">The UI renders exactly what the backend returns — nothing else.</div>
      </div>
    )
  }
  if (empty) {
    return (
      <div className="statev">
        <span className="label">no data</span>
        {emptyHint ? <div className="hint">{emptyHint}</div> : null}
      </div>
    )
  }
  return <>{children}</>
}

// ── severity ───────────────────────────────────────────────────

export function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={`sev-badge sev-${sev}`}>
      <span className="dot" />
      {sev}
    </span>
  )
}

// ── signature: risk spectrum ───────────────────────────────────

export function Spectrum({ bySeverity }: { bySeverity: Record<string, number> }) {
  const counts = SEVERITY_ORDER.map((s) => ({ sev: s, n: bySeverity[s] ?? 0 })).filter(
    (c) => c.n > 0,
  )
  const total = counts.reduce((a, c) => a + c.n, 0)
  if (total === 0) {
    return (
      <div>
        <div className="spectrum" aria-hidden />
        <div className="spectrum-legend">
          <span className="hint" style={{ color: 'var(--text-3)', fontSize: 12.5 }}>
            No open findings.
          </span>
        </div>
      </div>
    )
  }
  return (
    <div>
      <div className="spectrum" role="img" aria-label={`${total} open findings by severity`}>
        {counts.map((c) => (
          <div
            key={c.sev}
            className="seg"
            style={{ width: `${(c.n / total) * 100}%`, background: `var(--sev-${c.sev})` }}
          />
        ))}
      </div>
      <div className="spectrum-legend">
        {counts.map((c) => (
          <span key={c.sev} className={`item sev-${c.sev}`}>
            <span className="dot" />
            <span className="label" style={{ color: 'var(--text-2)' }}>
              {c.sev}
            </span>
            <span className="num">{num(c.n)}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

// ── cards ──────────────────────────────────────────────────────

export function StatCard({
  label,
  value,
  sub,
  crit,
  i,
}: {
  label: string
  value: string | number | null
  sub?: string
  crit?: boolean
  i?: number
}) {
  return (
    <div className={`card stat reveal${crit ? ' crit' : ''}`} style={{ ['--i' as string]: i ?? 0 }}>
      <span className="label">{label}</span>
      <div className="v">{value === null ? <span className="skel" style={{ display: 'inline-block', width: 56, height: 24 }} /> : value}</div>
      {sub ? <div className="s">{sub}</div> : null}
    </div>
  )
}

export function Card({
  title,
  right,
  children,
  i,
  bodyPad,
}: {
  title?: string
  right?: ReactNode
  children: ReactNode
  i?: number
  bodyPad?: boolean
}) {
  return (
    <section className="card reveal" style={{ ['--i' as string]: i ?? 0 }}>
      {title ? (
        <div className="card-head">
          <span className="label" style={{ color: 'var(--text-2)' }}>
            {title}
          </span>
          {right}
        </div>
      ) : null}
      {bodyPad === false ? children : <div className="card-body">{children}</div>}
    </section>
  )
}

// ── bar list (dashboard) ───────────────────────────────────────

export function BarList({ entries }: { entries: Array<[string, number]> }) {
  const max = Math.max(1, ...entries.map(([, n]) => n))
  return (
    <div>
      {entries.map(([k, n]) => (
        <div key={k} className="bar-row">
          <span className="k" title={k}>
            {k}
          </span>
          <span className="n num">{num(n)}</span>
          <span className="bar-track">
            <span className="fill" style={{ width: `${(n / max) * 100}%` }} />
          </span>
        </div>
      ))}
    </div>
  )
}

// ── score ring (compliance) ────────────────────────────────────

export function Ring({ pct, size = 52 }: { pct: number; size?: number }) {
  const r = (size - 6) / 2
  const c = 2 * Math.PI * r
  return (
    <svg className="ring" width={size} height={size} aria-hidden>
      <circle className="track" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={4} />
      <circle
        className="arc"
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        strokeWidth={4}
        strokeLinecap="round"
        strokeDasharray={c}
        strokeDashoffset={c * (1 - Math.min(Math.max(pct, 0), 100) / 100)}
      />
    </svg>
  )
}

// ── skeleton rows ──────────────────────────────────────────────

export function SkeletonRows({ n = 5 }: { n?: number }) {
  return (
    <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
      {Array.from({ length: n }, (_, i) => (
        <div key={i} className="skel" style={{ height: 14, width: `${88 - i * 9}%` }} />
      ))}
    </div>
  )
}
