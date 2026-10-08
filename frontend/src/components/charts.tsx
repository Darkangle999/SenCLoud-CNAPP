// Beacon-themed recharts wrappers. recharts is already a dependency; these just
// pin its SVG fills/strokes to our CSS tokens. SVG presentation attributes don't
// resolve var(), so we read the computed values and re-resolve on theme toggle.
import { useMemo } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { num } from '../lib/format'
import { useTheme } from '../theme'
import type { CompliancePoint, Severity } from '../types'
import { SEVERITY_ORDER } from './ui'

function readVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}

function useChartTokens() {
  const { theme } = useTheme() // re-resolve when the palette flips
  return useMemo(
    () => ({
      brand: readVar('--brand', '#1e3a8a'),
      signal: readVar('--signal', '#f5c518'),
      text: readVar('--text', '#161618'),
      text2: readVar('--text-2', '#5f6167'),
      text3: readVar('--text-3', '#9b9ca3'),
      border: readVar('--border', '#e7e7ea'),
      surface: readVar('--surface', '#ffffff'),
      sev: {
        critical: readVar('--sev-critical', '#d6293a'),
        high: readVar('--sev-high', '#df5c0c'),
        medium: readVar('--sev-medium', '#af7e03'),
        low: readVar('--sev-low', '#6e7077'),
        info: readVar('--sev-info', '#9b9ca3'),
      } as Record<Severity, string>,
    }),
    [theme],
  )
}

type Tokens = ReturnType<typeof useChartTokens>

// shared tooltip skin
function tip(t: Tokens) {
  return {
    contentStyle: {
      background: t.surface,
      border: `1px solid ${t.border}`,
      borderRadius: 8,
      fontFamily: 'var(--font-mono)',
      fontSize: 12,
      color: t.text,
      boxShadow: 'none',
    },
    itemStyle: { color: t.text2 },
    labelStyle: { color: t.text3 },
  }
}

// ── findings by severity ───────────────────────────────────────
export function SeverityDonut({ bySeverity }: { bySeverity: Record<string, number> }) {
  const t = useChartTokens()
  const data = SEVERITY_ORDER.map((s) => ({ name: s, value: bySeverity[s] ?? 0, fill: t.sev[s] })).filter(
    (d) => d.value > 0,
  )
  const total = data.reduce((a, d) => a + d.value, 0)
  if (total === 0)
    return (
      <div className="hint" style={{ color: 'var(--text-3)', padding: '40px 0', textAlign: 'center' }}>
        No open findings.
      </div>
    )
  return (
    <div>
      <div style={{ position: 'relative', height: 200 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={82} paddingAngle={2} strokeWidth={0}>
              {data.map((d) => (
                <Cell key={d.name} fill={d.fill} />
              ))}
            </Pie>
            <Tooltip {...tip(t)} />
          </PieChart>
        </ResponsiveContainer>
        <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', pointerEvents: 'none' }}>
          <div style={{ textAlign: 'center' }}>
            <div className="num" style={{ fontSize: 28, fontWeight: 600, lineHeight: 1 }}>{num(total)}</div>
            <div className="label" style={{ marginTop: 4 }}>open</div>
          </div>
        </div>
      </div>
      <div className="spectrum-legend" style={{ justifyContent: 'center', marginTop: 6 }}>
        {data.map((d) => (
          <span key={d.name} className={`item sev-${d.name}`}>
            <span className="dot" />
            <span className="label" style={{ color: 'var(--text-2)' }}>{d.name}</span>
            <span className="num">{num(d.value)}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

// ── compliance score over time ─────────────────────────────────
export function TrendArea({ points }: { points: CompliancePoint[] }) {
  const t = useChartTokens()
  const data = points.map((p) => ({
    d: p.captured_at ? new Date(p.captured_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '',
    score: p.score,
  }))
  return (
    <div style={{ height: 200 }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="cs-trend" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={t.brand} stopOpacity={0.35} />
              <stop offset="100%" stopColor={t.brand} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke={t.border} strokeDasharray="2 4" vertical={false} />
          <XAxis dataKey="d" tick={{ fill: t.text3, fontSize: 10 }} tickLine={false} axisLine={{ stroke: t.border }} />
          <YAxis domain={[0, 100]} width={34} tick={{ fill: t.text3, fontSize: 10 }} tickLine={false} axisLine={false} />
          <Tooltip {...tip(t)} />
          <Area type="monotone" dataKey="score" stroke={t.brand} strokeWidth={2} fill="url(#cs-trend)" dot={{ r: 2, fill: t.brand }} activeDot={{ r: 4 }} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

// ── per-framework compliance score ─────────────────────────────
// color carries meaning: >=80 brand (good), >=50 signal (watch), else high (bad).
export function ScoreColumns({ data }: { data: Array<{ name: string; score: number }> }) {
  const t = useChartTokens()
  return (
    <div style={{ height: 220 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke={t.border} strokeDasharray="2 4" vertical={false} />
          <XAxis dataKey="name" tick={{ fill: t.text3, fontSize: 10 }} tickLine={false} axisLine={{ stroke: t.border }} interval={0} />
          <YAxis domain={[0, 100]} width={34} tick={{ fill: t.text3, fontSize: 10 }} tickLine={false} axisLine={false} />
          <Tooltip {...tip(t)} cursor={{ fill: t.border, fillOpacity: 0.3 }} />
          <Bar dataKey="score" radius={[4, 4, 0, 0]} maxBarSize={48}>
            {data.map((d) => (
              <Cell key={d.name} fill={d.score >= 80 ? t.brand : d.score >= 50 ? t.signal : t.sev.high} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
