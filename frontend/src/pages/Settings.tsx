import { Download, Play, Plus, Trash2, Upload } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'

import { Card, PageHead } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import type {
  ControlOverride,
  CustomFramework,
  CustomPolicy,
  FrameworkImportResult,
  PolicyRuleType,
} from '../types'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const RULE_TYPES: PolicyRuleType[] = ['tag_required', 'encryption_required', 'no_public', 'network_max']
const inp: React.CSSProperties = {
  background: 'var(--surface-2, #1a1a1a)', color: 'inherit', border: '1px solid var(--border, #333)',
  borderRadius: 6, padding: '4px 8px', fontSize: 12.5,
}

// ── 1. Control overrides: toggle / re-severity / waive per control ─────────────
function ControlOverrides() {
  const frameworks = useApi(() => api.availableFrameworks())
  const overrides = useApi(() => api.controlOverrides())
  const [fw, setFw] = useState<string | null>(null)
  const selected = fw ?? frameworks.data?.items[0]?.id ?? null
  const controls = useApi(() => api.frameworkControls(selected as string), [selected], {
    enabled: !!selected,
  })

  const ovMap = useMemo(() => {
    const m = new Map<string, ControlOverride>()
    for (const o of overrides.data?.items ?? []) m.set(`${o.framework}:${o.control_id}`, o)
    return m
  }, [overrides.data])

  async function save(control_id: string, patch: Partial<ControlOverride>) {
    if (!selected) return
    await api.saveOverride({ framework: selected, control_id, ...patch })
    overrides.refetch()
  }
  async function reset(control_id: string) {
    if (!selected) return
    try { await api.deleteOverride(selected, control_id) } catch { /* no row yet */ }
    overrides.refetch()
  }

  return (
    <Card title="Control overrides" i={1} bodyPad={false}
      right={
        <select style={inp} value={selected ?? ''} onChange={(e) => setFw(e.target.value)}>
          {frameworks.data?.items.map((f) => (
            <option key={f.id} value={f.id}>{f.name}{f.builtin ? '' : ' (custom)'}</option>
          ))}
        </select>
      }
    >
      {controls.data && controls.data.controls.length > 0 ? (
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 80 }}>Enabled</th>
              <th style={{ width: 90 }}>Control</th>
              <th>Title</th>
              <th style={{ width: 120 }}>Severity</th>
              <th>Waiver note</th>
              <th style={{ width: 40 }} />
            </tr>
          </thead>
          <tbody>
            {controls.data.controls.map((c) => {
              const o = ovMap.get(`${selected}:${c.id}`)
              const enabled = o?.enabled ?? true
              return (
                <tr key={c.id} style={enabled ? undefined : { opacity: 0.5 }}>
                  <td>
                    <input type="checkbox" checked={enabled}
                      onChange={(e) => save(c.id, { enabled: e.target.checked })} />
                  </td>
                  <td className="mono">{c.id}</td>
                  <td>{c.title}</td>
                  <td>
                    <select style={inp} value={o?.severity ?? ''}
                      onChange={(e) => save(c.id, { severity: e.target.value || null })}>
                      <option value="">— default —</option>
                      {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </td>
                  <td>
                    <input style={{ ...inp, width: '100%' }} defaultValue={o?.note ?? ''}
                      placeholder="accepted-risk rationale…"
                      onBlur={(e) => e.target.value !== (o?.note ?? '') && save(c.id, { note: e.target.value || null })} />
                  </td>
                  <td>
                    {o ? (
                      <button className="btn" title="reset to default" onClick={() => reset(c.id)}>
                        <Trash2 size={13} />
                      </button>
                    ) : null}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      ) : (
        <div className="statev"><span className="label">no controls listed</span>
          <div className="hint">This framework curates no named controls to override.</div></div>
      )}
    </Card>
  )
}

// Import a framework's control matrix from an Excel file (each vendor's template
// differs — columns are auto-detected; unmapped controls get a best-practice
// check suggestion). Preview first, then confirm to persist.
function ExcelImport({ onImported }: { onImported: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [fwId, setFwId] = useState('')
  const [name, setName] = useState('')
  const [bytes, setBytes] = useState<ArrayBuffer | null>(null)
  const [preview, setPreview] = useState<FrameworkImportResult | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (fileRef.current) fileRef.current.value = ''
    if (!file) return
    setErr(null)
    if (!fwId.trim()) { setErr('enter a framework id first'); return }
    const buf = await file.arrayBuffer()
    setBytes(buf)
    setBusy(true)
    try {
      setPreview(await api.importFramework(fwId.trim(), buf, { name: name || undefined, dryRun: true }))
    } catch (e) { setErr(String(e)); setPreview(null) } finally { setBusy(false) }
  }

  async function confirm() {
    if (!bytes) return
    setBusy(true)
    try {
      await api.importFramework(fwId.trim(), bytes, { name: name || undefined, dryRun: false })
      setPreview(null); setBytes(null); setFwId(''); setName('')
      onImported()
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  return (
    <div style={{ marginBottom: 16, paddingBottom: 14, borderBottom: '1px solid var(--border, #333)' }}>
      <div className="hint" style={{ marginBottom: 6 }}>
        Import a control matrix (.xlsx) — columns auto-detected; controls with no check column get a best-practice suggestion.
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input style={inp} placeholder="FRAMEWORK-ID" value={fwId} onChange={(e) => setFwId(e.target.value)} />
        <input style={{ ...inp, minWidth: 160, flex: 1 }} placeholder="display name (optional)"
          value={name} onChange={(e) => setName(e.target.value)} />
        <label className="btn">
          <Upload size={13} /> {busy ? 'Working…' : 'Choose .xlsx'}
          <input ref={fileRef} type="file" accept=".xlsx" hidden onChange={onPick} disabled={busy} />
        </label>
      </div>
      {err ? <div className="hint" style={{ color: 'var(--sev-high)', marginTop: 6 }}>{err}</div> : null}
      {preview ? (
        <div style={{ marginTop: 10 }}>
          <div className="hint" style={{ marginBottom: 6 }}>
            {preview.control_count} controls parsed from <b>{preview.framework_id}</b> — review the mapping, then confirm:
          </div>
          <table className="tbl">
            <thead><tr>
              <th style={{ width: 90 }}>Control</th><th>Title</th>
              <th style={{ width: 120 }}>Section</th><th>Mapped checks</th>
            </tr></thead>
            <tbody>
              {Object.entries(preview.controls).map(([id, c]) => (
                <tr key={id}>
                  <td className="mono">{id}</td>
                  <td>{c.title}</td>
                  <td className="mono" style={{ color: 'var(--text-3)' }}>{c.section}</td>
                  <td className="mono" style={{ fontSize: 11.5 }}>
                    {c.checks.length ? c.checks.join(', ') : <span className="hint">— none —</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="btn primary" onClick={confirm} disabled={busy}>Confirm import</button>
            <button className="btn" onClick={() => { setPreview(null); setBytes(null) }}>Cancel</button>
          </div>
        </div>
      ) : null}
    </div>
  )
}

// ── 2. Custom frameworks: define a framework + its control→check map ───────────
type CtrlRow = { id: string; title: string; section: string; checks: string }
const blankCtrl: CtrlRow = { id: '', title: '', section: '', checks: '' }

function CustomFrameworks() {
  const list = useApi(() => api.customFrameworks())
  const [draft, setDraft] = useState<{ framework_id: string; name: string; version: string; controls: CtrlRow[] }>(
    { framework_id: '', name: '', version: '', controls: [{ ...blankCtrl }] },
  )
  const [err, setErr] = useState<string | null>(null)

  async function save() {
    setErr(null)
    const controls: CustomFramework['controls'] = {}
    for (const r of draft.controls) {
      if (!r.id.trim()) continue
      controls[r.id.trim()] = {
        title: r.title || r.id, section: r.section || 'General',
        checks: r.checks.split(',').map((s) => s.trim()).filter(Boolean),
      }
    }
    try {
      await api.saveFramework({
        framework_id: draft.framework_id.trim(), name: draft.name || draft.framework_id,
        version: draft.version || null, controls, enabled: true,
      })
      setDraft({ framework_id: '', name: '', version: '', controls: [{ ...blankCtrl }] })
      list.refetch()
    } catch (e) { setErr(String(e)) }
  }

  return (
    <Card title="Custom frameworks" i={2}>
      <ExcelImport onImported={() => list.refetch()} />
      {(list.data?.items.length ?? 0) > 0 && (
        <div style={{ marginBottom: 14, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {list.data!.items.map((f) => (
            <div key={f.framework_id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="pill">{f.framework_id}</span>
              <span style={{ flex: 1 }}>{f.name}{f.version ? ` · ${f.version}` : ''} · {Object.keys(f.controls).length} controls</span>
              <button className="btn" onClick={() => api.deleteFramework(f.framework_id).then(() => list.refetch())}>
                <Trash2 size={13} /> remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <input style={inp} placeholder="FRAMEWORK-ID" value={draft.framework_id}
          onChange={(e) => setDraft({ ...draft, framework_id: e.target.value })} />
        <input style={{ ...inp, flex: 1, minWidth: 160 }} placeholder="Display name" value={draft.name}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        <input style={{ ...inp, width: 90 }} placeholder="version" value={draft.version}
          onChange={(e) => setDraft({ ...draft, version: e.target.value })} />
      </div>

      <div className="hint" style={{ marginBottom: 6 }}>Controls — each maps to existing check ids (comma-separated):</div>
      {draft.controls.map((r, i) => (
        <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
          <input style={{ ...inp, width: 90 }} placeholder="ctrl id" value={r.id}
            onChange={(e) => upd(i, { id: e.target.value })} />
          <input style={{ ...inp, flex: 1, minWidth: 120 }} placeholder="title" value={r.title}
            onChange={(e) => upd(i, { title: e.target.value })} />
          <input style={{ ...inp, width: 120 }} placeholder="section" value={r.section}
            onChange={(e) => upd(i, { section: e.target.value })} />
          <input style={{ ...inp, flex: 1, minWidth: 120 }} placeholder="check_id, check_id" value={r.checks}
            onChange={(e) => upd(i, { checks: e.target.value })} />
        </div>
      ))}
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <button className="btn" onClick={() => setDraft({ ...draft, controls: [...draft.controls, { ...blankCtrl }] })}>
          <Plus size={13} /> add control
        </button>
        <button className="btn primary" onClick={save} disabled={!draft.framework_id.trim()}>Save framework</button>
        {err ? <span className="hint" style={{ color: 'var(--sev-high)' }}>{err}</span> : null}
      </div>
    </Card>
  )

  function upd(i: number, patch: Partial<CtrlRow>) {
    setDraft((d) => ({ ...d, controls: d.controls.map((c, j) => (j === i ? { ...c, ...patch } : c)) }))
  }
}

// ── 3. Custom policies: a rule over asset fields + framework mapping ───────────
function CustomPolicies() {
  const list = useApi(() => api.customPolicies())
  const [d, setD] = useState({
    policy_id: '', name: '', severity: 'medium', resource_type: '',
    ruleType: 'tag_required' as PolicyRuleType, param: '',
    framework: '', controls: '',
  })
  const [evalRes, setEvalRes] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  function buildRule(): CustomPolicy['rule'] {
    if (d.ruleType === 'tag_required') return { type: d.ruleType, params: { key: d.param } }
    if (d.ruleType === 'network_max') return { type: d.ruleType, params: { level: d.param || 'private' } }
    return { type: d.ruleType, params: {} }
  }

  async function save() {
    setErr(null)
    const frameworks: CustomPolicy['frameworks'] = {}
    if (d.framework.trim() && d.controls.trim()) {
      frameworks[d.framework.trim()] = d.controls.split(',').map((s) => s.trim()).filter(Boolean)
    }
    try {
      await api.savePolicy({
        policy_id: d.policy_id.trim(), name: d.name || d.policy_id, severity: d.severity,
        resource_type: d.resource_type || null, rule: buildRule(), frameworks, enabled: true,
      })
      setD({ ...d, policy_id: '', name: '', param: '', framework: '', controls: '' })
      list.refetch()
    } catch (e) { setErr(String(e)) }
  }

  async function runEval() {
    const r = await api.evaluatePolicies()
    setEvalRes(`${r.evaluated_policies} polic${r.evaluated_policies === 1 ? 'y' : 'ies'} · ${r.by_status.fail} fail / ${r.by_status.pass} pass across ${r.total} assets`)
  }

  const needsParam = d.ruleType === 'tag_required' || d.ruleType === 'network_max'

  return (
    <Card title="Custom policies" i={3}
      right={<button className="btn" onClick={runEval}><Play size={13} /> Evaluate now</button>}
    >
      {evalRes ? <div className="hint" style={{ marginBottom: 10 }}>{evalRes}</div> : null}

      {(list.data?.items.length ?? 0) > 0 && (
        <div style={{ marginBottom: 14, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {list.data!.items.map((p) => (
            <div key={p.policy_id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className={`pill sev-${p.severity}`}>{p.severity}</span>
              <span className="mono">{p.policy_id}</span>
              <span style={{ flex: 1 }}>{p.name} · {p.rule.type}{p.resource_type ? ` · ${p.resource_type}` : ''}</span>
              <button className="btn" onClick={() => api.deletePolicy(p.policy_id).then(() => list.refetch())}>
                <Trash2 size={13} /> remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <input style={inp} placeholder="policy-id" value={d.policy_id}
          onChange={(e) => setD({ ...d, policy_id: e.target.value })} />
        <input style={{ ...inp, flex: 1, minWidth: 140 }} placeholder="name" value={d.name}
          onChange={(e) => setD({ ...d, name: e.target.value })} />
        <select style={inp} value={d.severity} onChange={(e) => setD({ ...d, severity: e.target.value })}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input style={{ ...inp, width: 140 }} placeholder="asset type (or blank=all)" value={d.resource_type}
          onChange={(e) => setD({ ...d, resource_type: e.target.value })} />
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <select style={inp} value={d.ruleType} onChange={(e) => setD({ ...d, ruleType: e.target.value as PolicyRuleType })}>
          {RULE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        {needsParam ? (
          <input style={inp} placeholder={d.ruleType === 'tag_required' ? 'tag key' : 'max level (private|vpc|public)'}
            value={d.param} onChange={(e) => setD({ ...d, param: e.target.value })} />
        ) : null}
        <span className="hint">maps to →</span>
        <input style={{ ...inp, width: 120 }} placeholder="framework id" value={d.framework}
          onChange={(e) => setD({ ...d, framework: e.target.value })} />
        <input style={{ ...inp, width: 140 }} placeholder="control ids (csv)" value={d.controls}
          onChange={(e) => setD({ ...d, controls: e.target.value })} />
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn primary" onClick={save} disabled={!d.policy_id.trim()}>Save policy</button>
        {err ? <span className="hint" style={{ color: 'var(--sev-high)' }}>{err}</span> : null}
      </div>
    </Card>
  )
}

// ── 4. Statement of Applicability: the ISO 27001 audit artifact, any framework ─
function SoaCard() {
  const frameworks = useApi(() => api.availableFrameworks())
  const [fw, setFw] = useState<string | null>(null)
  const selected = fw ?? frameworks.data?.items[0]?.id ?? null
  const soa = useApi(() => api.soa(selected as string), [selected], { enabled: !!selected })
  const auto = soa.data ? soa.data.controls.filter((c) => c.assessment === 'Automated').length : 0

  return (
    <Card title="Statement of Applicability" i={4}
      right={selected ? (
        <a className="btn primary" href={api.soaExportUrl(selected)}>
          <Download size={13} /> Download .xlsx
        </a>
      ) : null}
    >
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <select style={inp} value={selected ?? ''} onChange={(e) => setFw(e.target.value)}>
          {frameworks.data?.items.map((f) => (
            <option key={f.id} value={f.id}>{f.name}{f.builtin ? '' : ' (custom)'}</option>
          ))}
        </select>
        {soa.data ? (
          <span className="hint">
            {soa.data.total} controls · {soa.data.applicable} applicable · <b>{auto}</b> auto-assessed by AWS checks, the rest manual
          </span>
        ) : null}
      </div>
      <div className="hint" style={{ marginTop: 8 }}>
        The SoA lists every control with its applicability, justification (from control overrides) and
        assessment method — the document an ISO 27001 auditor asks for first.
      </div>
    </Card>
  )
}

export function Settings() {
  return (
    <div className="page">
      <PageHead crumb="settings" title="Settings"
        sub="Customize controls, build frameworks, and write policies. Empty = stock defaults." />
      <ControlOverrides />
      <CustomFrameworks />
      <CustomPolicies />
      <SoaCard />
    </div>
  )
}
