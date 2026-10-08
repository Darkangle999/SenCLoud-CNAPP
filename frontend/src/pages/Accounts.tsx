import { Copy, Download, ExternalLink, FileCode, Link2, Plug, Plus, Play, RefreshCw, Trash2, UploadCloud } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import { Banner, Card, CheckList, CopyButton, KeyValues, PageHead, Pill, StateView } from '../components/ui'
import { ProgressBar } from '../components/ProgressBar'
import { useApi } from '../hooks/useApi'
import { api, ApiError } from '../lib/api'
import type { Account, LaunchLink, OnboardingSession, OnboardingTemplate } from '../types'
import { relTime, shortHash, timeUntil } from '../lib/format'

const TTL_CHOICES: [number, string][] = [
  [900, '15 minutes'],
  [3600, '1 hour'],
  [14400, '4 hours'],
  [86400, '24 hours'],
]

const inp: React.CSSProperties = {
  background: 'var(--surface-2, #1a1a1a)', color: 'inherit', border: '1px solid var(--border, #333)',
  borderRadius: 6, padding: '4px 8px', fontSize: 12.5,
}

const pre: React.CSSProperties = {
  fontSize: 11, background: 'var(--surface-2, #111)', border: '1px solid var(--border, #333)',
  borderRadius: 6, padding: 10, overflowX: 'auto', maxHeight: 320, cursor: 'pointer',
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ? `${error.message} — ${error.detail}` : error.message
  }
  return String(error)
}

function scanLabel(account: Account): string {
  const scan = account.latest_scan
  if (!scan) return 'awaiting initial scan'
  if (scan.status === 'queued') return 'scan queued'
  if (scan.status === 'running') return 'scanning'
  if (scan.status === 'failed') return 'scan failed'
  return `scanned ${scan.assets_found} assets`
}

function CopyBlock({ text, onCopied }: { text: string; onCopied: () => void }) {
  return (
    <pre className="mono" style={pre} title="Click to copy"
      onClick={() => { navigator.clipboard?.writeText(text); onCopied() }}>
      {text}
    </pre>
  )
}

function downloadCloudFormationTemplate(accountIdentifier: string, template: string) {
  const blob = new Blob([template], { type: 'application/x-yaml;charset=utf-8' })
  const href = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = href
  link.download = `odineyes-onboarding-${accountIdentifier}.yaml`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(href)
}

function AccountSetup({ account_identifier, provider, name, onDraftCreated }: {
  account_identifier: string; provider: string; name: string; onDraftCreated: () => void
}) {
  const [policyMode, setPolicyMode] = useState<'managed' | 'least-privilege'>('managed')
  const [format, setFormat] = useState<'cloudformation' | 'terraform' | 'terraform-auto'>('cloudformation')
  const [tpl, setTpl] = useState<OnboardingTemplate | null>(null)
  const [genErr, setGenErr] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [verifyingSetup, setVerifyingSetup] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const idLooksValid = provider === 'aws' ? /^\d{12}$/.test(account_identifier.trim()) : account_identifier.trim().length > 0

  function copied(label: string) {
    setToast(label)
    setTimeout(() => setToast(null), 2000)
  }

  async function generate(mode: 'managed' | 'least-privilege') {
    setPolicyMode(mode); setGenErr(null); setGenerating(true)
    try {
      const t = await api.onboardingTemplate({
        provider, account_identifier: account_identifier.trim(),
        name: name.trim() || undefined, policy_mode: mode,
      })
      setTpl(t)
      onDraftCreated()
    } catch (e) {
      setGenErr(errorMessage(e))
    } finally { setGenerating(false) }
  }

  async function verifySetup(silent = false) {
    if (!tpl || verifyingSetup) return
    setVerifyingSetup(true)
    try {
      const result = await api.verifyOnboarding(tpl.account_id)
      if (result.connected) {
        copied('Connected. First scan started.')
        onDraftCreated()
      } else if (!silent) {
        setToast('Stack not ready yet. Finish CREATE_COMPLETE, then retry.')
      }
    } catch (e) {
      if (!silent) setGenErr(errorMessage(e))
    } finally { setVerifyingSetup(false) }
  }

  useEffect(() => {
    if (!tpl?.cloudformation_quick_create_url) return
    const onFocus = () => { void verifySetup(true) }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [tpl?.account_id, tpl?.cloudformation_quick_create_url])

  if (provider !== 'aws') return null

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <button className="btn" onClick={() => generate(policyMode)} disabled={generating || !idLooksValid}>
          <FileCode size={13} /> {generating ? 'Generating…' : tpl ? 'Regenerate setup files' : 'Generate setup files'}
        </button>
        {!idLooksValid ? <span className="hint">enter a 12-digit account id first</span> : null}
        {toast ? <span className="hint" style={{ color: 'var(--sev-low)' }}>{toast}</span> : null}
      </div>
      {genErr ? <div className="hint" style={{ color: 'var(--sev-high)', marginBottom: 8 }}>{genErr}</div> : null}

      {tpl ? (
        <div style={{ border: '1px solid var(--border, #333)', borderRadius: 8, padding: 12 }}>
          {tpl.cloudformation_quick_create_url ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
              <a className="btn primary" href={tpl.cloudformation_quick_create_url} target="_blank" rel="noreferrer">
                <ExternalLink size={13} /> Launch AWS CloudFormation
              </a>
              <button
                className="btn"
                onClick={() => downloadCloudFormationTemplate(account_identifier.trim(), tpl.cloudformation_template)}
              >
                <Download size={13} /> Download YAML
              </button>
              <button className="btn" onClick={() => void verifySetup()} disabled={verifyingSetup}>
                {verifyingSetup ? 'Verifying…' : 'Verify setup'}
              </button>
              <span className="hint">
                Opens the full-visibility AWS stack with a unique ExternalId. On CREATE_COMPLETE, its one-time callback registers the role and starts the first scan automatically.
              </span>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
              <div className="hint" style={{ color: 'var(--sev-high)' }}>
                One-click CloudFormation is not enabled for this deployment. {tpl.one_click_setup_error ?? 'Use downloaded YAML for manual upload.'}
              </div>
              <button
                className="btn"
                onClick={() => downloadCloudFormationTemplate(account_identifier.trim(), tpl.cloudformation_template)}
              >
                <Download size={13} /> Download YAML
              </button>
            </div>
          )}
          <div style={{ display: 'flex', gap: 16, marginBottom: 10, flexWrap: 'wrap', fontSize: 11.5 }}>
            <div><span className="hint">ExternalId&nbsp;</span><span className="mono">{tpl.external_id}</span></div>
            <div><span className="hint">Trust account&nbsp;</span><span className="mono">{tpl.trust_account_id}</span></div>
            {tpl.scanner_principal_arn ? <div><span className="hint">Scanner principal&nbsp;</span><span className="mono">{tpl.scanner_principal_arn.split('/').pop()}</span></div> : null}
            {tpl.cloudformation_template_s3_uri ? (
              <div><span className="hint">Private YAML&nbsp;</span><span className="mono">{tpl.cloudformation_template_s3_uri}</span></div>
            ) : null}
            {tpl.cloudformation_template_reused !== null ? (
              <div className="hint">{tpl.cloudformation_template_reused ? 'Reused stored YAML with a fresh launch link.' : 'Stored a new YAML version for this account.'}</div>
            ) : null}
          </div>

          <div style={{ display: 'flex', gap: 12, marginBottom: 10, flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}>
              <input type="radio" checked={policyMode === 'managed'} onChange={() => generate('managed')} />
              Full CSPM visibility (guarded read policies + SecurityAudit + ViewOnlyAccess)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}>
              <input type="radio" checked={policyMode === 'least-privilege'} onChange={() => generate('least-privilege')} />
              Least-privilege (current collector contract; update after scanner upgrades)
            </label>
          </div>

          <div style={{ display: 'flex', gap: 4, marginBottom: 8, flexWrap: 'wrap' }}>
            <button className={`btn${format === 'terraform-auto' ? ' primary' : ''}`}
              disabled={!tpl.terraform_autoconnect_snippet}
              title={tpl.terraform_autoconnect_snippet ? undefined : 'only available right after generating (needs the one-time secret) — regenerate to get it back'}
              onClick={() => setFormat('terraform-auto')}>Terraform (auto-connect)</button>
            <button className={`btn${format === 'terraform' ? ' primary' : ''}`}
              onClick={() => setFormat('terraform')}>Terraform (manual)</button>
            <button className={`btn${format === 'cloudformation' ? ' primary' : ''}`}
              onClick={() => setFormat('cloudformation')}>CloudFormation</button>
          </div>

          <CopyBlock
            text={
              format === 'cloudformation' ? tpl.cloudformation_template
              : format === 'terraform-auto' ? (tpl.terraform_autoconnect_snippet ?? tpl.terraform_snippet)
              : tpl.terraform_snippet
            }
            onCopied={() => copied('copied')}
          />

          <div className="hint" style={{ marginTop: 8, display: 'flex', gap: 4 }}>
            <Copy size={12} style={{ flex: 'none', marginTop: 2 }} />
            {format === 'cloudformation'
              ? 'Launch AWS CloudFormation keeps automatic registration. Download YAML is manual fallback for customer change-control upload: it creates same read-only role, but callback is disabled, so register returned RoleArn after CREATE_COMPLETE.'
              : format === 'terraform-auto'
              ? 'Recommended — save as main.tf and run terraform apply. It creates the role AND submits the ARN to Odineyes automatically (needs python3 on the machine running apply). No paste needed; the account will auto-scan within a minute.'
              : 'Copy this into your Terraform module, apply it, then copy the odineyes_role_arn output and paste it below.'}
          </div>
        </div>
      ) : null}
    </div>
  )
}

// ── hosting readiness ──────────────────────────────────────────

/** Preflight. Everything that can make a launch link dead — no public callback
 *  URL, no signing secret, an unpublished template, a URL CloudFormation will
 *  refuse — is answered here rather than by the customer's failed stack. */
function HostingCard({ onReady }: { onReady: (ready: boolean) => void }) {
  const hosting = useApi(() => api.hostingStatus())
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<string | null>(null)

  useEffect(() => {
    if (hosting.data) onReady(hosting.data.ready)
  }, [hosting.data, onReady])

  async function publish() {
    setBusy(true); setNote(null)
    try {
      const t = await api.publishTemplate()
      setNote(`${t.reused ? 'reused unchanged template' : 'uploaded new template'} · sha256 ${shortHash(t.checksum)}`)
      hosting.refetch()
    } catch (e) { setNote(errorMessage(e)) } finally { setBusy(false) }
  }

  return (
    <Card title="Template hosting" i={1}
      right={
        <>
          <button className="btn" onClick={() => hosting.refetch()} disabled={hosting.loading}>
            <RefreshCw size={12} /> Re-check
          </button>
          <button className="btn" onClick={publish} disabled={busy}>
            <UploadCloud size={12} /> {busy ? 'Publishing…' : 'Publish template'}
          </button>
        </>
      }
    >
      <StateView loading={hosting.loading && !hosting.data} error={hosting.error}>
        {hosting.data ? (
          <>
            <Banner kind={hosting.data.ready ? 'ok' : 'fail'}>
              {hosting.data.ready
                ? 'Hosting is ready — launch links will resolve.'
                : 'One-click onboarding is disabled until the failures below are fixed.'}
            </Banner>
            <CheckList checks={hosting.data.checks} />
          </>
        ) : null}
      </StateView>
      {note ? <div className="hint mono" style={{ marginTop: 8 }}>{note}</div> : null}
    </Card>
  )
}

// ── launch link ────────────────────────────────────────────────

/** The account-id-free path: the operator sends a link, the customer opens it
 *  while signed into whichever account they want connected, and the stack
 *  reports its own role ARN back. Nothing is typed and nothing is pasted. */
function LinkCard({ ready, onIssued }: { ready: boolean; onIssued: () => void }) {
  const [label, setLabel] = useState('')
  const [ttl, setTtl] = useState(3600)
  const [region, setRegion] = useState('')
  // Off unless the platform has a publicly reachable callback endpoint: a stack
  // that cannot reach its callback fails the custom resource and rolls itself
  // back, taking the created role with it.
  const [withCallback, setWithCallback] = useState(true)
  const [link, setLink] = useState<LaunchLink | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [remaining, setRemaining] = useState<string | null>(null)

  // A link that has quietly expired should look expired, not live.
  useEffect(() => {
    if (!link) return
    const tick = () => setRemaining(timeUntil(link.expires_at))
    tick()
    const timer = window.setInterval(tick, 1000)
    return () => window.clearInterval(timer)
  }, [link])

  async function generate() {
    setBusy(true); setError(null)
    try {
      setLink(await api.onboardingLink({
        label: label.trim() || undefined,
        ttl_seconds: ttl,
        console_region: region.trim() || undefined,
        with_callback: withCallback,
      }))
      onIssued()
    } catch (e) { setError(errorMessage(e)); setLink(null) } finally { setBusy(false) }
  }

  return (
    <Card title="One-click onboarding" i={2}>
      <div className="hint" style={{ marginBottom: 10 }}>
        Generate a link and send it to the customer. They open it while signed into whichever AWS
        account they want connected, review the stack, and create it. The stack reports its own role
        ARN back, so the account is discovered rather than typed.
      </div>

      {!ready ? (
        <Banner kind="warn">
          Template hosting is not ready, so a generated link would not resolve. Fix the failures above first.
        </Banner>
      ) : null}

      <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <input style={{ ...inp, flex: 1, minWidth: 180 }} placeholder="customer label (optional)"
          value={label} onChange={(e) => setLabel(e.target.value)} />
        <select style={inp} value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
          {TTL_CHOICES.map(([s, text]) => <option key={s} value={s}>{text}</option>)}
        </select>
        <input style={{ ...inp, width: 130 }} placeholder="console region"
          value={region} onChange={(e) => setRegion(e.target.value)} />
      </div>
      <div className="hint" style={{ marginBottom: 8 }}>
        Regenerating for the same label retires every earlier link with that label.
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, marginBottom: 10 }}>
        <input type="checkbox" checked={withCallback} onChange={(e) => setWithCallback(e.target.checked)} />
        Automatic callback
        <span className="hint">
          {withCallback
            ? 'the stack reports its own role ARN — needs a publicly reachable ODINEYES_PUBLIC_API_URL'
            : 'no Lambda is created; register the stack’s RoleArn output below'}
        </span>
      </label>

      <button className="btn primary" onClick={generate} disabled={busy || !ready}>
        <Link2 size={13} /> {busy ? 'Generating…' : link ? 'Generate a new link' : 'Generate launch link'}
      </button>
      {link && link.superseded_links > 0 ? (
        <span className="hint" style={{ marginLeft: 8, color: 'var(--sev-medium)' }}>
          {link.superseded_links} earlier link{link.superseded_links === 1 ? '' : 's'} for this label now return 409
        </span>
      ) : null}

      {error ? <Banner kind="fail">{error}</Banner> : null}

      {link ? (
        <>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12, flexWrap: 'wrap' }}>
            <code className="mono" style={{ ...pre, cursor: 'default', flex: 1, minWidth: 240, maxHeight: 90, padding: 8 }}>
              {link.launch_url}
            </code>
            <CopyButton text={link.launch_url} label="Copy link" />
            <a className="btn" href={link.launch_url} target="_blank" rel="noreferrer">
              <ExternalLink size={12} /> Open
            </a>
          </div>

          {link.callback_enabled ? (
            <Banner kind="warn">
              This link carries a single-use onboarding token. Send it over an authenticated channel —
              not a shared ticket.{remaining ? ` Expires in ${remaining}.` : ' It has expired; generate a new one.'}
            </Banner>
          ) : (
            <Banner kind="ok">
              No callback: the stack creates no Lambda and cannot roll back over an unreachable
              endpoint. After CREATE_COMPLETE, register its RoleArn output below with session{' '}
              <span className="mono">{link.session_id}</span>.
            </Banner>
          )}

          {/* KMS is dual-authorised: the stack grants the disk-scan role its
              half, but only the key owner can grant the other. Missing it fails
              at scan time, not at stack time, so it has to be said up front. */}
          <p className="hint" style={{ marginTop: 8 }}>
            If the customer enables disk scanning and any EBS volume uses a customer managed KMS
            key, they must also add the stack's <span className="mono">DiskScanRoleArn</span> output
            to each of those key policies. Encrypted volumes are skipped silently otherwise.
          </p>

          <KeyValues rows={[
            ['session', link.session_id],
            ['template', `${link.template_reused ? 'reused' : 'uploaded'} · sha256 ${shortHash(link.template_checksum)}`],
            ['callback', link.callback_enabled ? link.callback_url : 'disabled — register manually'],
          ]} />
        </>
      ) : null}
    </Card>
  )
}

// ── sessions ───────────────────────────────────────────────────

function sessionPill(status: OnboardingSession['status']) {
  const map = {
    pending: ['neutral', 'awaiting stack'],
    redeemed: ['ok', 'connected'],
    superseded: ['warn', 'replaced'],
    expired: ['warn', 'expired'],
  } as const
  const [kind, text] = map[status]
  return <Pill kind={kind}>{text}</Pill>
}

/** While a link is outstanding the operator is waiting on a stack they cannot
 *  see. This table is the only signal that the customer's CloudFormation ran,
 *  so it polls rather than waiting for a manual refresh. */
function SessionsCard({ nonce, onRedeemed }: { nonce: number; onRedeemed: () => void }) {
  const sessions = useApi(() => api.onboardingSessions(), [nonce])
  const items = sessions.data?.sessions ?? []
  const waiting = items.some((s) => s.status === 'pending')
  const redeemed = items.filter((s) => s.status === 'redeemed').length

  useEffect(() => {
    if (!waiting) return
    const timer = window.setInterval(() => sessions.refetch(), 4000)
    return () => window.clearInterval(timer)
  }, [waiting, sessions.refetch])

  // A session that just flipped to redeemed means a new connected account.
  // ponytail: the callback lives in a ref because the parent passes an inline
  // arrow — a plain dep would re-fire on every render and the refetch it
  // triggers renders again, looping until the tab runs out of memory.
  const onRedeemedRef = useRef(onRedeemed)
  onRedeemedRef.current = onRedeemed
  useEffect(() => { if (redeemed) onRedeemedRef.current() }, [redeemed])

  return (
    <Card title="Onboarding sessions" i={4} bodyPad={false}
      right={
        <button className="btn" onClick={() => sessions.refetch()} disabled={sessions.loading}>
          <RefreshCw size={12} /> {waiting ? 'Polling…' : 'Refresh'}
        </button>
      }
    >
      <StateView loading={sessions.loading && !sessions.data} error={sessions.error}
        empty={!!sessions.data && items.length === 0}
        emptyHint="Generate a launch link above to start.">
        <table className="tbl">
          <thead>
            <tr><th>Session</th><th>Label</th><th>Status</th><th>Account</th><th>Expires</th></tr>
          </thead>
          <tbody>
            {items.map((s) => (
              <tr key={s.session_id}>
                <td className="mono" title={s.session_id}>{s.session_id.slice(0, 10)}…</td>
                <td>{s.label ?? '—'}</td>
                <td>{sessionPill(s.status)}</td>
                <td className="mono">{s.account_identifier ?? '—'}</td>
                <td className="mono">
                  {s.status === 'pending'
                    ? (timeUntil(s.expires_at) ?? 'expired')
                    : relTime(s.redeemed_at ?? s.created_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </StateView>
    </Card>
  )
}

function ConnectForm({ onConnected }: { onConnected: () => void }) {
  const [f, setF] = useState(() => {
    const saved = localStorage.getItem('odineyes_connect_form')
    if (saved) {
      try { return JSON.parse(saved) } catch (_) {}
    }
    return { provider: 'aws', account_identifier: '', name: '', role_arn: '' }
  })
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    localStorage.setItem('odineyes_connect_form', JSON.stringify(f))
  }, [f])

  async function connect() {
    setErr(null); setMsg(null); setBusy(true)
    try {
      await api.registerAccount({
        provider: f.provider,
        account_identifier: f.account_identifier.trim(),
        name: f.name.trim() || undefined,
        role_arn: f.role_arn.trim() || undefined,
      })
      const emptyForm = { provider: f.provider, account_identifier: '', name: '', role_arn: '' }
      setF(emptyForm)
      localStorage.setItem('odineyes_connect_form', JSON.stringify(emptyForm))
      setMsg('Connected — scan started automatically. Data appears in ~30–60s.')
      onConnected()
    } catch (e) { setErr(errorMessage(e)) } finally { setBusy(false) }
  }

  // The session path: the stack ran with CallbackUrl empty, so its RoleArn
  // output is registered here instead. The ExternalId still comes from our
  // session row, never from this form — a mistyped ARN cannot bind a trust we
  // do not know.
  const [sessionId, setSessionId] = useState('')
  const [sessionArn, setSessionArn] = useState('')
  const [sessionBusy, setSessionBusy] = useState(false)

  async function registerSession() {
    setErr(null); setMsg(null); setSessionBusy(true)
    try {
      const r = await api.registerManual({
        session_id: sessionId.trim(), role_arn: sessionArn.trim(),
      })
      setSessionArn('')
      setMsg(`Connected ${r.account_identifier} — scan started automatically.`)
      onConnected()
    } catch (e) { setErr(errorMessage(e)) } finally { setSessionBusy(false) }
  }

  return (
    <Card title="Manual deployment" i={3}>
      <div className="hint" style={{ marginBottom: 10 }}>
        For when the stack could not call back — no public endpoint yet, or a customer network that
        blocks the Lambda. Deploy with <span className="mono">CallbackUrl</span> empty and register
        the stack’s <span className="mono">RoleArn</span> output against the session that issued the link.
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <input style={{ ...inp, width: 220 }} className="mono" placeholder="onboarding session id"
          value={sessionId} onChange={(e) => setSessionId(e.target.value)} />
        <input style={{ ...inp, flex: 1, minWidth: 280 }} className="mono"
          placeholder="arn:aws:iam::<account>:role/OdineyesReadOnly"
          value={sessionArn} onChange={(e) => setSessionArn(e.target.value)} />
        <button className="btn primary" onClick={registerSession}
          disabled={sessionBusy || !sessionId.trim() || !sessionArn.trim()}>
          <Plug size={13} /> {sessionBusy ? 'Registering…' : 'Register connection'}
        </button>
      </div>

      <details style={{ marginTop: 12 }}>
        <summary className="hint" style={{ cursor: 'pointer' }}>
          Per-account setup files (needs the account id up front)
        </summary>
        <div style={{ display: 'flex', gap: 8, margin: '10px 0 8px', flexWrap: 'wrap' }}>
          <select style={inp} value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })}>
            <option value="aws">aws</option>
            <option value="azure">azure</option>
            <option value="gcp">gcp</option>
          </select>
          <input style={inp} placeholder={f.provider === 'aws' ? '12-digit account id' : 'subscription / project id'}
            value={f.account_identifier} onChange={(e) => setF({ ...f, account_identifier: e.target.value })} />
          <input style={{ ...inp, flex: 1, minWidth: 140 }} placeholder="display name (optional)"
            value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
        </div>

        <AccountSetup account_identifier={f.account_identifier} provider={f.provider} name={f.name} onDraftCreated={onConnected} />

        <div style={{ display: 'flex', gap: 8, marginTop: 12, marginBottom: 8, flexWrap: 'wrap' }}>
          <input style={{ ...inp, flex: 1, minWidth: 280 }} className="mono"
            placeholder="arn:aws:iam::<account>:role/OdineyesReadOnly"
            value={f.role_arn} onChange={(e) => setF({ ...f, role_arn: e.target.value })} />
          <button className="btn" onClick={connect}
            disabled={busy || !f.account_identifier.trim() || !f.role_arn.trim()}>
            <Plus size={13} /> {busy ? 'Connecting…' : 'Connect by ARN'}
          </button>
        </div>
      </details>

      {err ? <div className="hint" style={{ color: 'var(--sev-high)' }}>{err}</div> : null}
      {msg ? <div className="hint" style={{ color: 'var(--sev-low)' }}>{msg}</div> : null}
    </Card>
  )
}

function verifyPill(account: Account) {
  const status = account.last_verify_status
  if (!status) return <Pill>not verified</Pill>
  if (status === 'healthy') return <Pill kind="ok">healthy</Pill>
  if (status === 'degraded') return <Pill kind="warn">degraded</Pill>
  return <Pill kind="fail">{status === 'no_read' ? 'no read' : 'unreachable'}</Pill>
}

export function Accounts() {
  const accounts = useApi(() => api.accounts())
  const [hostingReady, setHostingReady] = useState(false)
  const [nonce, setNonce] = useState(0)
  const [scan, setScan] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [scanningId, setScanningId] = useState<number | null>(null)
  const [verifyingId, setVerifyingId] = useState<number | null>(null)

  // The sweep runs on the server and takes minutes. Waiting on one response
  // meant CloudFront cut the connection at 30s and reported a 504 for a scan
  // that was in fact running fine, so start it and follow the status route.
  async function scanAll() {
    setScan(null); setScanning(true)
    try {
      const started = await api.scanAll()
      if (started.status === 'already_running') {
        setScan(`a scan is already running on ${started.in_flight} account(s)`)
      } else {
        setScan(`scanning ${started.accounts} account(s)…`)
      }
      // eslint-disable-next-line no-constant-condition
      while (true) {
        await new Promise((r) => setTimeout(r, 4000))
        const s = await api.scanAllStatus()
        const done = s.completed + s.failed
        setScan(s.running
          ? `scanning… ${done}/${s.accounts.length} done${s.failed ? ` · ${s.failed} failed` : ''}`
          : `${s.completed}/${s.accounts.length} scanned · ${s.failed} failed`)
        accounts.refetch()
        if (!s.running) break
      }
    } catch (e) { setScan(errorMessage(e)) } finally { setScanning(false) }
  }

  // Same reason as scanAll: one account is still a multi-region scan, so it
  // outlives CloudFront's 30s origin timeout. Start it, then follow the row for
  // this account on the shared status route.
  async function scanOne(id: number, label: string) {
    setScan(null); setScanningId(id)
    try {
      const { last_job_id } = await api.scanAccount(id)
      setScan(`${label}: scanning…`)
      // eslint-disable-next-line no-constant-condition
      while (true) {
        await new Promise((r) => setTimeout(r, 4000))
        const row = (await api.scanAllStatus()).accounts.find((a) => a.account_id === id)
        accounts.refetch()
        // A missing row means the account was deactivated mid-scan; stop
        // polling rather than spinning forever on a row that will never arrive.
        if (!row) { setScan(`${label}: no longer active`); break }
        const job = row.job
        if (!job || job.id <= last_job_id) continue          // previous scan's row
        if (job.status === 'queued' || job.status === 'running') continue
        setScan(job.status === 'failed'
          ? `${label}: failed — ${job.error ?? 'scan failed'}`
          : `${label}: ${job.status} · ${job.assets_found ?? 0} assets`)
        break
      }
    } catch (e) { setScan(`${label}: ${errorMessage(e)}`) } finally { setScanningId(null) }
  }

  async function verifyOne(id: number, label: string) {
    setScan(null); setVerifyingId(id)
    try {
      const r = await api.verifyAccount(id)
      if (!r.assume.ok) {
        setScan(`${label}: assume-role failed — ${r.assume.error}`)
      } else if (!r.read.ok) {
        setScan(`${label}: role assumed OK, but can't read (missing permissions) — ${r.read.error}`)
      } else {
        // Assume + read passing only proves the role works at all. Report the
        // per-domain probe result too, so a stale stack shows up as named gaps
        // rather than as findings that silently never appear.
        const p = r.permissions
        const gaps = [
          ...(p?.missing ?? []).map(m => `missing ${m.action}`),
          ...(p?.guard_failures ?? []).map(g => `deny-guard not enforced for ${g.action}`),
        ]
        const domains = Object.entries(p?.coverage ?? {})
        const covered = domains.filter(([, c]) => c.ok === c.total).length
        const scope = domains.length ? `, ${covered}/${domains.length} domains fully covered` : ''
        setScan(
          gaps.length
            ? `${label}: role works but incomplete${scope} — ${gaps.slice(0, 5).join('; ')}` +
              (gaps.length > 5 ? ` (+${gaps.length - 5} more)` : '')
            : `${label}: verified — assume OK, read OK${scope} (${r.read.sample?.ec2_instances_seen ?? 0} EC2 instances visible)`,
        )
      }
      accounts.refetch()   // the verdict is persisted; refresh the standing pill
    } catch (e) { setScan(`${label}: ${errorMessage(e)}`) } finally { setVerifyingId(null) }
  }

  async function disable(id: number, label: string) {
    // Hard remove: purge the account AND all its data. Irreversible → confirm.
    const ok = window.confirm(
      `Remove account ${label} and permanently delete ALL its data ` +
      `(assets, findings, issues, vulnerabilities, runtime events, compliance)?\n\n` +
      `This cannot be undone.`,
    )
    if (!ok) return
    await api.deactivateAccount(id, true)
    accounts.refetch()
  }

  const items = accounts.data?.items ?? []
  const hasLiveScan = items.some((account) =>
    account.latest_scan?.status === 'queued' || account.latest_scan?.status === 'running',
  )

  // Account creation returns before FastAPI starts its background auto-scan.
  // Refresh this small status view while it is open so operators see its
  // running/failed state without guessing or manually reloading.
  useEffect(() => {
    if (items.length === 0) return
    const timer = window.setInterval(() => accounts.refetch(), 5000)
    return () => window.clearInterval(timer)
  }, [items.length, accounts.refetch])

  return (
    <div className="page">
      <PageHead crumb="settings" title="Accounts"
        sub="Connect cloud accounts for scanning. Odineyes assumes a read-only role per account — nothing is deployed in the client's environment." />

      <HostingCard onReady={setHostingReady} />
      <LinkCard ready={hostingReady} onIssued={() => setNonce((n) => n + 1)} />
      <ConnectForm onConnected={() => { accounts.refetch(); setNonce((n) => n + 1) }} />
      <SessionsCard nonce={nonce} onRedeemed={() => accounts.refetch()} />

      <Card title="Connected accounts" i={5} bodyPad={false}
        right={
          <button className="btn primary" onClick={scanAll} disabled={scanning || hasLiveScan || items.length === 0}
            title={hasLiveScan ? 'Wait for the active account scan to finish first.' : undefined}>
            <Play size={13} /> {scanning ? 'Scanning…' : 'Scan all'}
          </button>
        }
      >
        <div style={{ padding: '0 16px' }}>
          <ProgressBar isScanning={scanning || scanningId !== null || hasLiveScan} />
        </div>
        {scan ? <div className="hint" style={{ padding: '8px 16px 0' }}>{scan}</div> : null}
        {items.length > 0 ? (
          <table className="tbl">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Account</th>
                <th>Name</th>
                <th>Role ARN</th>
                <th>Scan status</th>
                <th>Verification</th>
                <th>Connected</th>
                <th style={{ width: 130 }} />
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id} style={a.is_active ? undefined : { opacity: 0.5 }}>
                  <td className="mono">{a.provider}</td>
                  <td className="mono">{a.account_identifier}</td>
                  <td>{a.name ?? '—'}</td>
                  <td className="mono" style={{ fontSize: 11 }} title={a.role_arn ?? ''}>
                    {a.role_arn ? a.role_arn.split('/').pop() : <span className="hint">awaiting stack</span>}
                  </td>
                  <td>
                    <div>
                      <span className="sev-badge" style={{ color: 'var(--text-2)', gap: 6 }}>
                        <span className={`dot ${!a.is_active ? 'hollow' : a.latest_scan?.status === 'failed' ? 'sev-critical' : a.latest_scan?.status === 'running' || a.latest_scan?.status === 'queued' ? 'sev-high' : 'sev-low'}`} />
                        {a.is_active ? scanLabel(a) : a.onboarding_status === 'awaiting_stack' ? 'awaiting CloudFormation' : 'disabled'}
                      </span>
                      {a.latest_scan?.error ? (
                        <div className="hint" title={a.latest_scan.error}
                          style={{ maxWidth: 310, marginTop: 4, color: 'var(--sev-high)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {a.latest_scan.error}
                        </div>
                      ) : null}
                    </div>
                  </td>
                  <td title={a.last_verified_at ? `verified ${relTime(a.last_verified_at)}` : undefined}>
                    {verifyPill(a)}
                  </td>
                  <td className="mono">{a.created_at ? relTime(a.created_at) : '—'}</td>
                  <td style={{ display: 'flex', gap: 6 }}>
                    {a.is_active ? (
                      <>
                        <button
                          className="btn"
                          title="diagnose: can we assume the role, and can we read anything with it"
                          disabled={verifyingId !== null}
                          onClick={() => verifyOne(a.id, a.name || a.account_identifier)}
                        >
                          {verifyingId === a.id ? 'Verifying…' : 'Verify'}
                        </button>
                        <button
                          className="btn"
                          title="scan only this account (assumes its role)"
                          disabled={scanningId !== null || a.latest_scan?.status === 'queued' || a.latest_scan?.status === 'running'}
                          onClick={() => scanOne(a.id, a.name || a.account_identifier)}
                        >
                          <Play size={13} /> {scanningId === a.id ? 'Scanning…' : 'Scan'}
                        </button>
                        <button className="btn" title="remove account + delete all its data"
                          onClick={() => disable(a.id, a.name || a.account_identifier)}>
                          <Trash2 size={13} />
                        </button>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="statev"><span className="label">no accounts connected</span>
            <div className="hint">Connect an account above to start scanning.</div></div>
        )}
      </Card>
    </div>
  )
}
