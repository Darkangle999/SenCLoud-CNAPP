import {
  ArrowLeft,
  Braces,
  CircleAlert,
  Cloud,
  ExternalLink,
  Fingerprint,
  KeyRound,
  Network,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  Wrench,
} from 'lucide-react'
import { useMemo } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'

import { CiemPanel } from '../components/CiemPanel'
import { Card, SevBadge, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { api, ApiError } from '../lib/api'
import { relTime, shortId, shortType } from '../lib/format'
import type { AssetDetail, IdentityPrincipal } from '../types'

const TABS = [
  ['overview', 'Overview', ShieldCheck],
  ['permissions', 'Permissions', KeyRound],
  ['findings', 'Findings', ShieldAlert],
  ['relationships', 'Relationships', Network],
  ['evidence', 'Technical evidence', Braces],
] as const

type IdentityTab = (typeof TABS)[number][0]
type ProblemTone = 'critical' | 'high' | 'medium' | 'low'

interface IdentityProblem {
  id: string
  title: string
  severity: ProblemTone
  source: 'Rule finding' | 'Model observation' | 'Coverage gap'
  why: string
  remediation: string
  evidence: string
}

function saveJson(name: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = name
  anchor.click()
  URL.revokeObjectURL(url)
}

function display(value: unknown) {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function trustLabel(principal: IdentityPrincipal) {
  if (principal.trust.onboarding_verified) return 'Verified Odineyes scanner trust'
  if (principal.trust.publicly_assumable) return 'Publicly assumable'
  if (principal.trust.external) return 'External cross-account trust'
  if (principal.trust.level === 'account') return 'Same-account trust'
  return 'No assumable principal collected'
}

function buildProblems(principal: IdentityPrincipal, asset: AssetDetail): IdentityProblem[] {
  const problems: IdentityProblem[] = asset.findings.map((finding) => ({
    id: `finding:${finding.id}`,
    title: finding.title,
    severity: (['critical', 'high', 'medium', 'low'].includes(finding.severity)
      ? finding.severity
      : 'medium') as ProblemTone,
    source: 'Rule finding',
    why: finding.why,
    remediation: finding.remediation,
    evidence: finding.rule_id,
  }))
  const findingText = asset.findings.map((item) => `${item.rule_id} ${item.title}`.toLowerCase()).join(' ')
  const addObservation = (
    pattern: RegExp,
    problem: Omit<IdentityProblem, 'id' | 'source'> & { id: string },
  ) => {
    if (!pattern.test(findingText)) problems.push({ ...problem, source: 'Model observation' })
  }

  if (principal.trust.publicly_assumable) {
    addObservation(/public|anonymous|assum/, {
      id: 'trust:public',
      title: 'Role can be assumed without a bounded AWS principal',
      severity: 'critical',
      why: 'The trust policy exposes an identity entry point beyond a known account or role. Any permissions on this role become part of the external attack surface.',
      remediation: 'Replace wildcard or public trust with exact principal ARNs and restrictive trust conditions.',
      evidence: `${principal.trust.principals.length} trusted principal entries`,
    })
  } else if (principal.trust.external && !principal.trust.onboarding_verified) {
    addObservation(/cross.account|external trust|trusts external/, {
      id: 'trust:external',
      title: 'Role trusts a principal outside this AWS account',
      severity: 'high',
      why: 'Compromise or misconfiguration in the trusted account can provide a path into this account. This is relevant only when the relationship is not the verified Odineyes onboarding trust.',
      remediation: 'Confirm the business owner, scope trust to exact role ARNs, require an ExternalId for third parties, and remove stale relationships.',
      evidence: principal.trust.principals.join(', ') || 'External trust flag observed',
    })
  }

  if (principal.privilege.admin_grant) {
    addObservation(/admin|administrator/, {
      id: 'privilege:admin',
      title: principal.privilege.boundary_restricts_admin
        ? 'Administrator grant is restricted by a permissions boundary'
        : 'Identity policy contains an unrestricted administrator grant',
      severity: principal.privilege.boundary_restricts_admin ? 'medium' : 'critical',
      why: principal.privilege.boundary_restricts_admin
        ? 'The identity policy requests administrator access, but the collected boundary prevents the full grant. The grant is still dangerous if that boundary is removed or changed.'
        : 'The collected identity-policy evidence grants administrator capability without a restricting permissions boundary.',
      remediation: 'Replace broad grants with task-specific actions and resources. Keep a restrictive permissions boundary on delegated identities.',
      evidence: principal.privilege.admin_reason || 'Administrator policy grant detected',
    })
  }

  if (principal.privilege.effective_privilege_escalation_actions.length) {
    addObservation(/privilege|escalat|passrole/, {
      id: 'privilege:escalation',
      title: 'Boundary-permitted privilege-escalation actions detected',
      severity: 'high',
      why: 'These actions can change policy, pass a role, or create an execution path that acquires permissions the principal does not directly hold.',
      remediation: 'Remove unnecessary escalation actions, scope resources and conditions, and break dangerous action combinations.',
      evidence: principal.privilege.effective_privilege_escalation_actions.join(', '),
    })
  }

  if (principal.authentication.console_enabled && !principal.authentication.mfa_enabled) {
    addObservation(/mfa|multi.factor/, {
      id: 'auth:mfa',
      title: 'Console access is enabled without MFA',
      severity: 'high',
      why: 'A stolen or reused password is enough to authenticate this principal because no second factor was observed.',
      remediation: 'Require MFA, preferably phishing-resistant MFA, and disable console access when it is not needed.',
      evidence: 'console_enabled=true, mfa_enabled=false',
    })
  }

  if (
    principal.authentication.access_key_active
    && principal.authentication.access_key_max_age_days >= 90
  ) {
    addObservation(/access key|credential|key age/, {
      id: 'auth:stale-key',
      title: 'Long-lived access key is older than 90 days',
      severity: 'high',
      why: 'Long-lived credentials have a larger theft and accidental-exposure window than temporary workload credentials.',
      remediation: 'Remove unused keys and migrate automation to an IAM role. Rotate any key that must temporarily remain.',
      evidence: `${principal.authentication.access_key_max_age_days} days old`,
    })
  }

  if (!principal.authorization.effective_access_complete) {
    problems.push({
      id: 'coverage:effective-access',
      title: 'Effective-access evaluation is incomplete',
      severity: 'medium',
      source: 'Coverage gap',
      why: 'Identity policies were analyzed, but every AWS authorization layer required for a final allow/deny verdict was not collected. Grants shown here are candidates, not proof of effective access.',
      remediation: 'Collect and evaluate the missing SCP, resource-policy, session-policy, and trust-condition layers before closing the investigation.',
      evidence: principal.authorization.unevaluated_policy_layers.join(', ') || 'Required authorization layers are not evaluated',
    })
  }

  return problems
}

function ProblemSummary({ principal, asset }: { principal: IdentityPrincipal; asset: AssetDetail }) {
  const problems = useMemo(() => buildProblems(principal, asset), [principal, asset])
  const confirmed = problems.filter((item) => item.source === 'Rule finding').length
  const coverage = problems.filter((item) => item.source === 'Coverage gap').length
  return (
    <Card
      title="What is the problem?"
      i={1}
      right={<span className="label">{confirmed} confirmed · {coverage} coverage gaps</span>}
    >
      {problems.length ? (
        <div className="identity-problem-list">
          {problems.map((problem) => (
            <article className={`identity-problem ${problem.severity}`} key={problem.id}>
              <div className="identity-problem-icon">
                {problem.source === 'Coverage gap' ? <ScanSearch size={18} /> : <CircleAlert size={18} />}
              </div>
              <div className="identity-problem-body">
                <div className="identity-problem-head">
                  <div>
                    <span className="identity-problem-source">{problem.source} · {problem.evidence}</span>
                    <h3>{problem.title}</h3>
                  </div>
                  <SevBadge sev={problem.severity} />
                </div>
                <p><b>Why it matters:</b> {problem.why}</p>
                <div className="identity-problem-fix"><Wrench size={14} /><span>{problem.remediation}</span></div>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="identity-clean">
          <ShieldCheck size={28} />
          <div>
            <strong>No current identity problem was confirmed</strong>
            <p>The collected policy, authentication, and trust evidence produced no open finding or risky model observation.</p>
          </div>
        </div>
      )}
    </Card>
  )
}

function Overview({ principal, asset }: { principal: IdentityPrincipal; asset: AssetDetail }) {
  return (
    <div className="asset-tab-stack">
      <ProblemSummary principal={principal} asset={asset} />
      <div className="identity-overview-grid">
        <Card title="Resource identity" i={2}>
          <dl className="identity-field-list">
            <dt>Principal type<span>Native IAM object represented by this record.</span></dt>
            <dd>{principal.identity.principal_type}</dd>
            <dt>Provider ID<span>The immutable ARN used to correlate policy, trust, findings, and graph edges.</span></dt>
            <dd className="mono">{principal.identity.resource_id}</dd>
            <dt>AWS account<span>Security boundary that owns this principal.</span></dt>
            <dd>{principal.identity.account_name ?? principal.identity.account_id}</dd>
            <dt>Identity age<span>Older identities are not unsafe by themselves; age becomes relevant with stale credentials or privilege.</span></dt>
            <dd>{principal.lifecycle.age_days === null ? 'Unknown' : `${principal.lifecycle.age_days} days`}</dd>
            <dt>Last used<span>Unknown is not treated as unused because AWS activity evidence may be incomplete.</span></dt>
            <dd>{principal.lifecycle.last_used_days === null ? 'Never or unknown' : `${principal.lifecycle.last_used_days} days ago`}</dd>
          </dl>
        </Card>

        <Card title="Authentication" i={3}>
          <dl className="identity-field-list compact">
            <dt>Console access<span>Password-based AWS console sign-in.</span></dt>
            <dd>{principal.authentication.console_enabled ? 'Enabled' : 'Disabled'}</dd>
            <dt>MFA<span>Problem only when interactive console access exists without a second factor.</span></dt>
            <dd className={principal.authentication.console_enabled && !principal.authentication.mfa_enabled ? 'danger-text' : 'ok-text'}>
              {principal.authentication.mfa_enabled ? 'Enabled' : 'Not observed'}
            </dd>
            <dt>Access key<span>Long-lived programmatic credential; IAM roles with temporary sessions are preferred.</span></dt>
            <dd>{principal.authentication.access_key_active ? 'Active' : 'Inactive'}</dd>
            <dt>Oldest active key<span>Keys older than 90 days are highlighted for rotation or replacement.</span></dt>
            <dd>{principal.authentication.access_key_active ? `${principal.authentication.access_key_max_age_days} days` : 'Not applicable'}</dd>
            <dt>Key last used<span>Helps distinguish an active integration from a removable stale credential.</span></dt>
            <dd>{principal.authentication.access_key_last_used_days === null ? 'Never or unknown' : `${principal.authentication.access_key_last_used_days} days ago`}</dd>
          </dl>
        </Card>

        <Card title="Trust decision" i={4}>
          <div className={`identity-verdict ${principal.trust.publicly_assumable ? 'critical' : principal.trust.external ? 'high' : 'ok'}`}>
            {principal.trust.publicly_assumable || principal.trust.external ? <ShieldAlert size={18} /> : <ShieldCheck size={18} />}
            <div><strong>{trustLabel(principal)}</strong><span>{principal.trust.principals.length} trusted principal entries collected</span></div>
          </div>
          {principal.trust.onboarding_verified ? (
            <p className="identity-explainer">This cross-account relationship matches the registered Odineyes role, exact scanner principal, and account ExternalId. It is shown as expected onboarding infrastructure, not an external-trust finding.</p>
          ) : (
            <p className="identity-explainer">External trust is a review condition, not automatic proof of compromise. Validate the owner, exact trusted ARN, conditions, and whether the relationship is still required.</p>
          )}
          <dl className="identity-mini-kv">
            <dt>Public trust</dt><dd>{principal.trust.publicly_assumable ? 'Yes' : 'No'}</dd>
            <dt>Unverified external trust</dt><dd>{principal.trust.external ? 'Yes' : 'No'}</dd>
            <dt>Onboarding exception</dt><dd>{principal.trust.onboarding_verified ? 'Verified' : 'Not applicable'}</dd>
          </dl>
        </Card>

        <Card title="Security context" i={5}>
          <div className="identity-score"><span className={principal.posture.severity}>{Math.round(principal.posture.risk_score)}</span><div><strong>Contextual risk score</strong><small>Prioritization signal, not a vulnerability count</small></div></div>
          <dl className="identity-mini-kv">
            <dt>Open rule findings</dt><dd>{asset.findings.length}</dd>
            <dt>Attack paths touching identity</dt><dd>{asset.attack_paths.length}</dd>
            <dt>Authorization complete</dt><dd>{principal.authorization.effective_access_complete ? 'Yes' : 'No'}</dd>
            <dt>Last scanned</dt><dd>{relTime(principal.lifecycle.last_scanned_at)}</dd>
          </dl>
        </Card>
      </div>
    </div>
  )
}

function Permissions({ principal }: { principal: IdentityPrincipal }) {
  return (
    <div className="asset-tab-stack">
      <Card title="Privilege and authorization decision" i={1}>
        <div className="identity-permission-intro">
          <KeyRound size={18} />
          <p><b>Grant is not the same as effective access.</b> Odineyes first models what identity policies grant, then applies the collected permissions boundary. Because SCPs, resource policies, and session policies are not all evaluated yet, the UI labels the result as candidate access.</p>
        </div>
        <CiemPanel identity={{ privilege: principal.privilege, authorization: principal.authorization }} />
      </Card>
      <Card title="How to read these fields" i={2} bodyPad={false}>
        <div className="asset-table-wrap">
          <table className="tbl identity-guide-table">
            <thead><tr><th>Field</th><th>What it proves</th><th>Security question</th></tr></thead>
            <tbody>
              <tr><td>Admin policy grant</td><td>An identity policy contains administrator-equivalent allow statements.</td><td>Is the grant narrowed by a boundary or another unevaluated policy layer?</td></tr>
              <tr><td>Boundary-permitted admin</td><td>The collected permissions boundary does not remove the administrator candidate.</td><td>Does an SCP, resource policy, or session policy still constrain it?</td></tr>
              <tr><td>Privilege escalation</td><td>Dangerous IAM/action combinations remain after boundary evaluation.</td><td>Can the principal pass, create, modify, or invoke a more privileged role?</td></tr>
              <tr><td>Explicit denies</td><td>A collected identity-policy statement denies an action.</td><td>Does the deny cover the dangerous action and resource combination?</td></tr>
              <tr><td>Wildcard statements</td><td>An allow or deny uses broad action/resource matching.</td><td>Is wildcard scope necessary, conditional, and bounded?</td></tr>
              <tr><td>Not evaluated yet</td><td>Required AWS authorization layers were not part of this result.</td><td>What evidence is missing before calling access effective?</td></tr>
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

function Findings({ asset }: { asset: AssetDetail }) {
  if (!asset.findings.length) {
    return <div className="asset-empty"><ShieldCheck size={28} /><strong>No open identity findings</strong><p>No currently-open detection rule targets this principal.</p></div>
  }
  return (
    <div className="asset-finding-list">
      {asset.findings.map((finding) => (
        <Card key={finding.id} i={1}>
          <div className="asset-finding-head">
            <div><span className="mono">{finding.rule_id}</span><h3>{finding.title}</h3></div>
            <SevBadge sev={finding.severity} />
          </div>
          <p><b>Why this matters:</b> {finding.why}</p>
          <div className="asset-remediation"><Wrench size={15} /><span>{finding.remediation}</span></div>
        </Card>
      ))}
    </div>
  )
}

function Relationships({ principal, asset }: { principal: IdentityPrincipal; asset: AssetDetail }) {
  return (
    <div className="asset-tab-stack">
      <Card title="Trust relationships" i={1} bodyPad={false}>
        {principal.trust.principals.length ? (
          <div className="identity-relationship-list">
            {principal.trust.principals.map((trusted) => (
              <div className="identity-relationship-row" key={trusted}>
                <span className={`pill ${principal.trust.external ? 'model-elevated' : 'tint'}`}>
                  {principal.trust.onboarding_verified ? 'VERIFIED SCANNER' : 'TRUSTS'}
                </span>
                <span className="mono">{trusted}</span>
              </div>
            ))}
          </div>
        ) : <div className="asset-empty compact"><Network size={24} /><strong>No trusted principals collected</strong></div>}
      </Card>

      <Card title="Inventory relationships" i={2} bodyPad={false}>
        {asset.related_resources.length ? (
          <div className="asset-table-wrap">
            <table className="tbl">
              <thead><tr><th>Relationship</th><th>Target</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>
                {asset.related_resources.map((relationship) => (
                  <tr key={`${relationship.type}:${relationship.target_id}`}>
                    <td>{relationship.type.replace(/_/g, ' ')}</td>
                    <td>
                      {relationship.asset ? (
                        <Link className="asset-cve-link" to={`/inventory/${relationship.asset.id}`}>
                          <Cloud size={14} /> {relationship.asset.name}
                        </Link>
                      ) : <span className="mono">{relationship.target_id}</span>}
                    </td>
                    <td>{relationship.asset ? shortType(relationship.asset.asset_type) : 'External or unresolved'}</td>
                    <td>{relationship.asset ? (relationship.asset.is_active ? 'Active' : 'Inactive') : 'Not in inventory'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="asset-empty compact"><Network size={24} /><strong>No inventory relationships collected</strong></div>}
      </Card>

      <Card title="Attack paths touching this identity" i={3}>
        {asset.attack_paths.length ? (
          <div className="identity-path-list">
            {asset.attack_paths.map((path) => (
              <div className="identity-path-row" key={path.id}>
                <SevBadge sev={path.severity} />
                <div><strong>{path.title}</strong><span>{Math.round(path.risk_score)}/100 risk · {Math.round(path.confidence * 100)}% confidence</span></div>
                <Link className="btn" to="/attack-paths">Open graph</Link>
              </div>
            ))}
          </div>
        ) : <div className="asset-empty compact"><ShieldCheck size={24} /><strong>No open attack path references this identity</strong></div>}
      </Card>
    </div>
  )
}

function Evidence({ principal, asset }: { principal: IdentityPrincipal; asset: AssetDetail }) {
  return (
    <div className="asset-tab-stack">
      <Card title="Normalized identity fields" i={1} bodyPad={false}>
        <div className="asset-table-wrap">
          <table className="tbl asset-config-table">
            <thead><tr><th>Field</th><th>Observed value</th></tr></thead>
            <tbody>
              {Object.entries(asset.properties ?? {}).map(([key, value]) => (
                <tr key={key}><td>{key.replace(/_/g, ' ')}</td><td className="mono">{display(value)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <details className="asset-json-panel" open>
        <summary>Modeled CIEM response</summary>
        <pre className="json">{JSON.stringify(principal, null, 2)}</pre>
      </details>
      <details className="asset-json-panel">
        <summary>Normalized asset JSON</summary>
        <pre className="json">{JSON.stringify(asset.normalized, null, 2)}</pre>
      </details>
      <details className="asset-json-panel">
        <summary>Raw AWS API response</summary>
        <pre className="json">{JSON.stringify(asset.raw, null, 2)}</pre>
      </details>
    </div>
  )
}

export function IdentityDetails() {
  const { identityId } = useParams()
  const [params, setParams] = useSearchParams()
  const requestedTab = params.get('tab') as IdentityTab | null
  const tab: IdentityTab = TABS.some(([key]) => key === requestedTab) ? requestedTab! : 'overview'
  const id = Number(identityId)
  const validId = Number.isInteger(id) && id > 0
  const principalRequest = useApi(
    () => validId
      ? api.identityResource(id)
      : Promise.reject(new ApiError('GET', `/api/inventory/identity/resources/${identityId}`, 400, 'Invalid identity id')),
    [id],
  )
  const assetRequest = useApi(
    () => validId
      ? api.asset(id)
      : Promise.reject(new ApiError('GET', `/api/inventory/assets/${identityId}`, 400, 'Invalid identity id')),
    [id],
  )
  const principal = principalRequest.data
  const asset = assetRequest.data
  const loading = principalRequest.loading || assetRequest.loading
  const error = principalRequest.error ?? assetRequest.error

  return (
    <div className="page asset-details-page identity-details-page">
      <StateView loading={loading} error={error} empty={!loading && !error && (!principal || !asset)}>
        {principal && asset ? (
          <>
            <Link to="/identity" className="asset-back"><ArrowLeft size={14} /> Identity and access</Link>
            <header className="asset-hero identity-hero">
              <div className="asset-hero-identity">
                <span className="asset-hero-icon"><Fingerprint size={22} /></span>
                <div>
                  <span className="crumb">{principal.identity.provider.toUpperCase()} / IAM {principal.identity.principal_type}</span>
                  <h1>{principal.identity.name}</h1>
                  <p className="mono" title={principal.identity.resource_id}>{principal.identity.resource_id}</p>
                  <div className="identity-hero-badges">
                    <span className={`pill ${principal.posture.severity === 'critical' || principal.posture.severity === 'high' ? 'model-elevated' : 'tint'}`}>
                      risk {Math.round(principal.posture.risk_score)}
                    </span>
                    <span className="pill tint">{trustLabel(principal)}</span>
                    <span className="pill tint">{principal.authorization.effective_access_complete ? 'effective access evaluated' : 'candidate access'}</span>
                  </div>
                </div>
              </div>
              <div className="asset-actions">
                {asset.cloud_console_url ? (
                  <a className="btn" href={asset.cloud_console_url} target="_blank" rel="noreferrer">
                    <Cloud size={14} /> Open in AWS <ExternalLink size={12} />
                  </a>
                ) : null}
                <Link className="btn" to={`/inventory/${asset.id}`}><UserRound size={14} /> Inventory record</Link>
                <button className="btn" onClick={() => saveJson(`${shortId(principal.identity.resource_id)}-identity.json`, { principal, asset })}>
                  <Braces size={14} /> JSON
                </button>
              </div>
            </header>

            <nav className="asset-tabs" aria-label="identity detail sections" role="tablist">
              {TABS.map(([key, label, Icon]) => (
                <button
                  key={key}
                  role="tab"
                  aria-selected={tab === key}
                  className={tab === key ? 'active' : ''}
                  onClick={() => setParams(key === 'overview' ? {} : { tab: key })}
                >
                  <Icon size={15} /> {label}
                  {key === 'findings' && asset.findings.length ? <b>{asset.findings.length}</b> : null}
                  {key === 'relationships' && asset.related_resources.length ? <b>{asset.related_resources.length}</b> : null}
                </button>
              ))}
            </nav>

            <main className="asset-tab-content">
              {tab === 'overview' ? <Overview principal={principal} asset={asset} /> : null}
              {tab === 'permissions' ? <Permissions principal={principal} /> : null}
              {tab === 'findings' ? <Findings asset={asset} /> : null}
              {tab === 'relationships' ? <Relationships principal={principal} asset={asset} /> : null}
              {tab === 'evidence' ? <Evidence principal={principal} asset={asset} /> : null}
            </main>
          </>
        ) : null}
      </StateView>
    </div>
  )
}
