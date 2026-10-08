import { KeyRound } from 'lucide-react'

import type { IdentityCiem } from '../types'

// Boundary-aware privilege verdict. Deliberately labels a candidate grant as a
// grant, never as proven effective access — the point of the CIEM model.
export function privilegeVerdict(identity: IdentityCiem) {
  const { privilege } = identity
  if (privilege.admin_grant) {
    return privilege.boundary_restricts_admin
      ? { value: 'Admin grant (bounded)', tone: 'high', label: 'privilege — boundary restricts it' }
      : { value: 'Admin grant', tone: 'critical', label: 'privilege — unrestricted' }
  }
  if (privilege.effective_privilege_escalation_actions.length) {
    return { value: 'Privilege escalation', tone: 'high', label: 'boundary-permitted escalation' }
  }
  return { value: 'No elevated grant', tone: 'ok', label: 'privilege' }
}

/**
 * Detailed CIEM evidence for a principal: policy grant vs boundary-permitted
 * candidate, escalation actions, policy sources, statement counts, boundary
 * state, and the authorization layers not evaluated yet. Renders as two drawer
 * sections; the caller decides where it sits.
 */
export function CiemPanel({ identity }: { identity: IdentityCiem }) {
  const { privilege, authorization } = identity
  const verdict = privilegeVerdict(identity)
  return (
    <>
      <div className="drawer-section">
        <span className="label">Privilege</span>
        <div className={`asset-insight ${verdict.tone}`}>
          <KeyRound size={15} />
          <b>{verdict.value}</b>
          <span>{privilege.admin_reason || `${authorization.policy_sources} policy sources evaluated`}</span>
        </div>
        <dl className="kv" style={{ marginTop: 10 }}>
          <dt>Admin policy grant</dt>
          <dd className={privilege.admin_grant ? 'danger-text' : 'ok-text'}>{privilege.admin_grant ? 'Yes' : 'No'}</dd>
          <dt>Boundary-permitted admin</dt>
          <dd>{privilege.admin ? 'Yes' : privilege.boundary_restricts_admin ? 'No — restricted by boundary' : 'No'}</dd>
          <dt>Granted escalation</dt>
          <dd className="mono">{privilege.privilege_escalation_actions.join(' · ') || 'None'}</dd>
          <dt>Boundary-permitted escalation</dt>
          <dd className="mono">{privilege.effective_privilege_escalation_actions.join(' · ') || 'None'}</dd>
        </dl>
      </div>
      <div className="drawer-section">
        <span className="label">Authorization evidence</span>
        <dl className="kv">
          <dt>Evaluation scope</dt>
          <dd>{authorization.scope.split('_').join(' ')}</dd>
          <dt>Effective access complete</dt>
          <dd>{authorization.effective_access_complete ? 'Yes' : 'No — candidate access only'}</dd>
          <dt>Policy sources</dt>
          <dd>{authorization.policy_sources} total · {authorization.direct_policy_sources} direct · {authorization.inherited_policy_sources} inherited</dd>
          <dt>IAM groups</dt>
          <dd>{authorization.groups.join(' · ') || 'None'}</dd>
          <dt>Permissions boundary</dt>
          <dd className="mono">{authorization.permissions_boundary_arn || 'Not configured'} ({authorization.permissions_boundary_state})</dd>
          <dt>Statements</dt>
          <dd>{authorization.allow_statements} allow · {authorization.explicit_denies} deny · {authorization.conditional_statements} conditional</dd>
          <dt>Wildcard statements</dt>
          <dd>{authorization.wildcard_action_statements} action · {authorization.wildcard_resource_statements} resource</dd>
          <dt>Not evaluated yet</dt>
          <dd className="model-elevated">{authorization.unevaluated_policy_layers.join(' · ') || 'None'}</dd>
        </dl>
      </div>
    </>
  )
}
