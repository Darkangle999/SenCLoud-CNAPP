// Typed fetch layer. Same-origin /api paths (vite dev-proxies to FastAPI).
// No retries, no fallbacks: a failed request surfaces as an ApiError that the
// UI renders verbatim.

import type {
  Account,
  AssetDetail,
  AssetPage,
  InventoryResourcePage,
  CspmScan,
  ComplianceCurrent,
  ComplianceHistory,
  ComplianceDriftResult,
  EvaluateResult,
  FindingsPage,
  ModeledFindingPage,
  IdentityPrincipal,
  IdentityPrincipalPage,
  DataSecurityPage,
  FindingsSummary,
  InventorySummary,
  GeoDistribution,
  Coverage,
  IssuesPage,
  IssuesSummary,
  SecurityGraph,
  VulnsPage,
  VulnsSummary,
  CveCatalogPage,
  CveCatalogSummary,
  CveDetail,
  RuntimeEventsPage,
  RuntimeEventsSummary,
  AgentsResult,
  IacScanResult,
  DspmResult,
  DspmStore,
  AvailableFramework,
  ControlOverride,
  CustomFramework,
  CustomPolicy,
  PolicyEvalResult,
  FrameworkControls,
  FrameworkImportResult,
  SoaResult,
  ScanAllStarted,
  ScanAllStatus,
  HostingStatus,
  LaunchLink,
  OnboardingSession,
  OnboardingTemplate,
  FrameworkScore,
} from '../types'

export class ApiError extends Error {
  constructor(
    public method: string,
    public path: string,
    public status: number | null,
    public detail: string | null,
  ) {
    super(
      status === null
        ? `${method} ${path} → network error`
        : `${method} ${path} → HTTP ${status}`,
    )
  }
}

type Query = Record<string, string | number | boolean | undefined>

function qs(params?: Query): string {
  if (!params) return ''
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}

async function request<T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method,
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError(method, path, null, 'backend unreachable')
  }
  if (!res.ok) {
    let detail: string | null = null
    try {
      const data = await res.json()
      detail = typeof data?.detail === 'string' ? data.detail : JSON.stringify(data)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(method, path, res.status, detail)
  }
  return res.json() as Promise<T>
}

// Raw binary upload (e.g. an .xlsx) — bypasses JSON encoding. The backend reads
// the request body directly, so no multipart is needed.
async function postRaw<T>(path: string, body: ArrayBuffer): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body,
    })
  } catch {
    throw new ApiError('POST', path, null, 'backend unreachable')
  }
  if (!res.ok) {
    let detail: string | null = null
    try {
      const data = await res.json()
      detail = typeof data?.detail === 'string' ? data.detail : JSON.stringify(data)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError('POST', path, res.status, detail)
  }
  return res.json() as Promise<T>
}

export const api = {
  // inventory
  inventorySummary: (accountId?: number | null, provider?: string | null) =>
    request<InventorySummary>('GET', `/api/inventory/summary${qs({ account_id: accountId ?? undefined, provider: provider && provider !== 'all' ? provider : undefined })}`),
  geo: (opts?: { provider?: string | null; accountId?: number | null }) =>
    request<GeoDistribution>('GET', `/api/inventory/geo${qs({ provider: opts?.provider && opts.provider !== 'all' ? opts.provider : undefined, account_id: opts?.accountId ?? undefined })}`),
  coverage: (accountId?: number | null) =>
    request<Coverage>('GET', `/api/inventory/coverage${qs({ account_id: accountId ?? undefined })}`),
  accounts: () => request<{ items: Account[] }>('GET', '/api/inventory/accounts'),
  accountRegions: (accountId: number) =>
    request<{
      account_id: number
      regions: { region: string; active_resources: number; excluded: boolean }[]
      excluded_regions: string[]
    }>('GET', `/api/inventory/accounts/${accountId}/regions`),
  registerAccount: (body: {
    provider: string; account_identifier: string; name?: string; role_arn?: string
  }) => request<Account>('POST', '/api/inventory/accounts', body),
  deactivateAccount: (id: number, purge = false) =>
    request<Account | { deleted: boolean; purged: boolean; account_id: number }>(
      'DELETE', `/api/inventory/accounts/${id}${qs({ purge: purge || undefined })}`),
  onboardingTemplate: (body: {
    provider: string; account_identifier: string; name?: string
    policy_mode?: 'managed' | 'least-privilege'
  }) => request<OnboardingTemplate>('POST', '/api/inventory/accounts/onboarding-template', body),
  // Returns as soon as the sweep is queued; watch scanAllStatus for progress.
  scanAll: (body?: { provider?: string; region?: string; max_workers?: number }) =>
    request<ScanAllStarted>('POST', '/api/inventory/scan-all', body ?? {}),
  scanAllStatus: (provider = 'aws') =>
    request<ScanAllStatus>('GET', `/api/inventory/scan-all/status${qs({ provider })}`),
  // Returns as soon as the scan is queued; watch this account's row in
  // scanAllStatus, ignoring jobs up to last_job_id (the previous scan's).
  scanAccount: (accountId: number, region = 'us-east-1') =>
    request<{
      status: 'started'; account_id: number; account_identifier: string
      last_job_id: number; poll: string
    }>('POST', `/api/inventory/accounts/${accountId}/scan`, { region }),
  verifyAccount: (accountId: number, region = 'us-east-1') =>
    request<{
      account_identifier: string
      assume: { ok: boolean; error: string | null }
      read: { ok: boolean; error: string | null; sample: { ec2_instances_seen: number } | null }
      // One probe per collection domain. Absent when the role could not be assumed.
      permissions?: {
        healthy: boolean
        coverage: Record<string, { ok: number; total: number }>
        missing: { domain: string; action: string; detail: string }[]
        // Actions the onboarding template's Deny guard must block but didn't.
        guard_failures: { domain: string; action: string; detail: string }[]
      }
      verify_status: 'healthy' | 'degraded' | 'no_read' | 'unreachable'
    }>('POST', `/api/inventory/accounts/${accountId}/verify`, { region }),

  // session-based one-click onboarding: no account id is declared up front —
  // the stack's callback reports which account it actually ran in.
  hostingStatus: () =>
    request<HostingStatus>('GET', '/api/inventory/onboarding/hosting-status'),
  publishTemplate: () =>
    request<{ bucket: string; key: string; checksum: string; reused: boolean }>(
      'POST', '/api/inventory/onboarding/publish', {}),
  onboardingLink: (body: {
    label?: string
    ttl_seconds?: number
    console_region?: string
    with_callback?: boolean
    policy_mode?: 'managed' | 'least-privilege'
  }) => request<LaunchLink>('POST', '/api/inventory/onboarding/link', body),
  onboardingSessions: () =>
    request<{ sessions: OnboardingSession[] }>('GET', '/api/inventory/onboarding/sessions'),
  registerManual: (body: { session_id: string; role_arn: string }) =>
    request<{ status: string; account_id: number; account_identifier: string; registered: string }>(
      'POST', '/api/inventory/onboarding/register-manual', body),

  verifyOnboarding: (accountId: number, region = 'us-east-1') =>
    request<{
      status: 'awaiting_stack' | 'connected'
      connected: boolean
      verification: {
        account_identifier: string
        assume: { ok: boolean; error: string | null }
        read: { ok: boolean; error: string | null; sample: { ec2_instances_seen: number } | null }
      }
    }>('POST', `/api/inventory/accounts/${accountId}/verify-onboarding`, { region }),
  assets: (params: Query) => request<AssetPage>('GET', `/api/inventory${qs(params)}`),
  inventoryResources: (params: Query) =>
    request<InventoryResourcePage>('GET', `/api/inventory/resources${qs(params)}`),
  asset: (id: number) => request<AssetDetail>('GET', `/api/inventory/assets/${id}`),

  // findings
  findings: (params: Query) => request<FindingsPage>('GET', `/api/inventory/findings${qs(params)}`),
  findingResources: (params: Query) =>
    request<ModeledFindingPage>('GET', `/api/inventory/findings/resources${qs(params)}`),
  findingsSummary: (accountId?: number | null, provider?: string | null) =>
    request<FindingsSummary>('GET', `/api/inventory/findings/summary${qs({ account_id: accountId ?? undefined, provider: provider && provider !== 'all' ? provider : undefined })}`),
  findingsExportUrl: (params: Query) => `/api/inventory/findings/export${qs(params)}`,
  evaluate: (provider: string, account_identifier: string) =>
    request<EvaluateResult>('POST', '/api/inventory/findings/evaluate', {
      provider,
      account_identifier,
    }),

  // attack-path issues
  issues: (params: Query) => request<IssuesPage>('GET', `/api/inventory/issues${qs(params)}`),
  issuesSummary: (accountId?: number | null, provider?: string | null) =>
    request<IssuesSummary>('GET', `/api/inventory/issues/summary${qs({ account_id: accountId ?? undefined, provider: provider && provider !== 'all' ? provider : undefined })}`),
  evaluateIssues: (provider: string, account_identifier: string) =>
    request<EvaluateResult>('POST', '/api/inventory/issues/evaluate', {
      provider,
      account_identifier,
    }),
  graph: (params?: Query) => request<SecurityGraph>('GET', `/api/inventory/graph${qs(params)}`),
  identityResources: (params: Query) =>
    request<IdentityPrincipalPage>('GET', `/api/inventory/identity/resources${qs(params)}`),
  identityResource: (id: number) =>
    request<IdentityPrincipal>('GET', `/api/inventory/identity/resources/${id}`),
  dataSecurityResources: (params: Query) =>
    request<DataSecurityPage>('GET', `/api/inventory/data-security/resources${qs(params)}`),

  // vulnerabilities (CWPP)
  vulnerabilities: (params?: Query) =>
    request<VulnsPage>('GET', `/api/inventory/vulnerabilities${qs(params)}`),
  vulnerabilitiesSummary: (accountId?: number | null) =>
    request<VulnsSummary>('GET', `/api/inventory/vulnerabilities/summary${qs({ account_id: accountId ?? undefined })}`),
  scanVulnerabilities: (provider: string, account_identifier: string, region = 'us-east-1') =>
    request<{ total: number; new: number; instances_scanned: number; ssm_managed: number }>(
      'POST',
      '/api/inventory/vulnerabilities/scan',
      { provider, account_identifier, region },
    ),
  scanContainerImages: (provider: string, account_identifier: string, region = 'us-east-1') =>
    request<{ total: number; new: number; images_discovered: number; images_scanned: number }>(
      'POST',
      '/api/inventory/vulnerabilities/scan-images',
      { provider, account_identifier, region },
    ),
  generateImageSbom: (image_ref: string, region = 'us-east-1') =>
    request<{
      image_ref: string
      generated: boolean
      format: 'cyclonedx'
      component_count: number
      skipped_reason: string
      sbom: Record<string, unknown>
    }>('POST', '/api/inventory/vulnerabilities/sbom', { image_ref, region }),

  // NVD CVE catalog (browse the full CVE dictionary)
  cveCatalog: (params?: Query) =>
    request<CveCatalogPage>('GET', `/api/inventory/cve-catalog${qs(params)}`),
  cveCatalogSummary: () =>
    request<CveCatalogSummary>('GET', '/api/inventory/cve-catalog/summary'),
  cve: (cveId: string) => request<CveDetail>('GET', `/api/inventory/cve-catalog/${cveId}`),
  ingestCveCatalog: (body: { directory?: string; incremental?: boolean; days?: number }) =>
    request<{ source: string; ingested: number; days?: number }>(
      'POST',
      '/api/inventory/cve-catalog/ingest',
      body,
    ),

  // runtime / threat events
  runtimeEvents: (params?: Query) =>
    request<RuntimeEventsPage>('GET', `/api/inventory/runtime-events${qs(params)}`),
  runtimeEventsSummary: (accountId?: number | null) =>
    request<RuntimeEventsSummary>('GET', `/api/inventory/runtime-events/summary${qs({ account_id: accountId ?? undefined })}`),
  // eBPF sensor agents (by OS platform + liveness status) and detection findings
  runtimeAgents: (accountId?: number | null) =>
    request<AgentsResult>('GET', `/api/inventory/runtime/agents${qs({ account_id: accountId ?? undefined })}`),
  runtimeFindings: (params?: Query) =>
    request<RuntimeEventsPage>('GET', `/api/inventory/runtime/findings${qs(params)}`),

  // IaC pre-deploy scan (stateless)
  iacScan: (content: string, filename?: string) =>
    request<IacScanResult>('POST', '/api/inventory/iac/scan', { content, filename }),

  // live compliance (heavy: runs the boto3 check engine server-side)
  cspm: (params: Query) => request<CspmScan>('GET', `/api/live/cspm${qs(params)}`),
  // continuous compliance (persisted snapshots + drift)
  complianceCurrent: (accountId?: number | null, provider?: string | null) =>
    request<ComplianceCurrent>('GET', `/api/inventory/compliance/current${qs({ account_id: accountId ?? undefined, provider: provider && provider !== 'all' ? provider : undefined })}`),
  complianceReport: (accountId?: number | null, frameworks?: string) =>
    request<{ compliance: Record<string, FrameworkScore> }>('GET', `/api/inventory/compliance/report${qs({ account_id: accountId ?? undefined, frameworks })}`),
  complianceHistory: (framework: string) =>
    request<ComplianceHistory>('GET', `/api/inventory/compliance/history${qs({ framework })}`),
  complianceDrift: (params?: Query) =>
    request<ComplianceDriftResult>('GET', `/api/inventory/compliance/drift${qs(params)}`),
  complianceSnapshot: (params?: { account_id?: number | null } & Query) =>
    request<{ persisted: { snapshots: number; drifts: number }; account: string | null }>(
      'POST', `/api/live/compliance/snapshot${qs(params)}`),
  // DSPM data-store classifications from the persisted spine (populated by the
  // scan cycle). Reshaped from the inventory list payload to the DspmResult the
  // Data page renders.
  dspm: (accountId?: number | null) =>
    request<{ items: DspmStore[]; total: number }>(
      'GET', `/api/inventory/dspm${qs({ account_id: accountId ?? undefined })}`,
    ).then((r) => ({ stores: r.items, total: r.total, by_label: {} }) as DspmResult),

  // ── product customization (control overrides, custom frameworks/policies) ──
  availableFrameworks: () =>
    request<{ items: AvailableFramework[] }>('GET', '/api/config/available-frameworks'),
  frameworkControls: (id: string) =>
    request<FrameworkControls>('GET', `/api/config/frameworks/${id}/controls`),

  controlOverrides: () =>
    request<{ items: ControlOverride[] }>('GET', '/api/config/overrides'),
  saveOverride: (body: Partial<ControlOverride> & { framework: string; control_id: string }) =>
    request<ControlOverride>('PUT', '/api/config/overrides', body),
  deleteOverride: (framework: string, controlId: string) =>
    request<{ deleted: boolean }>('DELETE', `/api/config/overrides/${framework}/${controlId}`),

  customFrameworks: () =>
    request<{ items: CustomFramework[] }>('GET', '/api/config/frameworks'),
  saveFramework: (body: CustomFramework) =>
    request<CustomFramework>('PUT', '/api/config/frameworks', body),
  deleteFramework: (frameworkId: string) =>
    request<{ deleted: boolean }>('DELETE', `/api/config/frameworks/${frameworkId}`),
  importFramework: (
    frameworkId: string,
    bytes: ArrayBuffer,
    opts: { name?: string; version?: string; dryRun?: boolean } = {},
  ) =>
    postRaw<FrameworkImportResult>(
      `/api/config/frameworks/import${qs({
        framework_id: frameworkId, name: opts.name, version: opts.version, dry_run: opts.dryRun,
      })}`,
      bytes,
    ),

  customPolicies: () =>
    request<{ items: CustomPolicy[] }>('GET', '/api/config/policies'),
  savePolicy: (body: CustomPolicy) =>
    request<CustomPolicy>('PUT', '/api/config/policies', body),
  deletePolicy: (policyId: string) =>
    request<{ deleted: boolean }>('DELETE', `/api/config/policies/${policyId}`),
  evaluatePolicies: () =>
    request<PolicyEvalResult>('POST', '/api/config/policies/evaluate'),

  // Statement of Applicability (ISO 27001 SoA; works for any framework)
  soa: (framework: string) =>
    request<SoaResult>('GET', `/api/config/soa/${encodeURIComponent(framework)}`),
  soaExportUrl: (framework: string) =>
    `/api/config/soa/${encodeURIComponent(framework)}/export`,
}
