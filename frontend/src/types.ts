// Shapes mirror exactly what the FastAPI backend returns. There is no mock
// layer and no fallback data — the UI renders these or an honest error state.

// ── inventory spine (/api/inventory/*) ─────────────────────────

export interface Account {
  id: number
  provider: string
  account_identifier: string
  name: string | null
  role_arn: string | null
  disk_scan_role_arn: string | null
  is_active: boolean
  onboarding_status?: 'awaiting_stack' | 'connected' | string
  // Last permission-probe outcome, so standing health survives a page reload.
  last_verify_status: 'healthy' | 'degraded' | 'no_read' | 'unreachable' | null
  last_verified_at: string | null
  created_at: string | null
  latest_scan: ScanJob | null
}

// GET /api/inventory/onboarding/hosting-status — every failure here is one a
// customer would otherwise meet as a dead launch link.
export interface HostingStatus {
  ready: boolean
  checks: { name: string; status: 'pass' | 'fail' | 'warn' | 'info'; detail: string }[]
}

// POST /api/inventory/onboarding/link — issued before any account is known.
export interface LaunchLink {
  session_id: string
  // Carries a single-use onboarding token in its query string. Sensitive.
  launch_url: string
  template_url: string
  template_checksum: string
  template_reused: boolean
  external_id: string
  expires_at: string
  label: string | null
  // Earlier pending links for the same label that this one retired.
  superseded_links: number
  callback_url: string
  callback_enabled: boolean
}

export interface OnboardingSession {
  session_id: string
  label: string | null
  status: 'pending' | 'redeemed' | 'superseded' | 'expired'
  expires_at: string
  created_at: string
  redeemed_at: string | null
  // Both null until the stack reports which account it ran in.
  account_identifier: string | null
  role_arn: string | null
}

export interface ScanJob {
  id: number
  account_id: number
  scan_type: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  started_at: string | null
  completed_at: string | null
  duration_seconds: number | null
  assets_found: number
  assets_changed: number
  assets_deleted: number
  error_count: number
  error?: string | null
}

// POST /api/inventory/accounts/onboarding-template
export interface OnboardingTemplate {
  account_id: number
  external_id: string
  trust_account_id: string
  scanner_principal_arn: string | null
  policy_mode: 'managed' | 'least-privilege'
  onboarding_token_expires_at: string
  cloudformation_quick_create_url: string | null
  cloudformation_template_url: string | null
  cloudformation_template_expires_at: string | null
  cloudformation_template_s3_uri: string | null
  cloudformation_template_version_id: string | null
  cloudformation_template_reused: boolean | null
  one_click_setup_error: string | null
  cloudformation_template: string
  terraform_snippet: string
  // Self-contained Terraform: `apply` posts the role ARN back automatically —
  // no manual paste. Only present on first generation (needs the one-time
  // api_secret); null on a repeat call, fall back to terraform_snippet.
  terraform_autoconnect_snippet: string | null
}

// POST /api/inventory/scan-all — 202, the sweep runs in the background. It used
// to block until every account finished, which CloudFront cut off at 30s with a
// 504 while the scan carried on unseen. Progress comes from the status route.
export interface ScanAllStarted {
  status: 'started' | 'already_running'
  accounts: number
  in_flight: number
  poll: string
}

// GET /api/inventory/scan-all/status
export interface ScanAllStatus {
  running: boolean
  completed: number
  failed: number
  pending: number
  accounts: Array<{
    account_id: number
    account_identifier: string
    name: string | null
    // null means this account has never been scanned — "not started", which is
    // a different answer from "finished with nothing".
    job: {
      id: number
      status: string
      assets_found: number
      assets_changed: number
      assets_deleted: number
      error_count: number
      duration_seconds: number | null
      error?: string | null
    } | null
  }>
}

export interface Asset {
  id: number
  resource_id: string
  cloud_provider: string
  account_id: number
  asset_type: string
  name: string | null
  region: string
  tags: Record<string, unknown>
  is_public: boolean
  encryption_enabled: boolean | null
  network_exposure: 'private' | 'vpc' | 'public'
  properties: Record<string, unknown>
  risk_score: number
  is_active: boolean
  first_seen_at: string | null
  last_scanned_at: string | null
}

export interface AssetEvent {
  event_type: string
  previous_value: Record<string, unknown> | null
  new_value: Record<string, unknown> | null
  changed_at: string | null
}

/** A relationship target resolved to the asset it points at (null if the id is
 *  outside the scanned inventory: an account, a boundary policy, a foreign id). */
export interface RelatedResource {
  type: string
  target_id: string
  asset: {
    id: number
    name: string
    resource_id: string
    asset_type: string
    region: string
    is_active: boolean
    cloud_provider: string
  } | null
}

/** Boundary-aware CIEM evidence for a principal asset (same shape the Identity
 *  page uses), present only when the asset is an identity. */
export interface IdentityCiem {
  privilege: IdentityPrincipal['privilege']
  authorization: IdentityPrincipal['authorization']
}

export interface AssetDetail extends Asset {
  raw: Record<string, unknown>
  normalized: Record<string, unknown>
  properties: Record<string, unknown>
  relationships: Array<Record<string, unknown>>
  related_resources: RelatedResource[]
  identity: IdentityCiem | null
  resource_created_at: string | null
  events: AssetEvent[]
  account: {
    id: number
    identifier: string
    name: string | null
    provider: string
  } | null
  cloud_console_url: string | null
  internet_reachability: InternetReachability | null
  findings: AssetFinding[]
  attack_paths: AssetAttackPath[]
  vulnerability_posture: AssetVulnerabilityPosture
}

/** One piece of proof: which API said what, and why it matters to the path. */
export interface ReachabilityEvidence {
  source: string
  observation: string
  effect: string
}

/**
 * Verified network reachability, present only for resources that configure a
 * public endpoint. `blocked` and `unverified` are different answers: the first
 * is proof that a control stops the path, the second is a collection gap that
 * must never be read as safe.
 */
export interface InternetReachability {
  status: 'reachable' | 'blocked' | 'unverified' | 'not_applicable'
  evidence: ReachabilityEvidence[]
  missing: string[]
  blockers: string[]
}

export interface AssetFinding {
  id: number
  rule_id: string
  title: string
  severity: string
  why: string
  remediation: string
  compliance: Record<string, unknown>
  first_seen_at: string | null
  last_seen_at: string | null
}

export interface AssetAttackPath {
  id: number
  title: string
  severity: string
  risk_score: number
  confidence: number
  evidence_status?: 'confirmed' | 'stale' | 'partial'
  actively_exploited: boolean
}

export interface VulnerabilityComponent {
  package: string
  installed_version: string | null
  package_type: string | null
  fixed_versions: string[]
  paths: string[]
  targets: string[]
  scanner_sources: string[]
  vulnerability_count: number
  fixable_count: number
  by_severity: Record<string, number>
}

export interface VulnerabilityCoverage {
  status: 'completed' | 'skipped' | 'failed' | 'not_scanned' | 'not_applicable' | 'legacy_evidence'
  scanner: string | null
  scan_kind: string | null
  scanned_at: string | null
  package_count: number | null
  findings_count: number
  reason: string | null
  evidence: Record<string, unknown>
}

export interface AssetVulnerabilityPosture {
  coverage: VulnerabilityCoverage
  summary: {
    open: number
    fixable: number
    affected_components: number
    kev: number
    by_severity: Record<string, number>
  }
  components: VulnerabilityComponent[]
  items: Vulnerability[]
}

export interface AssetPage {
  items: Asset[]
  total: number
  page: number
  page_size: number
}

export type InventoryCategory = 'identity' | 'compute' | 'network' | 'data' | 'security' | 'management' | 'other'
export type InventoryRiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface InventoryResource {
  id: number
  identity: {
    name: string
    resource_id: string
    provider: string
    account_id: number
    account_name: string | null
    asset_type: string
    service: string
    category: InventoryCategory
    kind: string
  }
  scope: {
    region: string
    level: 'global' | 'regional'
  }
  posture: {
    exposure: 'private' | 'vpc' | 'public'
    is_public: boolean
    encryption: { status: 'enabled' | 'disabled' | 'not_applicable' }
    risk: { score: number; severity: InventoryRiskSeverity }
    findings: { total: number; by_severity: Record<string, number> }
  }
  lifecycle: {
    status: 'active' | 'inactive'
    first_seen_at: string | null
    last_scanned_at: string | null
    resource_created_at: string | null
  }
  metadata: {
    tags: Record<string, unknown>
    relationship_count: number
  }
}

export interface InventoryFacet {
  value: string
  label: string
  count: number
}

export interface InventoryResourcePage {
  schema_version: '1.0'
  items: InventoryResource[]
  totals: {
    assets: number
    filtered: number
    public: number
    elevated_risk: number
  }
  facets: {
    categories: InventoryFacet[]
    services: InventoryFacet[]
    types: InventoryFacet[]
    regions: InventoryFacet[]
    exposures: InventoryFacet[]
  }
  pagination: {
    page: number
    page_size: number
    pages: number
    total: number
  }
}

// ── real asset geography (GET /api/inventory/geo) ──────────────
export interface GeoRegion {
  region: string
  total: number
  public: number
  compute: number
  storage: number
  other: number
  by_category: Record<string, number>
}

export interface GeoDistribution {
  regions: GeoRegion[]
  total_assets: number
  providers: string[]
}

export interface InventorySummary {
  total_assets: number
  public_assets: number
  by_type: Record<string, number>
  by_provider: Record<string, number>
  by_exposure: Record<string, number>
  by_region: Record<string, number>
  // region -> { asset_type: count }; "global" key = account-wide services (IAM…)
  by_region_type: Record<string, Record<string, number>>
}

// ── source coverage per pillar (is each pillar producing fresh data) ──
export type PillarStatus = 'healthy' | 'degraded' | 'absent' | 'not_applicable'

export interface PillarCoverage {
  pillar: string
  status: PillarStatus
  detail: string
  observed: number
  last_seen: string | null
}

export interface Coverage {
  pillars: PillarCoverage[]
  healthy: number
  total: number
}

// ── persisted rule findings ────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface RuleFinding {
  id: number
  rule_id: string
  title: string
  severity: Severity
  status: 'open' | 'suppressed' | 'resolved'
  signal: 'active_threat' | 'network_hygiene'
  suppressed_by?: string | null
  suppressed_why?: string | null
  resource_id: string
  asset_type: string
  why: string
  remediation: string
  remediation_cli: string
  compliance: Record<string, string[]>
  related: string[]
  first_seen_at: string | null
  last_seen_at: string | null
  resolved_at: string | null
  // §4.2/§4.5 cross-signal enrichment (absent when no asset/DSPM match).
  risk_score?: number
  exposure?: 'public' | 'vpc' | 'private'
  elevated?: boolean
  data_sensitivity?: { label: string; taxonomies: string[] }
}

export interface FindingsPage {
  items: RuleFinding[]
  total: number
}

export interface FindingsSummary {
  open: number
  active_threats: number
  network_hygiene: number
  suppressed: number
  resolved: number
  by_severity: Record<string, number>
  active_threat_by_severity: Record<string, number>
  by_rule: Record<string, number>
  active_threat_by_rule: Record<string, number>
  network_hygiene_by_rule: Record<string, number>
}

export interface ModeledFinding {
  id: number
  verdict: {
    title: string
    rule_id: string
    category: InventoryCategory
    signal: 'active_threat' | 'network_hygiene'
  }
  resource: {
    resource_id: string
    name: string
    asset_type: string
    provider: string
    service: string
    account_id: number
    account_name: string | null
  }
  posture: {
    severity: Severity
    status: 'open' | 'suppressed' | 'resolved'
    risk_score: number
    exposure: 'public' | 'vpc' | 'private' | 'unknown'
    elevated: boolean
    data_sensitivity: { label: string; taxonomies: string[] } | null
  }
  evidence: {
    why: string
    compliance: Record<string, string[]>
    related_resources: string[]
    suppressed_by: string | null
    suppressed_why: string | null
  }
  remediation: { guidance: string; cli: string | null }
  lifecycle: { first_seen_at: string | null; last_seen_at: string | null; resolved_at: string | null }
}

export interface ModeledFindingPage {
  schema_version: '1.0'
  items: ModeledFinding[]
  totals: {
    open: number
    active_threats: number
    network_hygiene: number
    suppressed: number
    resolved: number
    critical: number
    elevated: number
    filtered: number
  }
  facets: {
    severities: InventoryFacet[]
    statuses: InventoryFacet[]
    rules: InventoryFacet[]
    categories: InventoryFacet[]
    services: InventoryFacet[]
    signals: InventoryFacet[]
  }
  pagination: { page: number; page_size: number; pages: number; total: number }
}

export interface IdentityPrincipal {
  id: number
  identity: {
    name: string
    resource_id: string
    provider: string
    account_id: number
    account_name: string | null
    principal_type: string
  }
  privilege: {
    admin: boolean
    admin_grant: boolean
    boundary_restricts_admin: boolean
    admin_reason: string
    privilege_escalation_actions: string[]
    effective_privilege_escalation_actions: string[]
  }
  authorization: {
    scope: string
    effective_access_complete: boolean
    unevaluated_policy_layers: string[]
    policy_sources: number
    direct_policy_sources: number
    inherited_policy_sources: number
    allow_statements: number
    explicit_denies: number
    conditional_statements: number
    wildcard_action_statements: number
    wildcard_resource_statements: number
    groups: string[]
    permissions_boundary_arn: string | null
    permissions_boundary_state: string
    analysis_complete: boolean
  }
  authentication: {
    console_enabled: boolean
    mfa_enabled: boolean
    access_key_active: boolean
    access_key_max_age_days: number
    access_key_last_used_days: number | null
  }
  trust: {
    level: 'public' | 'external' | 'verified' | 'account' | 'none'
    publicly_assumable: boolean
    external: boolean
    onboarding_verified: boolean
    principals: string[]
  }
  posture: {
    risk_score: number
    severity: InventoryRiskSeverity
    open_findings: number
    attack_paths: number
  }
  lifecycle: { age_days: number | null; last_used_days: number | null; last_scanned_at: string | null }
  metadata: { tags?: Record<string, unknown>; path?: string | null }
}

export interface IdentityPrincipalPage {
  schema_version: '1.0'
  items: IdentityPrincipal[]
  totals: {
    principals: number
    roles: number
    users: number
    admins: number
    admin_grants: number
    bounded: number
    inherited_access: number
    incomplete_evaluations: number
    mfa_gaps: number
    external_trust: number
    filtered: number
  }
  facets: {
    principal_types: InventoryFacet[]
    trust_levels: InventoryFacet[]
    severities: InventoryFacet[]
  }
  pagination: { page: number; page_size: number; pages: number; total: number }
}

export interface DataSecurityStore {
  id: number
  identity: {
    name: string
    resource_id: string
    provider: string
    account_id: number
    account_name: string | null
    asset_type: string
    service: string
    store_type: string
    region: string
  }
  classification: {
    status: 'classified' | 'unclassified'
    label: string
    data_types: string[]
    taxonomies: string[]
    frameworks: string[]
    sensitivity_score: number
    records_estimated: number
    objects_sampled: number
  }
  protection: {
    public: boolean
    exposure: 'public' | 'vpc' | 'private'
    encryption: 'enabled' | 'disabled' | 'unknown'
    posture_findings: string[]
  }
  risk: { score: number; severity: InventoryRiskSeverity; open_findings: number }
  lifecycle: { first_seen_at: string | null; last_seen_at: string | null }
  metadata: { tags?: Record<string, unknown>; properties?: Record<string, unknown> }
}

export interface DataSecurityPage {
  schema_version: '1.0'
  items: DataSecurityStore[]
  totals: { stores: number; classified: number; public: number; unencrypted: number; sensitive: number; filtered: number }
  facets: {
    services: InventoryFacet[]
    store_types: InventoryFacet[]
    labels: InventoryFacet[]
    regions: InventoryFacet[]
    exposures: InventoryFacet[]
  }
  pagination: { page: number; page_size: number; pages: number; total: number }
}

export interface EvaluateResult {
  total: number
  new: number
  reopened: number
  resolved: number
  suppressed?: number
}

// ── attack-path issues (correlated, risk-scored) ───────────────

export interface PathHop {
  kind: 'internet' | 'external' | 'compute' | 'security_group' | 'role' | 'bucket' | 'database'
  id: string
  name: string
}

export interface EvidenceItem {
  source: string        // the API query that produced it (e.g. rds:DescribeDBInstances)
  observation: string   // the observed value, log-like (e.g. PubliclyAccessible = true)
  effect: string        // how it moves the score
}

export interface AttackPathIssue {
  id: number
  issue_type: string
  title: string
  severity: Severity
  status: 'open' | 'resolved'
  risk_score: number
  confidence: number // 0–1: how completely the route is evidenced
  evidence_status?: 'confirmed' | 'stale' | 'partial'
  resource_id: string
  why: string
  remediation: string
  path: PathHop[]
  compliance: Record<string, string[]>
  related: string[]
  evidence?: EvidenceItem[]
  scoring?: string
  actively_exploited?: boolean
  exploit_count?: number
  last_exploit_at?: string | null
  first_seen_at: string | null
  last_seen_at: string | null
  resolved_at: string | null
}

export interface IssuesPage {
  items: AttackPathIssue[]
  total: number
}

export interface IssuesSummary {
  open: number
  resolved: number
  max_risk: number
  by_severity: Record<string, number>
  by_type: Record<string, number>
}

// ── security graph (/api/inventory/graph) ──────────────────────

export type GraphKind =
  | 'internet'
  | 'external'
  | 'user'
  | 'compute'
  | 'security_group'
  | 'role'
  | 'bucket'
  | 'database'
  | 'finding'

export interface GraphNode {
  id: string
  kind: GraphKind
  name: string
  asset_type?: string | null
  region?: string | null
  is_public?: boolean
  risk_score?: number
  severity?: Severity
  issue_type?: string
  resource_id?: string
  properties?: Record<string, unknown>
}

export interface GraphEdge {
  source: string
  target: string
  type:
    | 'EXPOSED_TO'
    | 'USES_SECURITY_GROUP'
    | 'CAN_ASSUME'
    | 'CAN_ACCESS'
    | 'CAN_MODIFY_AND_INVOKE'
    | 'CAN_IMPERSONATE_VIA_SERVICE'
    | 'HAS_FINDING'
  ports?: string[]
  wildcard?: boolean
}

export interface AttackRoute {
  id: string
  nodes: string[] // ordered node ids, entry → target
  length: number
  entry: GraphKind
  target: string
  target_kind: GraphKind
  severity: Severity
}

export interface AccountRef {
  provider: string
  account_identifier: string
  name: string | null
}

export interface GraphCoverageSignal {
  key: 'inventory' | 'identity' | 'data' | 'relationships' | 'entry_points'
  status: 'ready' | 'partial' | 'missing' | 'not_observed'
  observed: number
  detail: string
}

export interface GraphAnalysis {
  status: 'ready' | 'partial' | 'insufficient'
  conclusion: 'not_analyzed' | 'insufficient_identity_evidence' | 'paths_detected' | 'no_entry_points_observed' | 'no_path_to_target'
  message: string
  metrics: {
    assets: number
    graph_nodes: number
    graph_edges: number
    attack_edges: number
    entry_edges: number
    paths: number
  }
  coverage: GraphCoverageSignal[]
  limitations: string[]
}

export interface SecurityGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  paths: AttackRoute[]
  account: string | null
  provider: string
  accounts: AccountRef[]
  analysis: GraphAnalysis
}

// ── vulnerabilities (CWPP, /api/inventory/vulnerabilities) ─────

export interface Vulnerability {
  id: number
  resource_id: string
  cve_id: string
  package: string
  installed_version: string | null
  severity: string
  cvss: number | null
  summary: string | null
  fixed_version: string | null
  scanner_source: string
  package_type: string | null
  target: string | null
  package_path: string | null
  epss: number | null
  epss_percentile: number | null
  kev: boolean
  exploit_maturity: number
  status: 'open' | 'resolved'
  first_seen_at: string | null
  last_seen_at: string | null
  resolved_at: string | null
  // enriched from the NVD catalog when the CVE is present there
  cvss_vector?: string | null
  cwes?: string[]
  nvd_url?: string
}

export interface VulnsPage {
  items: Vulnerability[]
  total: number
}

export interface VulnsSummary {
  open: number
  affected_assets: number
  by_severity: Record<string, number>
  kev: number
  high_epss: number
}

// ── NVD CVE catalog (/api/inventory/cve-catalog) ───────────────

export interface CveRow {
  cve_id: string
  severity: string | null
  cvss_score: number | null
  cvss_version: string | null
  description: string | null
  published: string | null
  last_modified: string | null
}

export interface CveDetail extends CveRow {
  cvss_vector: string | null
  cwes: string[]
  refs: string[]
  source: string
}

export interface CveCatalogPage {
  items: CveRow[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface CveCatalogSummary {
  total: number
  by_severity: Record<string, number>
}

// ── runtime / threat events (/api/inventory/runtime-events) ────

export interface RuntimeEvent {
  id: number
  event_type: string
  severity: string
  resource_id: string | null
  workload: string | null
  process: string | null
  pid: number | null
  summary: string | null
  count: number // burst-collapsed occurrences (1 = single observation)
  observed_at: string | null
  // lineage / enrichment (eBPF sensor) — used by the process-tree view
  comm?: string | null
  command?: string | null
  parent?: string | null
  ppid?: number | null
  lineage?: string | null
  container?: string | null
  dest?: string | null
  node?: string | null
  benign?: boolean
  simulated?: boolean
  // detection-engine metadata (present on runtime *findings*)
  rule_id?: string | null
  rule_name?: string | null
  tactic?: string | null
  technique?: string | null
}

export interface RuntimeEventsPage {
  items: RuntimeEvent[]
  total: number
}

// ── eBPF sensor agents (derived: EC2 inventory ∪ runtime hosts) ─────────────
export type AgentStatus = 'online' | 'stale' | 'no_sensor' | 'unsupported'

export interface Agent {
  host: string
  name: string | null
  region: string | null
  resource_id: string
  os: string // linux | windows | unknown
  os_detail: string
  ebpf_supported: boolean
  events: number
  findings: number
  last_seen: string | null
  status: AgentStatus
}

export interface AgentsResult {
  items: Agent[]
  by_os: Record<string, number>
  by_status: Record<string, number>
  total: number
}

export interface RuntimeEventsSummary {
  total: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
}

// ── IaC scan (/api/inventory/iac/scan) ─────────────────────────

export interface IacFinding {
  check_id: string
  title: string
  severity: Severity
  resource: string
  resource_type: string
  why: string
  remediation: string
  compliance: Record<string, string[]>
}

export interface IacScanResult {
  format: 'terraform' | 'cloudformation' | null
  resources_scanned: number
  findings: IacFinding[]
  total: number
  by_severity: Record<string, number>
}

// ── live DSPM data stores (/api/live/dspm) ─────────────────────

export interface DspmStore {
  store_id: string
  store_name: string
  store_type: string
  label: string
  risk_score: number
  sensitivity_score: number
  exposure_score: number
  engine: string
  public: boolean
  posture_findings: string[]
  findings?: string[]
}

export interface DspmResult {
  stores: DspmStore[]
  total: number
  by_label: Record<string, number>
}

// ── live CSPM compliance (/api/live/cspm) ──────────────────────

export type ControlState = 'pass' | 'fail' | 'not_assessed'

export interface ComplianceControl {
  id: string
  title: string
  section: string
  state: ControlState
  checks: string[]
}

export interface SectionScore {
  passing: number
  total: number
  pct: number
}

export interface FrameworkScore {
  name: string
  version: string | null
  score: number
  passing: number
  total: number
  not_assessed: number
  sections: Record<string, SectionScore>
  controls: ComplianceControl[]
}

export interface CspmSummary {
  total_checks: number
  total_findings: number
  passed: number
  failed: number
  errors: number
  pass_rate: number
  by_severity: Record<string, number>
  by_provider: Record<string, number>
  by_category: Record<string, number>
}

// ── continuous compliance (persisted snapshots + drift) ────────

export interface ComplianceSnapshot {
  framework: string
  version: string | null
  account: string | null
  region: string | null
  score: number
  passing: number
  total: number
  not_assessed: number
  origin: string | null // 'steampipe' (Powerpipe) | 'python' (fallback)
  captured_at: string | null
}

export interface ComplianceCurrent {
  items: ComplianceSnapshot[]
  total: number
}

export interface CompliancePoint {
  captured_at: string | null
  score: number
  passing: number
  total: number
}

export interface ComplianceHistory {
  framework: string
  points: CompliancePoint[]
}

export interface ComplianceDriftItem {
  framework: string
  control_id: string
  control_title: string | null
  from_state: string | null
  to_state: string
  direction: 'regression' | 'remediation'
  detected_at: string | null
}

export interface ComplianceDriftResult {
  items: ComplianceDriftItem[]
  total: number
  regressions: number
  remediations: number
}

export interface CspmScan {
  account: string | null
  region: string
  summary: CspmSummary
  risk_score: number
  risk_level: string
  findings: unknown[]
  compliance: Record<string, FrameworkScore>
  generated_at: string
}

// ── product customization (/api/config/*) ──────────────────────

export interface AvailableFramework {
  id: string
  name: string
  builtin: boolean
}

export interface ControlRef {
  id: string
  title: string
  section: string
}

export interface FrameworkControls {
  framework: string
  name: string | null
  controls: ControlRef[]
}

export interface SoaControl {
  id: string
  title: string
  theme: string
  applicable: boolean
  justification: string
  assessment: 'Automated' | 'Manual'
  status: string
  checks: string[]
  severity?: string | null
}

export interface SoaResult {
  framework: string
  name: string
  version: string | null
  generated_at: string
  total: number
  applicable: number
  controls: SoaControl[]
}

// Result of importing a framework from .xlsx (preview when dry_run, else saved).
export interface FrameworkImportResult {
  preview: boolean
  control_count: number
  framework_id: string
  name: string
  version: string | null
  controls: Record<string, CustomControl>
  enabled?: boolean
}

export interface ControlOverride {
  framework: string
  control_id: string
  enabled?: boolean
  severity?: string | null
  note?: string | null
  waived_until?: string | null
  updated_at?: string | null
}

// One control inside a custom framework: maps to existing check ids.
export interface CustomControl {
  title: string
  section: string
  checks: string[]
}

export interface CustomFramework {
  framework_id: string
  name: string
  version?: string | null
  controls: Record<string, CustomControl>
  enabled?: boolean
}

export type PolicyRuleType =
  | 'tag_required'
  | 'encryption_required'
  | 'no_public'
  | 'network_max'

export interface PolicyRule {
  type: PolicyRuleType
  params?: Record<string, unknown>
}

export interface CustomPolicy {
  policy_id: string
  name: string
  description?: string | null
  severity: string
  resource_type?: string | null
  rule: PolicyRule
  frameworks: Record<string, string[]> // {framework_id: [control_id, ...]}
  enabled?: boolean
}

export interface PolicyFinding {
  check_id: string
  resource_id: string
  status: 'pass' | 'fail'
  severity: string
  category: string
  message: string
}

export interface PolicyEvalResult {
  findings: PolicyFinding[]
  total: number
  evaluated_policies: number
  by_status: { pass: number; fail: number }
}
