import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  ExternalLink,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Network,
  ShieldAlert,
  UserRound,
  UsersRound,
} from "lucide-react";
import {
  accounts,
  accountFor,
  assets,
  attackPaths,
  type Finding,
} from "./data";
import { useProduct } from "./store";
import {
  Badge,
  Details,
  Empty,
  Filters,
  Head,
  Notice,
  Overlay,
  Panel,
  Table,
  Tabs,
  useFilters,
} from "./ui";

type PrincipalType = "Role" | "User" | "Service account" | "Federated identity";
type IdentityRisk = "Critical" | "High" | "Medium" | "Low";
type Principal = {
  id: string;
  name: string;
  account: string;
  type: PrincipalType;
  source: string;
  risk: IdentityRisk;
  score: number;
  privilege: string;
  trust: string;
  lastActivity: string;
  mfa: string;
  access: string;
  owner: string;
  asset: string;
  evidence: string;
  gap?: string;
};

const principalSeed: Omit<Principal, "account" | "asset">[] = [
  {
    id: "id-prod-app",
    name: "application-role-prod",
    type: "Role",
    source: "EC2 instance profile",
    risk: "Critical",
    score: 96,
    privilege: "Administrator candidate",
    trust: "Same account",
    lastActivity: "18 min ago",
    mfa: "Not applicable",
    access: "s3:GetObject · s3:PutObject",
    owner: "Platform Team",
    evidence: "iam:GetRolePolicy · iam:ListAttachedRolePolicies",
  },
  {
    id: "id-prod-data",
    name: "data-pipeline-role-prod",
    type: "Role",
    source: "ECS task role",
    risk: "High",
    score: 82,
    privilege: "Privilege escalation path",
    trust: "External account",
    lastActivity: "2h ago",
    mfa: "Not applicable",
    access: "iam:PassRole · sts:AssumeRole",
    owner: "Data Engineering",
    evidence: "iam:GetRole · iam:GetRolePolicy",
  },
  {
    id: "id-prod-breakglass",
    name: "breakglass-admin-prod",
    type: "User",
    source: "IAM user",
    risk: "High",
    score: 76,
    privilege: "Administrator access",
    trust: "Console sign-in",
    lastActivity: "13 days ago",
    mfa: "Enabled",
    access: "AdministratorAccess",
    owner: "Security Team",
    evidence: "iam:GetUser · iam:ListMFADevices",
  },
  {
    id: "id-prod-vendor",
    name: "vendor-support-prod",
    type: "Federated identity",
    source: "SAML provider",
    risk: "Medium",
    score: 58,
    privilege: "Scoped support access",
    trust: "External account",
    lastActivity: "6 days ago",
    mfa: "Provider managed",
    access: "ec2:Describe* · logs:Get*",
    owner: "Platform Team",
    evidence: "iam:GetSAMLProvider · role trust policy",
    gap: "Session policy was not collected",
  },
  {
    id: "id-dev-ci",
    name: "github-actions-dev",
    type: "Federated identity",
    source: "OIDC provider",
    risk: "High",
    score: 74,
    privilege: "Deployment permissions",
    trust: "External account",
    lastActivity: "3h ago",
    mfa: "Not applicable",
    access: "cloudformation:* · iam:PassRole",
    owner: "Payments Team",
    evidence: "iam:GetOpenIDConnectProvider · role trust policy",
  },
  {
    id: "id-shared-audit",
    name: "audit-exporter-shared",
    type: "Service account",
    source: "Lambda execution role",
    risk: "Low",
    score: 21,
    privilege: "Read-only",
    trust: "Same account",
    lastActivity: "49 min ago",
    mfa: "Not applicable",
    access: "s3:PutObject",
    owner: "Security Team",
    evidence: "iam:GetRolePolicy · lambda:GetFunction",
  },
  {
    id: "id-security-auditor",
    name: "security-auditor-role",
    type: "Role",
    source: "Security service role",
    risk: "Low",
    score: 18,
    privilege: "Read-only security access",
    trust: "Same account",
    lastActivity: "24 min ago",
    mfa: "Not applicable",
    access: "securityhub:Get* · guardduty:Get*",
    owner: "Security Team",
    evidence: "iam:GetRolePolicy · iam:ListAttachedRolePolicies",
  },
];

function principalFor(
  seed: Omit<Principal, "account" | "asset">,
  index: number,
): Principal {
  const account = [
    "production",
    "production",
    "production",
    "production",
    "development",
    "shared-services",
    "security",
  ][index];
  const asset =
    assets.find((a) => a.account === account && a.category === "Identity")
      ?.id ||
    assets.find((a) => a.account === account)?.id ||
    "";
  return { ...seed, account, asset };
}

const seededPrincipals = principalSeed.map(principalFor);
const seededPrincipalAccounts = new Set(
  seededPrincipals.map((principal) => principal.account),
);
const generatedPrincipals: Principal[] = accounts
  .filter((account) => !seededPrincipalAccounts.has(account.id))
  .map((account, index) => {
    const asset = assets.find(
      (item) => item.account === account.id && item.category === "Identity",
    );
    return {
      id: `id-${account.id}-application`,
      name: asset?.name || `${account.id}-application-role`,
      account: account.id,
      type: "Role",
      source: "EC2 instance profile",
      risk: index % 2 ? "High" : "Medium",
      score: index % 2 ? 78 : 61,
      privilege: index % 2 ? "Privilege escalation path" : "Scoped service access",
      trust: index % 2 ? "External account" : "Same account",
      lastActivity: `${18 + index * 11} min ago`,
      mfa: "Not applicable",
      access: index % 2 ? "iam:PassRole · sts:AssumeRole" : "s3:GetObject",
      owner: asset?.owner || "Platform Team",
      asset: asset?.id || "",
      evidence: "iam:GetRole · iam:GetRolePolicy",
    };
  });
const allPrincipals = [...seededPrincipals, ...generatedPrincipals];
const typeIcon: Record<PrincipalType, typeof KeyRound> = {
  Role: KeyRound,
  User: UserRound,
  "Service account": Fingerprint,
  "Federated identity": UsersRound,
};

function relatedFindings(principal: Principal, findings: Finding[]) {
  const asset = assets.find((a) => a.id === principal.asset);
  return findings.filter(
    (f) =>
      f.asset === principal.asset ||
      (asset?.account === "production" &&
        principal.id === "id-prod-app" &&
        f.policy === "CS-IAM-012"),
  );
}

function IdentityBadge({ value }: { value: string }) {
  return (
    <Badge
      kind={
        value === "External account"
          ? "High"
          : value.includes("gap")
            ? "Unknown"
            : undefined
      }
    >
      {value}
    </Badge>
  );
}

export function Identities() {
  const { workspace, inScope, canAct, tenantAccounts } = useProduct();
  const filters = useFilters();
  const { params, set } = filters;
  const [selected, setSelected] = useState<Principal | null>(null);
  const tab = params.get("tab") || "All principals";
  const principals = allPrincipals.filter((principal) =>
    inScope(principal.account),
  );
  const rows = principals.filter((principal) => {
    const selectedRisk = params.get("risk")?.split(",") || [];
    return (
      (tab === "All principals" || principal.type === tab) &&
      (!selectedRisk.length || selectedRisk.includes(principal.risk)) &&
      (!params.get("trust") || principal.trust === params.get("trust")) &&
      (!params.get("account") ||
        accountFor(principal.account).name === params.get("account")) &&
      `${principal.name} ${principal.source} ${principal.access} ${principal.id}`
        .toLowerCase()
        .includes((params.get("q") || "").toLowerCase())
    );
  });
  const risky = principals.filter((principal) =>
    ["Critical", "High"].includes(principal.risk),
  );
  const external = principals.filter(
    (principal) => principal.trust === "External account",
  );
  const incomplete = principals.filter((principal) => principal.gap);
  const permissionRows = principals.slice(0, 4).map((principal, index) => ({
    name: principal.name,
    values: [0, 1, 2, 3, 4, 5].map(
      (offset) => ((principal.score + index + offset * 2) % 5) + 1,
    ),
  }));
  const primaryIdentity = risky[0] || principals[0];
  const secondaryIdentity = external[0] || principals[1] || primaryIdentity;
  const signals: Array<[string, number, string, typeof LockKeyhole]> = [
    ["Elevated access", risky.length, "Critical,High", LockKeyhole],
    ["External trust", external.length, "", Network],
    [
      "Inactive 30+ days",
      principals.filter((p) => p.lastActivity.includes("days")).length,
      "",
      CircleAlert,
    ],
    ["Coverage gaps", incomplete.length, "", ShieldAlert],
  ];
  return (
    <div className="cs-page cs-identities">
      <Head title="Identities">
        <Link className="cs-button" to="/reports?type=Findings+Report">
          <ArrowUpRight size={15} />
          Identity report
        </Link>
      </Head>
      <div className="cs-identity-overview">
        <Panel
          title="Identity risk posture"
          action={
            <Badge kind={incomplete.length ? "Degraded" : "Healthy"}>
              {incomplete.length ? "Partial evaluation" : "Evaluated"}
            </Badge>
          }
        >
          <div className="cs-identity-score">
            <div className="cs-score-ring small">
              <svg
                viewBox="0 0 164 164"
                role="img"
                aria-label="Identity posture score 71 out of 100"
              >
                <circle
                  cx="82"
                  cy="82"
                  r="68"
                  fill="none"
                  stroke="#eef2ef"
                  strokeWidth="12"
                />
                <circle
                  cx="82"
                  cy="82"
                  r="68"
                  fill="none"
                  stroke="#cf9346"
                  strokeWidth="12"
                  strokeLinecap="round"
                  strokeDasharray="303 427"
                  transform="rotate(-90 82 82)"
                />
              </svg>
              <div>
                <strong>71</strong>
                <span>/100</span>
              </div>
            </div>
            <div>
              <Badge kind="High">Needs review</Badge>
              <h3>Identity exposure needs attention</h3>
              <p>
                {risky.length} principals have elevated access or a risky trust
                relationship.
              </p>
              <Link className="cs-jump" to="/findings?policy=CS-IAM-012">
                Review IAM findings
                <ArrowRight size={13} />
              </Link>
            </div>
          </div>
        </Panel>
        <Panel title="Identity signals">
          <div className="cs-identity-signals">
            {signals.map(([label, count, risk, SignalIcon]) => {
              return (
                <button key={label} onClick={() => risk && set("risk", risk)}>
                  <span className="cs-health-icon amber">
                    <SignalIcon size={16} />
                  </span>
                  <span>
                    {label}
                    <strong>{count}</strong>
                  </span>
                  <ChevronRight size={15} />
                </button>
              );
            })}
          </div>
        </Panel>
      </div>
      {incomplete.length > 0 && (
        <Notice>
          Identity grants are not final proof of effective access.{" "}
          {incomplete.length} principal has unevaluated authorization layers and
          remains partially evaluated.
        </Notice>
      )}
      <div className="cs-visual-grid cs-identity-intelligence">
        <Panel
          title="Granted vs used permissions"
          action={
            <Link className="cs-jump" to="/security-graph">
              Open graph <ArrowUpRight size={13} />
            </Link>
          }
        >
          <div className="cs-permission-heatmap">
            <span />
            {["S3", "IAM", "EC2", "KMS", "RDS", "Lambda"].map((service) => (
              <b key={service}>{service}</b>
            ))}
            {permissionRows.map((row) => (
              <div key={row.name} className="cs-heatmap-row">
                <strong>{row.name}</strong>
                {row.values.map((value, index) => (
                  <i
                    key={index}
                    className={`level-${value}`}
                    title={`${row.name}: ${["S3", "IAM", "EC2", "KMS", "RDS", "Lambda"][index]} permission gap level ${value}`}
                  />
                ))}
              </div>
            ))}
          </div>
          <div className="cs-heatmap-legend">
            <span>Used</span>
            {[1, 2, 3, 4, 5].map((level) => (
              <i key={level} className={`level-${level}`} />
            ))}
            <span>Granted but unused</span>
          </div>
        </Panel>
        <Panel title="Identity relationships">
          <div className="cs-identity-paths">
            {secondaryIdentity && <Link to={`/identities/${secondaryIdentity.id}`}>
              <span className="cs-resource-icon identity">
                <UsersRound size={16} />
              </span>
              <span>
                <strong>External account</strong>
                <small>can assume</small>
              </span>
              <ChevronRight size={14} />
              <span className="cs-resource-icon identity">
                <KeyRound size={16} />
              </span>
              <span>
                <strong>{secondaryIdentity.name}</strong>
                <small>2 sensitive targets</small>
              </span>
            </Link>}
            {primaryIdentity && <Link to={`/identities/${primaryIdentity.id}`}>
              <span className="cs-resource-icon network">
                <Network size={16} />
              </span>
              <span>
                <strong>{accountFor(primaryIdentity.account).name}</strong>
                <small>uses role</small>
              </span>
              <ChevronRight size={14} />
              <span className="cs-resource-icon identity">
                <KeyRound size={16} />
              </span>
              <span>
                <strong>{primaryIdentity.name}</strong>
                <small>admin candidate</small>
              </span>
            </Link>}
            <div className="cs-stale-identity">
              <CircleAlert size={16} />
              <span>
                <strong>2 dormant identities</strong>
                <small>No activity for 30+ days</small>
              </span>
              <button onClick={() => set("q", "days")}>Review</button>
            </div>
          </div>
        </Panel>
      </div>
      <Panel>
        <Tabs
          items={[
            "All principals",
            "Role",
            "User",
            "Federated identity",
            "Service account",
          ]}
          value={tab}
          onChange={(value) => set("tab", value)}
        />
        <Filters
          filters={filters}
          placeholder="Search identities, principal IDs, access..."
          fields={{
            risk: ["Critical", "High", "Medium", "Low"],
            trust: ["Same account", "External account", "Console sign-in"],
            account: tenantAccounts.map((account) => account.name),
          }}
        />
        <Table
          headers={[
            "Identity",
            "Type",
            "Account",
            "Privilege",
            "Trust",
            "Last activity",
            "Risk",
            "Findings",
            "",
          ]}
          count={rows.length}
          empty={!rows.length}
        >
          {rows.map((principal) => {
            const Icon = typeIcon[principal.type];
            const findings = relatedFindings(principal, workspace.findings);
            return (
              <tr
                key={principal.id}
                onClick={(event) => {
                  if (!(event.target as HTMLElement).closest("a,button"))
                    setSelected(principal);
                }}
              >
                <td>
                  <button
                    className="cs-resource-button"
                    onClick={() => setSelected(principal)}
                  >
                    <span className="cs-resource">
                      <span className="cs-resource-icon identity">
                        <Icon size={17} />
                      </span>
                      <span>
                        <strong>{principal.name}</strong>
                        <small>{principal.source}</small>
                      </span>
                    </span>
                  </button>
                </td>
                <td>{principal.type}</td>
                <td>
                  <Link to={`/accounts/${principal.account}`}>
                    {accountFor(principal.account).name}
                  </Link>
                </td>
                <td className="cs-wrap-cell">
                  <strong>{principal.privilege}</strong>
                  <span className="cs-cell-sub">{principal.access}</span>
                </td>
                <td>
                  <IdentityBadge value={principal.trust} />
                </td>
                <td>{principal.lastActivity}</td>
                <td>
                  <span
                    className={`cs-priority ${principal.risk.toLowerCase()}`}
                  >
                    {principal.score}
                  </span>
                </td>
                <td>
                  <Link to={`/findings?asset=${principal.asset}`}>
                    {findings.length} open
                  </Link>
                </td>
                <td>
                  <button
                    className="cs-icon"
                    aria-label={`Inspect ${principal.name}`}
                    onClick={() => setSelected(principal)}
                  >
                    <ChevronRight size={16} />
                  </button>
                </td>
              </tr>
            );
          })}
        </Table>
      </Panel>
      {selected && (
        <IdentityDrawer
          principal={selected}
          findings={workspace.findings}
          onClose={() => setSelected(null)}
          canAct={canAct}
        />
      )}
    </div>
  );
}

function IdentityDrawer({
  principal,
  findings,
  onClose,
  canAct,
}: {
  principal: Principal;
  findings: Finding[];
  onClose: () => void;
  canAct: boolean;
}) {
  const related = relatedFindings(principal, findings);
  return (
    <Overlay drawer title={principal.name} onClose={onClose}>
      <div className="cs-inline">
        <Badge>{principal.risk}</Badge>
        <IdentityBadge value={principal.trust} />
      </div>
      <Details
        rows={[
          ["Principal type", principal.type],
          [
            "Account",
            <Link to={`/accounts/${principal.account}`}>
              {accountFor(principal.account).name}
            </Link>,
          ],
          ["Owner", principal.owner],
          ["Privilege", principal.privilege],
          ["Effective access", principal.access],
          ["Evidence source", <code>{principal.evidence}</code>],
          ["Last activity", principal.lastActivity],
          [
            "Evaluation",
            principal.gap ? (
              <Badge kind="Unknown">Partial</Badge>
            ) : (
              <Badge>Verified</Badge>
            ),
          ],
        ]}
      />
      {principal.gap && (
        <Notice>
          {principal.gap}. Do not treat policy grants as effective access until
          missing policy layers are collected.
        </Notice>
      )}
      {related.length > 0 && (
        <Link className="cs-button" to={`/findings?asset=${principal.asset}`}>
          <ShieldAlert size={15} />
          View related findings
        </Link>
      )}
      {canAct && (
        <Link className="cs-button primary" to={`/identities/${principal.id}`}>
          Open full investigation
          <ExternalLink size={14} />
        </Link>
      )}
    </Overlay>
  );
}

export function IdentityDetail() {
  const { identityId } = useParams();
  const { workspace, inScope, canAct } = useProduct();
  const filters = useFilters();
  const principal = allPrincipals.find(
    (item) => item.id === identityId && inScope(item.account),
  );
  const tab = filters.params.get("tab") || "Overview";
  if (!principal)
    return (
      <Empty
        title="Identity unavailable in current scope"
        text="Select the account containing this principal or return to Identities."
      />
    );
  const asset = assets.find((item) => item.id === principal.asset);
  const related = relatedFindings(principal, workspace.findings);
  const path = attackPaths.find(
    (item) =>
      item.account === principal.account && principal.id === "id-prod-app",
  );
  const factors = [
    [
      "Privilege",
      principal.privilege,
      "Role policies and permissions boundary",
    ],
    ["Trust", principal.trust, "Trust policy principal and conditions"],
    [
      "Activity",
      principal.lastActivity,
      "Credential and access activity metadata",
    ],
    ["Authentication", principal.mfa, "Console and MFA configuration"],
    [
      "Evidence",
      principal.gap ? "Partial" : "High",
      principal.gap || "Source API evidence collected",
    ],
    [
      "Environment",
      accountFor(principal.account).environment,
      "Account inventory metadata",
    ],
  ];
  return (
    <div className="cs-page">
      <Link className="cs-back" to="/identities">
        <ArrowLeft size={14} />
        Identities
      </Link>
      <Head
        title={principal.name}
        meta={
          <>
            <Badge>{principal.risk}</Badge>
            <span>{principal.type}</span>
            <span>{accountFor(principal.account).name}</span>
            <span>Owner: {principal.owner}</span>
            <Badge>
              {principal.gap ? "Partial evaluation" : "Verified evidence"}
            </Badge>
          </>
        }
      >
        {asset && (
          <Link className="cs-button" to={`/inventory/${asset.id}`}>
            View resource
            <ArrowUpRight size={14} />
          </Link>
        )}
      </Head>
      <div className="cs-investigation-layout">
        <Panel>
          <Tabs
            items={[
              "Overview",
              "Permissions",
              "Trust",
              "Findings",
              "Evidence",
              "History",
            ]}
            value={tab}
            onChange={(value) => filters.set("tab", value)}
          />
          <div className="cs-panel-body">
            {tab === "Overview" && (
              <>
                <div className="cs-finding-why">
                  <span className="cs-eyebrow">IDENTITY RISK</span>
                  <h2>
                    {principal.privilege} with {principal.trust.toLowerCase()}
                  </h2>
                  <p>
                    Prioritize trust relationships, policy grants, and routes to
                    sensitive resources. Identity policy grants remain
                    candidates until every authorization layer is evaluated.
                  </p>
                </div>
                <h3>Risk factors</h3>
                <div className="cs-factor-grid">
                  {factors.map(([label, value, reason]) => (
                    <button
                      key={label}
                      onClick={() => filters.set("tab", "Evidence")}
                    >
                      <span>{label}</span>
                      <strong>{value}</strong>
                      <small>
                        {reason}
                        <ArrowUpRight size={12} />
                      </small>
                    </button>
                  ))}
                </div>
                {path && (
                  <>
                    <h3>Related attack path</h3>
                    <div className="cs-link-cards">
                      <Link to={`/attack-paths/${path.id}`}>
                        <Network size={20} />
                        <span>
                          <strong>{path.name}</strong>
                          <small>
                            {path.nodes.length} evidence-backed hops
                          </small>
                        </span>
                        <ArrowRight size={15} />
                      </Link>
                    </div>
                  </>
                )}
              </>
            )}
            {tab === "Permissions" && (
              <>
                <Notice kind="blue">
                  Grant is not the same as effective access. Permissions
                  boundaries, resource policies, SCPs, and session policies can
                  narrow an identity grant.
                </Notice>
                <Details
                  rows={[
                    ["Principal", principal.name],
                    ["Policy source", principal.evidence],
                    ["Observed access", <code>{principal.access}</code>],
                    ["Privilege assessment", principal.privilege],
                    [
                      "Permissions boundary",
                      principal.id === "id-prod-app"
                        ? "No restricting boundary observed"
                        : "Boundary evaluation pending",
                    ],
                    [
                      "Authorization completeness",
                      principal.gap
                        ? "Partial"
                        : "Collected identity and role policy evidence",
                    ],
                  ]}
                />
              </>
            )}
            {tab === "Trust" && (
              <>
                <Details
                  rows={[
                    [
                      "Trust classification",
                      <IdentityBadge value={principal.trust} />,
                    ],
                    ["Identity source", principal.source],
                    [
                      "Trusted principal",
                      principal.trust === "External account"
                        ? "arn:aws:iam::999999999999:root"
                        : "Account-scoped AWS principal",
                    ],
                    [
                      "Condition evidence",
                      principal.trust === "External account"
                        ? "Audience and ExternalId review required"
                        : "No external trust condition required",
                    ],
                    [
                      "Assessment",
                      principal.trust === "External account"
                        ? "Review ownership and least privilege"
                        : "No external trust observed",
                    ],
                  ]}
                />
              </>
            )}
            {tab === "Findings" &&
              (related.length ? (
                <Table
                  headers={["Finding", "Severity", "Status", "Last confirmed"]}
                >
                  {related.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <Link to={`/findings/${finding.id}`}>
                          {finding.title}
                        </Link>
                        <span className="cs-cell-sub">
                          {finding.id} · {finding.policy}
                        </span>
                      </td>
                      <td>
                        <Badge>{finding.severity}</Badge>
                      </td>
                      <td>
                        <Badge>{finding.status}</Badge>
                      </td>
                      <td>Sep 6, 08:48 UTC</td>
                    </tr>
                  ))}
                </Table>
              ) : (
                <Empty
                  title="No identity findings"
                  text="No active finding is associated with this principal in the current demo evidence."
                />
              ))}
            {tab === "Evidence" && (
              <>
                <Details
                  rows={[
                    ["Source", <code>{principal.evidence}</code>],
                    ["Observed value", <code>{principal.access}</code>],
                    ["Collection time", "Sep 6, 2026 · 08:48 UTC"],
                    ["Policy version", "AWS identity pack · v2.4.1"],
                    ["Confidence", principal.gap ? "Partial" : "High · 96%"],
                    [
                      "Freshness",
                      <Badge>
                        {accountFor(principal.account).health === "Stale"
                          ? "Stale"
                          : "Verified"}
                      </Badge>,
                    ],
                    ["Account", accountFor(principal.account).number],
                    ["Region", "Global"],
                  ]}
                />
                <div className="cs-code-block">
                  <span>Normalized identity evidence</span>
                  <pre>
                    {JSON.stringify(
                      {
                        principal: principal.name,
                        type: principal.type,
                        source: principal.evidence,
                        trust: principal.trust,
                        observed_access: principal.access,
                        collected_at: "2026-09-06T08:48:00Z",
                        authorization_state: principal.gap
                          ? "partial"
                          : "evaluated",
                      },
                      null,
                      2,
                    )}
                  </pre>
                </div>
              </>
            )}
            {tab === "History" && (
              <div className="cs-timeline">
                <div>
                  <span />
                  <strong>Identity evaluated</strong>
                  <p>Sep 6, 08:50 UTC · AWS identity policy pack v2.4.1</p>
                </div>
                <div>
                  <span />
                  <strong>Source evidence collected</strong>
                  <p>Sep 6, 08:48 UTC · {principal.evidence}</p>
                </div>
                <div>
                  <span />
                  <strong>Principal discovered</strong>
                  <p>Aug 18, 10:14 UTC · AWS inventory collector</p>
                </div>
              </div>
            )}
          </div>
        </Panel>
        <div className="cs-detail-rail">
          <Panel title="Identity context">
            <div className="cs-panel-body">
              <div className="cs-risk-score">
                <strong>{principal.score}</strong>
                <span>
                  /100
                  <br />
                  Contextual risk
                </span>
              </div>
              <Details
                rows={[
                  [
                    "Account",
                    <Link to={`/accounts/${principal.account}`}>
                      {accountFor(principal.account).name}
                    </Link>,
                  ],
                  ["Owner", principal.owner],
                  ["MFA", principal.mfa],
                  ["Last activity", principal.lastActivity],
                  ["Related findings", related.length],
                  ["Attack paths", path ? 1 : 0],
                ]}
              />
            </div>
          </Panel>
          {canAct && (
            <Panel title="Review actions">
              <div className="cs-rail-actions">
                <Link to={`/findings?asset=${principal.asset}`}>
                  <ShieldAlert size={15} />
                  Investigate findings
                  <ChevronRight size={13} />
                </Link>
                <Link to="/remediation">
                  <CheckCircle2 size={15} />
                  Review access changes
                  <ChevronRight size={13} />
                </Link>
                <Link to="/exceptions">
                  <CircleAlert size={15} />
                  Request exception
                  <ChevronRight size={13} />
                </Link>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
