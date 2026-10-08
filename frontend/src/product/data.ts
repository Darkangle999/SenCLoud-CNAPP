export type Severity = "Critical" | "High" | "Medium" | "Low";
export type FindingStatus =
  | "Open"
  | "In Progress"
  | "Pending Verification"
  | "Verified Resolved"
  | "Reopened"
  | "Accepted Risk"
  | "Suppressed";
export type EvidenceState = "Verified" | "Inferred" | "Stale" | "Missing";
export type SecurityService = "CSPM" | "DSPM" | "CIEM" | "CWPP";
export interface Account {
  id: string;
  name: string;
  number: string;
  environment: string;
  health: string;
  coverage: number;
  regions: string[];
}
export interface Tenant {
  id: string;
  name: string;
  initials: string;
  plan: string;
  services: SecurityService[];
  accountIds: string[];
}
export interface Asset {
  id: string;
  name: string;
  type: string;
  service: string;
  category: string;
  account: string;
  region: string;
  exposure: string;
  risk: Severity;
  owner: string;
  arn: string;
  sensitivity: string;
}
export interface Finding {
  id: string;
  title: string;
  asset: string;
  policy: string;
  severity: Severity;
  vendor: Severity;
  status: FindingStatus;
  owner: string;
  score: number;
  observed: string;
  required: string;
  source: string;
  fix: string;
}
export interface AttackPath {
  id: string;
  name: string;
  account: string;
  target: string;
  severity: Severity;
  score: number;
  confidence: number;
  state: EvidenceState;
  nodes: {
    name: string;
    type: string;
    relationship: string;
    observed: string;
    state: EvidenceState;
  }[];
}
export const observedAt = "2026-09-06T08:48:00Z";
export const accounts: Account[] = [
  {
    id: "production",
    name: "Production",
    number: "111111111111",
    environment: "Production",
    health: "Healthy",
    coverage: 100,
    regions: ["ap-south-1", "us-east-1", "eu-west-1"],
  },
  {
    id: "development",
    name: "Development",
    number: "222222222222",
    environment: "Development",
    health: "Degraded",
    coverage: 76,
    regions: ["ap-south-1", "us-east-1"],
  },
  {
    id: "security",
    name: "Security",
    number: "333333333333",
    environment: "Production",
    health: "Healthy",
    coverage: 100,
    regions: ["ap-south-1", "us-east-1"],
  },
  {
    id: "shared-services",
    name: "Shared Services",
    number: "444444444444",
    environment: "Production",
    health: "Stale",
    coverage: 88,
    regions: ["ap-south-1", "eu-west-1"],
  },
  {
    id: "retail-production",
    name: "Retail Production",
    number: "555555555555",
    environment: "Production",
    health: "Healthy",
    coverage: 96,
    regions: ["us-east-1", "us-west-2"],
  },
  {
    id: "retail-development",
    name: "Retail Development",
    number: "666666666666",
    environment: "Development",
    health: "Degraded",
    coverage: 81,
    regions: ["us-east-1", "us-west-2"],
  },
  {
    id: "finance-production",
    name: "Finance Production",
    number: "777777777777",
    environment: "Production",
    health: "Healthy",
    coverage: 100,
    regions: ["eu-west-1", "eu-central-1"],
  },
  {
    id: "finance-security",
    name: "Finance Security",
    number: "888888888888",
    environment: "Production",
    health: "Stale",
    coverage: 89,
    regions: ["eu-west-1", "eu-central-1"],
  },
];
export const tenants: Tenant[] = [
  {
    id: "acme",
    name: "Acme Corporation",
    initials: "AC",
    plan: "Enterprise CNAPP",
    services: ["CSPM", "DSPM", "CIEM", "CWPP"],
    accountIds: ["production", "security"],
  },
  {
    id: "northstar",
    name: "Northstar Health",
    initials: "NH",
    plan: "CSPM + DSPM + CIEM",
    services: ["CSPM", "DSPM", "CIEM"],
    accountIds: ["development", "shared-services"],
  },
  {
    id: "meridian",
    name: "Meridian Retail",
    initials: "MR",
    plan: "CSPM + CWPP",
    services: ["CSPM", "CWPP"],
    accountIds: ["retail-production", "retail-development"],
  },
  {
    id: "atlas",
    name: "Atlas Finance",
    initials: "AF",
    plan: "DSPM + CIEM",
    services: ["DSPM", "CIEM"],
    accountIds: ["finance-production", "finance-security"],
  },
];
export const tenantForAccount = (accountId: string) =>
  tenants.find((tenant) => tenant.accountIds.includes(accountId));
const resources = [
  ["customer-data", "S3 bucket", "S3", "Data", "Platform Team"],
  ["payments-api", "EC2 instance", "EC2", "Compute", "Payments Team"],
  ["web-ingress", "Security group", "VPC", "Network", "Platform Team"],
  ["analytics-db", "RDS instance", "RDS", "Data", "Data Engineering"],
  ["application-role", "IAM role", "IAM", "Identity", "Platform Team"],
  ["public-gateway", "Load balancer", "ELB", "Network", "Platform Team"],
  [
    "organization-trail",
    "CloudTrail trail",
    "CloudTrail",
    "Management",
    "Security Team",
  ],
  ["private-network", "VPC", "VPC", "Network", "Platform Team"],
  ["worker-service", "ECS service", "ECS", "Compute", "Payments Team"],
  ["audit-archive", "S3 bucket", "S3", "Data", "Security Team"],
  ["api-function", "Lambda function", "Lambda", "Compute", "Platform Team"],
  [
    "threat-detector",
    "GuardDuty detector",
    "GuardDuty",
    "Security",
    "Security Team",
  ],
];
export const assets: Asset[] = accounts.flatMap((account, ai) =>
  resources.map(([name, type, service, category, owner], i) => {
    const suffix =
      ["prod", "dev", "security", "shared", "retail-prod", "retail-dev", "finance-prod", "finance-sec"][ai] ||
      account.id.replace(/[^a-z0-9]+/g, "-");
    const resourceName = `${name}-${suffix}`;
    // Keep each account's investigation scenario together in its primary region.
    // The archive and serverless application retain secondary-region inventory.
    const region =
      i === 9 || i === 10
        ? account.regions[1 + ((i - 9) % (account.regions.length - 1))]
        : account.regions[0];
    const nativeId =
      service === "EC2"
        ? `i-0a7d91c3e${ai}8246b0${i}`
        : service === "IAM"
          ? `role/${resourceName}`
          : `${service === "RDS" ? "db:" : ""}${resourceName}`;
    return {
      id: `${account.id}-${i}`,
      name: resourceName,
      type,
      service,
      category,
      account: account.id,
      region: service === "IAM" ? "Global" : region,
      exposure:
        i === 0 || i === 1 || i === 5
          ? "Public"
          : account.health === "Degraded" && i === 3
            ? "Unknown"
            : "Private",
      risk: (i < 2 && ai === 0
        ? "Critical"
        : i < 5
          ? "High"
          : i < 8
            ? "Medium"
            : "Low") as Severity,
      owner,
      arn:
        service === "S3"
          ? `arn:aws:s3:::${resourceName}`
          : `arn:aws:${service.toLowerCase()}:${service === "IAM" ? "" : region}:${account.number}:${nativeId}`,
      sensitivity:
        i === 0
          ? "Sensitive · PII"
          : i === 3
            ? "Confidential"
            : "Not classified",
    };
  }),
);
const templates = [
  [
    "Public S3 bucket allows public access",
    "CS-S3-001",
    "BlockPublicPolicy = false; Principal = *; s3:GetObject allowed",
    "All four S3 Block Public Access settings = true",
    "s3:GetPublicAccessBlock + s3:GetBucketPolicyStatus",
    "Enable all four Block Public Access settings after validating public consumers.",
  ],
  [
    "Internet-facing workload has excessive privileges",
    "CS-EC2-014",
    "Ingress TCP/443 reachable; instance profile permits s3:*",
    "Restrict role permissions to the application resource scope",
    "ec2:DescribeInstances + iam:GetRolePolicy",
    "Replace wildcard role permissions with the minimum required resource actions.",
  ],
  [
    "Security group permits unrestricted SSH",
    "CS-VPC-003",
    "TCP/22 ingress from 0.0.0.0/0",
    "SSH ingress restricted to approved administration CIDRs",
    "ec2:DescribeSecurityGroups",
    "Remove unrestricted SSH ingress after confirming an approved management path.",
  ],
  [
    "Database encryption is not enabled",
    "CS-RDS-008",
    "StorageEncrypted = false",
    "StorageEncrypted = true",
    "rds:DescribeDBInstances",
    "Create an encrypted snapshot copy and restore to a new database; validate before cutover.",
  ],
  [
    "IAM role permits wildcard resource access",
    "CS-IAM-012",
    "Action = s3:*; Resource = *",
    "Action and resource restricted to business requirements",
    "iam:GetRolePolicy",
    "Scope role permissions to approved buckets and required actions.",
  ],
  [
    "Load balancer does not redirect HTTP to HTTPS",
    "CS-ELB-005",
    "HTTP/80 listener forwards requests",
    "HTTP/80 listener redirects to HTTPS/443",
    "elasticloadbalancing:DescribeListeners",
    "Configure the HTTP listener to redirect to the existing HTTPS listener.",
  ],
  [
    "CloudTrail log validation is disabled",
    "CS-CT-002",
    "LogFileValidationEnabled = false",
    "LogFileValidationEnabled = true",
    "cloudtrail:DescribeTrails",
    "Enable log file validation on the organization trail.",
  ],
  [
    "VPC flow logging is not configured",
    "CS-VPC-009",
    "No active VPC flow logs found",
    "Flow logs enabled for accepted and rejected traffic",
    "ec2:DescribeFlowLogs",
    "Create a VPC flow log with an approved destination and retention period.",
  ],
];
export const initialFindings: Finding[] = accounts.flatMap((account, ai) =>
  templates.map(([title, policy, observed, required, source, fix], i) => ({
    id: `CS-${1041 + ai * 8 + i}`,
    title,
    asset: `${account.id}-${i}`,
    policy,
    severity: (i < 2 && ai < 2
      ? "Critical"
      : i < 5
        ? "High"
        : i === 7
          ? "Low"
          : "Medium") as Severity,
    vendor: (i < 5 ? "High" : i === 7 ? "Low" : "Medium") as Severity,
    status:
      ai === 3 && i > 5
        ? "Pending Verification"
        : ai === 2 && i > 5
          ? "Verified Resolved"
          : ai === 0 && i === 2
            ? "Accepted Risk"
            : "Open",
    owner: assets.find((a) => a.id === `${account.id}-${i}`)!.owner,
    score: i < 2 && ai < 2 ? 98 - i * 3 : i < 5 ? 86 - i * 3 : 48 - i * 2,
    observed,
    required,
    source,
    fix,
  })),
);
const ingressAttackPaths: AttackPath[] = accounts
  .filter((_, index) => [0, 1, 2, 4, 6].includes(index))
  .map((account, i) => ({
    id: `AP-00${i + 1}`,
    name:
      i === 1
        ? "Unverified ingress to customer data"
        : "Public workload can access sensitive data",
    account: account.id,
    target: `${account.id}-0`,
    severity: i === 2 ? "High" : "Critical",
    score: i === 0 ? 98 : i === 1 ? 91 : 84,
    confidence: i === 1 ? 64 : 98,
    state: i === 1 ? "Missing" : "Verified",
    nodes: [
      {
        name: "Internet",
        type: "External",
        relationship: "HTTPS · TCP/443",
        observed: "Internet gateway attached; default route present",
        state: "Verified",
      },
      {
        name:
          assets.find(
            (asset) => asset.account === account.id && asset.service === "ELB",
          )?.name || `${account.id}-gateway`,
        type: "Load balancer",
        relationship: "Routes to target group",
        observed: "Public listener forwards to payments target group",
        state: "Verified",
      },
      {
        name:
          assets.find(
            (asset) =>
              asset.account === account.id && asset.type === "Security group",
          )?.name || `${account.id}-ingress`,
        type: "Security group",
        relationship: "Allows ingress · TCP/443",
        observed:
          i === 1
            ? "Network ACL collection denied; reachability unverified"
            : "Security group, route table, IGW, and NACL permit traffic",
        state: i === 1 ? "Missing" : "Verified",
      },
      {
        name:
          assets.find(
            (asset) => asset.account === account.id && asset.service === "EC2",
          )?.name || `${account.id}-compute`,
        type: "EC2 instance",
        relationship: "Instance profile attachment",
        observed:
          "Running instance associated with application instance profile",
        state: "Verified",
      },
      {
        name:
          assets.find(
            (asset) => asset.account === account.id && asset.service === "IAM",
          )?.name || `${account.id}-role`,
        type: "IAM role",
        relationship: "Allows s3:GetObject",
        observed:
          "Effective role and resource policies allow access; no explicit deny observed",
        state: "Verified",
      },
      {
        name: assets.find((a) => a.id === `${account.id}-0`)!.name,
        type: "Sensitive S3",
        relationship: "Target · PII",
        observed: "Sample classification: personal data; values redacted",
        state: "Verified",
      },
    ],
  }));
export const attackPaths: AttackPath[] = [
  ...ingressAttackPaths,
  ...accounts.flatMap<AttackPath>((account, index) => {
    const bucket = assets.find((asset) => asset.id === `${account.id}-0`)!;
    const role = assets.find((asset) => asset.id === `${account.id}-4`)!;
    const publicFinding = initialFindings.find(
      (finding) => finding.asset === bucket.id,
    )!;
    const accessFinding = initialFindings.find(
      (finding) => finding.asset === role.id,
    )!;
    const dataTarget: AttackPath["nodes"][number] = {
      name: bucket.name,
      type: "Sensitive S3",
      relationship: "Target · PII",
      observed: "Sample classification: personal data; values redacted",
      state: "Verified",
    };
    return [
      {
        id: `AP-${String(6 + index * 2).padStart(3, "0")}`,
        name: "Public bucket exposes sensitive data",
        account: account.id,
        target: bucket.id,
        severity: publicFinding.severity,
        score: publicFinding.score,
        confidence: 98,
        state: "Verified",
        nodes: [
          {
            name: "Internet",
            type: "External",
            relationship: "Anonymous s3:GetObject",
            observed: publicFinding.observed,
            state: "Verified",
          },
          dataTarget,
        ],
      },
      {
        id: `AP-${String(7 + index * 2).padStart(3, "0")}`,
        name: "Overprivileged role can access sensitive data",
        account: account.id,
        target: bucket.id,
        severity: accessFinding.severity,
        score: accessFinding.score,
        confidence: 98,
        state: "Verified",
        nodes: [
          {
            name: role.name,
            type: role.type,
            relationship: "Allows s3:GetObject",
            observed:
              `${accessFinding.observed}; effective role and resource policies allow access; no explicit deny observed`,
            state: "Verified",
          },
          dataTarget,
        ],
      },
    ];
  }),
];
export const frameworks = [
  {
    id: "cis",
    name: "CIS AWS Foundations",
    version: "v3.0",
    score: 82,
    passed: 49,
    failed: 8,
    unknown: 2,
    uncovered: 1,
  },
  {
    id: "nist",
    name: "NIST CSF",
    version: "v2.0",
    score: 76,
    passed: 38,
    failed: 9,
    unknown: 2,
    uncovered: 1,
  },
  {
    id: "pci",
    name: "PCI DSS",
    version: "v4.0.1",
    score: 79,
    passed: 38,
    failed: 7,
    unknown: 2,
    uncovered: 1,
  },
  {
    id: "soc2",
    name: "SOC 2",
    version: "Trust Services",
    score: 88,
    passed: 44,
    failed: 4,
    unknown: 1,
    uncovered: 1,
  },
  {
    id: "iso",
    name: "ISO 27001",
    version: "2022",
    score: 81,
    passed: 42,
    failed: 7,
    unknown: 2,
    uncovered: 1,
  },
];
export const isActive = (f: Finding) =>
  !["Verified Resolved", "Suppressed"].includes(f.status);
export const assetFor = (finding: Finding) =>
  assets.find((a) => a.id === finding.asset)!;
export const accountFor = (id: string) => accounts.find((a) => a.id === id)!;
