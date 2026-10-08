import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  ChevronRight,
  Database,
  Download,
  ExternalLink,
  FileText,
  GitBranch,
  Globe2,
  Layers,
  LockKeyhole,
  Network,
  Plus,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  Wrench,
} from "lucide-react";
import {
  accounts,
  accountFor,
  assets,
  assetFor,
  attackPaths,
  isActive,
  observedAt,
  type Asset,
  type Finding,
} from "./data";
import { useProduct } from "./store";
import { serviceAllowsAsset } from "./services";
import { AwsResourceIcon } from "./AwsResourceIcon";
import {
  Badge,
  Details,
  Empty,
  Field,
  Filters,
  Head,
  Jump,
  Notice,
  Overlay,
  Panel,
  Table,
  Tabs,
  download,
  useFilters,
} from "./ui";

const owners = [
  "Platform Team",
  "Payments Team",
  "Data Engineering",
  "Security Team",
];
const severities = ["Critical", "High", "Medium", "Low"];
function Resource({
  asset,
  linked = true,
}: {
  asset: Asset;
  linked?: boolean;
}) {
  const content = (
    <>
      <span className={`cs-resource-icon ${asset.category.toLowerCase()}`}>
        <AwsResourceIcon service={asset.service} type={asset.type} size={18} />
      </span>
      <span>
        <strong>{asset.name}</strong>
        <small>{asset.type}</small>
      </span>
    </>
  );
  return linked ? (
    <Link className="cs-resource" to={`/inventory/${asset.id}`}>
      {content}
    </Link>
  ) : (
    <span className="cs-resource">{content}</span>
  );
}
export function FindingTable({ findings }: { findings: Finding[] }) {
  return (
    <Table
      headers={[
        "Priority",
        "Finding",
        "Affected asset",
        "Severity",
        "Exposure",
        "Owner",
        "Status",
        "Last confirmed",
      ]}
      count={findings.length}
      empty={!findings.length}
    >
      {findings.map((f) => {
        const asset = assetFor(f);
        return (
          <tr key={f.id}>
            <td>
              <span className={`cs-priority ${f.severity.toLowerCase()}`}>
                {f.score}
              </span>
            </td>
            <td>
              <Link className="cs-finding-title" to={`/findings/${f.id}`}>
                {f.title}
                <ArrowUpRight size={12} />
              </Link>
              <Link className="cs-cell-sub" to={`/policies/${f.policy}`}>
                {f.id} · {f.policy}
              </Link>
            </td>
            <td>
              <Resource asset={asset} />
            </td>
            <td>
              <Badge>{f.severity}</Badge>
            </td>
            <td>
              <Badge>{asset.exposure}</Badge>
            </td>
            <td>
              <span className="cs-owner">
                <UserRound size={13} />
                {f.owner}
              </span>
            </td>
            <td>
              <Badge>{f.status}</Badge>
            </td>
            <td>
              <span className="cs-cell-time">Sep 6, 08:48 UTC</span>
            </td>
          </tr>
        );
      })}
    </Table>
  );
}
export function Findings() {
  const { workspace, inScope, tenantAccounts, service, subscribedServices } = useProduct();
  const filters = useFilters();
  const { params, set } = filters;
  const tab = params.get("tab") || "Active Threats";
  const scoped = workspace.findings.filter((f) =>
    inScope(assetFor(f).account, assetFor(f).region) &&
      serviceAllowsAsset(service, assetFor(f), subscribedServices),
  );
  const rows = scoped.filter((f) => {
    const a = assetFor(f);
    return (
      (tab === "All Signals" || isActive(f)) &&
      (tab !== "Network Hygiene" || a.category === "Network") &&
      ["severity", "status", "owner", "policy"].every(
        (key) =>
          !params.get(key) ||
          params
            .get(key)!
            .split(",")
            .includes(String(f[key as keyof Finding])),
      ) &&
      (!params.get("account") ||
        accountFor(a.account).name === params.get("account")) &&
      (!params.get("region") || a.region === params.get("region")) &&
      (!params.get("service") || a.service === params.get("service")) &&
      (!params.get("priority") ||
        (params.get("priority") === "90–100" ? f.score >= 90 : f.score < 90)) &&
      (!params.get("asset") || f.asset === params.get("asset")) &&
      `${f.title} ${f.id} ${f.policy} ${a.name} ${a.arn}`
        .toLowerCase()
        .includes((params.get("q") || "").toLowerCase())
    );
  });
  return (
    <div className="cs-page">
      <Head title="Findings">
        <button
          className="cs-button"
          onClick={() =>
            download(
              "cloudsentinel-findings",
              rows.map((f) => ({
                ...f,
                account: assetFor(f).account,
                evidence_observed: observedAt,
                data_mode: "demo",
                coverage_limitation:
                  "Development degraded; Shared Services stale",
              })),
              "csv",
            )
          }
        >
          <Download size={15} />
          Export findings
        </button>
      </Head>
      <div className="cs-summary-row">
        {[
          ...severities,
          "Open",
          "Verified Resolved",
          "Accepted Risk",
          "Suppressed",
        ].map((s, i) => (
          <button
            key={s}
            className={
              params.get(i < 4 ? "severity" : "status") === s ? "active" : ""
            }
            onClick={() => {
              set(i < 4 ? "severity" : "status", s);
              if (i >= 4) set("tab", "All Signals");
            }}
          >
            <span>{s}</span>
            <strong>
              {
                scoped.filter((f) =>
                  i < 4 ? f.severity === s && isActive(f) : f.status === s,
                ).length
              }
            </strong>
          </button>
        ))}
      </div>
      <Panel>
        <Tabs
          items={
            service === "CNAPP" || service === "CSPM"
              ? ["Active Threats", "Network Hygiene", "All Signals"]
              : ["Active Threats", "All Signals"]
          }
          value={tab}
          onChange={(v) => set("tab", v)}
        />
        <Filters
          filters={filters}
          placeholder="Search findings, assets, policy IDs..."
          fields={{
            severity: severities,
            priority: ["90–100", "Below 90"],
            status: [
              "Open",
              "In Progress",
              "Pending Verification",
              "Verified Resolved",
              "Reopened",
              "Accepted Risk",
              "Suppressed",
            ],
            policy: [...new Set(scoped.map((f) => f.policy))],
            account: tenantAccounts.map((a) => a.name),
            region: ["ap-south-1", "us-east-1", "eu-west-1", "Global"],
            service: [...new Set(scoped.map((f) => assetFor(f).service))],
            owner: owners,
          }}
        />
        <FindingTable findings={rows} />
      </Panel>
    </div>
  );
}
export function Inventory() {
  const { inScope, tenantAccounts, service, subscribedServices } = useProduct();
  const filters = useFilters();
  const { params, set } = filters;
  const [selected, select] = useState<Asset | null>(null);
  const tab = params.get("tab") || "All";
  const scoped = assets.filter(
    (a) =>
      inScope(a.account, a.region) &&
      serviceAllowsAsset(service, a, subscribedServices),
  );
  const rows = scoped.filter(
    (a) =>
      (tab === "All" || a.category === tab) &&
      ["region", "service", "exposure", "risk", "owner"].every(
        (k) =>
          !params.get(k) ||
          params
            .get(k)!
            .split(",")
            .includes(a[k as keyof Asset]),
      ) &&
      (!params.get("account") ||
        accountFor(a.account).name === params.get("account")) &&
      (!params.get("environment") ||
        accountFor(a.account).environment === params.get("environment")) &&
      `${a.name} ${a.arn} ${a.id}`
        .toLowerCase()
        .includes((params.get("q") || "").toLowerCase()),
  );
  return (
    <div className="cs-page">
      <Head title="Cloud Inventory">
        <button
          className="cs-button"
          onClick={() =>
            download(
              "cloudsentinel-inventory",
              rows.map((a) => ({
                ...a,
                observed_at: observedAt,
                source: "Demo evidence snapshot",
              })),
              "csv",
            )
          }
        >
          <Download size={15} />
          Export inventory
        </button>
      </Head>
      <div className="cs-summary-row">
        {[
          ["Total assets", scoped.length, ""],
          [
            "Public",
            scoped.filter((a) => a.exposure === "Public").length,
            "Public",
          ],
          [
            "Private",
            scoped.filter((a) => a.exposure === "Private").length,
            "Private",
          ],
          [
            "Unknown",
            scoped.filter((a) => a.exposure === "Unknown").length,
            "Unknown",
          ],
          [
            "High risk",
            scoped.filter((a) => ["Critical", "High"].includes(a.risk)).length,
            "High",
          ],
        ].map(([label, value, filter]) => (
          <button
            key={label}
            onClick={() =>
              set(
                filter === "High" ? "risk" : "exposure",
                filter === "High" ? "Critical,High" : String(filter),
              )
            }
          >
            <span>{label}</span>
            <strong>{value}</strong>
          </button>
        ))}
      </div>
      <Panel>
        <Tabs
          items={
            service === "DSPM"
              ? ["All", "Data"]
              : service === "CIEM"
                ? ["All", "Identity"]
                : service === "CWPP"
                  ? ["All", "Compute"]
                  : [
                      "All",
                      "Network",
                      "Data",
                      "Compute",
                      "Identity",
                      "Security",
                      "Management",
                      "Other",
                    ]
          }
          value={tab}
          onChange={(v) => set("tab", v)}
        />
        <Filters
          filters={filters}
          placeholder="Search resource name, ARN, native ID..."
          fields={{
            account: tenantAccounts.map((a) => a.name),
            region: ["ap-south-1", "us-east-1", "eu-west-1", "Global"],
            service: [...new Set(scoped.map((a) => a.service))],
            exposure: ["Public", "Private", "Unknown"],
            risk: severities,
            owner: owners,
            environment: ["Production", "Development"],
          }}
        />
        <Table
          headers={[
            "Resource",
            "Service",
            "Account",
            "Region",
            "Exposure",
            "Risk",
            "Owner",
            "Last seen",
            "",
          ]}
          count={rows.length}
          empty={!rows.length}
        >
          {rows.map((a) => (
            <tr
              key={a.id}
              onClick={(e) => {
                if (!(e.target as HTMLElement).closest("a,button")) select(a);
              }}
            >
              <td>
                <button
                  className="cs-resource-button"
                  onClick={() => select(a)}
                >
                  <Resource asset={a} linked={false} />
                </button>
              </td>
              <td>{a.service}</td>
              <td>
                <Link to={`/accounts/${a.account}`}>
                  {accountFor(a.account).name}
                </Link>
              </td>
              <td className="cs-mono">{a.region}</td>
              <td>
                <Badge>{a.exposure}</Badge>
              </td>
              <td>
                <Badge>{a.risk}</Badge>
              </td>
              <td>{a.owner}</td>
              <td>
                <Badge
                  kind={
                    accountFor(a.account).health === "Stale"
                      ? "Stale"
                      : "Verified"
                  }
                >
                  {accountFor(a.account).health === "Stale"
                    ? "2 days ago"
                    : "12 min ago"}
                </Badge>
              </td>
              <td>
                <button
                  className="cs-icon"
                  aria-label={`Inspect ${a.name}`}
                  onClick={() => select(a)}
                >
                  <ChevronRight size={16} />
                </button>
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {selected && (
        <Overlay drawer title={selected.name} onClose={() => select(null)}>
          <div className="cs-inline">
            <Badge>{selected.risk}</Badge>
            <Badge>{selected.exposure}</Badge>
          </div>
          <AssetOverview asset={selected} />
          <Link
            className="cs-button primary"
            to={`/inventory/${selected.id}?return=${encodeURIComponent("/inventory?" + params.toString())}`}
          >
            <ExternalLink size={15} />
            Open full details
          </Link>
        </Overlay>
      )}
    </div>
  );
}
function AssetOverview({ asset }: { asset: Asset }) {
  return (
    <>
      <Details
        rows={[
          ["Service", `AWS ${asset.service}`],
          [
            "Account",
            <Link to={`/accounts/${asset.account}`}>
              {accountFor(asset.account).name}
            </Link>,
          ],
          ["Region", asset.region],
          ["Owner", asset.owner],
          [
            "Business criticality",
            accountFor(asset.account).environment === "Production"
              ? "Business critical"
              : "Non-production",
          ],
          ["Data sensitivity", asset.sensitivity],
          [
            "Network reachability",
            <Badge>
              {asset.exposure === "Unknown"
                ? "Unverified"
                : asset.exposure === "Public"
                  ? "Reachable"
                  : "Blocked"}
            </Badge>,
          ],
          [
            "Last observed",
            accountFor(asset.account).health === "Stale"
              ? "Sep 4, 2026 · 08:48 UTC"
              : "Sep 6, 2026 · 08:48 UTC",
          ],
          ["Last evaluated", "Sep 6, 2026 · 08:50 UTC"],
        ]}
      />
      <div className="cs-code-block">
        <span>Resource ARN</span>
        <code>{asset.arn}</code>
      </div>
    </>
  );
}
export function AssetDetail() {
  const { assetId } = useParams();
  const { workspace, inScope, service, subscribedServices } = useProduct();
  const { params, set } = useFilters();
  const asset = assets.find((a) =>
    a.id === assetId &&
      inScope(a.account, a.region) &&
      serviceAllowsAsset(service, a, subscribedServices),
  );
  if (!asset)
    return (
      <Empty
        title="Asset unavailable in current scope"
        text="Select its connected account or return to inventory."
      />
    );
  const related = workspace.findings.filter((f) => f.asset === asset.id);
  const tab = params.get("tab") || "Overview";
  const path = attackPaths.find((p) => p.account === asset.account);
  const back = params.get("return")?.startsWith("/inventory?")
    ? params.get("return")!
    : "/inventory";
  return (
    <div className="cs-page">
      <Link className="cs-back" to={back}>
        <ArrowLeft size={14} />
        Inventory
      </Link>
      <Head
        title={asset.name}
        meta={
          <>
            <Badge>{asset.risk} Risk</Badge>
            <span>AWS {asset.service}</span>
            <span>{accountFor(asset.account).name}</span>
            <span>{asset.region}</span>
            <span>Owner: {asset.owner}</span>
          </>
        }
      >
        <Link className="cs-button" to={`/findings?asset=${asset.id}`}>
          Related findings
          <ArrowUpRight size={14} />
        </Link>
      </Head>
      <Panel>
        <Tabs
          items={[
            "Overview",
            "Configuration",
            "Findings",
            "Relationships",
            "Evidence",
            "History",
          ]}
          value={tab}
          onChange={(v) => set("tab", v)}
        />
        <div className="cs-panel-body">
          {tab === "Overview" && (
            <div className="cs-two-col">
              <div>
                <h3>Asset context</h3>
                <AssetOverview asset={asset} />
              </div>
              <div>
                <h3>Risk context</h3>
                <Notice kind={asset.exposure === "Unknown" ? "amber" : "blue"}>
                  {asset.exposure === "Unknown"
                    ? "Missing network evidence. This asset cannot be classified as reachable or blocked."
                    : `${asset.exposure} exposure · ${asset.sensitivity}. Evaluate permissions and related findings before taking action.`}
                </Notice>
                <FindingTable findings={related} />
                {path && (
                  <Jump to={`/attack-paths/${path.id}`}>
                    Investigate related attack path
                  </Jump>
                )}
              </div>
            </div>
          )}
          {tab === "Configuration" &&
            (related[0] ? (
              <StateComparison finding={related[0]} />
            ) : (
              <Notice kind="blue">
                No evaluated configuration gap for this resource in the current
                snapshot.
              </Notice>
            ))}
          {tab === "Findings" && <FindingTable findings={related} />}
          {tab === "Relationships" &&
            (path ? (
              <PathGraph pathId={path.id} />
            ) : (
              <Empty
                title="No modeled relationships"
                text="Relationship evidence is not available for this asset in the sample snapshot."
              />
            ))}
          {tab === "Evidence" &&
            (related[0] ? (
              <Evidence finding={related[0]} />
            ) : (
              <Details
                rows={[
                  "Source",
                  "Observed value",
                  "Collection time",
                  "Policy version",
                  "Confidence",
                  "Freshness",
                ].map((key, i) => [
                  key,
                  [
                    `AWS ${asset.service} inventory`,
                    asset.arn,
                    observedAt,
                    "Not Applicable",
                    "Inventory metadata only",
                    accountFor(asset.account).health,
                  ][i],
                ])}
              />
            ))}
          {tab === "History" && (
            <div className="cs-timeline">
              <div>
                <span />
                <strong>Configuration evaluated</strong>
                <p>Sep 6, 08:50 UTC · Policy pack v2.4.1</p>
              </div>
              <div>
                <span />
                <strong>Inventory evidence collected</strong>
                <p>Sep 6, 08:48 UTC · AWS collector</p>
              </div>
              <div>
                <span />
                <strong>Asset discovered</strong>
                <p>Aug 18, 10:14 UTC · {asset.arn}</p>
              </div>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
function StateComparison({ finding }: { finding: Finding }) {
  return (
    <div className="cs-state-comparison">
      <div>
        <span className="cs-eyebrow">OBSERVED STATE</span>
        <Badge kind="Fail">Configuration gap</Badge>
        <code>{finding.observed}</code>
      </div>
      <ArrowRight size={20} />
      <div>
        <span className="cs-eyebrow">REQUIRED STATE</span>
        <Badge kind="Healthy">Policy expectation</Badge>
        <code>{finding.required}</code>
      </div>
    </div>
  );
}
function Evidence({ finding }: { finding: Finding }) {
  const a = assetFor(finding);
  return (
    <>
      <StateComparison finding={finding} />
      <Details
        rows={[
          ["Source", <code>{finding.source}</code>],
          ["Collection time", observedAt],
          [
            "Policy version",
            <Link to={`/policies/${finding.policy}`}>
              {finding.policy} · v2.4.1
            </Link>,
          ],
          [
            "Account",
            `${accountFor(a.account).name} · ${accountFor(a.account).number}`,
          ],
          ["Region", a.region],
          [
            "Confidence",
            accountFor(a.account).health === "Degraded"
              ? "Partial · Network proof missing"
              : "98% · Source evidence available",
          ],
          [
            "Freshness",
            <Badge>
              {accountFor(a.account).health === "Stale" ? "Stale" : "Verified"}
            </Badge>,
          ],
          ["Source environment", "Demo snapshot · Not live cloud evidence"],
        ]}
      />
      <div className="cs-code-block">
        <span>Evidence record · EVD-{finding.id}</span>
        <pre>
          {JSON.stringify(
            {
              resource_arn: a.arn,
              observed: finding.observed,
              required: finding.required,
              collected_at: observedAt,
              policy_version: "2.4.1",
              source: finding.source,
              evidence_state:
                accountFor(a.account).health === "Stale" ? "stale" : "observed",
            },
            null,
            2,
          )}
        </pre>
      </div>
    </>
  );
}
export function FindingDetail() {
  const { findingId } = useParams();
  const { workspace, inScope, service, subscribedServices, canAct, update, notify, log } = useProduct();
  const { params, set } = useFilters();
  const navigate = useNavigate();
  const [modal, setModal] = useState("");
  const f = workspace.findings.find(
    (f) =>
      f.id === findingId &&
      inScope(assetFor(f).account, assetFor(f).region) &&
      serviceAllowsAsset(service, assetFor(f), subscribedServices),
  );
  if (!f)
    return (
      <Empty
        title="Finding unavailable in current scope"
        text="Check the finding ID and selected cloud account."
      />
    );
  const a = assetFor(f);
  const path = attackPaths.find((p) => p.account === a.account);
  const tab = params.get("tab") || "Overview";
  const start = () => {
    let task = workspace.remediations.find((r) => r.finding === f.id);
    if (!task) {
      task = {
        id: `REM-${Date.now().toString().slice(-6)}`,
        finding: f.id,
        status: "Review",
        created: new Date().toISOString(),
      };
      const newTask = task;
      update((s) => ({
        ...s,
        remediations: [...s.remediations, newTask],
        findings: s.findings.map((row) =>
          row.id === f.id ? { ...row, status: "In Progress" } : row,
        ),
      }));
      log("Remediation created", f.id, f.status, "Review");
    }
    navigate(`/remediation?task=${task.id}`);
  };
  return (
    <div className="cs-page">
      <Link className="cs-back" to="/findings">
        <ArrowLeft size={14} />
        Findings
      </Link>
      <Head
        title={f.title}
        meta={
          <>
            <Badge>{f.severity}</Badge>
            <span>{f.id}</span>
            <Badge>{f.status}</Badge>
            <span>Vendor severity: {f.vendor}</span>
            <span>Contextual priority: {f.severity}</span>
          </>
        }
      >
        {canAct && (
          <>
            <button className="cs-button" onClick={() => setModal("assign")}>
              <UserRound size={15} />
              Assign
            </button>
            <button className="cs-button primary" onClick={start}>
              <Wrench size={15} />
              Start remediation
            </button>
          </>
        )}
      </Head>
      <div className="cs-investigation-layout">
        <Panel>
          <Tabs
            items={[
              "Overview",
              "Evidence",
              "Attack Path",
              "Remediation",
              "History",
            ]}
            value={tab}
            onChange={(v) => set("tab", v)}
          />
          <div className="cs-panel-body">
            {tab === "Overview" && (
              <>
                <div className="cs-finding-why">
                  <span className="cs-eyebrow">WHY THIS MATTERS</span>
                  <h2>
                    {a.exposure === "Public"
                      ? "External exposure increases the impact of this configuration."
                      : "This configuration weakens your cloud security controls."}
                  </h2>
                  <p>
                    {f.observed}. {accountFor(a.account).name} hosts{" "}
                    {accountFor(a.account).environment === "Production"
                      ? "business-critical services"
                      : "development workloads"}
                    .{" "}
                    {a.sensitivity.includes("PII")
                      ? "Sensitive customer data raises the contextual priority above vendor severity."
                      : "Review effective access, asset ownership, and business dependencies."}
                  </p>
                </div>
                <h3>Risk factors</h3>
                <div className="cs-factor-grid">
                  {[
                    [
                      "Exposure",
                      a.exposure,
                      "Network and resource policy evidence",
                    ],
                    [
                      "Privilege",
                      f.policy.includes("IAM") || f.policy.includes("EC2")
                        ? "Elevated"
                        : "Resource access",
                      "Effective permissions evaluated",
                    ],
                    [
                      "Data sensitivity",
                      a.sensitivity,
                      "Classification evidence, values redacted",
                    ],
                    [
                      "Business criticality",
                      accountFor(a.account).environment === "Production"
                        ? "Critical service"
                        : "Development",
                      "Account and asset context",
                    ],
                    [
                      "Environment",
                      accountFor(a.account).environment,
                      "Account inventory metadata",
                    ],
                    [
                      "Confidence",
                      accountFor(a.account).health === "Degraded"
                        ? "Partial"
                        : "High · 98%",
                      "Collection completeness",
                    ],
                  ].map(([label, value, reason]) => (
                    <button key={label} onClick={() => set("tab", "Evidence")}>
                      <span>{label}</span>
                      <strong>{value}</strong>
                      <small>
                        {reason}
                        <ArrowUpRight size={12} />
                      </small>
                    </button>
                  ))}
                </div>
                <h3>Configuration evidence</h3>
                <StateComparison finding={f} />
                <Jump to={`/findings/${f.id}?tab=Evidence`}>
                  Inspect source evidence
                </Jump>
              </>
            )}
            {tab === "Evidence" && <Evidence finding={f} />}
            {tab === "Attack Path" &&
              (path ? (
                <>
                  <PathGraph pathId={path.id} />
                  <Jump to={`/attack-paths/${path.id}`}>
                    Open full investigation
                  </Jump>
                </>
              ) : (
                <Empty
                  title="No verified attack path"
                  text="This posture finding is not currently connected to an evidence-backed attack path."
                />
              ))}
            {tab === "Remediation" && (
              <>
                <h3>Recommended fix</h3>
                <p>{f.fix}</p>
                <Details
                  rows={[
                    [
                      "Expected risk reduction",
                      `Contextual score ${f.score} to an estimated ${Math.max(f.score - 60, 10)}; verify after change`,
                    ],
                    [
                      "Operational impact",
                      a.service === "RDS"
                        ? "Database cutover and downtime may be required"
                        : "Existing public or cross-account consumers may lose access",
                    ],
                    [
                      "Prerequisites",
                      "Confirm owner, dependencies, change window, and approved execution role",
                    ],
                    [
                      "Rollback",
                      "Restore the reviewed prior configuration through the approved change process",
                    ],
                    [
                      "Permissions",
                      "Scoped mutation permissions separate from the read-only collection role",
                    ],
                  ]}
                />
                {canAct && (
                  <button className="cs-button primary" onClick={start}>
                    Review remediation
                    <ArrowRight size={15} />
                  </button>
                )}
              </>
            )}
            {tab === "History" && (
              <div className="cs-timeline">
                {workspace.audit
                  .filter((event) => event.object === f.id)
                  .map((event) => (
                    <div key={event.id}>
                      <span />
                      <strong>{event.action}</strong>
                      <p>
                        {event.time} · {event.actor} · {event.next}
                      </p>
                    </div>
                  ))}
                <div>
                  <span />
                  <strong>Finding confirmed</strong>
                  <p>
                    {observedAt} · {f.policy} v2.4.1
                  </p>
                </div>
              </div>
            )}
          </div>
        </Panel>
        <div className="cs-detail-rail">
          <Panel title="Finding context">
            <div className="cs-panel-body">
              <div className="cs-risk-score">
                <strong>{f.score}</strong>
                <span>
                  /100
                  <br />
                  Contextual risk
                </span>
              </div>
              <Details
                rows={[
                  ["Owner", f.owner],
                  ["Status", <Badge>{f.status}</Badge>],
                  [
                    "Account",
                    <Link to={`/accounts/${a.account}`}>
                      {accountFor(a.account).name}
                    </Link>,
                  ],
                  ["Region", a.region],
                  [
                    "Policy",
                    <Link to={`/policies/${f.policy}`}>{f.policy}</Link>,
                  ],
                  ["Last confirmed", "Sep 6, 08:48 UTC"],
                ]}
              />
              <h3>Affected asset</h3>
              <Resource asset={a} />
            </div>
          </Panel>
          {canAct && (
            <Panel title="Actions">
              <div className="cs-rail-actions">
                <button onClick={() => setModal("ticket")}>
                  <FileText size={15} />
                  Create ticket
                  <ArrowUpRight size={13} />
                </button>
                <button onClick={() => setModal("exception")}>
                  <Shield size={15} />
                  Request exception
                  <ChevronRight size={13} />
                </button>
                <button onClick={() => setModal("false-positive")}>
                  <ShieldAlert size={15} />
                  Report false positive
                  <ChevronRight size={13} />
                </button>
                <button
                  onClick={() => {
                    notify(
                      "Demo re-evaluation queued. Resolution requires fresh evidence.",
                    );
                    log(
                      "Re-evaluation requested",
                      f.id,
                      f.status,
                      "Awaiting evidence",
                    );
                  }}
                >
                  <RefreshCw size={15} />
                  Re-evaluate
                  <ChevronRight size={13} />
                </button>
              </div>
            </Panel>
          )}
        </div>
      </div>
      {modal === "exception" && (
        <ExceptionModal finding={f} onClose={() => setModal("")} />
      )}
      {modal === "assign" && (
        <Overlay title="Assign finding" onClose={() => setModal("")}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const owner = String(new FormData(e.currentTarget).get("owner"));
              update((s) => ({
                ...s,
                findings: s.findings.map((row) =>
                  row.id === f.id ? { ...row, owner } : row,
                ),
              }));
              log("Owner assigned", f.id, f.owner, owner);
              notify(`Assigned to ${owner}`);
              setModal("");
            }}
          >
            <Field label="Owner">
              <select name="owner" defaultValue={f.owner}>
                {owners.map((owner) => (
                  <option key={owner}>{owner}</option>
                ))}
              </select>
            </Field>
            <button className="cs-button primary">Save assignment</button>
          </form>
        </Overlay>
      )}
      {modal === "ticket" && (
        <Overlay title="Create ticket draft" onClose={() => setModal("")}>
          <Notice kind="blue">
            Download a ticket draft or connect your ticketing provider in
            Integrations.
          </Notice>
          <Details
            rows={[
              ["Title", f.title],
              ["Finding", f.id],
              ["Asset", a.arn],
              ["Owner", f.owner],
              ["Recommended fix", f.fix],
            ]}
          />
          <button
            className="cs-button primary"
            onClick={() => {
              download(`ticket-${f.id}`, {
                title: f.title,
                finding: f.id,
                asset: a.arn,
                owner: f.owner,
                evidence: f.observed,
                remediation: f.fix,
                source: "Demo workspace",
              });
              log("Ticket draft exported", f.id, "None", "Downloaded");
              setModal("");
            }}
          >
            <Download size={15} />
            Download ticket draft
          </button>
        </Overlay>
      )}
      {modal === "false-positive" && (
        <Overlay title="Report false positive" onClose={() => setModal("")}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              log(
                "False positive review requested",
                f.id,
                f.status,
                String(new FormData(e.currentTarget).get("reason")),
              );
              notify(
                "Review recorded. Finding remains open until evidence is reviewed.",
              );
              setModal("");
            }}
          >
            <Field label="Evidence and reason">
              <textarea
                required
                minLength={20}
                name="reason"
                placeholder="Explain which evidence contradicts this finding."
              />
            </Field>
            <button className="cs-button primary">Submit for review</button>
          </form>
        </Overlay>
      )}
    </div>
  );
}
export function ExceptionModal({
  finding,
  onClose,
}: {
  finding: Finding;
  onClose: () => void;
}) {
  const { update, notify, log, canAct } = useProduct();
  return (
    <Overlay title="Request risk exception" onClose={onClose}>
      <Notice>
        Exception does not remove the underlying security finding.
      </Notice>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!canAct) return;
          const data = new FormData(e.currentTarget);
          const value = (k: string) => String(data.get(k) || "");
          const exception = {
            id: `EX-${Date.now().toString().slice(-6)}`,
            finding: finding.id,
            reason: value("reason"),
            scope: value("scope"),
            justification: value("justification"),
            control: value("control"),
            evidence: value("evidence"),
            expiry: value("expiry"),
            approver: value("approver"),
            status: "Pending Approval",
          };
          update((s) => ({ ...s, exceptions: [...s.exceptions, exception] }));
          log("Exception requested", finding.id, "None", "Pending Approval");
          notify("Exception request submitted for approval");
          onClose();
        }}
      >
        <Field label="Finding">
          <input readOnly value={`${finding.id} · ${finding.title}`} />
        </Field>
        <Field label="Reason">
          <select name="reason">
            <option>Business requirement</option>
            <option>Migration in progress</option>
            <option>Third-party dependency</option>
          </select>
        </Field>
        <Field label="Scope">
          <input name="scope" defaultValue={finding.asset} required />
        </Field>
        <Field label="Business justification">
          <textarea
            name="justification"
            required
            minLength={20}
            placeholder="Explain why the risk must be accepted temporarily."
          />
        </Field>
        <Field label="Compensating control">
          <textarea
            name="control"
            required
            minLength={10}
            placeholder="Describe controls that limit exposure."
          />
        </Field>
        <Field label="Evidence reference">
          <input
            name="evidence"
            required
            placeholder="Change request, document, or evidence ID"
          />
        </Field>
        <div className="cs-two-col">
          <Field label="Expiry">
            <input
              name="expiry"
              type="date"
              min={new Date(Date.now() + 86400000).toISOString().slice(0, 10)}
              required
            />
          </Field>
          <Field label="Approver">
            <select name="approver">
              <option>Priya Mehta</option>
              <option>Arjun Rao</option>
            </select>
          </Field>
        </div>
        <div className="cs-modal-actions">
          <button type="button" className="cs-button" onClick={onClose}>
            Cancel
          </button>
          <button className="cs-button primary">Request approval</button>
        </div>
      </form>
    </Overlay>
  );
}
export function Accounts() {
  const {
    inTenant,
    canManage,
    canAct,
    notify,
    log,
    setDemo,
    setScope,
    tenantAccounts,
    workspace,
    service,
    subscribedServices,
    update,
  } = useProduct();
  const navigate = useNavigate();
  const [modal, setModal] = useState("");
  const filters = useFilters();
  const rows = accounts.filter(
    (a) =>
      inTenant(a.id) &&
      !workspace.disconnected.includes(a.id) &&
      a.name
        .toLowerCase()
        .includes((filters.params.get("q") || "").toLowerCase()) &&
      (!filters.params.get("health") ||
        a.health === filters.params.get("health")),
  );
  return (
    <div className="cs-page">
      <Head title="Cloud Accounts">
        {canManage && (
          <button
            className="cs-button primary"
            onClick={() => setModal("connect")}
          >
            <Plus size={15} />
            Connect account
          </button>
        )}
      </Head>
      <div className="cs-summary-row">
        {["Connected accounts", "Healthy", "Degraded", "Stale"].map(
          (status, i) => (
            <button
              key={status}
              onClick={() => filters.set("health", i ? status : "")}
            >
              <span>{status}</span>
              <strong>
                {
                  tenantAccounts.filter(
                    (a) =>
                      !workspace.disconnected.includes(a.id) &&
                      (!i || a.health === status),
                  ).length
                }
              </strong>
            </button>
          ),
        )}
      </div>
      {rows.some((a) => a.health !== "Healthy") && (
        <Notice>
          Collection gaps affect evaluation. Development is missing network ACL
          evidence; Shared Services evidence is stale.
        </Notice>
      )}
      <Panel>
        <Filters
          filters={filters}
          placeholder="Search cloud accounts..."
          fields={{ health: ["Healthy", "Degraded", "Stale"] }}
        />
        <Table
          headers={[
            "Account",
            "Environment",
            "Provider",
            "Regions",
            "Assets",
            "Findings",
            "Coverage",
            "Health",
            "Last scan",
            "Last verified",
            "Actions",
          ]}
          count={rows.length}
          empty={!rows.length}
        >
          {rows.map((a) => (
            <tr key={a.id}>
              <td>
                <Link className="cs-resource" to={`/accounts/${a.id}`} onClick={() => setScope(a.id)}>
                  <span className="cs-aws-small">aws</span>
                  <span>
                    <strong>{a.name}</strong>
                    <small>{a.number}</small>
                  </span>
                </Link>
              </td>
              <td>{a.environment}</td>
              <td>AWS</td>
              <td>{a.regions.length} regions</td>
              <td>
                <Link to={`/inventory?account=${encodeURIComponent(a.name)}`} onClick={() => setScope(a.id)}>
                  {
                    assets.filter(
                      (asset) =>
                        asset.account === a.id &&
                        serviceAllowsAsset(service, asset, subscribedServices),
                    ).length
                  }
                </Link>
              </td>
              <td>
                <Link to={`/findings?account=${encodeURIComponent(a.name)}`} onClick={() => setScope(a.id)}>
                  {
                    workspace.findings.filter(
                      (f) =>
                        assetFor(f).account === a.id &&
                        serviceAllowsAsset(
                          service,
                          assetFor(f),
                          subscribedServices,
                        ) &&
                        isActive(f),
                    ).length
                  }
                </Link>
              </td>
              <td>
                <div className="cs-coverage-cell">
                  <span className="cs-progress">
                    <span style={{ width: `${a.coverage}%` }} />
                  </span>
                  {a.coverage}%
                </div>
              </td>
              <td>
                <Badge>{a.health}</Badge>
              </td>
              <td>{a.health === "Stale" ? "2 days ago" : "12 min ago"}</td>
              <td>Sep 6, 08:40</td>
              <td>
                <div className="cs-inline">
                  <Link
                    className="cs-icon"
                    aria-label={`View ${a.name}`}
                    to={`/accounts/${a.id}`}
                    onClick={() => setScope(a.id)}
                  >
                    <ExternalLink size={14} />
                  </Link>
                  {canAct && (
                    <button
                      className="cs-icon"
                      aria-label={`Verify ${a.name}`}
                      onClick={() => {
                        log(
                          "Connection verification",
                          a.name,
                          a.health,
                          a.health,
                        );
                        notify(
                          `Demo verification: ${a.name} remains ${a.health.toLowerCase()}.`,
                        );
                      }}
                    >
                      <ShieldCheck size={14} />
                    </button>
                  )}
                  {canManage && (
                    <button
                      className="cs-icon"
                      aria-label={`Disconnect ${a.name}`}
                      onClick={() => setModal(a.id)}
                    >
                      <ExternalLink size={14} className="cs-rotate" />
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {modal === "connect" && (
        <Overlay title="Connect AWS account" onClose={() => setModal("")}>
          <div className="cs-onboarding-step">
            <span>1</span>
            <div>
              <h3>Deploy read-only collection role</h3>
              <p>
                Use the existing account-onboarding workflow to generate your
                CloudFormation template.
              </p>
            </div>
          </div>
          <div className="cs-onboarding-step">
            <span>2</span>
            <div>
              <h3>Verify permission coverage</h3>
              <p>
                Confirm regions, services, and collection permissions before
                evaluation.
              </p>
            </div>
          </div>
          <div className="cs-onboarding-step">
            <span>3</span>
            <div>
              <h3>Enable workload inspection separately</h3>
              <p>
                Agentless snapshot inspection uses a separate, scoped role and
                cleanup workflow.
              </p>
            </div>
          </div>
          <Notice kind="blue">
            You are in the demo workspace. Continue to the connected workspace
            to onboard a real account.
          </Notice>
          <button
            className="cs-button primary"
            onClick={() => {
              setDemo(false);
              navigate("/accounts");
              setModal("");
            }}
          >
            Open connected onboarding
            <ArrowRight size={15} />
          </button>
          {workspace.disconnected.length > 0 && (
            <button
              className="cs-button"
              onClick={() => {
                update((s) => ({ ...s, disconnected: [] }));
                notify("Demo accounts restored");
                setModal("");
              }}
            >
              Restore disconnected demo accounts
            </button>
          )}
        </Overlay>
      )}
      {modal && modal !== "connect" && (
        <Overlay title="Disconnect demo account" onClose={() => setModal("")}>
          <p>
            Remove {accountFor(modal).name} from the demo workspace scope? Its
            sample history is retained. No AWS account is modified.
          </p>
          <div className="cs-modal-actions">
            <button className="cs-button" onClick={() => setModal("")}>
              Cancel
            </button>
            <button
              className="cs-button danger"
              onClick={() => {
                update((s) => ({
                  ...s,
                  disconnected: [...s.disconnected, modal],
                }));
                log(
                  "Demo account disconnected",
                  modal,
                  "Connected",
                  "Disconnected",
                );
                notify(
                  "Demo account disconnected; history retained. Restore through Connect account.",
                );
                setModal("");
              }}
            >
              Disconnect
            </button>
          </div>
        </Overlay>
      )}
    </div>
  );
}
export function AccountDetail() {
  const { accountId } = useParams();
  const { inTenant, setScope, workspace, service, subscribedServices, canAct, canManage, notify, log } = useProduct();
  const { params, set } = useFilters();
  const a = accounts.find(
    (item) =>
      item.id === accountId &&
      inTenant(item.id) &&
      !workspace.disconnected.includes(item.id),
  );
  useEffect(() => {
    if (a) setScope(a.id);
  }, [a, setScope]);
  if (!a)
    return (
      <Empty
        title="Account unavailable in current scope"
        text="Choose this connected account from account selector."
      />
    );
  const tab = params.get("tab") || "Overview";
  return (
    <div className="cs-page">
      <Link to="/accounts" className="cs-back">
        <ArrowLeft size={14} />
        Cloud Accounts
      </Link>
      <Head
        title={`${a.name} AWS Account`}
        meta={
          <>
            <span className="cs-mono">{a.number}</span>
            <Badge>{a.health}</Badge>
            <span>{a.coverage}% coverage</span>
            <span>Last verified Sep 6, 08:40 UTC</span>
          </>
        }
      >
        {canAct && (
          <button
            className="cs-button"
            onClick={() => {
              log("Demo scan requested", a.name, a.health, "Queued");
              notify("Demo scan requested; sample coverage remains unchanged.");
            }}
          >
            <RefreshCw size={15} />
            Scan account
          </button>
        )}
        {canManage && (
          <button
            className="cs-button primary"
            onClick={() => set("tab", "Configuration")}
          >
            Configure
          </button>
        )}
      </Head>
      <Panel>
        <Tabs
          items={[
            "Overview",
            "Inventory",
            "Findings",
            "Coverage",
            "Scan History",
            "Configuration",
          ]}
          value={tab}
          onChange={(v) => set("tab", v)}
        />
        <div className="cs-panel-body">
          {tab === "Overview" && (
            <>
              <div className="cs-two-col">
                <Details
                  rows={[
                    ["Account ID", a.number],
                    ["Environment", a.environment],
                    ["Connection status", <Badge>{a.health}</Badge>],
                    ["Coverage", `${a.coverage}%`],
                    ["Regions", a.regions.join(", ")],
                    [
                      "Last scan",
                      a.health === "Stale"
                        ? "Sep 4, 08:48 UTC · Stale"
                        : "Sep 6, 08:48 UTC",
                    ],
                  ]}
                />
                <div className="cs-link-cards">
                  <Link to={`/inventory?account=${encodeURIComponent(a.name)}`}>
                    <BoxesIcon />
                    <strong>Resource inventory</strong>
                    <ArrowUpRight size={16} />
                  </Link>
                  <Link to={`/findings?account=${encodeURIComponent(a.name)}`}>
                    <ShieldAlert size={20} />
                    <strong>Account findings</strong>
                    <ArrowUpRight size={16} />
                  </Link>
                </div>
              </div>
            </>
          )}
          {tab === "Inventory" && (
            <Table headers={["Resource", "Region", "Exposure", "Risk"]}>
              {assets
                .filter(
                  (asset) =>
                    asset.account === a.id &&
                    serviceAllowsAsset(service, asset, subscribedServices),
                )
                .map((asset) => (
                  <tr key={asset.id}>
                    <td>
                      <Resource asset={asset} />
                    </td>
                    <td>{asset.region}</td>
                    <td>
                      <Badge>{asset.exposure}</Badge>
                    </td>
                    <td>
                      <Badge>{asset.risk}</Badge>
                    </td>
                  </tr>
                ))}
            </Table>
          )}
          {tab === "Findings" && (
            <FindingTable
              findings={workspace.findings.filter(
                (f) =>
                  assetFor(f).account === a.id &&
                  serviceAllowsAsset(service, assetFor(f), subscribedServices),
              )}
            />
          )}
          {tab === "Coverage" && (
            <>
              {a.health !== "Healthy" && (
                <Notice>
                  {a.health === "Degraded"
                    ? "Network ACL evidence is missing. Reachability is Unverified until collection succeeds."
                    : "Collection has not completed for 48 hours. Existing findings are retained; absence of new findings is not evidence of security."}
                </Notice>
              )}
              <Table headers={["Dimension", "Status", "Coverage", "Evidence"]}>
                {[
                  ["Accounts", "Healthy", "1 / 1", "Connection role verified"],
                  [
                    "Regions",
                    a.health,
                    `${a.regions.length} configured`,
                    a.regions.join(", "),
                  ],
                  [
                    "Services",
                    a.health,
                    `${a.coverage}%`,
                    "AWS service metadata collection",
                  ],
                  [
                    "Permissions",
                    a.health === "Degraded" ? "Missing" : "Healthy",
                    a.health === "Degraded" ? "Partial" : "Complete",
                    a.health === "Degraded"
                      ? "ec2:DescribeNetworkAcls collection denied"
                      : "Collection permission check passed",
                  ],
                  [
                    "Freshness",
                    a.health === "Stale" ? "Stale" : "Healthy",
                    a.health === "Stale" ? "48 hours" : "12 minutes",
                    observedAt,
                  ],
                  [
                    "Agentless inspection",
                    "Unsupported",
                    "Not enabled",
                    "Separate workload inspection integration required",
                  ],
                ].map((row) => (
                  <tr key={row[0]}>
                    {row.map((cell, i) => (
                      <td key={i}>{i === 1 ? <Badge>{cell}</Badge> : cell}</td>
                    ))}
                  </tr>
                ))}
              </Table>
            </>
          )}
          {tab === "Scan History" && (
            <Table
              headers={["Scan", "Started", "Duration", "Status", "Coverage"]}
            >
              <tr>
                <td>SCAN-20260906-{a.id}</td>
                <td>Sep 6, 08:42 UTC</td>
                <td>6 min 12 sec</td>
                <td>
                  <Badge>{a.health}</Badge>
                </td>
                <td>{a.coverage}%</td>
              </tr>
              <tr>
                <td>SCAN-20260905-{a.id}</td>
                <td>Sep 5, 20:42 UTC</td>
                <td>5 min 48 sec</td>
                <td>
                  <Badge>Healthy</Badge>
                </td>
                <td>100%</td>
              </tr>
            </Table>
          )}
          {tab === "Configuration" && (
            <>
              <Details
                rows={[
                  [
                    "Collection role",
                    `arn:aws:iam::${a.number}:role/CloudSentinelReadOnly`,
                  ],
                  ["Scan schedule", workspace.settings.cadence],
                  ["Configured regions", a.regions.join(", ")],
                  ["Cloud mutation", "Separate execution role required"],
                  ["Workload inspection", "Not enabled"],
                ]}
              />
              {canManage && (
                <Jump to="/settings">Manage scanning and routing</Jump>
              )}
            </>
          )}
        </div>
      </Panel>
    </div>
  );
}
function BoxesIcon() {
  return <Layers size={20} />;
}
export function PathGraph({ pathId }: { pathId: string }) {
  const path = attackPaths.find((p) => p.id === pathId)!;
  const [selected, setSelected] = useState<number | null>(null);
  const icons = [Globe2, Network, Shield, Server, LockKeyhole, Database];
  return (
    <>
      <div className="cs-graph-legend">
        <span>
          <i />
          Verified relationship
        </span>
        <span>
          <i className="dashed" />
          Missing evidence
        </span>
        <Badge>{path.state === "Missing" ? "Unverified" : path.state}</Badge>
      </div>
      <div className="cs-path-graph">
        {path.nodes.map((node, i) => {
          const Icon = icons[i];
          return (
            <div className="cs-graph-step" key={node.name}>
              <button
                className={`cs-graph-node ${i === 5 ? "target" : ""} ${selected === i ? "selected" : ""}`}
                onClick={() => setSelected(selected === i ? null : i)}
                aria-expanded={selected === i}
              >
                <span className="cs-node-icon">
                  <Icon size={25} />
                </span>
                <small>{node.type}</small>
                <strong>{node.name}</strong>
                <Badge>{node.state}</Badge>
              </button>
              {i < path.nodes.length - 1 && (
                <div
                  className={`cs-graph-edge ${path.nodes[i + 1].state === "Missing" ? "missing" : ""}`}
                >
                  <span>{node.relationship}</span>
                  <ArrowRight size={16} />
                </div>
              )}
            </div>
          );
        })}
      </div>
      {selected !== null && (
        <div className="cs-node-evidence">
          <div className="cs-inline">
            <strong>{path.nodes[selected].name}</strong>
            <Badge>{path.nodes[selected].state}</Badge>
          </div>
          <p>{path.nodes[selected].observed}</p>
          <span className="cs-muted">
            Relationship: {path.nodes[selected].relationship} · Snapshot{" "}
            {observedAt}
          </span>
        </div>
      )}
    </>
  );
}
export function AttackPaths() {
  const { inScope } = useProduct();
  const filters = useFilters();
  const [view, setView] = useState("List");
  const rows = attackPaths.filter(
    (p) =>
      inScope(p.account) &&
      (!filters.params.get("evidence") ||
        p.state === filters.params.get("evidence")) &&
      (!filters.params.get("severity") ||
        filters.params.get("severity")!.split(",").includes(p.severity)) &&
      `${p.name} ${p.id}`
        .toLowerCase()
        .includes((filters.params.get("q") || "").toLowerCase()),
  );
  return (
    <div className="cs-page">
      <Head title="Attack Paths">
        <div className="cs-segment">
          {["List", "Graph"].map((v) => (
            <button
              className={view === v ? "active" : ""}
              key={v}
              onClick={() => setView(v)}
            >
              {v === "List" ? <FileText size={14} /> : <GitBranch size={14} />}
              {v}
            </button>
          ))}
        </div>
      </Head>
      <div className="cs-summary-row">
        {[
          [
            "Critical paths",
            rows.filter(
              (p) => p.severity === "Critical" && p.state === "Verified",
            ).length,
          ],
          ["High paths", rows.filter((p) => p.severity === "High").length],
          ["Open", rows.length],
          ["Resolved", 0],
          [
            "Partial evidence",
            rows.filter((p) => p.state === "Missing").length,
          ],
          ["Stale evidence", rows.filter((p) => p.state === "Stale").length],
        ].map(([label, count]) => (
          <div key={label}>
            <span>{label}</span>
            <strong>{count}</strong>
          </div>
        ))}
      </div>
      <Notice kind="blue">
        Only verified relationships establish an attack path. Missing network
        evidence remains Unverified, never Reachable or Blocked.
      </Notice>
      <Panel>
        <Filters
          filters={filters}
          placeholder="Search attack paths..."
          fields={{
            severity: severities,
            evidence: ["Verified", "Inferred", "Stale", "Missing"],
          }}
        />
        {view === "List" ? (
          <Table
            headers={[
              "Risk",
              "Attack path",
              "Entry point",
              "Target",
              "Severity",
              "Confidence",
              "Hops",
              "Owner",
              "Status",
            ]}
            count={rows.length}
            empty={!rows.length}
          >
            {rows.map((p) => (
              <tr key={p.id}>
                <td>
                  <span className="cs-priority critical">{p.score}</span>
                </td>
                <td>
                  <Link
                    className="cs-finding-title"
                    to={`/attack-paths/${p.id}`}
                  >
                    {p.name}
                    <ArrowUpRight size={12} />
                  </Link>
                  <span className="cs-cell-sub">
                    {p.id} · {accountFor(p.account).name}
                  </span>
                </td>
                <td>Internet · TCP/443</td>
                <td>
                  <Resource asset={assets.find((a) => a.id === p.target)!} />
                </td>
                <td>
                  <Badge>{p.severity}</Badge>
                </td>
                <td>{p.confidence}%</td>
                <td>{p.nodes.length - 1}</td>
                <td>Platform Team</td>
                <td>
                  <Badge>
                    {p.state === "Missing" ? "Unverified" : p.state}
                  </Badge>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <div className="cs-panel-body">
            {rows.map((p) => (
              <Panel
                title={`${p.id} · ${accountFor(p.account).name}`}
                action={<Jump to={`/attack-paths/${p.id}`}>Investigate</Jump>}
                key={p.id}
              >
                <PathGraph pathId={p.id} />
              </Panel>
            ))}
            {!rows.length && (
              <Empty
                title="No matching paths"
                text="Review scope and evidence filters."
              />
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
export function AttackPathDetail() {
  const { pathId } = useParams();
  const { inScope } = useProduct();
  const path = attackPaths.find((p) => p.id === pathId && inScope(p.account));
  if (!path)
    return (
      <Empty
        title="Attack path unavailable"
        text="Check selected account and path ID."
      />
    );
  return (
    <div className="cs-page">
      <Link className="cs-back" to="/attack-paths">
        <ArrowLeft size={14} />
        Attack paths
      </Link>
      <Head
        title={path.name}
        meta={
          <>
            <Badge>{path.severity}</Badge>
            <span>{path.id}</span>
            <span>{accountFor(path.account).name}</span>
            <Badge>
              {path.state === "Missing" ? "Unverified" : "Verified"}
            </Badge>
          </>
        }
      />
      <div className="cs-summary-row">
        <div>
          <span>Attack path risk</span>
          <strong>
            {path.score}
            <small>/100</small>
          </strong>
        </div>
        <div>
          <span>Confidence</span>
          <strong>{path.confidence}%</strong>
        </div>
        <div>
          <span>Evidence coverage</span>
          <strong>
            {path.nodes.filter((n) => n.state === "Verified").length} /{" "}
            {path.nodes.length}
          </strong>
        </div>
        <div>
          <span>Network reachability</span>
          <strong className="cs-smaller">
            {path.state === "Missing" ? "Unverified" : "Reachable"}
          </strong>
        </div>
      </div>
      <Panel title="Relationship graph" action={<Badge>Demo evidence</Badge>}>
        <PathGraph pathId={path.id} />
      </Panel>
      <Panel title="Hop-by-hop evidence">
        <Table
          headers={[
            "Hop",
            "Resource",
            "Relationship",
            "Observed evidence",
            "Confidence",
            "Evidence state",
          ]}
        >
          {path.nodes.map((n, i) => (
            <tr key={n.name}>
              <td>{i + 1}</td>
              <td>
                <strong>{n.name}</strong>
                <span className="cs-cell-sub">{n.type}</span>
              </td>
              <td>{n.relationship}</td>
              <td className="cs-wrap-cell">{n.observed}</td>
              <td>{n.state === "Missing" ? "Unknown" : "98%"}</td>
              <td>
                <Badge>{n.state}</Badge>
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      <Panel title="Recommended break point">
        <div className="cs-breakpoint">
          <span className="cs-health-icon green">
            <ShieldCheck size={24} />
          </span>
          <div>
            <h3>Restrict effective access to sensitive S3 data</h3>
            <p>
              Scope the application role and validate the resource policy. This
              affects{" "}
              {attackPaths.filter((p) => p.account === path.account).length}{" "}
              modeled path in this account.
            </p>
          </div>
          <Link
            className="cs-button primary"
            to={`/findings/CS-${1042 + accounts.findIndex((a) => a.id === path.account) * 8}?tab=Remediation`}
          >
            View remediation
            <ArrowRight size={15} />
          </Link>
        </div>
      </Panel>
    </div>
  );
}
