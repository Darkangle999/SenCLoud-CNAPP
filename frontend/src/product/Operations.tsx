import { lazy, Suspense, useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  Check,
  ChevronRight,
  Cloud,
  Download,
  FileCode2,
  GitBranch,
  HardDrive,
  RefreshCw,
  Server,
  Settings2,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { accountFor, accounts, assetFor, assets } from "./data";
import { useProduct, type Remediation } from "./store";
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

const IntegrationIconCloud = lazy(() =>
  import("./IntegrationIconCloud").then((module) => ({
    default: module.IntegrationIconCloud,
  })),
);
const IntegrationBrandIcon = lazy(() =>
  import("./IntegrationIconCloud").then((module) => ({
    default: module.IntegrationBrandIcon,
  })),
);

export function Remediations() {
  const { workspace, inScope, canManage, canAct, update, log, notify } =
    useProduct();
  const filters = useFilters();
  const [confirm, setConfirm] = useState(false);
  const tasks = workspace.remediations.filter((r) =>
    workspace.findings.some(
      (f) => f.id === r.finding && inScope(assetFor(f).account, assetFor(f).region),
    ),
  );
  const selected =
    tasks.find((r) => r.id === filters.params.get("task")) || tasks[0];
  const finding = workspace.findings.find((f) => f.id === selected?.finding);
  const transition = (status: Remediation["status"]) => {
    if (
      !selected ||
      !finding ||
      !canAct ||
      (status === "Approved" && !canManage)
    )
      return;
    update((s) => ({
      ...s,
      remediations: s.remediations.map((r) =>
        r.id === selected.id ? { ...r, status } : r,
      ),
      findings: s.findings.map((f) =>
        f.id === finding.id
          ? {
              ...f,
              status:
                status === "Pending Verification"
                  ? "Pending Verification"
                  : status === "Approved"
                    ? "In Progress"
                    : f.status,
            }
          : f,
      ),
    }));
    log("Remediation state changed", finding.id, selected.status, status);
    notify(`Remediation ${status.toLowerCase()}`);
    setConfirm(false);
  };
  return (
    <div className="cs-page">
      <Head title="Remediation">
        <Link className="cs-button" to="/findings">
          Review findings
          <ArrowRight size={15} />
        </Link>
      </Head>
      <div className="cs-remediation-stages">
        {["Review", "Approve", "Execute", "Verify"].map((s, i) => (
          <div key={s}>
            <span>{i + 1}</span>
            <strong>{s}</strong>
            <small>
              {
                [
                  "Assess fix and impact",
                  "Authorize scoped change",
                  "Apply approved change",
                  "Confirm with fresh evidence",
                ][i]
              }
            </small>
            {i < 3 && <ChevronRight size={18} />}
          </div>
        ))}
      </div>
      <div className="cs-remediation-layout">
        <Panel
          title="Change queue"
          action={<span className="cs-count">{tasks.length}</span>}
        >
          <div className="cs-task-list">
            {tasks.map((task) => {
              const f = workspace.findings.find((f) => f.id === task.finding)!;
              return (
                <button
                  key={task.id}
                  className={selected?.id === task.id ? "active" : ""}
                  onClick={() => filters.set("task", task.id)}
                >
                  <div>
                    <Badge>{f.severity}</Badge>
                    <span>{task.id}</span>
                  </div>
                  <strong>{f.title}</strong>
                  <small>{assetFor(f).name}</small>
                  <Badge>{task.status}</Badge>
                </button>
              );
            })}
            {!tasks.length && (
              <Empty
                title="No remediation tasks"
                text="Start remediation from a finding to create a review task."
              />
            )}
          </div>
        </Panel>
        {finding && selected && (
          <Panel
            title={`${selected.id} · Change review`}
            action={<Badge>{selected.status}</Badge>}
          >
            <div className="cs-panel-body">
              <div className="cs-inline">
                <Badge>Guidance</Badge>
                <span className="cs-muted">
                  Demo workflow · No cloud mutation
                </span>
              </div>
              <h2>{finding.title}</h2>
              <Link className="cs-jump" to={`/findings/${finding.id}`}>
                {finding.id} · Investigate original finding
                <ArrowRight size={14} />
              </Link>
              <Details
                rows={[
                  [
                    "Resource",
                    <Link to={`/inventory/${finding.asset}`}>
                      {assetFor(finding).arn}
                    </Link>,
                  ],
                  ["Current state", <code>{finding.observed}</code>],
                  ["Proposed state", <code>{finding.required}</code>],
                  [
                    "Expected risk reduction",
                    `${finding.score} to an estimated ${Math.max(10, finding.score - 60)}; not verified`,
                  ],
                  [
                    "Operational impact",
                    assetFor(finding).service === "RDS"
                      ? "A restore and cutover can interrupt database connections."
                      : "Existing consumers may lose access. Confirm dependencies with the resource owner.",
                  ],
                  [
                    "Prerequisites",
                    "Owner review, approved change window, dependency validation",
                  ],
                  [
                    "Permissions",
                    "Separate scoped execution role; read-only collection role cannot execute changes",
                  ],
                  [
                    "Rollback",
                    "Restore the reviewed prior configuration; re-evaluate affected dependencies",
                  ],
                  ["Owner", finding.owner],
                ]}
              />
              <div className="cs-code-block">
                <span>Recommended guidance</span>
                <p>{finding.fix}</p>
              </div>
              {selected.status === "Review" && (
                <div className="cs-modal-actions">
                  {canManage ? (
                    <button
                      className="cs-button primary"
                      onClick={() => transition("Approved")}
                    >
                      <Check size={15} />
                      Approve demo change
                    </button>
                  ) : (
                    <Notice>Administrator approval required.</Notice>
                  )}
                </div>
              )}
              {selected.status === "Approved" && (
                <>
                  <Notice>
                    Live Change requires a connected execution service and
                    server-side authorization. This workspace can preview the
                    execution workflow.
                  </Notice>
                  {canManage && (
                    <button
                      className="cs-button primary"
                      onClick={() => setConfirm(true)}
                    >
                      <Wrench size={15} />
                      Preview execution
                    </button>
                  )}
                </>
              )}
              {[
                "Pending Verification",
                "Unknown",
                "Still Open",
                "Reopened",
              ].includes(selected.status) && (
                <div className="cs-verification">
                  <span className="cs-health-icon amber">
                    <RefreshCw size={20} />
                  </span>
                  <h3>{selected.status}</h3>
                  <p>Waiting for fresh cloud evidence...</p>
                  <p className="cs-muted">
                    Submitting a change does not prove resolution. The sample
                    snapshot still contains the original configuration.
                  </p>
                  {canAct && (
                    <button
                      className="cs-button"
                      onClick={() => {
                        log(
                          "Verification requested",
                          finding.id,
                          selected.status,
                          "Unknown · Fresh evidence unavailable",
                        );
                        notify(
                          "Verification unknown: fresh cloud evidence is unavailable in demo mode.",
                        );
                        update((s) => ({
                          ...s,
                          remediations: s.remediations.map((r) =>
                            r.id === selected.id
                              ? { ...r, status: "Unknown" }
                              : r,
                          ),
                        }));
                      }}
                    >
                      Request verification
                    </button>
                  )}
                  <div className="cs-verification-states">
                    {[
                      "Verified Resolved",
                      "Still Open",
                      "Reopened",
                      "Unknown",
                    ].map((s) => (
                      <Badge key={s}>{s}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Panel>
        )}
      </div>
      {confirm && finding && (
        <Overlay
          title="Confirm demo execution"
          onClose={() => setConfirm(false)}
        >
          <Notice>
            No AWS resources will be changed. This preview moves the task to
            Pending Verification.
          </Notice>
          <Details
            rows={[
              ["Target resource", assetFor(finding).name],
              ["Proposed change", finding.required],
              [
                "Impact",
                "Access disruption for existing consumers is possible",
              ],
              ["Rollback", "Restore reviewed prior configuration"],
            ]}
          />
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (
                String(new FormData(e.currentTarget).get("confirmation")) ===
                assetFor(finding).name
              )
                transition("Pending Verification");
            }}
          >
            <Field label={`Type ${assetFor(finding).name} to confirm`}>
              <input
                name="confirmation"
                required
                autoComplete="off"
                onInput={(e) =>
                  e.currentTarget.setCustomValidity(
                    e.currentTarget.value === assetFor(finding).name
                      ? ""
                      : "Resource name must match exactly.",
                  )
                }
              />
            </Field>
            <label className="cs-checkbox">
              <input type="checkbox" required />I reviewed operational impact
              and rollback.
            </label>
            <div className="cs-modal-actions">
              <button
                className="cs-button"
                type="button"
                onClick={() => setConfirm(false)}
              >
                Cancel
              </button>
              <button className="cs-button primary">
                Confirm demo execution
              </button>
            </div>
          </form>
        </Overlay>
      )}
    </div>
  );
}
export function Workloads() {
  const { inScope, canAct, notify, log } = useProduct();
  const filters = useFilters();
  const [asset, setAsset] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [completed, setCompleted] = useState(false);
  const tab = filters.params.get("tab") || "Workloads";
  const workloads = assets.filter(
    (a) => a.category === "Compute" && inScope(a.account, a.region),
  );
  const selected = workloads.find((a) => a.id === asset);
  const inspect = () => {
    setRunning(true);
    setTimeout(() => {
      setRunning(false);
      setCompleted(true);
      notify("Sample inspection cycle completed; demo cleanup confirmed.");
      log(
        "Demo workload inspection",
        "Sample workloads",
        "Queued",
        "Completed · No cloud changes",
      );
    }, 1600);
  };
  return (
    <div className="cs-page">
      <Head title="Workload Security">
        <Badge kind="Inferred">Agentless inspection</Badge>
        {canAct && (
          <button
            className="cs-button primary"
            onClick={inspect}
            disabled={running}
          >
            <RefreshCw size={15} className={running ? "cs-spin" : ""} />
            {running ? "Inspecting sample…" : "Run sample inspection"}
          </button>
        )}
      </Head>
      <div className="cs-summary-row">
        {[
          ["Workloads", workloads.length],
          [
            "Snapshot eligible",
            workloads.filter((a) => a.service === "EC2").length,
          ],
          [
            "Pending inspection",
            completed ? 0 : workloads.filter((a) => a.service === "EC2").length,
          ],
          [
            "Coverage gaps",
            workloads.filter((a) => a.service !== "EC2").length,
          ],
        ].map(([label, count]) => (
          <div key={label}>
            <span>{label}</span>
            <strong>{count}</strong>
          </div>
        ))}
      </div>
      <Panel
        title="Agentless inspection lifecycle"
        action={
          <Badge>
            {running ? "In Progress" : completed ? "Verified" : "Review"}
          </Badge>
        }
      >
        <div className="cs-inspection-flow">
          {[
            [Cloud, "Discover", "EC2 and attached volumes"],
            [HardDrive, "Snapshot", "Separate scoped role"],
            [LockIcon, "Inspect", "Isolated read-only mount"],
            [ShieldCheck, "Correlate", "Vulnerabilities and exposure"],
            [Check, "Clean up", "Volume and snapshot teardown"],
          ].map(([Icon, title, text], i) => {
            const Component = Icon as typeof Cloud;
            return (
              <div key={String(title)}>
                <span>
                  <Component size={21} />
                </span>
                <strong>{String(title)}</strong>
                <small>{String(text)}</small>
                {i < 4 && <ChevronRight size={16} />}
              </div>
            );
          })}
        </div>
      </Panel>
      <Notice kind="blue">
        Sample inspection records illustrate the planned workload workflow. Live
        snapshot orchestration and cleanup monitoring require backend
        integration.
      </Notice>
      <Panel>
        <Tabs
          items={[
            "Workloads",
            "Vulnerabilities",
            "Inspection Jobs",
            "Coverage",
          ]}
          value={tab}
          onChange={(v) => filters.set("tab", v)}
        />
        {tab === "Workloads" && (
          <>
            <Filters
              filters={filters}
              placeholder="Search workloads..."
              fields={{
                service: ["EC2", "ECS", "Lambda"],
                exposure: ["Public", "Private", "Unknown"],
              }}
            />
            <Table
              headers={[
                "Workload",
                "Type",
                "Account",
                "Exposure",
                "Inspection",
                "Evidence",
                "Cleanup",
                "Actions",
              ]}
              count={
                workloads.filter(
                  (a) =>
                    a.name.includes(filters.params.get("q") || "") &&
                    (!filters.params.get("service") ||
                      a.service === filters.params.get("service")) &&
                    (!filters.params.get("exposure") ||
                      a.exposure === filters.params.get("exposure")),
                ).length
              }
            >
              {workloads
                .filter(
                  (a) =>
                    a.name.includes(filters.params.get("q") || "") &&
                    (!filters.params.get("service") ||
                      a.service === filters.params.get("service")) &&
                    (!filters.params.get("exposure") ||
                      a.exposure === filters.params.get("exposure")),
                )
                .map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Link to={`/inventory/${a.id}`}>{a.name}</Link>
                    </td>
                    <td>{a.type}</td>
                    <td>{accountFor(a.account).name}</td>
                    <td>
                      <Badge>{a.exposure}</Badge>
                    </td>
                    <td>
                      <Badge>
                        {a.service !== "EC2"
                          ? "Unsupported"
                          : running
                            ? "In Progress"
                            : completed
                              ? "Verified"
                              : "Pending"}
                      </Badge>
                    </td>
                    <td>
                      {a.service === "EC2" && completed
                        ? "Sample snapshot"
                        : "Not collected"}
                    </td>
                    <td>
                      <Badge>
                        {a.service === "EC2" && completed
                          ? "Verified"
                          : "Not Applicable"}
                      </Badge>
                    </td>
                    <td>
                      <button
                        className="cs-button small"
                        onClick={() => setAsset(a.id)}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
            </Table>
          </>
        )}
        {tab === "Vulnerabilities" && (
          <div className="cs-panel-body">
            <Notice>
              No live workload vulnerability evidence collected. Uninspected
              workloads are Unknown, not vulnerability-free.
            </Notice>
            <div className="cs-link-cards">
              <Link to="/findings?service=EC2">
                <Server size={20} />
                <strong>Workload posture findings</strong>
                <ArrowRight size={15} />
              </Link>
              <Link to="/attack-paths">
                <GitBranch size={20} />
                <strong>Correlated attack paths</strong>
                <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        )}
        {tab === "Inspection Jobs" && (
          <Table
            headers={[
              "Job",
              "Source",
              "State",
              "Mount mode",
              "Cleanup",
              "Artifacts",
            ]}
          >
            {completed || running ? (
              <tr>
                <td>INSP-DEMO-001</td>
                <td>Sample EC2 snapshot</td>
                <td>
                  <Badge>{running ? "In Progress" : "Verified"}</Badge>
                </td>
                <td className="cs-mono">ro,noexec,nodev,nosuid</td>
                <td>
                  <Badge>{running ? "Pending" : "Verified"}</Badge>
                </td>
                <td>
                  {running
                    ? "Inspection in progress"
                    : "No cloud artifacts created"}
                </td>
              </tr>
            ) : (
              <tr>
                <td colSpan={6}>
                  <Empty
                    title="No inspection jobs"
                    text="Run a sample inspection to explore the job lifecycle."
                  />
                </td>
              </tr>
            )}
          </Table>
        )}
        {tab === "Coverage" && (
          <div className="cs-panel-body">
            <Details
              rows={[
                ["EC2 / EBS", "Snapshot inspection workflow planned"],
                ["ECS and Lambda", "Unsupported by the EBS snapshot workflow"],
                [
                  "Encrypted volumes",
                  "Key policy and scoped execution permissions must be validated",
                ],
                [
                  "Data handling",
                  "Store classifications and redacted evidence only",
                ],
                [
                  "Cleanup",
                  "Decoupled cleanup process and orphan resource tracking required",
                ],
                [
                  "Network reachability",
                  "Reachable / Blocked / Unverified / Not Applicable",
                ],
              ]}
            />
          </div>
        )}
      </Panel>
      {selected && (
        <Overlay title={selected.name} drawer onClose={() => setAsset(null)}>
          <Badge>
            {selected.service === "EC2" ? "Snapshot eligible" : "Unsupported"}
          </Badge>
          <Details
            rows={[
              ["Workload type", selected.type],
              ["Account", accountFor(selected.account).name],
              ["Region", selected.region],
              [
                "Inspection method",
                selected.service === "EC2"
                  ? "Agentless volume snapshot"
                  : "No EBS snapshot source",
              ],
              [
                "Inspection state",
                completed && selected.service === "EC2"
                  ? "Sample completed"
                  : "No fresh evidence",
              ],
              [
                "Cleanup state",
                completed && selected.service === "EC2"
                  ? "Demo verified; no artifacts created"
                  : "Not Applicable",
              ],
            ]}
          />
          <Jump to={`/inventory/${selected.id}`}>Open asset investigation</Jump>
        </Overlay>
      )}
    </div>
  );
}
function LockIcon(props: { size?: number }) {
  return <ShieldCheck {...props} />;
}
const terraformSample = `resource "aws_s3_bucket" "customer_data" {\n  bucket = "customer-data-prod"\n}\n\nresource "aws_s3_bucket_public_access_block" "customer_data" {\n  bucket = aws_s3_bucket.customer_data.id\n  block_public_acls       = false\n  block_public_policy     = false\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`;
const cloudFormationSample = `Resources:\n  CustomerData:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: customer-data-prod\n      PublicAccessBlockConfiguration:\n        BlockPublicAcls: false\n        BlockPublicPolicy: false\n        IgnorePublicAcls: true\n        RestrictPublicBuckets: true`;
export function IacSecurity() {
  const { canAct, notify, log } = useProduct();
  const [kind, setKind] = useState("Terraform");
  const [code, setCode] = useState(terraformSample);
  const [results, setResults] = useState<
    { line: number; text: string }[] | null
  >(null);
  const [baseline, setBaseline] = useState(false);
  const [scanning, setScanning] = useState(false);
  const scan = () => {
    setScanning(true);
    setTimeout(() => {
      const matches = code
        .split("\n")
        .map((text, i) => ({ text, line: i + 1 }))
        .filter((row) =>
          /(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets|BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)\s*[:=]\s*false\b/.test(
            row.text,
          ),
        );
      setResults(matches);
      setScanning(false);
      log(
        "IaC sample check",
        kind,
        "Unscanned",
        matches.length ? "BLOCK" : "WARN · Full parser not connected",
      );
      notify(
        matches.length
          ? `${matches.length} explicit public-access violations found`
          : "No sample-rule matches. Full policy evaluation required.",
      );
    }, 900);
  };
  return (
    <div className="cs-page">
      <Head title="Infrastructure as Code Security">
        {results && (
          <Badge>{results.length && !baseline ? "BLOCK" : "WARN"}</Badge>
        )}
        {canAct && (
          <button
            className="cs-button primary"
            disabled={scanning || !code.trim()}
            onClick={scan}
          >
            <RefreshCw size={15} className={scanning ? "cs-spin" : ""} />
            {scanning ? "Checking…" : "Scan configuration"}
          </button>
        )}
      </Head>
      <div className="cs-iac-inputs">
        {["Terraform", "CloudFormation"].map((k) => (
          <button
            className={`cs-panel ${kind === k ? "selected" : ""}`}
            key={k}
            onClick={() => {
              setKind(k);
              setCode(
                k === "Terraform" ? terraformSample : cloudFormationSample,
              );
              setResults(null);
              setBaseline(false);
            }}
          >
            <FileCode2 size={26} />
            <strong>{k}</strong>
            <span>
              {k === "Terraform"
                ? ".tf · HCL configuration"
                : ".yaml · Infrastructure template"}
            </span>
            {kind === k && <Check size={16} />}
          </button>
        ))}
      </div>
      <Notice kind="blue">
        Local preview checks explicit S3 public-access settings only. A complete
        parser and policy engine run in the connected IaC workspace. No match is
        not a passing security assessment.
      </Notice>
      <div className="cs-two-col">
        <Panel
          title={kind === "Terraform" ? "main.tf" : "template.yaml"}
          action={<Badge>Local preview</Badge>}
        >
          <textarea
            className="cs-code-editor"
            aria-label="Infrastructure configuration"
            value={code}
            onChange={(e) => {
              setCode(e.target.value);
              setResults(null);
              setBaseline(false);
            }}
            spellCheck={false}
          />
        </Panel>
        <Panel title="Pipeline evaluation">
          <div className="cs-panel-body">
            <Details
              rows={[
                [
                  "Pipeline status",
                  <Badge>
                    {results === null
                      ? "Not evaluated"
                      : results.length && !baseline
                        ? "BLOCK"
                        : "WARN"}
                  </Badge>,
                ],
                [
                  "Resources detected",
                  kind === "Terraform"
                    ? (code.match(/resource\s+"/g) || []).length
                    : (code.match(/Type:\s*AWS::/g) || []).length,
                ],
                ["Findings", results?.length ?? "Unknown"],
                [
                  "New violations",
                  results ? (baseline ? 0 : results.length) : "Unknown",
                ],
                [
                  "Baseline",
                  baseline
                    ? "Current preview accepted as baseline"
                    : "No baseline set",
                ],
                ["Policy coverage", "One sample rule · Partial"],
              ]}
            />
            {canAct && results && (
              <button
                className="cs-button"
                onClick={() => {
                  setBaseline(true);
                  log(
                    "IaC baseline saved",
                    kind,
                    "None",
                    "Current local preview",
                  );
                  notify(
                    "Local baseline saved for this session; pipeline remains WARN.",
                  );
                }}
              >
                Set current baseline
              </button>
            )}
          </div>
        </Panel>
      </div>
      <Panel title="Scan results">
        <Table
          headers={[
            "Severity",
            "Policy",
            "Resource",
            "File",
            "Source location",
            "Status",
          ]}
          empty={results !== null && !results.length}
        >
          {results?.map((r) => (
            <tr key={r.line}>
              <td>
                <Badge>High</Badge>
              </td>
              <td>
                <Link to="/policies/CS-S3-001">
                  CS-S3-001 · Public access setting disabled
                </Link>
              </td>
              <td>{kind === "Terraform" ? "customer_data" : "CustomerData"}</td>
              <td className="cs-mono">
                {kind === "Terraform" ? "main.tf" : "template.yaml"}
              </td>
              <td>
                <code>
                  Line {r.line}: {r.text.trim()}
                </code>
              </td>
              <td>
                <Badge>{baseline ? "Baseline" : "Open"}</Badge>
              </td>
            </tr>
          ))}
        </Table>
        {results === null && (
          <Empty
            title="Ready to inspect configuration"
            text="Paste Terraform or CloudFormation content and run the sample check."
          />
        )}
      </Panel>
    </div>
  );
}
export function Integrations() {
  const { workspace, update, canManage, log, notify } = useProduct();
  const [selected, setSelected] = useState("");
  const filters = useFilters();
  const tab = filters.params.get("tab") || "All";
  const integrations = [
    ["Jira", "Ticketing"],
    ["ServiceNow", "Ticketing"],
    ["Splunk", "SIEM"],
    ["Microsoft Sentinel", "SIEM"],
    ["GitHub", "Source Control"],
    ["GitLab", "Source Control"],
    ["Custom webhook", "Webhooks"],
    ["AWS", "Cloud"],
  ];
  return (
    <div className="cs-page">
      <Head title="Integrations" />
      <Tabs
        items={[
          "All",
          "Ticketing",
          "SIEM",
          "Webhooks",
          "Source Control",
          "Cloud",
        ]}
        value={tab}
        onChange={(v) => filters.set("tab", v)}
      />
      <Panel title="Security integration ecosystem">
        <Suspense fallback={<div className="cs-icon-cloud-loading">Loading integration icons…</div>}>
          <IntegrationIconCloud onSelect={setSelected} />
        </Suspense>
      </Panel>
      <div className="cs-integration-grid">
        {integrations
          .filter(([, category]) => tab === "All" || tab === category)
          .map(([name, category]) => (
            <Panel key={name}>
              <div className="cs-integration-card">
                <div className="cs-inline">
                  <span className="cs-integration-mark">
                    <Suspense fallback={name.slice(0, 2)}>
                      <IntegrationBrandIcon name={name} />
                    </Suspense>
                  </span>
                  <Badge>
                    {workspace.settings[`integration.${name}`]
                      ? "Draft configured"
                      : "Not connected"}
                  </Badge>
                </div>
                <h2>{name}</h2>
                <span className="cs-eyebrow">{category}</span>
                {name === "AWS" ? (
                  <Link className="cs-button" to="/accounts">
                    Manage accounts
                    <ArrowRight size={14} />
                  </Link>
                ) : canManage ? (
                  <button
                    className="cs-button"
                    onClick={() => setSelected(name)}
                  >
                    <Settings2 size={14} />
                    Configure
                  </button>
                ) : (
                  <Badge>Read Only</Badge>
                )}
              </div>
            </Panel>
          ))}
      </div>
      {selected && (
        <Overlay
          title={`Configure ${selected}`}
          onClose={() => setSelected("")}
        >
          <Notice kind="blue">
            Save a routing draft. Delivery remains disabled until the backend
            integration is connected.
          </Notice>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const values = Object.fromEntries(new FormData(e.currentTarget));
              update((s) => ({
                ...s,
                settings: {
                  ...s.settings,
                  [`integration.${selected}`]: JSON.stringify(values),
                },
              }));
              log(
                "Integration draft saved",
                selected,
                "Not connected",
                "Draft configured",
              );
              notify("Integration draft saved. No outbound delivery enabled.");
              setSelected("");
            }}
          >
            <Field label="Display name">
              <input name="name" defaultValue={selected} required />
            </Field>
            <Field label="Workspace URL">
              <input
                name="url"
                type="url"
                required
                placeholder="https://your-workspace.example.com"
              />
            </Field>
            <Field label="Routing scope">
              <select name="scope">
                <option>Critical and high findings</option>
                <option>All open findings</option>
                <option>Verification events</option>
              </select>
            </Field>
            <Field label="Owning team">
              <select name="team">
                <option>Platform Team</option>
                <option>Security Team</option>
              </select>
            </Field>
            <button className="cs-button primary">Save routing draft</button>
          </form>
        </Overlay>
      )}
    </div>
  );
}
export function AuditLogs() {
  const { workspace, inScope } = useProduct();
  const filters = useFilters();
  const rows = workspace.audit.filter((a) => {
    const finding = workspace.findings.find((f) => f.id === a.object);
    const account = accounts.find(
      (acc) => acc.id === a.object || acc.name === a.object,
    );
    return (
      (!finding || inScope(assetFor(finding).account, assetFor(finding).region)) &&
      (!account || inScope(account.id)) &&
      `${a.actor} ${a.action} ${a.object} ${a.next}`
        .toLowerCase()
        .includes((filters.params.get("q") || "").toLowerCase()) &&
      (!filters.params.get("actor") || a.actor === filters.params.get("actor"))
    );
  });
  return (
    <div className="cs-page">
      <Head title="Audit Logs">
        <button
          className="cs-button"
          onClick={() => download("cloudsentinel-audit", rows, "csv")}
        >
          <Download size={15} />
          Export log
        </button>
      </Head>
      <Panel>
        <Filters
          filters={filters}
          placeholder="Search actor, action, or object..."
          fields={{ actor: [...new Set(workspace.audit.map((a) => a.actor))] }}
        />
        <Table
          headers={[
            "Timestamp",
            "Actor",
            "Action",
            "Object",
            "Previous value",
            "New value",
            "Result",
          ]}
          count={rows.length}
          empty={!rows.length}
        >
          {rows.map((a) => (
            <tr key={a.id}>
              <td className="cs-mono">
                {a.time.replace("T", " ").slice(0, 19)} UTC
              </td>
              <td>{a.actor}</td>
              <td>{a.action}</td>
              <td>
                {a.object.startsWith("CS-") ? (
                  <Link to={`/findings/${a.object}`}>{a.object}</Link>
                ) : (
                  a.object
                )}
              </td>
              <td>{a.previous}</td>
              <td className="cs-wrap-cell">{a.next}</td>
              <td>
                <Badge>{a.result}</Badge>
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
    </div>
  );
}
export function Settings() {
  const { workspace, canManage, update, notify, log, role } = useProduct();
  const filters = useFilters();
  const tab = filters.params.get("tab") || "Cloud Scope";
  const settings = workspace.settings;
  const fieldGroups: Record<string, [string, string, string[]][]> = {
    "Cloud Scope": [
      ["Default region", "region", ["ap-south-1", "us-east-1", "eu-west-1"]],
    ],
    Scanning: [
      [
        "Scan frequency",
        "cadence",
        ["Every 6 hours", "Every 12 hours", "Daily"],
      ],
    ],
    Risk: [
      ["Escalation threshold", "threshold", ["Critical", "High", "Medium"]],
    ],
    Policies: [
      [
        "Default policy pack",
        "pack",
        ["AWS foundational controls", "Production baseline"],
      ],
    ],
    Exceptions: [
      [
        "Maximum exception duration",
        "expiry",
        ["7 days", "30 days", "90 days"],
      ],
    ],
    Routing: [
      [
        "Default finding owner",
        "routing",
        ["Platform Team", "Security Team", "Payments Team"],
      ],
    ],
    Authentication: [
      ["Session lifetime", "session", ["1 hour", "8 hours", "24 hours"]],
    ],
  };
  return (
    <div className="cs-page">
      <Head title="Settings">
        <Badge>{role}</Badge>
      </Head>
      <div className="cs-settings-layout">
        <nav aria-label="Settings sections" className="cs-settings-nav">
          {[
            "Cloud Scope",
            "Scanning",
            "Risk",
            "Policies",
            "Exceptions",
            "Routing",
            "Authentication",
            "RBAC",
          ].map((item) => (
            <button
              key={item}
              className={tab === item ? "active" : ""}
              onClick={() => filters.set("tab", item)}
            >
              {item}
              <ChevronRight size={14} />
            </button>
          ))}
        </nav>
        <Panel title={tab}>
          <div className="cs-panel-body">
            {tab === "RBAC" ? (
              <>
                <Notice kind="blue">
                  Role preview controls demo actions. Production permissions
                  require enforcement by the API.
                </Notice>
                <Table
                  headers={[
                    "Capability",
                    "Read Only",
                    "Security Analyst",
                    "Administrator",
                  ]}
                >
                  {[
                    ["View and investigate", "Yes", "Yes", "Yes"],
                    ["Assign and request exception", "No", "Yes", "Yes"],
                    ["Approve and configure", "No", "No", "Yes"],
                    [
                      "Live cloud mutation",
                      "No",
                      "No",
                      "Backend authorization required",
                    ],
                  ].map((row) => (
                    <tr key={row[0]}>
                      {row.map((v, i) => (
                        <td key={i}>{v}</td>
                      ))}
                    </tr>
                  ))}
                </Table>
              </>
            ) : (
              <form
                key={tab}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!canManage) return;
                  const changes = Object.fromEntries(
                    new FormData(e.currentTarget),
                  ) as Record<string, string>;
                  update((s) => ({
                    ...s,
                    settings: { ...s.settings, ...changes },
                  }));
                  log(
                    "Workspace settings updated",
                    tab,
                    JSON.stringify(
                      Object.fromEntries(
                        Object.keys(changes).map((k) => [k, settings[k]]),
                      ),
                    ),
                    JSON.stringify(changes),
                  );
                  notify("Demo workspace preferences saved");
                }}
              >
                <Notice kind="blue">
                  Preferences persist in this demo browser. Production schedules
                  and controls require backend integration.
                </Notice>
                {(fieldGroups[tab] || fieldGroups["Cloud Scope"]).map(
                  ([label, key, choices]) => (
                    <Field label={label} key={key}>
                      <select
                        name={key}
                        defaultValue={settings[key] || choices[0]}
                        disabled={!canManage}
                      >
                        {choices.map((choice) => (
                          <option key={choice}>{choice}</option>
                        ))}
                      </select>
                    </Field>
                  ),
                )}
                {tab === "Authentication" && (
                  <Details
                    rows={[
                      ["Identity provider", "Not connected"],
                      ["SSO", "Requires identity provider integration"],
                      ["Production authorization", "Enforced server-side"],
                    ]}
                  />
                )}
                {canManage && (
                  <button className="cs-button primary">Save changes</button>
                )}
              </form>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
export function ConnectedUnavailable({ title }: { title: string }) {
  const { setDemo } = useProduct();
  return (
    <div className="cs-page">
      <Head title={title} />
      <Panel>
        <Empty
          title="Backend integration required"
          text="This workflow is available in the demo workspace. Its live data source has not been connected."
        />
        <div className="cs-empty-action">
          <button className="cs-button" onClick={() => setDemo(true)}>
            Explore demo workspace
            <ArrowRight size={15} />
          </button>
        </div>
      </Panel>
    </div>
  );
}
