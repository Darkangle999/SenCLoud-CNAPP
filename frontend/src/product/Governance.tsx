import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Download,
  FileCheck2,
  FileText,
  Plus,
  ShieldCheck,
} from "lucide-react";
import { accounts, assetFor, assets, frameworks, isActive } from "./data";
import { useProduct } from "./store";
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
import { ExceptionModal, FindingTable } from "./Investigations";
import { useAccountScope } from "../lib/accountScope";
import { serviceAllowsAsset } from "./services";

export function Compliance() {
  const { frameworkId } = useParams();
  const { workspace, inScope } = useProduct();
  const filters = useFilters();
  const selected = frameworks.find((f) => f.id === frameworkId);
  const findings = workspace.findings.filter((f) =>
    inScope(assetFor(f).account, assetFor(f).region),
  );
  const controls = [...new Map(findings.map((f) => [f.policy, f])).values()];
  const statuses = [
    "Fail",
    "Fail",
    "Fail",
    "Pass",
    "Unknown",
    "Error",
    "Not Applicable",
    "Uncovered",
  ];
  return (
    <div className="cs-page">
      {selected && (
        <Link className="cs-back" to="/compliance">
          <ArrowLeft size={14} />
          Compliance
        </Link>
      )}
      <Head title={selected ? selected.name : "Compliance Posture"}>
        <Link className="cs-button" to="/reports?type=Compliance+Report">
          <Download size={15} />
          Export evidence
        </Link>
      </Head>
      <Notice kind="blue">
        Technical posture evidence — not certification. Organizational and
        procedural controls require additional evidence.
      </Notice>
      {!selected ? (
        <div className="cs-framework-grid">
          {frameworks.map((f) => (
            <Link
              className="cs-panel cs-framework-card"
              to={`/compliance/${f.id}`}
              key={f.id}
            >
              <div className="cs-inline">
                <span className="cs-framework-icon">
                  <ShieldCheck size={24} />
                </span>
                <Badge>{f.version}</Badge>
              </div>
              <h2>{f.name}</h2>
              <div className="cs-framework-score">
                <strong>{f.score}</strong>
                <span>% technical posture</span>
              </div>
              <div className="cs-progress">
                <span style={{ width: `${f.score}%` }} />
              </div>
              <div className="cs-framework-counts">
                <span>
                  <i className="green" />
                  {f.passed} passed
                </span>
                <span>
                  <i className="red" />
                  {f.failed} failed
                </span>
                <span>{f.unknown} unknown</span>
                <span>{f.uncovered} uncovered</span>
              </div>
              <div className="cs-framework-footer">
                <span>
                  {
                    workspace.exceptions.filter((e) =>
                      findings.some((x) => x.id === e.finding),
                    ).length
                  }{" "}
                  exceptions
                </span>
                <span>
                  Review controls
                  <ArrowRight size={14} />
                </span>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <Panel
          title={`${selected.version} · Technical control evidence`}
          action={<Badge>Demo mapping</Badge>}
        >
          <Filters
            filters={filters}
            placeholder="Search controls or policies..."
            fields={{ status: statuses }}
          />
          <Table
            headers={[
              "Control ID",
              "Control",
              "Status",
              "Evidence",
              "Policy",
              "Exception",
              "Freshness",
            ]}
            count={
              controls.filter(
                (f, i) =>
                  (!filters.params.get("status") ||
                    filters.params.get("status") === statuses[i]) &&
                  `${f.title} ${f.policy}`
                    .toLowerCase()
                    .includes((filters.params.get("q") || "").toLowerCase()),
              ).length
            }
          >
            {controls
              .map((f, i) => ({ f, i }))
              .filter(
                ({ f, i }) =>
                  (!filters.params.get("status") ||
                    filters.params.get("status") === statuses[i]) &&
                  `${f.title} ${f.policy}`
                    .toLowerCase()
                    .includes((filters.params.get("q") || "").toLowerCase()),
              )
              .map(({ f, i }) => (
                <tr key={f.id}>
                  <td className="cs-mono">
                    {selected.id.toUpperCase()}-{i + 1}.1
                  </td>
                  <td>
                    <Link to={`/findings?policy=${f.policy}`}>{f.title}</Link>
                  </td>
                  <td>
                    <Badge>{statuses[i]}</Badge>
                  </td>
                  <td>
                    <Link to={`/findings/${f.id}?tab=Evidence`}>
                      {statuses[i] === "Uncovered"
                        ? "Not collected"
                        : "Inspect evidence"}
                    </Link>
                  </td>
                  <td>
                    <Link to={`/policies/${f.policy}`}>{f.policy}</Link>
                  </td>
                  <td>
                    <Link to="/exceptions">
                      {workspace.exceptions.filter((e) => e.finding === f.id)
                        .length || "None"}
                    </Link>
                  </td>
                  <td>
                    <Badge>
                      {statuses[i] === "Unknown" ? "Unknown" : "Verified"}
                    </Badge>
                  </td>
                </tr>
              ))}
          </Table>
          <div className="cs-panel-body">
            <Notice kind="blue">
              Control IDs and mappings are illustrative demo records, not an
              authoritative framework assessment.
            </Notice>
          </div>
        </Panel>
      )}
      {!selected && (
        <Panel
          title="Controls requiring attention"
          action={<Jump to="/findings">Review findings</Jump>}
        >
          <FindingTable
            findings={findings
              .filter((f) => f.severity === "Critical")
              .slice(0, 4)}
          />
        </Panel>
      )}
    </div>
  );
}
export function Policies() {
  const { policyId } = useParams();
  const { workspace, inScope, canManage, update, notify, log } = useProduct();
  const filters = useFilters();
  const tab = filters.params.get("tab") || "Built-in";
  const [create, setCreate] = useState(false);
  const policies = [
    ...new Map(workspace.findings.map((f) => [f.policy, f])).values(),
  ];
  const policy =
    workspace.findings.find(
      (f) =>
        f.policy === policyId &&
        inScope(assetFor(f).account, assetFor(f).region),
    ) || policies.find((f) => f.policy === policyId);
  const custom = Object.entries(workspace.settings).filter(([k]) =>
    k.startsWith("policy."),
  );
  if (policyId && !policy)
    return (
      <Empty
        title="Policy not found"
        text="Return to the catalog to select an available policy."
      />
    );
  return (
    <div className="cs-page">
      {policy && (
        <Link className="cs-back" to="/policies">
          <ArrowLeft size={14} />
          Policies
        </Link>
      )}
      <Head
        title={policy ? policy.title : "Policy Catalog"}
        meta={
          policy && (
            <>
              <Badge>{policy.severity}</Badge>
              <span>{policy.policy}</span>
              <Badge>Active</Badge>
              <span>v2.4.1</span>
            </>
          )
        }
      >
        {!policy && canManage && (
          <button className="cs-button primary" onClick={() => setCreate(true)}>
            <Plus size={15} />
            Create policy draft
          </button>
        )}
      </Head>
      {policy ? (
        <Panel>
          <Tabs
            items={[
              "Description",
              "Logic",
              "Parameters",
              "Evidence",
              "Remediation",
              "Compliance Mapping",
              "Version History",
            ]}
            value={filters.params.get("tab") || "Description"}
            onChange={(v) => filters.set("tab", v)}
          />
          <div className="cs-panel-body">
            {(!filters.params.get("tab") ||
              filters.params.get("tab") === "Description") && (
              <>
                <h3>Description & rationale</h3>
                <p>
                  {policy.title}. Evaluate the observed resource configuration
                  against the required state and retain source evidence.
                </p>
                <Details
                  rows={[
                    ["Policy ID", policy.policy],
                    ["Provider", "AWS"],
                    ["Resource type", assetFor(policy).type],
                    ["Vendor severity", policy.vendor],
                    ["Evidence source", policy.source],
                    ["Required state", policy.required],
                  ]}
                />
                <h3>Affected findings</h3>
                <FindingTable
                  findings={workspace.findings.filter(
                    (f) =>
                      f.policy === policy.policy &&
                      inScope(assetFor(f).account, assetFor(f).region),
                  )}
                />
              </>
            )}
            {filters.params.get("tab") === "Logic" && (
              <div className="cs-code-block">
                <span>Declarative policy · v2.4.1</span>
                <pre>
                  {JSON.stringify(
                    {
                      id: policy.policy,
                      resource_type: assetFor(policy).type,
                      source: policy.source,
                      required_state: policy.required,
                      on_missing_evidence: "Unknown",
                      evaluation:
                        "Compare observed configuration with required state",
                    },
                    null,
                    2,
                  )}
                </pre>
              </div>
            )}
            {filters.params.get("tab") === "Parameters" && (
              <Details
                rows={[
                  ["Scope", "All configured AWS accounts"],
                  ["Severity", policy.vendor],
                  ["Evaluation cadence", workspace.settings.cadence],
                  ["Missing evidence", "Unknown"],
                  ["Evidence retention", "90 days"],
                ]}
              />
            )}
            {filters.params.get("tab") === "Evidence" && (
              <>
                <Notice kind="blue">
                  Every evaluation retains source, observed state, timestamp,
                  and policy version.
                </Notice>
                <Jump to={`/findings/${policy.id}?tab=Evidence`}>
                  Inspect evaluation evidence
                </Jump>
              </>
            )}
            {filters.params.get("tab") === "Remediation" && (
              <>
                <p>{policy.fix}</p>
                <Jump to={`/findings/${policy.id}?tab=Remediation`}>
                  Review operational impact and rollback
                </Jump>
              </>
            )}
            {filters.params.get("tab") === "Compliance Mapping" && (
              <>
                <Notice kind="blue">
                  Illustrative technical mappings require review against
                  licensed framework control definitions.
                </Notice>
                <div className="cs-link-cards">
                  {frameworks.map((f) => (
                    <Link to={`/compliance/${f.id}`} key={f.id}>
                      <ShieldCheck size={18} />
                      <strong>{f.name}</strong>
                      <ArrowRight size={15} />
                    </Link>
                  ))}
                </div>
              </>
            )}
            {filters.params.get("tab") === "Version History" && (
              <Table headers={["Version", "Published", "Change", "Status"]}>
                <tr>
                  <td>2.4.1</td>
                  <td>Sep 1, 2026</td>
                  <td>Require explicit source evidence for evaluation</td>
                  <td>
                    <Badge>Active</Badge>
                  </td>
                </tr>
                <tr>
                  <td>2.3.0</td>
                  <td>Aug 12, 2026</td>
                  <td>Contextual risk enrichment</td>
                  <td>
                    <Badge>Deprecated</Badge>
                  </td>
                </tr>
              </Table>
            )}
          </div>
        </Panel>
      ) : (
        <Panel>
          <Tabs
            items={["Built-in", "Custom", "Draft", "Active", "Deprecated"]}
            value={tab}
            onChange={(v) => filters.set("tab", v)}
          />
          <Filters
            filters={filters}
            placeholder="Search policy names and IDs..."
            fields={{ severity: ["Critical", "High", "Medium", "Low"] }}
          />
          <Table
            headers={[
              "Policy ID",
              "Policy name",
              "Provider",
              "Resource type",
              "Severity",
              "Version",
              "Status",
              "Scope",
            ]}
            count={
              ["Custom", "Draft"].includes(tab)
                ? custom.length
                : tab === "Deprecated"
                  ? 0
                  : policies.filter(
                      (f) =>
                        `${f.title} ${f.policy}`
                          .toLowerCase()
                          .includes(
                            (filters.params.get("q") || "").toLowerCase(),
                          ) &&
                        (!filters.params.get("severity") ||
                          filters.params
                            .get("severity")!
                            .split(",")
                            .includes(f.vendor)),
                    ).length
            }
            empty={
              tab === "Deprecated" ||
              (["Custom", "Draft"].includes(tab) && !custom.length)
            }
          >
            {["Custom", "Draft"].includes(tab)
              ? custom.map(([key, raw]) => {
                  const item = JSON.parse(raw) as {
                    name: string;
                    logic: string;
                    severity: string;
                  };
                  return (
                    <tr key={key}>
                      <td>{key.slice(7)}</td>
                      <td>
                        <strong>{item.name}</strong>
                        <span className="cs-cell-sub">{item.logic}</span>
                      </td>
                      <td>AWS</td>
                      <td>Custom scope</td>
                      <td>
                        <Badge>{item.severity}</Badge>
                      </td>
                      <td>0.1.0</td>
                      <td>
                        <Badge>Draft</Badge>
                      </td>
                      <td>Not evaluated</td>
                    </tr>
                  );
                })
              : tab !== "Deprecated" &&
                policies
                  .filter(
                    (f) =>
                      `${f.title} ${f.policy}`
                        .toLowerCase()
                        .includes(
                          (filters.params.get("q") || "").toLowerCase(),
                        ) &&
                      (!filters.params.get("severity") ||
                        filters.params
                          .get("severity")!
                          .split(",")
                          .includes(f.vendor)),
                  )
                  .map((f) => (
                    <tr key={f.policy}>
                      <td>
                        <Link className="cs-mono" to={`/policies/${f.policy}`}>
                          {f.policy}
                        </Link>
                      </td>
                      <td>
                        <Link to={`/policies/${f.policy}`}>{f.title}</Link>
                      </td>
                      <td>AWS</td>
                      <td>{assetFor(f).type}</td>
                      <td>
                        <Badge>{f.vendor}</Badge>
                      </td>
                      <td>2.4.1</td>
                      <td>
                        <Badge>Active</Badge>
                      </td>
                      <td>All AWS accounts</td>
                    </tr>
                  ))}
          </Table>
        </Panel>
      )}
      {create && (
        <Overlay
          title="Create custom policy draft"
          onClose={() => setCreate(false)}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const form = new FormData(e.currentTarget);
              const id = `CUSTOM-${Date.now().toString().slice(-6)}`;
              update((s) => ({
                ...s,
                settings: {
                  ...s.settings,
                  [`policy.${id}`]: JSON.stringify(Object.fromEntries(form)),
                },
              }));
              log("Policy draft created", id, "None", "Draft");
              notify(
                "Policy draft saved. Evaluation requires backend policy integration.",
              );
              setCreate(false);
              filters.set("tab", "Draft");
            }}
          >
            <Field label="Policy name">
              <input name="name" required minLength={5} />
            </Field>
            <Field label="Evaluation logic">
              <textarea
                name="logic"
                required
                minLength={20}
                placeholder="Define the resource scope, expected state, and required evidence."
              />
            </Field>
            <Field label="Severity">
              <select name="severity">
                {["Critical", "High", "Medium", "Low"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </Field>
            <button className="cs-button primary">Save draft</button>
          </form>
        </Overlay>
      )}
    </div>
  );
}
export function Exceptions() {
  const { workspace, inScope, canAct, canManage, update, notify, log } =
    useProduct();
  const [request, setRequest] = useState(false);
  const [selected, setSelected] = useState(workspace.findings[0].id);
  const filters = useFilters();
  const findings = workspace.findings.filter((f) =>
    inScope(assetFor(f).account, assetFor(f).region),
  );
  const rows = workspace.exceptions.filter(
    (e) =>
      findings.some((f) => f.id === e.finding) &&
      (!filters.params.get("status") ||
        filters.params.get("status") === e.status) &&
      `${e.reason} ${e.finding}`
        .toLowerCase()
        .includes((filters.params.get("q") || "").toLowerCase()),
  );
  const change = (id: string, status: string) => {
    const old = workspace.exceptions.find((e) => e.id === id)!;
    update((s) => ({
      ...s,
      exceptions: s.exceptions.map((e) => (e.id === id ? { ...e, status } : e)),
      findings: s.findings.map((f) =>
        f.id === old.finding
          ? {
              ...f,
              status:
                status === "Active"
                  ? "Accepted Risk"
                  : f.status === "Accepted Risk"
                    ? "Open"
                    : f.status,
            }
          : f,
      ),
    }));
    log(`Exception ${status.toLowerCase()}`, old.finding, old.status, status);
    notify(`Exception ${status.toLowerCase()}`);
  };
  return (
    <div className="cs-page">
      <Head title="Exceptions">
        {canAct && findings.length > 0 && (
          <button
            className="cs-button primary"
            onClick={() => {
              setSelected(findings[0].id);
              setRequest(true);
            }}
          >
            <Plus size={15} />
            Request exception
          </button>
        )}
      </Head>
      <Notice>
        Exception does not remove the underlying security finding. Accepted risk
        remains visible until expiry or revocation.
      </Notice>
      <Panel>
        <Filters
          filters={filters}
          placeholder="Search findings or reasons..."
          fields={{
            status: [
              "Pending Approval",
              "Active",
              "Expiring Soon",
              "Expired",
              "Revoked",
            ],
          }}
        />
        <Table
          headers={[
            "Finding",
            "Risk",
            "Owner",
            "Reason",
            "Scope",
            "Expiry",
            "Approver",
            "Status",
            "Actions",
          ]}
          count={rows.length}
          empty={!rows.length}
        >
          {rows.map((e) => {
            const f = workspace.findings.find((f) => f.id === e.finding)!;
            return (
              <tr key={e.id}>
                <td>
                  <Link to={`/findings/${f.id}`}>{f.id}</Link>
                  <span className="cs-cell-sub">{e.id}</span>
                </td>
                <td>
                  <Badge>{f.severity}</Badge>
                </td>
                <td>{f.owner}</td>
                <td className="cs-wrap-cell">
                  <strong>{e.reason}</strong>
                  <span className="cs-cell-sub">{e.control}</span>
                </td>
                <td>{e.scope}</td>
                <td>{e.expiry}</td>
                <td>{e.approver}</td>
                <td>
                  <Badge>{e.status}</Badge>
                </td>
                <td>
                  {canManage && e.status === "Pending Approval" ? (
                    <button
                      className="cs-button small"
                      onClick={() => change(e.id, "Active")}
                    >
                      <Check size={13} />
                      Approve
                    </button>
                  ) : canManage &&
                    ["Active", "Expiring Soon"].includes(e.status) ? (
                    <button
                      className="cs-button small"
                      onClick={() => change(e.id, "Revoked")}
                    >
                      Revoke
                    </button>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            );
          })}
        </Table>
      </Panel>
      {request && (
        <Overlay title="Select finding" onClose={() => setRequest(false)}>
          <Field label="Finding">
            <select
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
            >
              {findings.map((f) => (
                <option value={f.id} key={f.id}>
                  {f.id} · {f.title}
                </option>
              ))}
            </select>
          </Field>
          <button
            className="cs-button primary"
            onClick={() => {
              setRequest(false);
              filters.set("request", selected);
            }}
          >
            Continue
            <ArrowRight size={15} />
          </button>
        </Overlay>
      )}
      {canAct &&
        filters.params.get("request") &&
        findings.some((f) => f.id === filters.params.get("request")) && (
          <ExceptionModal
            finding={findings.find(
              (f) => f.id === filters.params.get("request"),
            )!}
            onClose={() => filters.set("request", "")}
          />
        )}
    </div>
  );
}
export function Reports() {
  const { workspace, scope, service, subscribedServices, inScope, notify, log } = useProduct();
  const { region: serverRegion } = useAccountScope();
  const { params } = useFilters();
  const [type, setType] = useState(params.get("type") || "Executive Report");
  const [format, setFormat] = useState("csv");
  const [severity, setSeverity] = useState("");
  const [region, setRegion] = useState(serverRegion);
  const [framework, setFramework] = useState("cis");
  const [policy, setPolicy] = useState("");
  const [start, setStart] = useState("2026-08-07");
  const [end, setEnd] = useState("2026-09-06");
  useEffect(() => setRegion(serverRegion), [serverRegion]);
  const reportTypes = [
    "Executive Report",
    "Findings Report",
    "Asset Inventory",
    "Coverage Report",
    "Compliance Report",
    "Risk Trend",
    "Exception Report",
    "Remediation Report",
  ];
  const generate = () => {
    const evidenceIncluded = start <= "2026-09-06" && end >= "2026-09-06";
    const scopedAssets = assets.filter(
      (a) =>
        evidenceIncluded &&
        inScope(a.account, a.region) &&
        serviceAllowsAsset(service, a, subscribedServices) &&
        (a.region === region || a.region === "Global"),
    );
    const findings = workspace.findings.filter(
      (f) =>
        scopedAssets.some((a) => a.id === f.asset) &&
        (!severity || f.severity === severity) &&
        (!policy || f.policy === policy),
    );
    const meta = {
      data_mode: "demo",
      cnapp_service: service,
      scope,
      date_from: start,
      date_to: end,
      generated_at: new Date().toISOString(),
      evidence_observed: "2026-09-06T08:48:00Z",
      coverage_limitation:
        "Development: network ACL evidence missing; Shared Services: evidence stale. Technical posture is not certification.",
    };
    const records =
      type === "Asset Inventory"
        ? scopedAssets
        : type === "Exception Report"
          ? workspace.exceptions.filter((e) =>
              findings.some((f) => f.id === e.finding),
            )
          : type === "Remediation Report"
            ? workspace.remediations.filter((r) =>
                findings.some((f) => f.id === r.finding),
              )
            : type === "Coverage Report"
              ? accounts.filter(
                  (a) =>
                    evidenceIncluded &&
                    inScope(a.id),
                )
              : type === "Compliance Report"
                ? frameworks
                    .filter((f) => evidenceIncluded && f.id === framework)
                    .map((f) => ({
                      ...f,
                      mapping:
                        "Illustrative demo framework aggregate; not a scoped certification assessment",
                    }))
                : type === "Risk Trend"
                  ? evidenceIncluded
                    ? [
                        {
                          date: "2026-09-06",
                          active_findings: findings.filter(isActive).length,
                          historical_series:
                            "No historical evidence within this sample export",
                        },
                      ]
                    : []
                  : type === "Executive Report"
                    ? evidenceIncluded
                      ? [
                          {
                            active_findings: findings.filter(isActive).length,
                            critical_findings: findings.filter(
                              (f) => isActive(f) && f.severity === "Critical",
                            ).length,
                            assets: scopedAssets.length,
                          },
                        ]
                      : []
                    : findings;
    if (format === "report") {
      const escape = (s: string) =>
        s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      const html = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Odineyes ${escape(type)}</title><style>body{font:14px system-ui;color:#1c3028;max-width:960px;margin:48px auto;padding:24px}h1{font-size:28px}pre{white-space:pre-wrap;border:1px solid #ddd;padding:24px;background:#fafafa}p{line-height:1.6}</style><h1>Odineyes · ${escape(type)}</h1><p>Scope: ${escape(scope)} · ${escape(start)} through ${escape(end)}</p><p>${escape(meta.coverage_limitation)}</p><p>Demo evidence snapshot: ${meta.evidence_observed}</p><pre>${escape(JSON.stringify(records, null, 2))}</pre></html>`;
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `cloudsentinel-${type.toLowerCase().replace(/ /g, "-")}.html`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } else
      download(
        `cloudsentinel-${type.toLowerCase().replace(/ /g, "-")}`,
        format === "csv"
          ? records.length
            ? records.map((r) => ({ ...r, ...meta }))
            : [{ ...meta, result: "No matching records" }]
          : { ...meta, records },
        format,
      );
    log(
      "Report exported",
      type,
      "None",
      `${format.toUpperCase()} · ${records.length} records`,
    );
    notify(`Report exported · ${records.length} records`);
  };
  return (
    <div className="cs-page">
      <Head title="Reports" />
      <div className="cs-report-layout">
        <div className="cs-report-grid">
          {reportTypes.map((name, i) => (
            <button
              key={name}
              className={`cs-panel cs-report-card ${type === name ? "selected" : ""}`}
              onClick={() => setType(name)}
            >
              <span className="cs-report-icon">
                {i % 2 ? <FileCheck2 size={22} /> : <FileText size={22} />}
              </span>
              <h3>{name}</h3>
              <div>
                {type === name ? (
                  <>
                    <Check size={14} />
                    Selected
                  </>
                ) : (
                  <>
                    Configure report
                    <ArrowRight size={14} />
                  </>
                )}
              </div>
            </button>
          ))}
        </div>
        <Panel title="Report configuration">
          <form
            className="cs-panel-body"
            onSubmit={(e) => {
              e.preventDefault();
              generate();
            }}
          >
            <Field label="Report">
              <input readOnly value={type} />
            </Field>
            <Field label="Global scope">
              <input
                readOnly
                value={accounts.find((item) => item.id === scope)?.name || scope}
              />
            </Field>
            <div className="cs-two-col">
              <Field label="From">
                <input
                  type="date"
                  value={start}
                  max={end}
                  onChange={(e) => setStart(e.target.value)}
                  required
                />
              </Field>
              <Field label="To">
                <input
                  type="date"
                  value={end}
                  min={start}
                  onChange={(e) => setEnd(e.target.value)}
                  required
                />
              </Field>
            </div>
            <Field label="Account">
              <input
                readOnly
                value={accounts.find((item) => item.id === scope)?.name || scope}
              />
            </Field>
            <Field label="Region">
              <select
                value={region}
                onChange={(e) => setRegion(e.target.value)}
              >
                {(accounts.find((item) => item.id === scope)?.regions || [serverRegion]).map(
                  (item) => <option key={item}>{item}</option>,
                )}
              </select>
            </Field>
            <Field label="Severity">
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                <option value="">All severities</option>
                {["Critical", "High", "Medium", "Low"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </Field>
            <Field label="Policy">
              <select
                value={policy}
                onChange={(e) => setPolicy(e.target.value)}
              >
                <option value="">All policies</option>
                {[...new Set(workspace.findings.map((f) => f.policy))].map(
                  (p) => (
                    <option key={p}>{p}</option>
                  ),
                )}
              </select>
            </Field>
            {type === "Compliance Report" && (
              <Field label="Framework">
                <select
                  value={framework}
                  onChange={(e) => setFramework(e.target.value)}
                >
                  {frameworks.map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.name}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            <Field label="Format">
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value)}
              >
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
                <option value="report">Report · Printable HTML</option>
              </select>
            </Field>
            <Notice kind="blue">
              Exports include evidence timestamps and coverage limitations.
            </Notice>
            <button className="cs-button primary cs-full">
              <Download size={15} />
              Generate report
            </button>
          </form>
        </Panel>
      </div>
    </div>
  );
}
