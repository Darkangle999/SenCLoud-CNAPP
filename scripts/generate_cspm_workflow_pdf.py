"""Generate the CSPM code-and-data-flow walkthrough PDF without extra deps."""

from __future__ import annotations

from pathlib import Path
from textwrap import wrap


OUT = Path(__file__).resolve().parents[1] / "docs" / "CSPM_APPLICATION_WORKFLOW.pdf"
PAGE_W, PAGE_H = 612, 792
LEFT, RIGHT, TOP, BOTTOM = 48, 48, 742, 48


def safe(text: str) -> str:
    replacements = {
        "->": "->", "=>": "=>", "--": "--", "'": "'", '"': '"',
        "\u2013": "-", "\u2014": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u2192": "->",
        "\u00d7": "x", "\u2260": "!=",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode("latin-1", "replace").decode("latin-1")


def escape_pdf(text: str) -> str:
    return safe(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class FlowPDF:
    def __init__(self) -> None:
        self.pages: list[list[tuple[str, str, float]]] = []
        self.lines: list[tuple[str, str, float]] = []
        self.y = TOP

    def new_page(self) -> None:
        if self.lines:
            self.pages.append(self.lines)
        self.lines = []
        self.y = TOP

    def _room(self, needed: float) -> None:
        if self.y - needed < BOTTOM:
            self.new_page()

    def title(self, text: str) -> None:
        self._room(34)
        self.lines.append(("title", text, self.y))
        self.y -= 27

    def section(self, text: str) -> None:
        """Keep a numbered stage with a meaningful amount of opening content."""
        self._room(228)
        if self.y < TOP:
            self.y -= 8
        self.lines.append(("title", text, self.y))
        self.y -= 27

    def heading(self, text: str) -> None:
        # Keep a subheading with enough of its content to avoid lonely headings
        # at the bottom of a page.
        self._room(58)
        self.lines.append(("heading", text, self.y))
        self.y -= 19

    def body(self, text: str, bullet: bool = False) -> None:
        prefix = "- " if bullet else ""
        width = 90 if not bullet else 86
        pieces = wrap(safe(text), width=width, break_long_words=False, break_on_hyphens=False) or [""]
        for index, piece in enumerate(pieces):
            self._room(14)
            self.lines.append(("body", (prefix if index == 0 else "  ") + piece, self.y))
            self.y -= 13
        self.y -= 3

    def code(self, text: str) -> None:
        code_lines = text.strip("\n").splitlines()
        self._room(12 * min(len(code_lines), 14) + 12)
        for line in code_lines:
            # Keep code readable rather than overflowing its page.
            chunks = wrap(safe(line), width=92, replace_whitespace=False, drop_whitespace=False) or [""]
            for chunk in chunks:
                self._room(11)
                self.lines.append(("code", chunk, self.y))
                self.y -= 10
        self.y -= 7

    def callout(self, text: str) -> None:
        pieces = wrap(safe(text), width=84, break_long_words=False) or [""]
        self._room(13 * len(pieces) + 10)
        for piece in pieces:
            self.lines.append(("callout", piece, self.y))
            self.y -= 12
        self.y -= 4

    def architecture_diagram(self) -> None:
        """Add a compact, vector-rendered view of the Mermaid architecture model."""
        self._room(565)
        self.lines.append(("architecture", "", self.y))
        self.y -= 555

    def finalize(self) -> bytes:
        self.new_page()
        objects: list[bytes] = []
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        page_refs = []
        content_refs = []
        # Fonts are built-in PDF Type 1 fonts; no external renderer is needed.
        objects.extend([
            b"<< /Type /Pages /Kids [PLACEHOLDER] /Count PLACEHOLDER >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        ])
        first_page_obj = 6
        for index, page in enumerate(self.pages):
            page_obj = first_page_obj + index * 2
            content_obj = page_obj + 1
            page_refs.append(page_obj)
            content_refs.append(content_obj)
            objects.append(b"")
            stream = self._render_page(page, index + 1, len(self.pages))
            objects.append(
                f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
            )
        kids = " ".join(f"{ref} 0 R" for ref in page_refs)
        objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_refs)} >>".encode("ascii")
        for index, (page_obj, content_obj) in enumerate(zip(page_refs, content_refs)):
            objects[page_obj - 1] = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
                f"/Contents {content_obj} 0 R >>"
            ).encode("ascii")
        output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, obj in enumerate(objects, start=1):
            offsets.append(len(output))
            output.extend(f"{number} 0 obj\n".encode("ascii"))
            output.extend(obj)
            output.extend(b"\nendobj\n")
        xref = len(output)
        output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        output.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
        )
        return bytes(output)

    @staticmethod
    def _diagram_box(x: float, y: float, width: float, height: float, title: str, subtitle: str = "", fill: str = "0.94 0.97 1") -> list[str]:
        commands = [
            f"{fill} rg 0.11 0.27 0.45 RG 0.7 w {x:.1f} {y:.1f} {width:.1f} {height:.1f} re B",
            f"0.06 0.17 0.29 rg BT /F2 7.4 Tf 1 0 0 1 {x + 7:.1f} {y + height - 12:.1f} Tm ({escape_pdf(title)}) Tj ET",
        ]
        if subtitle:
            commands.append(
                f"0.12 0.15 0.20 rg BT /F1 6.5 Tf 1 0 0 1 {x + 7:.1f} {y + 8:.1f} Tm ({escape_pdf(subtitle)}) Tj ET"
            )
        return commands

    @staticmethod
    def _arrow(x1: float, y1: float, x2: float, y2: float) -> list[str]:
        """Draw a simple down/right arrow between architecture boxes."""
        commands = [f"0.19 0.34 0.49 RG 0.8 w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S"]
        if abs(y2 - y1) >= abs(x2 - x1):
            commands.append(f"{x2:.1f} {y2:.1f} m {x2 - 3.5:.1f} {y2 + 5:.1f} l {x2 + 3.5:.1f} {y2 + 5:.1f} l h f")
        else:
            commands.append(f"{x2:.1f} {y2:.1f} m {x2 - 5:.1f} {y2 + 3.5:.1f} l {x2 - 5:.1f} {y2 - 3.5:.1f} l h f")
        return commands

    @classmethod
    def _architecture_commands(cls, top: float) -> list[str]:
        """Vector version of docs/CSPM_PROJECT_ARCHITECTURE.mmd for the PDF."""
        commands: list[str] = []
        y = top - 43
        # Actors and entry points.
        commands += cls._diagram_box(48, y, 154, 31, "CISO / security analyst", "browser user", "0.95 0.98 0.95")
        commands += cls._diagram_box(229, y, 154, 31, "Scheduled monitor", "recurring inventory", "1 0.98 0.93")
        commands += cls._diagram_box(410, y, 154, 31, "CI/CD or IaC user", "pre-deploy scan", "1 0.98 0.93")
        y -= 57
        commands += cls._diagram_box(126, y, 360, 34, "React frontend", "dashboard | inventory | findings | graph | compliance")
        commands += cls._arrow(125, top - 43, 235, y + 34)
        y -= 54
        commands += cls._diagram_box(126, y, 360, 34, "FastAPI API + operator gate", "server.py | inventory_routes.py | admin token for mutations")
        # Scheduled scans and pre-deploy scans enter the API directly. Route
        # those arrows around the frontend box so the diagram preserves that
        # execution boundary instead of implying a browser dependency.
        api_center = y + 17
        commands += [
            f"0.19 0.34 0.49 RG 0.8 w 306 {top - 43:.1f} m 105 {top - 43:.1f} l 105 {api_center:.1f} l 126 {api_center:.1f} l S",
            f"0.19 0.34 0.49 rg 126 {api_center:.1f} m 121 {api_center + 3.5:.1f} l 121 {api_center - 3.5:.1f} l h f",
            f"0.19 0.34 0.49 RG 0.8 w 487 {top - 43:.1f} m 507 {top - 43:.1f} l 507 {api_center:.1f} l 486 {api_center:.1f} l S",
            f"0.19 0.34 0.49 rg 486 {api_center:.1f} m 491 {api_center + 3.5:.1f} l 491 {api_center - 3.5:.1f} l h f",
        ]
        commands += cls._arrow(306, y + 54, 306, y + 34)
        y -= 55
        commands += cls._diagram_box(126, y, 360, 34, "MultiAccountOrchestrator", "per-account guard | session creation | scan coordination", "0.94 0.96 1")
        commands += cls._arrow(306, y + 55, 306, y + 34)
        y -= 60
        commands += cls._diagram_box(48, y, 154, 35, "AWS collector", "STS + regions + SDK", "0.95 0.98 1")
        commands += cls._diagram_box(229, y, 154, 35, "Azure collector", "current resources", "0.95 0.98 1")
        commands += cls._diagram_box(410, y, 154, 35, "GCP collector", "current resources", "0.95 0.98 1")
        commands += cls._arrow(220, y + 60, 125, y + 35)
        commands += cls._arrow(306, y + 60, 306, y + 35)
        commands += cls._arrow(392, y + 60, 487, y + 35)
        y -= 56
        commands += cls._diagram_box(126, y, 360, 34, "Raw tuples -> coverage contract -> provider normalizers", "resource evidence | authoritative scopes | CollectionError | NormalizedAsset")
        commands += cls._arrow(125, y + 56, 245, y + 34)
        commands += cls._arrow(306, y + 56, 306, y + 34)
        commands += cls._arrow(487, y + 56, 367, y + 34)
        y -= 55
        commands += cls._diagram_box(126, y, 360, 34, "InventoryService + AssetRepository", "scan jobs/errors | upsert | events | scoped retirement", "0.94 0.97 1")
        commands += cls._arrow(306, y + 55, 306, y + 34)
        y -= 55
        commands += cls._diagram_box(126, y, 360, 35, "SQLAlchemy database", "accounts | assets/events | scan jobs/errors | findings | issues | compliance", "0.95 0.96 0.99")
        commands += cls._arrow(306, y + 55, 306, y + 35)
        y -= 59
        commands += cls._diagram_box(48, y, 154, 34, "Rules engine", "posture findings", "0.97 0.95 1")
        commands += cls._diagram_box(229, y, 154, 34, "Issue engine", "attack-path correlation", "0.97 0.95 1")
        commands += cls._diagram_box(410, y, 154, 34, "CSPM enrichments", "compliance | DSPM | runtime", "0.97 0.95 1")
        commands += cls._arrow(245, y + 59, 125, y + 34)
        commands += cls._arrow(306, y + 59, 306, y + 34)
        commands += cls._arrow(367, y + 59, 487, y + 34)
        y -= 52
        commands += cls._diagram_box(126, y, 360, 32, "Operator outcome", "prioritized risk | evidence | history | scan health -> frontend", "0.94 0.99 0.96")
        commands += cls._arrow(125, y + 52, 245, y + 32)
        commands += cls._arrow(306, y + 52, 306, y + 32)
        commands += cls._arrow(487, y + 52, 367, y + 32)
        return commands

    @staticmethod
    def _render_page(lines: list[tuple[str, str, float]], number: int, total: int) -> bytes:
        commands = ["0.13 0.16 0.23 rg", "0.5 w", "48 759 m 564 759 l S"]
        for style, text, y in lines:
            if style == "architecture":
                commands.extend(FlowPDF._architecture_commands(y))
                continue
            if style == "title":
                font, size, color = "F2", 20, "0.06 0.16 0.29"
                x = LEFT
            elif style == "heading":
                font, size, color = "F2", 13, "0.06 0.25 0.43"
                x = LEFT
            elif style == "code":
                font, size, color = "F3", 8.0, "0.14 0.16 0.20"
                x = LEFT + 8
                commands.append("0.96 0.97 0.99 rg")
                commands.append(f"44 {y - 7.5:.1f} 524 11 re f")
            elif style == "callout":
                font, size, color = "F2", 9, "0.16 0.28 0.18"
                x = LEFT + 8
                commands.append("0.92 0.97 0.93 rg")
                commands.append(f"44 {y - 9:.1f} 524 13 re f")
            else:
                font, size, color = "F1", 9.2, "0.12 0.13 0.16"
                x = LEFT
            commands.append(
                f"{color} rg BT /{font} {size} Tf 1 0 0 1 {x:.1f} {y:.1f} Tm ({escape_pdf(text)}) Tj ET"
            )
        commands.append("0.35 0.38 0.44 rg")
        commands.append(
            f"BT /F1 8 Tf 1 0 0 1 48 30 Tm (CloudSentinel CSPM workflow) Tj ET"
        )
        commands.append(
            f"BT /F1 8 Tf 1 0 0 1 510 30 Tm (Page {number} of {total}) Tj ET"
        )
        return "\n".join(commands).encode("latin-1")


def build_document(pdf: FlowPDF) -> None:
    pdf.title("CloudSentinel CSPM - Code, Data, and Outcome Workflow")
    pdf.body("A code-guided walkthrough of how the application turns cloud API responses into an operator-facing CSPM outcome.")
    pdf.callout("Scope: the current implementation, with AWS as the detailed example. Azure and GCP use the same collector -> normalizer -> persistence spine for the resources currently supported.")
    pdf.heading("What a CISO or security analyst receives")
    for item in [
        "A tenant-isolated cloud inventory: active assets, raw evidence, normalized posture fields, tags, relationships, and history.",
        "Prioritized posture findings, correlated attack paths, compliance snapshots, vulnerability context, runtime signals, and DSPM classifications.",
        "Honest partial-scan visibility: a denied, failed, or truncated cloud API scope is recorded as an error and does not make real assets disappear.",
    ]:
        pdf.body(item, bullet=True)
    pdf.heading("The high-level pipeline")
    pdf.code("Operator / scheduled monitor\n  -> FastAPI scan endpoint\n  -> MultiAccountOrchestrator\n  -> AwsRawCollector (parallel read-only API calls)\n  -> InventoryService (normalize + tracked scan job)\n  -> AssetRepository (upsert + asset events + safe retirement)\n  -> rules -> findings -> attack-path issues -> compliance snapshot\n  -> frontend dashboard, inventory, graph, reports")

    pdf.heading("Project elements and their actual role")
    elements = [
        ("frontend/", "CISO/analyst UI. It calls /api endpoints for dashboards, assets, findings, issues, graph, compliance, and onboarding."),
        ("api/inventory_routes.py", "HTTP boundary. Validates provider/account/region inputs, starts scans, exposes paginated inventory and scan-job status, and gates privileged mutations."),
        ("inventory/orchestrator.py", "Per-account coordinator. Builds an assumed-role session, selects the provider collector, serializes same-account scans, then triggers rules/issues/compliance."),
        ("inventory/aws_raw_collector.py", "Read-only AWS discovery. Discovers enabled regions, creates SDK clients, calls selected list/describe APIs in parallel, enriches key resources, and records coverage/errors."),
        ("inventory/normalizers.py", "Pure translators. They convert provider-specific dictionaries into one NormalizedAsset contract; they never call AWS."),
        ("inventory/service.py + repository.py", "Creates durable scan jobs, isolates bad records, upserts inventory, writes drift events, and safely retires assets only in fully collected scopes."),
        ("inventory/rules.py + issues.py", "Evaluates posture checks and correlated attack paths against normalized assets; findings and issues have open/resolved/reopened lifecycles."),
        ("db/models.py + db/base.py", "SQLAlchemy schema and engine management. SQLite for local/test, PostgreSQL for production; tenant-scoped asset identity and query indexes."),
        ("inventory/monitor.py", "Scheduled end-to-end cycle, optional DSPM scan, and alert-delta processing."),
    ]
    for name, outcome in elements:
        pdf.body(f"{name}: {outcome}", bullet=True)

    pdf.section("Project-wide architecture: the whole application")
    pdf.architecture_diagram()
    pdf.body("The vector diagram above is the rendered project model. The reusable Mermaid source lives in docs/CSPM_PROJECT_ARCHITECTURE.mmd, so it can be embedded in the repository README, GitHub, or a design document.")
    pdf.callout("Read the arrows as data ownership: cloud responses become evidence, evidence becomes account-scoped inventory, inventory produces risk records, and only the query/API layer returns those records to the UI.")

    pdf.section("1. Scan initiation and account boundary")
    pdf.body("A user connects a cloud account with a provider, account identifier, and read-only role ARN. The API persists a CloudAccount row; AWS onboarding provides an ExternalId to protect the cross-account AssumeRole trust relationship.")
    pdf.code("POST /api/inventory/accounts/{account_id}/scan\n{\n  \"region\": \"us-east-1\"\n}\n\n# endpoint calls\nresult = _run_account_scan(account_id, body.region)")
    pdf.body("The same account cannot run two scans at the same time in one API process. This prevents one scan from interpreting another scan's still-in-flight resources as missing.")
    pdf.code("with _account_scan_guard(account):\n    collector = self._make_collector(account)\n    resources = collector.collect()\n    scan = self.service.persist_scan(\n        account.provider, account.identifier, resources,\n        authoritative_scopes=collector.authoritative_scopes,\n        collection_errors=collector.collection_errors,\n    )")
    pdf.callout("Outcome: the scan is attached to exactly one CloudAccount. Data from another AWS account/subscription/project cannot overwrite it because assets are keyed by account_id + provider + resource_id.")

    pdf.section("2. AWS authentication and regional discovery")
    pdf.body("For another AWS account, the orchestrator calls sts:AssumeRole using the stored role ARN and ExternalId. For the scanner's own AWS account, it can use the ambient SDK identity only when the caller account matches the target account.")
    pdf.code("creds = sts.assume_role(\n    RoleArn=account.role_arn,\n    RoleSessionName=\"odineyes-inventory-scan\",\n    DurationSeconds=3600,\n    ExternalId=account.external_id,\n)[\"Credentials\"]\n\nreturn boto3.Session(\n    aws_access_key_id=creds[\"AccessKeyId\"],\n    aws_secret_access_key=creds[\"SecretAccessKey\"],\n    aws_session_token=creds[\"SessionToken\"],\n    region_name=self.region,\n)")
    pdf.body("The collector discovers enabled regions with EC2 DescribeRegions. If discovery is unavailable it scans the configured home region instead of silently collecting nothing.")
    pdf.code("resp = ec2.describe_regions(\n    Filters=[{\"Name\": \"opt-in-status\",\n              \"Values\": [\"opt-in-not-required\", \"opted-in\"]}]\n)\nregions = sorted(r[\"RegionName\"] for r in resp[\"Regions\"])\nreturn regions or [self.region]")
    pdf.callout("Outcome: rogue or shadow resources in enabled AWS regions are in scope by default. Global services such as S3 and IAM are collected once; regional services are collected per enabled region.")

    pdf.section("3. Raw AWS data fetching")
    pdf.body("The normal scan uses an explicit, posture-relevant registry. The collector creates service clients with adaptive retries, then uses a bounded thread pool for network I/O.")
    pdf.code("OPERATIONS = [\n  (\"ec2\", \"describe_instances\", {}, \"aws.ec2.instance\"),\n  (\"ec2\", \"describe_security_groups\", {}, \"aws.ec2.security_group\"),\n  (\"s3\", \"list_buckets\", {}, \"aws.s3.bucket\"),\n  (\"iam\", \"list_roles\", {}, \"aws.iam.role\"),\n  (\"rds\", \"describe_db_instances\", {}, \"aws.rds.db_instance\"),\n  (\"lambda\", \"list_functions\", {}, \"aws.lambda.function\"),\n  ...\n]")
    pdf.body("For each operation, the native SDK response is kept as a Python dict. The collector adds Region and performs best-effort enrichment for high-value types such as S3, IAM, Lambda, Secrets Manager, CloudTrail, Config, and KMS.")
    pdf.code("if client.can_paginate(snake_op):\n    pages = client.get_paginator(snake_op).paginate(\n        PaginationConfig={\"MaxItems\": 5000}, **kwargs\n    )\nelse:\n    pages = [getattr(client, snake_op)(**kwargs)]\n\nfor item in extracted_items:\n    item[\"Region\"] = region\n    out.append((source_type, item))")
    pdf.heading("Example: raw S3 resource after collection and enrichment")
    pdf.code("(\"aws.s3.bucket\", {\n  \"Name\": \"customer-exports\",\n  \"CreationDate\": \"2026-07-19T09:12:00Z\",\n  \"Region\": \"eu-west-1\",\n  \"PolicyStatus\": {\"IsPublic\": true},\n  \"PublicAccessBlock\": {},\n  \"Encryption\": {\"enabled\": true, \"algorithm\": \"AES256\"},\n  \"Versioning\": \"Enabled\",\n  \"Tags\": {\"env\": \"prod\", \"owner\": \"data\"}\n})")
    pdf.heading("Example: raw EC2 instance")
    pdf.code("(\"aws.ec2.instance\", {\n  \"InstanceId\": \"i-0ab123\",\n  \"Region\": \"us-east-1\",\n  \"PublicIpAddress\": \"198.51.100.20\",\n  \"VpcId\": \"vpc-01\", \"SubnetId\": \"subnet-01\",\n  \"SecurityGroups\": [{\"GroupId\": \"sg-01\"}],\n  \"State\": {\"Name\": \"running\"}\n})")
    pdf.callout("Outcome: raw evidence is preserved. Later normalizers and rules work from a stable collected record, while API-specific details remain available for investigation.")

    pdf.section("4. Collection completeness and error handling")
    pdf.body("A CSPM must not treat an AccessDenied, timeout, client construction failure, or 5,000-item safety cap as an empty cloud response. The collector records a CollectionError and only marks successfully completed type/region scopes as authoritative.")
    pdf.code("resources, complete = future.result()\nout.extend(resources)\nif complete:\n    authoritative_scopes.add((source_type, scope_region))\nelse:\n    collection_errors.append(CollectionError(\n        source_type=source_type,\n        operation=f\"{service}.{operation}\",\n        region=scope_region,\n        message=\"result exceeded the 5000-item safety limit\",\n    ))")
    pdf.body("For S3, a global successful list is authoritative for all bucket regions. For EC2, a successful DescribeInstances in eu-west-1 is authoritative only for EC2 instance assets in eu-west-1.")
    pdf.callout("Outcome: if an account lacks permission to list RDS in one region, existing RDS inventory there stays active and existing findings remain honest. The scan is marked partial with a stored scan error rather than silently resolving risk.")

    pdf.section("5. Normalization: raw provider data -> common asset contract")
    pdf.body("Normalizers are pure functions selected by source type. They extract the common posture fields that rules can query across clouds: identity, region, tags, public exposure, encryption, properties, and relationships.")
    pdf.code("def normalize_s3_bucket(raw, account_identifier):\n    name = raw.get(\"Name\")\n    region = raw.get(\"Region\") or \"global\"\n    is_public = _bucket_is_public(raw)\n    return NormalizedAsset(\n        resource_id=f\"arn:aws:s3:::{name}\",\n        cloud_provider=\"aws\",\n        account_identifier=account_identifier,\n        asset_type=\"aws.s3.bucket\",\n        region=region,\n        is_public=is_public,\n        encryption_enabled=bool(raw.get(\"Encryption\", {}).get(\"enabled\")),\n        network_exposure=\"public\" if is_public else \"private\",\n        raw=raw,\n    )")
    pdf.heading("Normalized S3 result")
    pdf.code("{\n  \"resource_id\": \"arn:aws:s3:::customer-exports\",\n  \"cloud_provider\": \"aws\",\n  \"account_identifier\": \"123456789012\",\n  \"asset_type\": \"aws.s3.bucket\",\n  \"region\": \"eu-west-1\",\n  \"tags\": {\"env\": \"prod\", \"owner\": \"data\"},\n  \"is_public\": true,\n  \"encryption_enabled\": true,\n  \"network_exposure\": \"public\",\n  \"relationships\": [{\"type\": \"BELONGS_TO\", \"target_id\": \"123456789012\"}]\n}")
    pdf.body("EC2 normalization builds an account-and-region-qualified ARN, derives public/vpc exposure from the public IP, and creates relationships to security groups and instance profiles. Security-group normalization derives world-open ports from ingress rules.")
    pdf.callout("Outcome: rules do not need to understand every AWS response shape. They evaluate a unified representation and can work across AWS, Azure, and GCP as normalizers are added.")

    pdf.section("6. Scan job, persistence, and asset lifecycle")
    pdf.body("InventoryService opens and starts a ScanJob before it persists the work. Each resource is normalized independently; a malformed record creates a ScanError but does not abort the entire scan.")
    pdf.code("job = ScanJobRepository.create(session, account, scan_type)\nScanJobRepository.start(job)\n\nfor source_type, raw in resources:\n    fn = get_normalizer(source_type)\n    try:\n        normalized_asset = fn(raw, account_identifier)\n        normalized.append(normalized_asset)\n    except Exception as exc:\n        ScanJobRepository.add_error(session, job, str(exc),\n                                    resource_type=source_type)\n\nstats = AssetRepository.upsert_assets(\n    session, account, job, normalized,\n    authoritative_scopes=effective_scopes,\n)\nScanJobRepository.complete(job, stats)")
    pdf.heading("Database records created or updated")
    for item in [
        "cloud_accounts: provider/account identity, role ARN, ExternalId, active status.",
        "scan_jobs and scan_errors: queued/running/completed/failed lifecycle, counts, and individual errors.",
        "assets: raw record, normalized posture projection, tags/properties/relationships, active state, timestamps, risk score.",
        "asset_events: created, configuration change, reactivated, or deleted events for audit/drift history.",
    ]:
        pdf.body(item, bullet=True)
    pdf.code("UNIQUE (account_id, cloud_provider, resource_id)\n\n# Safe retirement rule\n# full import: retire unseen assets\n# live collection: retire only assets whose (asset_type, region)\n#               is in authoritative_scopes and was not seen")
    pdf.callout("Outcome: the current inventory is accurate without destroying history. A disappearing resource becomes inactive; it can be reactivated on a later successful scan, and its prior evidence remains auditable.")

    pdf.section("6a. Data contracts, database queries, and tenant isolation")
    pdf.body("The system deliberately separates provider evidence from the projected fields the UI and rules query. This lets the product add a new cloud type without changing every downstream screen or rule.")
    contracts = [
        ("Raw tuple", "(source_type, raw_dict) exactly as collected from a provider, plus region and selected enrichment."),
        ("NormalizedAsset", "common resource_id, provider, account identifier, type, region, tags, posture booleans, raw evidence, properties, and relationships."),
        ("ScanJob / ScanError", "durable status, counts, timestamps, partial/failure context, and a per-operation diagnostic record."),
        ("Asset / AssetEvent", "the active inventory row plus a historical event when a resource is created, changed, reactivated, or retired."),
        ("Finding / Issue / ComplianceSnapshot", "posture result, correlated risk path, and framework score/control history tied back to the account and resource."),
    ]
    for name, description in contracts:
        pdf.body(f"{name}: {description}", bullet=True)
    pdf.heading("How inventory queries stay scoped and fast")
    pdf.body("All inventory reads start from the connected CloudAccount and filter the requested provider/account scope before optional asset-type, region, active-state, tag, or risk filters. The database has account/provider/resource identity and common query indexes; PostgreSQL is the intended production backend.")
    pdf.code("# Conceptual asset read used by the API\nquery = select(Asset).where(\n    Asset.account_id == account.id,\n    Asset.cloud_provider == provider,\n    Asset.is_active.is_(True),\n)\nquery = apply_region_type_tag_and_risk_filters(query)\nrows = session.execute(query.order_by(Asset.risk_score.desc()))")
    pdf.callout("Security property: a resource ID is not globally unique. The durable unique key includes account_id and provider, which prevents the same AWS ARN-like string in a different tenant/account from overwriting another customer's evidence.")

    pdf.section("7. Findings, attack paths, and compliance")
    pdf.body("After persistence, the orchestrator evaluates the active assets. The rules engine creates/updates posture findings; the issue engine correlates multiple conditions into attack paths; compliance maps open findings to frameworks.")
    pdf.code("findings = service.evaluate_findings(provider, account)\nissues = service.evaluate_issues(provider, account)\nservice.snapshot_compliance(\n    provider, account, [\"CIS\", \"SOC2\", \"NIST\", \"PCI-DSS\"]\n)")
    pdf.heading("Representative finding output")
    pdf.code("{\n  \"rule_id\": \"PUBLIC_S3_BUCKET\",\n  \"severity\": \"high\",\n  \"status\": \"open\",\n  \"resource_id\": \"arn:aws:s3:::customer-exports\",\n  \"why\": \"Bucket policy or ACL permits public access\",\n  \"remediation\": \"Enable S3 Block Public Access and remove public grants\",\n  \"risk_score\": 4.5,\n  \"exposure\": \"public\"\n}")
    pdf.heading("Representative correlated issue")
    pdf.code("{\n  \"issue_type\": \"PUBLIC_COMPUTE_TO_ADMIN\",\n  \"severity\": \"critical\",\n  \"risk_score\": 92.0,\n  \"resource_id\": \"arn:aws:ec2:...:instance/i-0ab123\",\n  \"path\": [\"internet\", \"i-0ab123\", \"sg-01\", \"admin-role\"],\n  \"status\": \"open\"\n}")
    pdf.body("A finding is one misconfiguration. An issue is a toxic combination or reachable route. Both have lifecycle reconciliation: still present = refresh; fixed = resolved; returned = reopened.")
    pdf.callout("Outcome: a CISO sees a prioritized risk story rather than an unranked list of cloud settings. Compliance snapshots retain score and control history for audit and drift analysis.")

    pdf.section("8. Other CSPM product paths")
    paths = [
        ("CWPP / vulnerabilities", "EC2 package inventory through SSM and container image scanning through Trivy/ECR are persisted as vulnerabilities, enriched by the NVD catalog, and prioritized with KEV/EPSS maturity."),
        ("DSPM", "Data-store classification adds sensitivity labels and taxonomies. Finding risk can be elevated where public exposure and sensitive data overlap."),
        ("Runtime", "The internal runtime-events endpoints persist enriched eBPF/sensor events. These can mark attack-path issues as actively exploited."),
        ("IaC", "Terraform-plan and CloudFormation content can be scanned before deployment. This is a stateless pre-deploy path rather than cloud-inventory persistence."),
        ("Graph", "Normalized relationships become graph edges and a security graph used to enumerate reachable attack paths across an account or fleet."),
    ]
    for name, description in paths:
        pdf.body(f"{name}: {description}", bullet=True)

    pdf.section("9. API outcomes for the UI")
    pdf.code("POST /api/inventory/accounts                 -> connected account row\nPOST /api/inventory/accounts/{id}/verify     -> assume/read diagnostics\nPOST /api/inventory/accounts/{id}/scan       -> one completed account scan\nPOST /api/inventory/scan-all                 -> per-account fleet results\nGET  /api/inventory                          -> paginated assets and filters\nGET  /api/inventory/scan-jobs/{job_id}       -> scan lifecycle/counts/errors\nGET  /api/inventory/findings                 -> prioritized posture findings\nGET  /api/inventory/issues                   -> correlated attack-path issues\nGET  /api/inventory/graph                    -> security graph + paths\nGET  /api/inventory/compliance/*             -> snapshot/history/drift")
    pdf.body("When ODINEYES_ADMIN_TOKEN is configured, write/scan/evaluation endpoints require Authorization: Bearer <token>. Local development remains open if no token is configured.")
    pdf.body("The frontend should present scan status, assets found/changed/deleted, errors, and the partial flag. A partial result is valuable security information: it tells the operator which cloud scope still needs permissions or a retry.")

    pdf.heading("What the UI should communicate at each state")
    for item in [
        "Connected but unscanned: show the provider, account identifier, role verification result, requested regions, and a clear Run scan action.",
        "Queued/running: show job start time, account, scan type, live counts where available, and prevent a duplicate same-account action.",
        "Completed: lead with critical/open findings, changed assets, compliance movement, and a direct link to raw evidence and remediation.",
        "Partial: keep last known assets and findings visible; list the failed API, region, and permission/remediation needed instead of showing a misleading zero.",
        "Failed: distinguish an authentication/configuration failure from an internal processing error; retain the prior successful inventory as historical context.",
    ]:
        pdf.body(item, bullet=True)

    pdf.section("10. One resource end-to-end: actual outcome")
    pdf.code("1. AWS S3 ListBuckets finds customer-exports\n2. Enrichment finds Region=eu-west-1, public policy, encryption enabled\n3. Collector emits (\"aws.s3.bucket\", raw_dict)\n4. normalize_s3_bucket emits a NormalizedAsset\n5. AssetRepository upserts assets row and writes created/config_change event\n6. Rule PUBLIC_S3_BUCKET opens or refreshes a high finding\n7. DSPM label, if present, increases risk for public + sensitive data\n8. Compliance mapper records affected CIS/SOC2/NIST/PCI controls\n9. UI shows the bucket in Inventory, Finding detail, Compliance, and Graph")
    pdf.callout("If the next successful S3 listing no longer contains the bucket, the asset is soft-deleted and the finding can resolve. If the S3 API was denied or truncated instead, neither event occurs: the prior asset and finding remain until evidence is trustworthy.")

    pdf.section("11. Scaling and Go boundary")
    pdf.body("The current AWS collector is primarily I/O-bound and already uses adaptive retry plus bounded threads. The next production step is a durable job queue and a database-backed distributed account lock, not a language rewrite.")
    pdf.code("Recommended future boundary\n\nGo collector worker\n  -> versioned raw-resource batches + coverage/error report\n  -> existing Python normalization, rules, persistence API\n\nKeep tenant identity, finding lifecycle, compliance semantics,\nand database ownership in one service until the event contract is stable.")
    pdf.body("Go becomes useful when measured fleet scale shows Python process overhead, connection reuse, streaming, or memory pressure dominating. It should optimize collection mechanics, while the CSPM decision model remains consistent and testable.")


def main() -> None:
    pdf = FlowPDF()
    build_document(pdf)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(pdf.finalize())
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
