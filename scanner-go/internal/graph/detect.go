package graph

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// privescActions are the primitives that let a principal grant itself more.
var privescActions = map[string]struct{}{
	"*": {}, "iam:*": {}, "iam:CreatePolicyVersion": {}, "iam:AttachRolePolicy": {},
	"iam:PutRolePolicy": {}, "iam:AttachUserPolicy": {}, "iam:PutUserPolicy": {},
	"iam:UpdateAssumeRolePolicy": {}, "iam:CreateAccessKey": {},
	"iam:SetDefaultPolicyVersion": {},
}

// cicdOIDC matches issuers that let an external build system assume a role.
// Terraform Cloud is here because a workspace there routinely holds the
// credentials that build the account itself, which makes it a higher-value
// pivot than any source-control provider. IAM Roles Anywhere is the same shape
// without a hosted issuer: a certificate outside AWS exchanged for credentials.
var cicdOIDC = regexp.MustCompile(`(?i)(` +
	`token\.actions\.githubusercontent\.com` +
	`|gitlab\.com` +
	`|bitbucket\.org` +
	`|oidc\.circleci\.com` +
	`|app\.terraform\.io` +
	`|\.hashicorp\.cloud` +
	`|rolesanywhere\.amazonaws\.com` +
	`|vstoken\.dev\.azure\.com` +
	`|accounts\.google\.com` +
	`|oidc\.eks\.[a-z0-9-]+\.amazonaws\.com` +
	`)`)

// compliance maps issue_type to the controls the path evidences.
var compliance = map[string]map[string][]string{
	"PUBLIC_COMPUTE_TO_ADMIN": {
		"CIS": {"1.16", "5.2"}, "SOC2": {"CC6.1"}, "NIST": {"AC-3", "AC-6"},
		"PCI-DSS": {"7.1"}, "ISO27001": {"A.5.15", "A.8.3"}},
	"PUBLIC_COMPUTE_TO_DATA": {
		"CIS": {"5.2"}, "SOC2": {"CC6.1", "CC6.7"}, "NIST": {"AC-3", "SC-7"},
		"PCI-DSS": {"1.3.1", "7.1"}, "ISO27001": {"A.8.3", "A.8.20"}},
	"PUBLIC_S3_EXPOSURE": {
		"CIS": {"2.1.1", "2.1.5"}, "SOC2": {"CC6.1", "CC6.7"},
		"NIST": {"AC-3", "SC-28"}, "PCI-DSS": {"3.5"},
		"HIPAA": {"164.312(a)(1)"}, "ISO27001": {"A.8.3", "A.8.24"}, "GDPR": {"Art.32"}},
	"PUBLIC_DATABASE_PATH": {
		"CIS": {"5.2"}, "SOC2": {"CC6.1", "CC6.7"}, "NIST": {"AC-3", "SC-7", "SC-28"},
		"PCI-DSS": {"1.3.1"}, "HIPAA": {"164.312(a)(1)"}, "ISO27001": {"A.8.20"}},
	"CROSS_ACCOUNT_LATERAL": {
		"CIS": {"1.16"}, "SOC2": {"CC6.1"}, "NIST": {"AC-3", "AC-6"},
		"PCI-DSS": {"7.1"}, "ISO27001": {"A.5.15"}},
	"IAM_PRIVILEGE_ESCALATION": {
		"CIS": {"1.16"}, "SOC2": {"CC6.1"}, "NIST": {"AC-6", "AC-2"},
		"PCI-DSS": {"7.1"}, "ISO27001": {"A.5.15", "A.5.16"}},
	"SECOND_ORDER_ROLE_ESCALATION": {
		"CIS": {"1.16"}, "SOC2": {"CC6.1"}, "NIST": {"AC-6", "AC-2"},
		"PCI-DSS": {"7.1"}, "ISO27001": {"A.5.15", "A.5.16"}},
	"OVERPRIVILEGED_CICD_ROLE": {
		"CIS": {"1.16"}, "SOC2": {"CC6.1", "CC8.1"}, "NIST": {"AC-6", "AC-2"},
		"PCI-DSS": {"7.1"}, "ISO27001": {"A.5.15", "A.8.2"}},
}

// pathHash is the dedup key: issue type plus the ordered hop ids.
func pathHash(issue *Issue) string {
	ids := make([]string, 0, len(issue.Path))
	for _, hop := range issue.Path {
		ids = append(ids, hop["id"])
	}
	sum := sha1.Sum([]byte(issue.IssueType + "|" + strings.Join(ids, "|")))
	return hex.EncodeToString(sum[:])
}

type detectorContext struct {
	g   *Graph
	now time.Time
}

// newIssue applies the shared business-context rescale and builds the Issue.
// Prod tags may only raise the badge (never soften a detector's intended
// severity); non-prod lowers the score for ranking but keeps the label.
func (c *detectorContext) newIssue(
	issueType, title, severity string, riskScore float64, hops []*Node,
	why, remediation string, related []string,
	ev []map[string]string, scoring string,
) Issue {
	entry := hops[0]
	for _, hop := range hops {
		if hop.Asset != nil {
			entry = hop
			break
		}
	}
	if weight := envWeight(hops); weight != 1.0 {
		riskScore = roundTo(minFloat(riskScore*weight, 100.0), 1)
		if weight > 1.0 {
			bumped := severityFor(riskScore)
			if rankOf(bumped) < rankOf(severity) {
				severity = bumped
			}
		}
	}
	path := make([]map[string]string, 0, len(hops))
	for _, hop := range hops {
		path = append(path, hop.Hop())
	}
	if related == nil {
		related = []string{}
	}
	if ev == nil {
		ev = []map[string]string{}
	}
	controls := compliance[issueType]
	if controls == nil {
		controls = map[string][]string{}
	}
	return Issue{
		IssueType: issueType, Title: title, Severity: severity, RiskScore: riskScore,
		ResourceID: entry.ID, Why: why, Remediation: remediation, Path: path,
		Compliance: controls, Related: related, Evidence: ev, Scoring: scoring,
		Confidence:     confidence(hops, entry, c.now),
		EvidenceStatus: evidenceStatus(hops, entry, c.now),
	}
}

func rankOf(severity string) int {
	if rank, ok := severityRank[severity]; ok {
		return rank
	}
	return 9
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ── detectors ──────────────────────────────────────────────────

func (c *detectorContext) publicComputeToAdmin() []Issue {
	var out []Issue
	internet := c.g.Node(InternetID)
	for _, e := range c.g.OutEdges(InternetID, "EXPOSED_TO") {
		inst := c.g.Node(e.Dst)
		if inst == nil || inst.Kind != "compute" {
			continue
		}
		ports := e.Strings("port_labels")
		remote := containsAny(ports, "SSH", "RDP", "ALL")
		for _, ae := range c.g.OutEdges(inst.ID, "CAN_ASSUME") {
			role := c.g.Node(ae.Dst)
			if role == nil || !role.Properties.HasAdmin {
				continue
			}
			base := 9.5
			if remote {
				base += 0.5
			}
			score := risk(base, 1.0, 1.0, freshness(inst, c.now), 1.0)
			portText := ""
			if len(ports) > 0 {
				portText = " on " + strings.Join(ports, ", ")
			}
			reason := role.Properties.AdminReason
			if reason == "" {
				reason = "admin policy"
			}
			out = append(out, c.newIssue(
				"PUBLIC_COMPUTE_TO_ADMIN",
				"Internet-exposed compute with admin credentials", "critical", score,
				[]*Node{internet, inst, role},
				fmt.Sprintf("%s is reachable from the internet%s and carries IAM role "+
					"'%s' with effective admin (%s). Compromise of the workload is full "+
					"account takeover.", inst.Name, portText, role.Name, reason),
				"Remove the public IP or restrict ingress, and replace the attached "+
					"role with a least-privilege one.",
				[]string{role.ID}, nil, "",
			))
		}
	}
	return out
}

func (c *detectorContext) publicComputeToData() []Issue {
	var out []Issue
	internet := c.g.Node(InternetID)
	for _, e := range c.g.OutEdges(InternetID, "EXPOSED_TO") {
		inst := c.g.Node(e.Dst)
		if inst == nil || inst.Kind != "compute" {
			continue
		}
		for _, ae := range c.g.OutEdges(inst.ID, "CAN_ASSUME") {
			role := c.g.Node(ae.Dst)
			if role == nil {
				continue
			}
			reachable := c.bucketsReachableFrom(role)
			if len(reachable) == 0 {
				continue
			}

			var buckets []*Node
			var sensitive []bucketRoute
			for _, route := range reachable {
				buckets = append(buckets, route.bucket)
				if classifiedSensitive(route.bucket) {
					sensitive = append(sensitive, route)
				}
			}
			showcase := reachable[0]
			isSensitive := len(sensitive) > 0
			if isSensitive {
				showcase = sensitive[0]
			}

			base := 7.0
			severity := "high"
			if isSensitive {
				base, severity = 8.5, "critical"
			}
			score := risk(base, 1.0, 0.85, freshness(inst, c.now), dataSensitivity(showcase.bucket))

			names := make([]string, 0, len(showcase.path))
			for _, hop := range showcase.path[:len(showcase.path)-1] {
				names = append(names, hop.Name)
			}
			sensitiveText := ""
			if isSensitive {
				sensitiveText = fmt.Sprintf(", including DSPM-classified %s data in '%s'",
					dataLabel(showcase.bucket), showcase.bucket.Name)
			}
			hops := append([]*Node{internet, inst}, showcase.path...)
			related := make([]string, 0, len(buckets))
			for _, bucket := range buckets {
				related = append(related, bucket.ID)
			}
			out = append(out, c.newIssue(
				"PUBLIC_COMPUTE_TO_DATA",
				"Internet-exposed compute with a path to S3 data", severity, score, hops,
				fmt.Sprintf("%s (internet-exposed) can follow IAM path '%s', which reaches "+
					"%d S3 bucket(s)%s. A foothold on the host reaches the data.",
					inst.Name, strings.Join(names, " -> "), len(buckets), sensitiveText),
				"Remove the unnecessary S3 or sts:AssumeRole grant, tighten the target "+
					"role trust policy, and move the host off the public internet.",
				related, []map[string]string{dataEvidence(showcase.bucket)}, "",
			))
		}
	}
	return out
}

type bucketRoute struct {
	bucket *Node
	path   []*Node
}

// bucketsReachableFrom walks bounded role chaining before reaching data, so a
// workload role that cannot read S3 directly but can assume a role that can is
// still caught.
//
// `visited` is shared across every branch, so each role is expanded once and
// the route recorded per bucket is the shortest found, not the only one that
// exists. That is the right trade for scoring — a shorter chain is never less
// severe — but it means the reported access path is *a* route, not an
// exhaustive list. Remediating it can leave a longer chain intact, which the
// next scan re-reports.
func (c *detectorContext) bucketsReachableFrom(role *Node) []bucketRoute {
	type traceNode struct {
		node   *Node
		parent int
		depth  uint8
	}
	traces := make([]traceNode, 1, 16)
	traces[0] = traceNode{node: role, parent: -1, depth: 1}
	queue := make([]int, 1, 16)
	visited := map[string]struct{}{role.ID: {}}
	byBucket := map[string]bucketRoute{}
	var order []string

	pathFor := func(index int, tail *Node) []*Node {
		length := int(traces[index].depth)
		if tail != nil {
			length++
		}
		path := make([]*Node, length)
		cursor := length - 1
		if tail != nil {
			path[cursor] = tail
			cursor--
		}
		for index >= 0 {
			path[cursor] = traces[index].node
			cursor--
			index = traces[index].parent
		}
		return path
	}

	for head := 0; head < len(queue); head++ {
		traceIndex := queue[head]
		current := traces[traceIndex]

		for _, be := range c.g.OutEdges(current.node.ID, "CAN_ACCESS") {
			bucket := c.g.Node(be.Dst)
			if bucket == nil || bucket.Kind != "bucket" {
				continue
			}
			route := bucketRoute{bucket: bucket, path: pathFor(traceIndex, bucket)}
			existing, seen := byBucket[bucket.ID]
			if !seen {
				byBucket[bucket.ID] = route
				order = append(order, bucket.ID)
			} else if len(route.path) < len(existing.path) {
				byBucket[bucket.ID] = route
			}
		}

		if current.depth >= 4 {
			continue
		}
		for _, re := range c.g.OutEdges(current.node.ID, "CAN_ASSUME") {
			next := c.g.Node(re.Dst)
			if next == nil || next.Kind != "role" {
				continue
			}
			if _, seen := visited[next.ID]; seen {
				continue
			}
			visited[next.ID] = struct{}{}
			traces = append(traces, traceNode{
				node: next, parent: traceIndex, depth: current.depth + 1,
			})
			queue = append(queue, len(traces)-1)
		}
	}

	out := make([]bucketRoute, 0, len(order))
	for _, id := range order {
		out = append(out, byBucket[id])
	}
	return out
}

func (c *detectorContext) publicBucketExposure() []Issue {
	var out []Issue
	internet := c.g.Node(InternetID)
	for _, e := range c.g.OutEdges(InternetID, "EXPOSED_TO") {
		bucket := c.g.Node(e.Dst)
		if bucket == nil || bucket.Kind != "bucket" {
			continue
		}
		isSensitive := classifiedSensitive(bucket)
		unencrypted := bucket.Asset != nil && bucket.Asset.EncryptionEnabled != nil &&
			!*bucket.Asset.EncryptionEnabled

		base := 6.5
		severity := "high"
		if isSensitive {
			base, severity = 8.5, "critical"
		}
		if unencrypted {
			base += 0.5
		}
		score := risk(base, 1.0, 0.6, freshness(bucket, c.now), dataSensitivity(bucket))

		out = append(out, c.newIssue(
			"PUBLIC_S3_EXPOSURE", "Publicly accessible S3 bucket", severity, score,
			[]*Node{internet, bucket},
			fmt.Sprintf("Bucket '%s' is publicly accessible%s%s. Anyone on the internet "+
				"may read its objects.", bucket.Name,
				textIf(unencrypted, ", unencrypted"),
				textIf(isSensitive, ", and DSPM classifies its data as "+dataLabel(bucket))),
			"Enable Block Public Access and remove public policy/ACL grants.",
			nil, []map[string]string{dataEvidence(bucket)}, "",
		))
	}
	return out
}

func (c *detectorContext) publicDatabase() []Issue {
	var out []Issue
	internet := c.g.Node(InternetID)
	for _, e := range c.g.OutEdges(InternetID, "EXPOSED_TO") {
		db := c.g.Node(e.Dst)
		if db == nil || db.Kind != "database" {
			continue
		}
		engine := db.Properties.Engine
		if engine == "" {
			engine = "unknown engine"
		}
		iamAuth := db.Properties.IAMAuthEnabled
		unencrypted := db.Asset != nil && db.Asset.EncryptionEnabled != nil &&
			!*db.Asset.EncryptionEnabled

		// The graph only creates this edge after the reachability evaluator has
		// verified SG ingress, default route, attached IGW and both NACL
		// directions, so configuration-only databases never arrive here.
		ev := reachabilityEvidence(e)
		ev = append(ev, evidence("rds:DescribeDBInstances",
			fmt.Sprintf("StorageEncrypted = %t", !unencrypted),
			pick(unencrypted,
				"data readable if storage/snapshot leaks → +1.0 base",
				"encrypted at rest")))
		ev = append(ev, evidence("rds:DescribeDBInstances",
			fmt.Sprintf("IAMDatabaseAuthenticationEnabled = %t", iamAuth),
			"connection still requires valid credentials — no anonymous access"))
		ev = append(ev, dataEvidence(db))

		// A database is credential-gated: unlike a public bucket there is no
		// anonymous read. Network exposure raises attack surface rather than
		// granting access, so base is moderate and severity follows the score.
		base := 6.0
		if unencrypted {
			base += 1.0
		}
		fresh := freshness(db, c.now)
		sens := dataSensitivity(db)
		score := risk(base, 1.0, 0.85, fresh, sens)
		severity := severityFor(score)

		out = append(out, c.newIssue(
			"PUBLIC_DATABASE_PATH", "Verified internet-reachable database", severity, score,
			[]*Node{internet, db},
			fmt.Sprintf("Database '%s' (%s) is verified reachable from 0.0.0.0/0 on the "+
				"database port%s. Access still requires valid credentials, so the exposure "+
				"raises attack surface — credential brute-force, pre-auth engine CVEs, "+
				"snapshot/backup leakage — rather than granting direct access.",
				db.Name, engine, textIf(unencrypted, ", and is unencrypted at rest")),
			"Set PubliclyAccessible=false and move the instance to private subnets; "+
				"restrict the security group to known CIDRs; enable encryption at rest "+
				"and IAM database authentication.",
			nil, ev,
			fmt.Sprintf("base %.1f%s × exposure %.2f × blast 0.85 × freshness %.2f "+
				"× data-sensitivity %.2f = %.1f/100 → %s",
				base, textIf(unencrypted, " (+1.0 unencrypted)"), 1.0, fresh, sens,
				score, strings.ToUpper(severity)),
		))
	}
	return out
}

func (c *detectorContext) crossAccountLateral() []Issue {
	var out []Issue
	for _, ext := range c.g.NodesOfKind("external") {
		for _, e := range c.g.OutEdges(ext.ID, "CAN_ASSUME") {
			// Odineyes onboarding intentionally creates a cross-account trust.
			// Suppressed only after the graph verified the exact scanner ARN and
			// this account's stored ExternalId — never blanket-suppressed.
			if e.Bool("verified_onboarding") {
				continue
			}
			role := c.g.Node(e.Dst)
			if role == nil || role.Kind != "role" {
				continue
			}
			wildcard := e.Bool("wildcard")
			admin := role.Properties.HasAdmin

			var buckets []*Node
			for _, be := range c.g.OutEdges(role.ID, "CAN_ACCESS") {
				if bucket := c.g.Node(be.Dst); bucket != nil {
					buckets = append(buckets, bucket)
				}
			}

			score := risk(
				pickFloat(admin || wildcard, 9.0, 7.0),
				pickFloat(wildcard, 1.0, 0.85),
				pickFloat(admin, 1.0, 0.7),
				freshness(role, c.now), 1.0)

			tail := textIf(admin, " The role has effective admin.")
			if len(buckets) > 0 {
				tail += fmt.Sprintf(" It can read %d S3 bucket(s).", len(buckets))
			}
			remediation := "Scope the trust policy to known principal ARNs and add an ExternalId condition."
			if e.Bool("external_id_protected") {
				remediation = "Verify that this external principal and its ExternalId are " +
					"approved for this role; restrict the trust to the exact required principal ARN."
			}
			hops := []*Node{ext, role}
			related := []string{}
			if len(buckets) > 0 {
				hops = append(hops, buckets[0])
				for _, bucket := range buckets {
					related = append(related, bucket.ID)
				}
			}
			out = append(out, c.newIssue(
				"CROSS_ACCOUNT_LATERAL", "IAM role assumable from outside the account",
				pick(admin && wildcard, "critical", "high"), score, hops,
				fmt.Sprintf("Role '%s' trusts %s. A principal there can assume it.%s",
					role.Name, pick(wildcard, "any AWS principal (wildcard)", ext.Name), tail),
				remediation, related, nil, "",
			))
		}
	}
	return out
}

func (c *detectorContext) iamPrivilegeEscalation() []Issue {
	var out []Issue
	for _, role := range c.g.NodesOfKind("role") {
		if role.Properties.HasAdmin {
			continue // already covered by stronger paths
		}
		dangerous := intersectPrivesc(role.Properties.PrivescActions)
		if len(dangerous) == 0 {
			continue
		}
		external := role.Properties.TrustExternal || role.Properties.PubliclyAssumable
		score := risk(7.5, pickFloat(external, 1.0, 0.6), 1.0, freshness(role, c.now), 1.0)
		out = append(out, c.newIssue(
			"IAM_PRIVILEGE_ESCALATION", "IAM role can escalate to admin", "high", score,
			[]*Node{role},
			fmt.Sprintf("Role '%s' is granted %s. A principal using this role can grant "+
				"itself further permissions and reach admin.", role.Name, strings.Join(dangerous, ", ")),
			"Remove the escalation primitives or constrain them with permission boundaries.",
			nil, nil, "",
		))
	}
	return out
}

func (c *detectorContext) secondOrderRoleEscalation() []Issue {
	var out []Issue

	// Existing Lambda takeover: principal -> mutable function -> execution role.
	for _, principal := range c.g.identities() {
		for _, edge := range c.g.OutEdges(principal.ID, "CAN_MODIFY_AND_INVOKE") {
			workload := c.g.Node(edge.Dst)
			if workload == nil {
				continue
			}
			for _, roleEdge := range c.g.OutEdges(workload.ID, "CAN_ASSUME") {
				target := c.g.Node(roleEdge.Dst)
				if target == nil || target.Kind != "role" {
					continue
				}
				if !target.Properties.HasAdmin && len(target.Properties.EffectivePrivescActions) == 0 {
					continue
				}
				external := principal.Properties.TrustExternal || principal.Properties.PubliclyAssumable
				score := risk(
					pickFloat(target.Properties.HasAdmin, 9.0, 7.5),
					pickFloat(external, 1.0, 0.85), 1.0,
					freshness(principal, c.now), 1.0)

				issue := c.newIssue(
					"SECOND_ORDER_ROLE_ESCALATION",
					"Principal can reach a privileged role through Lambda",
					severityFor(score), score,
					[]*Node{principal, workload, target},
					fmt.Sprintf("%s can replace and invoke code in Lambda '%s'. The function "+
						"executes as role '%s', so the principal can exercise that role "+
						"without sts:AssumeRole.", principal.Name, workload.Name, target.Name),
					"Remove either lambda:UpdateFunctionCode or lambda:InvokeFunction, "+
						"restrict both to approved deployment identities, and reduce the "+
						"function execution role.",
					[]string{target.ID},
					[]map[string]string{evidence(
						"normalized IAM policies + Lambda configuration",
						edge.Str("evidence"),
						"creates a service-mediated path to the execution role")},
					"",
				)
				if !edge.Bool("effective_access_complete") {
					issue.Confidence = minFloat(issue.Confidence, 0.8)
				}
				out = append(out, issue)
			}
		}
	}

	// New service workload + PassRole. Aggregate services for the same source
	// and target so one remediation decision does not become five alerts.
	type pair struct{ principal, target string }
	grouped := map[pair][]*Edge{}
	var order []pair
	for _, principal := range c.g.identities() {
		for _, edge := range c.g.OutEdges(principal.ID, "CAN_IMPERSONATE_VIA_SERVICE") {
			key := pair{principal.ID, edge.Dst}
			if _, seen := grouped[key]; !seen {
				order = append(order, key)
			}
			grouped[key] = append(grouped[key], edge)
		}
	}

	for _, key := range order {
		edges := grouped[key]
		principal, target := c.g.Node(key.principal), c.g.Node(key.target)
		if principal == nil || target == nil || target.Kind != "role" {
			continue
		}
		if !target.Properties.HasAdmin && len(target.Properties.EffectivePrivescActions) == 0 {
			continue
		}
		var services, evidenceParts []string
		complete := true
		for _, edge := range edges {
			service := edge.Str("via_service")
			if service == "" {
				service = "AWS service"
			}
			services = append(services, service)
			evidenceParts = append(evidenceParts, edge.Str("evidence"))
			if !edge.Bool("effective_access_complete") {
				complete = false
			}
		}
		services = sortedUnique(services)

		external := principal.Properties.TrustExternal || principal.Properties.PubliclyAssumable
		score := risk(
			pickFloat(target.Properties.HasAdmin, 9.0, 7.5),
			pickFloat(external, 1.0, 0.85), 1.0,
			freshness(principal, c.now), 1.0)

		issue := c.newIssue(
			"SECOND_ORDER_ROLE_ESCALATION",
			"Principal can PassRole into attacker-controlled service execution",
			severityFor(score), score,
			[]*Node{principal, target},
			fmt.Sprintf("%s can create and execute attacker-controlled %s work while "+
				"passing privileged role '%s'. The service assumes the role on the "+
				"principal's behalf.", principal.Name, strings.Join(services, ", "), target.Name),
			"Restrict iam:PassRole to approved role paths with iam:PassedToService, "+
				"remove unnecessary service creation/execution actions, and reduce the "+
				"target role privileges.",
			[]string{target.ID},
			[]map[string]string{evidence(
				"normalized IAM policies + role trust",
				strings.Join(evidenceParts, "; "),
				"proves the correlated service actions, exact PassRole grant, and service trust")},
			"",
		)
		if !complete {
			issue.Confidence = minFloat(issue.Confidence, 0.8)
		}
		out = append(out, issue)
	}

	return out
}

func (c *detectorContext) overprivilegedCICDRole() []Issue {
	var out []Issue
	for _, role := range c.g.NodesOfKind("role") {
		var providers []string
		for _, federated := range role.Properties.TrustFederated {
			if cicdOIDC.MatchString(federated) {
				providers = append(providers, federated)
			}
		}
		if len(providers) == 0 {
			continue
		}
		admin := role.Properties.HasAdmin
		privesc := intersectPrivesc(role.Properties.PrivescActions)
		if !admin && len(privesc) == 0 {
			continue // federated but least-privilege — not an escalation path
		}
		grant := strings.Join(privesc, ", ")
		if admin {
			grant = "effective admin"
		}
		provider := providers[0]
		if idx := strings.LastIndex(provider, "/"); idx >= 0 {
			provider = provider[idx+1:]
		}
		score := risk(pickFloat(admin, 9.0, 7.5), 1.0, pickFloat(admin, 1.0, 0.7),
			freshness(role, c.now), 1.0)

		out = append(out, c.newIssue(
			"OVERPRIVILEGED_CICD_ROLE", "CI/CD OIDC role with excessive privileges",
			pick(admin, "critical", "high"), score, []*Node{role},
			fmt.Sprintf("Role '%s' is assumable by external CI/CD via OIDC provider '%s' "+
				"and grants %s. A compromised or malicious pipeline run can assume it and "+
				"%s with no prior foothold.", role.Name, provider, grant,
				pick(admin, "take over the account", "escalate toward admin")),
			"Pin the OIDC trust with a sub/aud condition scoped to the exact repository "+
				"and branch, and replace admin/escalation grants with least privilege.",
			nil,
			[]map[string]string{
				evidence("iam:GetRole",
					"AssumeRolePolicyDocument.Principal.Federated = "+provider,
					"assumable by external CI/CD pipeline → exposure 1.00"),
				evidence("iam:ListAttachedRolePolicies",
					"role grants "+grant,
					"pipeline compromise → "+pick(admin, "account takeover", "privilege escalation")),
			},
			"",
		))
	}
	return out
}

// Analyze runs every detector, dedupes by path and ranks by risk. Large graphs
// use a bounded worker pool because detectors are independent readers. Results
// are concatenated in detector declaration order, not completion order, so
// concurrency cannot make equal-ranked findings shuffle between scans.
func Analyze(g *Graph, now time.Time) []Issue {
	c := &detectorContext{g: g, now: now}
	detectors := []func() []Issue{
		c.publicComputeToAdmin,
		c.publicComputeToData,
		c.publicBucketExposure,
		c.publicDatabase,
		c.crossAccountLateral,
		c.iamPrivilegeEscalation,
		c.secondOrderRoleEscalation,
		c.overprivilegedCICDRole,
	}
	results := make([][]Issue, len(detectors))

	const parallelDetectorMinNodes = 1_000
	workers := runtime.GOMAXPROCS(0)
	if workers > len(detectors) {
		workers = len(detectors)
	}
	if g.NodeCount() < parallelDetectorMinNodes || workers < 2 {
		for index, detector := range detectors {
			results[index] = detector()
		}
	} else {
		jobs := make(chan int)
		var wait sync.WaitGroup
		wait.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func() {
				defer wait.Done()
				for index := range jobs {
					results[index] = detectors[index]()
				}
			}()
		}
		for index := range detectors {
			jobs <- index
		}
		close(jobs)
		wait.Wait()
	}

	issueCount := 0
	for _, batch := range results {
		issueCount += len(batch)
	}
	issues := make([]Issue, 0, issueCount)
	for _, batch := range results {
		issues = append(issues, batch...)
	}

	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if rankOf(a.Severity) != rankOf(b.Severity) {
			return rankOf(a.Severity) < rankOf(b.Severity)
		}
		if a.IssueType != b.IssueType {
			return a.IssueType < b.IssueType
		}
		return a.ResourceID < b.ResourceID
	})

	seen := map[string]struct{}{}
	unique := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		hash := pathHash(&issue)
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		unique = append(unique, issue)
	}
	return unique
}

// ── helpers ────────────────────────────────────────────────────

func intersectPrivesc(actions []string) []string {
	var found []string
	for _, action := range actions {
		if _, ok := privescActions[action]; ok {
			found = append(found, action)
		}
	}
	return sortedUnique(found)
}

func containsAny(values []string, wanted ...string) bool {
	for _, value := range values {
		for _, want := range wanted {
			if value == want {
				return true
			}
		}
	}
	return false
}

func textIf(condition bool, text string) string {
	if condition {
		return text
	}
	return ""
}

func pick(condition bool, whenTrue, whenFalse string) string {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func pickFloat(condition bool, whenTrue, whenFalse float64) float64 {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func reachabilityEvidence(e *Edge) []map[string]string {
	reach, ok := e.Properties["reachability"].(map[string]interface{})
	if !ok {
		return []map[string]string{}
	}
	items, ok := reach["evidence"].([]interface{})
	if !ok {
		return []map[string]string{}
	}
	out := make([]map[string]string, 0, len(items))
	for _, item := range items {
		if record, ok := item.(map[string]interface{}); ok {
			converted := map[string]string{}
			for key, value := range record {
				if text, ok := value.(string); ok {
					converted[key] = text
				}
			}
			out = append(out, converted)
		}
	}
	return out
}
