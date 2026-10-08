package graph

import (
	"sort"
	"strings"
)

// assetKinds maps asset_type to graph node kind. An unmapped type stays out of
// the graph, exactly as in Python.
var assetKinds = map[string]string{
	"aws.ec2.instance":        "compute",
	"aws.lambda.function":     "compute",
	"aws.ecs.task_definition": "workload",
	"aws.eks.cluster":         "kubernetes",
	"aws.ecr.repository":      "container_registry",
	"aws.elbv2.load_balancer": "load_balancer",
	"aws.ec2.security_group":  "security_group",
	"aws.iam.role":            "role",
	"aws.iam.user":            "user",
	"aws.s3.bucket":           "bucket",
	"aws.rds.db_instance":     "database",
	"aws.rds.db_cluster":      "database",
	"aws.neptune.cluster":     "database",
	"aws.docdb.cluster":       "database",
	"aws.redshift.cluster":    "database",
}

// Build assembles the graph from a snapshot.
//
// The network reachability verdicts arrive already decided by Python — Go never
// re-derives whether a packet can reach a host. It only reads the verdict and
// creates the EXPOSED_TO edge when the verdict is "reachable", so a
// configuration flag alone can still never become an attacker edge.
func Build(snap *Snapshot) *Graph {
	g := New()
	g.AddNode(&Node{ID: InternetID, Kind: "internet", Name: "Internet", Properties: &Properties{}})

	graphed := make([]*Asset, 0, len(snap.Assets))
	byShort := map[string]string{}
	roleByName := map[string]string{}

	for i := range snap.Assets {
		asset := &snap.Assets[i]
		kind, ok := assetKinds[asset.AssetType]
		if !ok {
			continue
		}
		graphed = append(graphed, asset)
		name := asset.Name
		if name == "" {
			name = asset.ResourceID
		}
		properties := asset.Properties
		g.AddNode(&Node{ID: asset.ResourceID, Kind: kind, Name: name, Asset: asset, Properties: &properties})

		short := asset.ResourceID
		if idx := strings.LastIndex(short, "/"); idx >= 0 {
			short = short[idx+1:]
		}
		byShort[short] = asset.ResourceID
		if kind == "role" {
			roleByName[name] = asset.ResourceID
		}
	}

	for _, asset := range graphed {
		kind := assetKinds[asset.AssetType]
		node := g.Node(asset.ResourceID)

		switch {
		case kind == "compute" || kind == "workload" || kind == "kubernetes":
			buildComputeEdges(g, asset, byShort, roleByName)
			buildComputeExposure(g, snap, asset, kind)

		case kind == "database":
			if snap.NetworkStatus[asset.ResourceID] == "reachable" {
				properties := map[string]interface{}{"verified": true}
				if raw, ok := snap.NetworkVerdicts[asset.ResourceID]; ok {
					properties["reachability"] = rawJSON(raw)
				}
				g.AddEdge(InternetID, asset.ResourceID, "EXPOSED_TO", properties)
			}

		case kind == "bucket":
			if asset.IsPublic {
				g.AddEdge(InternetID, asset.ResourceID, "EXPOSED_TO", nil)
			}

		case kind == "role":
			buildRoleEdges(g, snap, asset, node)
		}
	}

	buildIdentityEdges(g)

	for _, rel := range snap.CIEM {
		if g.Node(rel.SourceID) != nil && g.Node(rel.TargetID) != nil {
			g.AddEdge(rel.SourceID, rel.TargetID, rel.RelationshipType, rel.Properties)
		}
	}

	return g
}

func buildComputeEdges(g *Graph, asset *Asset, byShort, roleByName map[string]string) {
	for _, rel := range asset.Relationships {
		switch rel.Type {
		case "USES_SECURITY_GROUP":
			if sgID, ok := byShort[rel.TargetID]; ok {
				g.AddEdge(asset.ResourceID, sgID, "USES_SECURITY_GROUP", nil)
			}
		case "EXECUTES_AS":
			if g.Node(rel.TargetID) != nil {
				g.AddEdge(asset.ResourceID, rel.TargetID, "CAN_ASSUME", nil)
			}
		}
	}
	// Instance profile to role by name: AWS names the profile after the role by
	// default, and the raw EC2 record carries only the profile ARN.
	if profile := asset.Properties.IAMInstanceProfile; profile != "" {
		name := profile
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		if roleID, ok := roleByName[name]; ok {
			g.AddEdge(asset.ResourceID, roleID, "CAN_ASSUME", nil)
		}
	}
}

func buildComputeExposure(g *Graph, snap *Snapshot, asset *Asset, kind string) {
	if asset.AssetType == "aws.ec2.instance" {
		if snap.NetworkStatus[asset.ResourceID] != "reachable" {
			return
		}
		var labels []string
		for _, e := range g.OutEdges(asset.ResourceID, "USES_SECURITY_GROUP") {
			if sg := g.Node(e.Dst); sg != nil && sg.Properties != nil {
				labels = append(labels, sg.Properties.OpenPortLabels...)
			}
		}
		g.AddEdge(InternetID, asset.ResourceID, "EXPOSED_TO", map[string]interface{}{
			"port_labels": sortedUnique(labels),
			"verified":    true,
		})
		return
	}
	// Lambda function URLs are service endpoints; unlike EC2 their path does not
	// depend on customer VPC routing, so is_public is sufficient.
	if kind == "compute" && asset.IsPublic {
		g.AddEdge(InternetID, asset.ResourceID, "EXPOSED_TO", nil)
	}
}

func buildRoleEdges(g *Graph, snap *Snapshot, asset *Asset, node *Node) {
	properties := asset.Properties
	if properties.HasAdmin {
		for _, bucket := range g.NodesOfKind("bucket") {
			g.AddEdge(asset.ResourceID, bucket.ID, "CAN_ACCESS", nil)
		}
	}
	if !properties.TrustExternal && !properties.PubliclyAssumable {
		return
	}

	wildcard := properties.PubliclyAssumable
	principals := properties.TrustPrincipals
	if wildcard {
		principals = []string{"*"}
	}
	if len(principals) == 0 {
		principals = []string{"unknown-external-principal"}
	}

	account := asset.AccountIdentifier
	if account == "" {
		account = accountFromARN(asset.ResourceID)
	}
	expectedExternalID := snap.AccountExternalIDs[account]
	expectedRoleARN := snap.AccountRoleARNs[account]

	for _, principal := range sortedUnique(principals) {
		verified, hasExternalID := verifiedOnboardingTrust(
			node, principal, snap.ScannerPrincipalARN, expectedExternalID, expectedRoleARN,
		)
		label := principal
		if principal == "*" {
			label = "Any AWS account"
		}
		ext := g.AddNode(&Node{
			ID:   "external:" + principal,
			Kind: "external",
			Name: label,
			Properties: &Properties{
				TrustPrincipals: []string{principal},
			},
		})
		g.AddEdge(ext.ID, asset.ResourceID, "CAN_ASSUME", map[string]interface{}{
			"wildcard":              principal == "*",
			"verified_onboarding":   verified,
			"external_id_protected": hasExternalID,
		})
	}
}

// verifiedOnboardingTrust reports (verified, hasExternalID) for one principal.
//
// A trust counts as this deployment's own onboarding connection only when three
// independently observed facts agree: it is the role registered for the
// account, the trust names this deployment's exact scanner principal, and the
// statement carries that account's stable ExternalId. A matching role name,
// account root, or merely *some* ExternalId is deliberately not enough — those
// are all things an attacker in the target account can write for themselves.
func verifiedOnboardingTrust(
	node *Node, principal, scannerPrincipalARN, expectedExternalID, expectedRoleARN string,
) (bool, bool) {
	hasExternalID := false
	if node == nil || node.Properties == nil {
		return false, false
	}
	for _, statement := range node.Properties.TrustStatements {
		if !contains(statement.Principals, principal) {
			continue
		}
		if len(statement.ExternalIDs) > 0 {
			hasExternalID = true
		}
		if scannerPrincipalARN != "" &&
			expectedExternalID != "" &&
			expectedRoleARN == node.ID &&
			principal == scannerPrincipalARN &&
			contains(statement.ExternalIDs, expectedExternalID) {
			return true, true
		}
	}
	return false, hasExternalID
}

// buildIdentityEdges derives the policy-backed CAN_ACCESS / CAN_ASSUME edges.
// Explicit-Allow only: an edge is asserted when the identity policy, the
// permissions boundary and (for role chaining) the target's trust policy all
// independently permit it.
func buildIdentityEdges(g *Graph) {
	identities := g.identities()
	roles := g.NodesOfKind("role")
	buckets := g.NodesOfKind("bucket")

	for _, principal := range identities {
		properties := principal.Properties
		boundaryState := properties.PermissionsBoundaryState
		if boundaryState == "" {
			boundaryState = "not_configured"
		}

		grants := append([]string{}, properties.S3ReadResources...)
		if properties.HasAdmin {
			grants = append(grants, "*")
		}
		bucketIndex := NewGrantIndex(grants)

		for _, match := range bucketIndex.MatchNodes(g, "bucket", buckets) {
			bucket, matched := match.Node, match.Grants
			if !boundaryAllows(boundaryState, properties.PermissionsBoundaryGrant, s3ReadActions, bucket.ID) {
				continue
			}
			if len(properties.PolicyGrants) > 0 &&
				!identityAllows(properties.PolicyGrants, s3ReadActions, bucket.ID) {
				continue
			}
			g.AddEdge(principal.ID, bucket.ID, "CAN_ACCESS", map[string]interface{}{
				"evidence":                  "explicit IAM Allow within permissions boundary",
				"resources":                 sortedUnique(matched),
				"authorization_scope":       properties.AuthorizationScope,
				"effective_access_complete": properties.EffectiveAccessComplete,
			})
		}

		assumeIndex := NewGrantIndex(properties.AssumeRoleResources)
		for _, match := range assumeIndex.MatchNodes(g, "role", roles) {
			target, matched := match.Node, match.Grants
			if target.ID == principal.ID {
				continue
			}
			if !boundaryAllows(boundaryState, properties.PermissionsBoundaryGrant, assumeRoleActions, target.ID) {
				continue
			}
			if len(properties.PolicyGrants) > 0 &&
				!identityAllows(properties.PolicyGrants, assumeRoleActions, target.ID) {
				continue
			}
			if !trustsPrincipal(target, principal.ID) {
				continue
			}
			g.AddEdge(principal.ID, target.ID, "CAN_ASSUME", map[string]interface{}{
				"evidence":                  "identity policy + permissions boundary + role trust",
				"resources":                 sortedUnique(matched),
				"authorization_scope":       properties.AuthorizationScope,
				"effective_access_complete": properties.EffectiveAccessComplete,
			})
		}
	}
}

// trustsPrincipal reports whether target's trust policy admits sourceID.
// A grant to assume is only half a path — the target must also accept it.
func trustsPrincipal(target *Node, sourceID string) bool {
	if target.Properties.PubliclyAssumable {
		return true
	}
	candidates := []string{sourceID}
	if account := accountFromARN(sourceID); account != "" {
		candidates = append(candidates, "arn:aws:iam::"+account+":root")
	}
	for _, principal := range target.Properties.TrustPrincipals {
		if principal == "*" {
			return true
		}
		for _, candidate := range candidates {
			if fnmatchCase(candidate, principal) {
				return true
			}
		}
	}
	return false
}

func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func sortStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
