package graph

import (
	"sort"
	"strings"
)

// Capability action sets, mirroring odineyes.inventory.iam_analysis.
var (
	assumeRoleActions = []string{"sts:AssumeRole"}
	s3ReadActions     = []string{
		"s3:GetObject", "s3:ListBucket", "s3:GetObjectVersion", "s3:*", "*",
	}
)

// actionMatches compares an action against a policy pattern, case-insensitively
// (IAM action matching is not case-sensitive).
func actionMatches(action, pattern string) bool {
	return fnmatchCase(strings.ToLower(action), strings.ToLower(pattern))
}

// policyResourceMatches is iam_analysis._resource_matches: a glob compare, with
// an S3 fallback that compares bucket names when both sides are S3 ARNs.
func policyResourceMatches(resource, pattern string) bool {
	if pattern == "*" || fnmatchCase(resource, pattern) {
		return true
	}
	if strings.HasPrefix(resource, "arn:aws:s3:::") && strings.HasPrefix(pattern, "arn:aws:s3:::") {
		return fnmatchCase(bucketOf(resource), bucketOf(pattern))
	}
	return false
}

// bucketOf reduces an S3 ARN to its bucket component.
func bucketOf(arn string) string {
	_, rest, found := strings.Cut(arn, ":::")
	if !found {
		return arn
	}
	name, _, _ := strings.Cut(rest, "/")
	return name
}

// isExplicitUnconditionalAllow mirrors _explicit_unconditional_allows: a grant
// only counts as proof when it is an unconditional Allow naming both actions
// and resources positively. NotAction/NotResource and conditions are treated as
// "not proven" rather than "permitted".
func isExplicitUnconditionalAllow(g Grant) bool {
	return g.Effect == "Allow" &&
		!g.Conditional &&
		len(g.NotActions) == 0 &&
		len(g.NotResources) == 0 &&
		len(g.Actions) > 0 &&
		len(g.Resources) > 0
}

// grantCovers reports whether a grant names any candidate action AND the
// resource.
func grantCovers(g Grant, candidates []string, resource string) bool {
	matchedAction := false
	for _, candidate := range candidates {
		for _, pattern := range g.Actions {
			if actionMatches(candidate, pattern) {
				matchedAction = true
				break
			}
		}
		if matchedAction {
			break
		}
	}
	if !matchedAction {
		return false
	}
	for _, pattern := range g.Resources {
		if policyResourceMatches(resource, pattern) {
			return true
		}
	}
	return false
}

// deniesCapability applies the shared explicit-Deny rule used by both
// identityAllows and boundaryAllows. A Deny that uses NotAction/NotResource
// fails closed: its true scope needs a condition evaluator we do not have, and
// guessing "it probably doesn't apply" would manufacture an access edge.
func deniesCapability(grants []Grant, candidates []string, resource string) bool {
	for _, g := range grants {
		if g.Effect != "Deny" {
			continue
		}
		if len(g.NotActions) > 0 || len(g.NotResources) > 0 {
			return true
		}
		matchedAction := false
		for _, candidate := range candidates {
			for _, pattern := range g.Actions {
				if actionMatches(candidate, pattern) {
					matchedAction = true
					break
				}
			}
			if matchedAction {
				break
			}
		}
		if !matchedAction {
			continue
		}
		for _, pattern := range g.Resources {
			if policyResourceMatches(resource, pattern) {
				return true
			}
		}
	}
	return false
}

// identityAllows reports whether normalized identity evidence supports a
// capability. Explicit Deny overrides Allow.
func identityAllows(grants []Grant, candidates []string, resource string) bool {
	if deniesCapability(grants, candidates, resource) {
		return false
	}
	for _, g := range grants {
		if isExplicitUnconditionalAllow(g) && grantCovers(g, candidates, resource) {
			return true
		}
	}
	return false
}

// boundaryAllows reports whether an observed permissions boundary permits a
// capability.
//
// "not_configured" means there is no boundary to intersect with, so it permits.
// A boundary that is configured but could not be read returns false so an
// attack-path edge fails closed rather than being asserted on missing evidence.
func boundaryAllows(state string, grants []Grant, candidates []string, resource string) bool {
	if state == "not_configured" {
		return true
	}
	if state != "observed" {
		return false
	}
	if deniesCapability(grants, candidates, resource) {
		return false
	}
	for _, g := range grants {
		if isExplicitUnconditionalAllow(g) && grantCovers(g, candidates, resource) {
			return true
		}
	}
	return false
}

// GrantIndex pre-sorts one principal's resource grants by how they match, so
// the identity cross-products do a map lookup in the common case instead of a
// glob evaluation per (grant, resource) pair.
//
// Mirrors AssetGraph._resource_matches, including its quirk that an S3 grant
// also matches its collapsed bucket ARN by equality rather than by glob.
type GrantIndex struct {
	star     []string
	exact    map[string][]string
	patterns []patternGrant
}

type patternGrant struct {
	grant string
}

// GrantMatch is one graph node and the normalized grants that cover it.
type GrantMatch struct {
	Node   *Node
	Grants []string
}

// NewGrantIndex compiles a principal's grants once.
func NewGrantIndex(grants []string) *GrantIndex {
	index := &GrantIndex{exact: make(map[string][]string, len(grants))}
	for _, grant := range grants {
		if grant == "*" {
			index.star = append(index.star, grant)
			continue
		}
		if strings.ContainsAny(grant, "*?[") {
			compilePattern(grant) // warm the cache
			index.patterns = append(index.patterns, patternGrant{grant: grant})
		} else {
			index.exact[grant] = append(index.exact[grant], grant)
		}
		// An S3 grant also matches its bucket node by exact ARN. Skip when the
		// grant already *is* that ARN, or a plain bucket grant would be
		// registered twice and returned duplicated.
		if strings.HasPrefix(grant, "arn:aws:s3:::") {
			if collapsed := "arn:aws:s3:::" + bucketOf(grant); collapsed != grant {
				index.exact[collapsed] = append(index.exact[collapsed], grant)
			}
		}
	}
	return index
}

// Empty reports whether the index can never match.
func (g *GrantIndex) Empty() bool {
	return len(g.star) == 0 && len(g.exact) == 0 && len(g.patterns) == 0
}

// Matches returns the grants covering nodeID.
func (g *GrantIndex) Matches(nodeID string) []string {
	var found []string
	found = append(found, g.star...)
	found = append(found, g.exact[nodeID]...)
	for _, p := range g.patterns {
		if fnmatchCase(nodeID, p.grant) {
			found = append(found, p.grant)
		}
	}
	return found
}

// MatchNodes resolves only the nodes a principal can possibly reach.
//
// Exact ARNs are direct graph lookups: O(G). A global wildcard necessarily
// touches every target: O(T). Only resource globs need matching against the
// target population: O(P*T). C is the number of candidates returned.
//
// This replaces the former unconditional O(T) loop per identity. In ordinary
// least-privilege policies, where grants are exact ARNs, graph construction is
// therefore proportional to grants rather than identities multiplied by all
// buckets/roles. Results retain graph insertion order for Python parity.
func (g *GrantIndex) MatchNodes(graph *Graph, targetKind string, targets []*Node) []GrantMatch {
	if g.Empty() || len(targets) == 0 {
		return []GrantMatch{}
	}

	matches := make(map[string][]string)
	if len(g.star) > 0 {
		for _, target := range targets {
			matches[target.ID] = append(matches[target.ID], g.star...)
		}
	}
	for id, grants := range g.exact {
		// The exact-grant fast path must not build a set containing every
		// target first; that would quietly leave it O(T) per identity. A graph
		// lookup plus the kind check resolves each literal ARN in O(1).
		if node := graph.Node(id); node != nil && node.Kind == targetKind {
			matches[id] = append(matches[id], grants...)
		}
	}
	if len(g.patterns) > 0 {
		for _, target := range targets {
			for _, pattern := range g.patterns {
				if fnmatchCase(target.ID, pattern.grant) {
					matches[target.ID] = append(matches[target.ID], pattern.grant)
				}
			}
		}
	}

	result := make([]GrantMatch, 0, len(matches))
	for id, grants := range matches {
		node := graph.Node(id)
		if node == nil {
			continue
		}
		result = append(result, GrantMatch{Node: node, Grants: sortedUnique(grants)})
	}
	sort.Slice(result, func(i, j int) bool {
		return graph.Order(result[i].Node.ID) < graph.Order(result[j].Node.ID)
	})
	return result
}
