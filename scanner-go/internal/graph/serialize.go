package graph

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// attackEdges are the types an attacker actually traverses.
// USES_SECURITY_GROUP is metadata, not a step.
var attackEdges = map[string]struct{}{
	"EXPOSED_TO": {}, "CAN_ASSUME": {}, "CAN_ACCESS": {},
	"CAN_MODIFY_AND_INVOKE": {}, "CAN_IMPERSONATE_VIA_SERVICE": {},
}

var targetKinds = map[string]struct{}{"role": {}, "bucket": {}, "database": {}}

var pathSensitive = regexp.MustCompile(
	`(?i)(data|backup|log|secret|cred|customer|cust|prod|pii|financ|private|confidential|admin)`)

// EnumeratePaths returns every distinct simple attacker route from an entry
// point to a valuable target. Superset of what the curated detectors flag, so
// it surfaces latent routes no single rule names. Depth- and count-capped so a
// dense graph cannot explode combinatorially.
func EnumeratePaths(g *Graph, maxDepth, maxPaths int) []map[string]interface{} {
	starts := []string{InternetID}
	for _, node := range g.NodesOfKind("external") {
		starts = append(starts, node.ID)
	}

	var results []map[string]interface{}
	seen := map[string]struct{}{}

	var dfs func(nodeID string, trail []string)
	dfs = func(nodeID string, trail []string) {
		if len(results) >= maxPaths {
			return
		}
		node := g.Node(nodeID)
		if node != nil && len(trail) >= 2 {
			if _, ok := targetKinds[node.Kind]; ok {
				key := strings.Join(trail, "|")
				if _, dup := seen[key]; !dup {
					seen[key] = struct{}{}
					results = append(results, pathMeta(g, trail))
				}
			}
		}
		if len(trail) >= maxDepth {
			return
		}
		for _, e := range g.OutEdges(nodeID, "") {
			if _, ok := attackEdges[e.Type]; !ok {
				continue
			}
			if e.Bool("verified_onboarding") {
				continue
			}
			if containsString(trail, e.Dst) {
				continue
			}
			dfs(e.Dst, append(append([]string{}, trail...), e.Dst))
		}
	}

	for _, start := range starts {
		if g.Node(start) != nil {
			dfs(start, []string{start})
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		ri := rankOf(results[i]["severity"].(string))
		rj := rankOf(results[j]["severity"].(string))
		if ri != rj {
			return ri < rj
		}
		return results[i]["length"].(int) > results[j]["length"].(int)
	})
	return results
}

func pathMeta(g *Graph, trail []string) map[string]interface{} {
	nodes := make([]*Node, 0, len(trail))
	for _, id := range trail {
		nodes = append(nodes, g.Node(id))
	}
	term := nodes[len(nodes)-1]

	hasAdmin := false
	sensitive := false
	for _, node := range nodes {
		if node.Kind == "role" && node.Properties.HasAdmin {
			hasAdmin = true
		}
		if (node.Kind == "bucket" || node.Kind == "database") && pathSensitive.MatchString(node.Name) {
			sensitive = true
		}
	}

	var severity string
	switch {
	case hasAdmin:
		severity = "critical"
	case term.Kind == "database" || sensitive:
		severity = "high"
	case term.Kind == "role":
		severity = "high"
	case term.Kind == "bucket":
		severity = "medium"
	default:
		severity = "low"
	}

	sum := sha1.Sum([]byte(strings.Join(trail, "|")))
	return map[string]interface{}{
		"id":          "path:" + hex.EncodeToString(sum[:])[:12],
		"nodes":       append([]string{}, trail...),
		"length":      len(trail) - 1,
		"entry":       nodes[0].Kind,
		"target":      term.Name,
		"target_kind": term.Kind,
		"severity":    severity,
	}
}

// propKeys are the node properties worth surfacing to the UI.
var propKeys = []string{"has_admin", "wildcard", "publicly_assumable", "engine", "open_port_labels"}

// Serialize flattens the graph for the UI canvas, matching AssetGraph.serialize.
func Serialize(g *Graph) SerializedGraph {
	out := SerializedGraph{Nodes: []map[string]interface{}{}, Edges: []map[string]interface{}{}}

	for _, node := range g.Nodes() {
		properties := map[string]interface{}{}
		if node.Properties != nil {
			if node.Properties.HasAdmin {
				properties["has_admin"] = true
			}
			if node.Properties.PubliclyAssumable {
				properties["publicly_assumable"] = true
			}
			if node.Properties.Engine != "" {
				properties["engine"] = node.Properties.Engine
			}
			if len(node.Properties.OpenPortLabels) > 0 {
				properties["open_port_labels"] = node.Properties.OpenPortLabels
			}
		}
		record := map[string]interface{}{
			"id": node.ID, "kind": node.Kind, "name": node.Name,
			"properties": properties,
		}
		if node.Asset != nil {
			record["asset_type"] = node.Asset.AssetType
			record["region"] = node.Asset.Region
			record["is_public"] = node.Asset.IsPublic
			record["risk_score"] = node.Asset.RiskScore
		} else {
			record["asset_type"] = nil
			record["region"] = nil
			record["is_public"] = false
			record["risk_score"] = 0.0
		}
		out.Nodes = append(out.Nodes, record)
	}

	for _, e := range g.AllEdges() {
		record := map[string]interface{}{"source": e.Src, "target": e.Dst, "type": e.Type}
		if labels := e.Strings("port_labels"); len(labels) > 0 {
			record["ports"] = labels
		}
		if e.Bool("wildcard") {
			record["wildcard"] = true
		}
		if e.Bool("verified_onboarding") {
			record["verified_onboarding"] = true
		}
		for _, key := range []string{
			"engine", "via_service", "actions", "evidence",
			"authorization_scope", "effective_access_complete",
		} {
			if value, ok := e.Properties[key]; ok {
				record[key] = value
			}
		}
		out.Edges = append(out.Edges, record)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func rawJSON(raw json.RawMessage) interface{} {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	return value
}
