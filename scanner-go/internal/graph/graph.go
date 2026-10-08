package graph

import (
	"sort"
)

// InternetID is the pseudo-node every external entry point hangs off.
const InternetID = "internet"

// Node is one vertex. Asset is nil for pseudo-nodes (internet, external
// principals), which is load-bearing: the confidence model counts a hop as
// evidenced only when a real asset backs it.
type Node struct {
	ID         string
	Kind       string
	Name       string
	Asset      *Asset
	Properties *Properties
	outAll     []*Edge
	outByType  [edgeTypeCount][]*Edge
	outOther   map[string][]*Edge
}

// edgeType is a compact slot for relationships traversed in detector hot
// paths. CIEM can still supply arbitrary relationship names; those are kept in
// outOther without forcing every known traversal through a string-keyed map.
type edgeType uint8

const (
	edgeExposedTo edgeType = iota
	edgeCanAssume
	edgeCanAccess
	edgeCanModifyAndInvoke
	edgeCanImpersonateViaService
	edgeUsesSecurityGroup
	edgeTypeCount
)

func knownEdgeType(value string) (edgeType, bool) {
	switch value {
	case "EXPOSED_TO":
		return edgeExposedTo, true
	case "CAN_ASSUME":
		return edgeCanAssume, true
	case "CAN_ACCESS":
		return edgeCanAccess, true
	case "CAN_MODIFY_AND_INVOKE":
		return edgeCanModifyAndInvoke, true
	case "CAN_IMPERSONATE_VIA_SERVICE":
		return edgeCanImpersonateViaService, true
	case "USES_SECURITY_GROUP":
		return edgeUsesSecurityGroup, true
	default:
		return 0, false
	}
}

func (n *Node) addOutEdge(edge *Edge) {
	n.outAll = append(n.outAll, edge)
	if slot, ok := knownEdgeType(edge.Type); ok {
		n.outByType[slot] = append(n.outByType[slot], edge)
		return
	}
	if n.outOther == nil {
		n.outOther = make(map[string][]*Edge)
	}
	n.outOther[edge.Type] = append(n.outOther[edge.Type], edge)
}

func (n *Node) outgoing(edgeType string) []*Edge {
	if edgeType == "" {
		return n.outAll
	}
	if slot, ok := knownEdgeType(edgeType); ok {
		return n.outByType[slot]
	}
	return n.outOther[edgeType]
}

// Hop is the path projection of a node.
func (n *Node) Hop() map[string]string {
	return map[string]string{"kind": n.Kind, "id": n.ID, "name": n.Name}
}

// Edge is one directed relationship.
type Edge struct {
	Src        string
	Dst        string
	Type       string
	Properties map[string]interface{}
}

// Bool reads a boolean edge property.
func (e *Edge) Bool(key string) bool {
	v, ok := e.Properties[key].(bool)
	return ok && v
}

// Str reads a string edge property.
func (e *Edge) Str(key string) string {
	v, _ := e.Properties[key].(string)
	return v
}

// Strings reads a []string edge property that may have arrived as []interface{}.
func (e *Edge) Strings(key string) []string {
	switch v := e.Properties[key].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Graph holds nodes and their outgoing edges, with the indexes the traversals
// need. Insertion order is preserved so output is deterministic run to run —
// a detection engine whose results reshuffle between identical scans is
// impossible to diff, and diffing is how a migration is proven.
type Graph struct {
	nodes     map[string]*Node
	nodeOrder []string
	order     map[string]int
	orphanOut map[string]*Node
	edgeIndex map[edgeKey]*Edge
	byKind    map[string][]*Node
}

type edgeKey struct {
	src, dst, edgeType string
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes:     map[string]*Node{},
		order:     map[string]int{},
		orphanOut: map[string]*Node{},
		edgeIndex: map[edgeKey]*Edge{},
		byKind:    map[string][]*Node{},
	}
}

// Node returns a node or nil.
func (g *Graph) Node(id string) *Node { return g.nodes[id] }

// AddNode inserts or replaces a node.
func (g *Graph) AddNode(n *Node) *Node {
	if previous, ok := g.nodes[n.ID]; ok {
		if previous.Kind == n.Kind {
			// Same identity re-declared (an external principal trusted by
			// several roles). Keep the original so ordering stays stable.
			return previous
		}
		bucket := g.byKind[previous.Kind]
		for i, item := range bucket {
			if item.ID == n.ID {
				g.byKind[previous.Kind] = append(bucket[:i], bucket[i+1:]...)
				break
			}
		}
		n.outAll = previous.outAll
		n.outByType = previous.outByType
		n.outOther = previous.outOther
	} else {
		g.order[n.ID] = len(g.nodeOrder)
		g.nodeOrder = append(g.nodeOrder, n.ID)
	}
	if orphan := g.orphanOut[n.ID]; orphan != nil {
		n.outAll = orphan.outAll
		n.outByType = orphan.outByType
		n.outOther = orphan.outOther
		delete(g.orphanOut, n.ID)
	}
	g.nodes[n.ID] = n
	g.byKind[n.Kind] = append(g.byKind[n.Kind], n)
	return n
}

// AddEdge inserts an edge, merging properties when it already exists.
func (g *Graph) AddEdge(src, dst, edgeType string, properties map[string]interface{}) {
	key := edgeKey{src, dst, edgeType}
	if existing, ok := g.edgeIndex[key]; ok {
		for k, v := range properties {
			existing.Properties[k] = v
		}
		return
	}
	if properties == nil {
		properties = map[string]interface{}{}
	}
	edge := &Edge{Src: src, Dst: dst, Type: edgeType, Properties: properties}
	g.edgeIndex[key] = edge
	source := g.nodes[src]
	if source == nil {
		source = g.orphanOut[src]
		if source == nil {
			source = &Node{ID: src}
			g.orphanOut[src] = source
		}
	}
	source.addOutEdge(edge)
}

// OutEdges returns outgoing edges, optionally filtered by type.
func (g *Graph) OutEdges(nodeID, edgeType string) []*Edge {
	if source := g.nodes[nodeID]; source != nil {
		return source.outgoing(edgeType)
	}
	if source := g.orphanOut[nodeID]; source != nil {
		return source.outgoing(edgeType)
	}
	return nil
}

// NodeCount returns the number of vertices without allocating a node slice.
func (g *Graph) NodeCount() int { return len(g.nodes) }

// NodesOfKind returns every node of a kind, in insertion order.
func (g *Graph) NodesOfKind(kind string) []*Node { return g.byKind[kind] }

// Order returns the stable insertion ordinal used to make indexed candidate
// resolution deterministic without scanning every node merely to recover its
// order. Unknown nodes sort last.
func (g *Graph) Order(id string) int {
	if ordinal, ok := g.order[id]; ok {
		return ordinal
	}
	return len(g.nodeOrder)
}

// AllEdges returns every edge, ordered by source insertion order so the
// serialized graph is stable.
func (g *Graph) AllEdges() []*Edge {
	out := make([]*Edge, 0, len(g.edgeIndex))
	for _, id := range g.nodeOrder {
		out = append(out, g.nodes[id].outAll...)
	}
	return out
}

// Nodes returns every node in insertion order.
func (g *Graph) Nodes() []*Node {
	out := make([]*Node, 0, len(g.nodes))
	for _, id := range g.nodeOrder {
		out = append(out, g.nodes[id])
	}
	return out
}

// identities returns roles then users, matching Python's
// nodes_of_kind("role") + nodes_of_kind("user").
func (g *Graph) identities() []*Node {
	return append(append([]*Node{}, g.NodesOfKind("role")...), g.NodesOfKind("user")...)
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
