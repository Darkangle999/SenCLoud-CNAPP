// Command odineyes-graph is the attack-path engine.
//
// It reads one account's normalized inventory snapshot as JSON on stdin and
// writes issues, the serialized graph and the enumerated paths as JSON on
// stdout. Pure function of its input: no cloud calls, no database, no clock
// except the `now` the caller supplies — so the same snapshot always produces
// the same output, which is what makes it diffable against the Python engine.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/odineyes/odineyes/scanner/internal/graph"
)

func main() {
	maxDepth := flag.Int("max-depth", 7, "maximum attacker path depth to enumerate")
	maxPaths := flag.Int("max-paths", 400, "maximum enumerated paths")
	skipPaths := flag.Bool("skip-paths", false, "skip path enumeration")
	// The serialized graph is by far the largest thing this command can emit —
	// tens of megabytes on a big account, since it carries every edge. The
	// issue pipeline does not read it, so encoding it there is pure cost.
	skipGraph := flag.Bool("skip-graph", false, "skip the serialized graph projection")
	flag.Parse()

	if err := run(*maxDepth, *maxPaths, *skipPaths, *skipGraph); err != nil {
		fmt.Fprintf(os.Stderr, "odineyes-graph: %v\n", err)
		os.Exit(1)
	}
}

func run(maxDepth, maxPaths int, skipPaths, skipGraph bool) error {
	var snap graph.Snapshot
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&snap); err != nil {
		return fmt.Errorf("decoding snapshot: %w", err)
	}
	// Refuse an unknown contract rather than silently misreading it. A graph
	// engine that drops fields it does not recognise returns confident wrong
	// answers, which is worse than returning none.
	if snap.Version != graph.SnapshotVersion {
		return fmt.Errorf("unsupported snapshot version %d (this engine speaks %d)",
			snap.Version, graph.SnapshotVersion)
	}

	now := time.Now().UTC()
	if snap.Now != "" {
		parsed, err := time.Parse(time.RFC3339Nano, snap.Now)
		if err != nil {
			return fmt.Errorf("parsing now %q: %w", snap.Now, err)
		}
		now = parsed.UTC()
	}

	g := graph.Build(&snap)
	issues := graph.Analyze(g, now)

	paths := []map[string]interface{}{}
	if !skipPaths {
		paths = graph.EnumeratePaths(g, maxDepth, maxPaths)
	}

	serialized := graph.SerializedGraph{
		Nodes: []map[string]interface{}{}, Edges: []map[string]interface{}{},
	}
	if !skipGraph {
		serialized = graph.Serialize(g)
	}

	result := graph.Result{
		Version: graph.SnapshotVersion,
		Issues:  issues,
		Graph:   serialized,
		Paths:   paths,
		Stats: map[string]int{
			"assets": len(snap.Assets),
			"nodes":  len(g.Nodes()),
			"edges":  len(g.AllEdges()),
			"issues": len(issues),
			"paths":  len(paths),
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	return encoder.Encode(result)
}
