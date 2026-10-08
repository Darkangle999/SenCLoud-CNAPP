package graph

import (
	"fmt"
	"testing"
)

func benchmarkGrantGraph(targets int) *Graph {
	g := New()
	for i := 0; i < targets; i++ {
		g.AddNode(&Node{
			ID:         fmt.Sprintf("arn:aws:s3:::tenant-%06d", i),
			Kind:       "bucket",
			Properties: &Properties{},
		})
	}
	return g
}

// Exact grants are the normal least-privilege case. Candidate resolution must
// depend on the number of grants, not the total inventory size.
func BenchmarkGrantIndexExact(b *testing.B) {
	for _, targets := range []int{1_000, 10_000, 100_000} {
		g := benchmarkGrantGraph(targets)
		index := NewGrantIndex([]string{
			"arn:aws:s3:::tenant-000001",
			"arn:aws:s3:::tenant-000017",
			"arn:aws:s3:::tenant-000099",
		})
		b.Run(fmt.Sprintf("targets=%d", targets), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				matches := index.MatchNodes(g, "bucket", g.NodesOfKind("bucket"))
				if len(matches) != 3 {
					b.Fatalf("unexpected candidate count: %d", len(matches))
				}
			}
		})
	}
}

// Wildcard policies genuinely describe the entire resource population, so
// linear work is both expected and the lower bound when every edge is emitted.
func BenchmarkGrantIndexWildcard(b *testing.B) {
	for _, targets := range []int{1_000, 10_000} {
		g := benchmarkGrantGraph(targets)
		index := NewGrantIndex([]string{"arn:aws:s3:::tenant-*"})
		b.Run(fmt.Sprintf("targets=%d", targets), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				matches := index.MatchNodes(g, "bucket", g.NodesOfKind("bucket"))
				if len(matches) != targets {
					b.Fatalf("unexpected candidate count: %d", len(matches))
				}
			}
		})
	}
}
