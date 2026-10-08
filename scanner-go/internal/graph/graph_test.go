package graph

import "testing"

// Python's fnmatch, not Go's path.Match. The cases with '/' are the ones that
// matter: path.Match refuses to let '*' cross a separator, and every identifier
// here is an ARN. Getting this wrong loses real IAM access edges.
func TestFnmatchMatchesPythonSemantics(t *testing.T) {
	cases := []struct {
		name, pattern string
		want          bool
	}{
		{"arn:aws:s3:::data-prod", "arn:aws:s3:::data-*", true},
		{"arn:aws:s3:::data-prod/objects/x", "arn:aws:s3:::data-*", true}, // '*' crosses '/'
		{"arn:aws:iam::123:role/app", "arn:aws:iam::*:role/app", true},
		{"arn:aws:iam::123:role/app/nested", "arn:aws:iam::123:role/*", true},
		{"arn:aws:s3:::other", "arn:aws:s3:::data-*", false},
		{"abc", "a?c", true},
		{"ac", "a?c", false},
		{"set7", "set[0-9]", true},
		{"setx", "set[0-9]", false},
		{"setx", "set[!0-9]", true},
		{"a.c", "a.c", true},
		{"axc", "a.c", false}, // '.' is literal in fnmatch, not "any char"
		{"anything", "*", true},
		{"a[b", "a[b", true}, // unterminated '[' is a literal
	}
	for _, c := range cases {
		if got := fnmatchCase(c.name, c.pattern); got != c.want {
			t.Errorf("fnmatchCase(%q, %q) = %v, want %v", c.name, c.pattern, got, c.want)
		}
	}
}

// roundTo must agree with Python's round(). math.Round(x*10)/10 does not:
// it scored a risk of 41.65 as 41.7 where Python gives 41.6, which showed up
// as a live parity failure before this was fixed.
func TestRoundToMatchesPythonRound(t *testing.T) {
	cases := []struct {
		value  float64
		places int
		want   float64
	}{
		{41.65, 1, 41.6},
		{7.0 * 10 * 0.85 * 0.7, 1, 41.6},
		{0.5, 0, 0.0}, // half to even
		{1.5, 0, 2.0}, // half to even
		{2.5, 0, 2.0}, // half to even, not 3
		{85.5, 1, 85.5},
		{0.675, 2, 0.68},
	}
	for _, c := range cases {
		if got := roundTo(c.value, c.places); got != c.want {
			t.Errorf("roundTo(%v, %d) = %v, want %v", c.value, c.places, got, c.want)
		}
	}
}

// A boundary that is configured but unreadable must fail closed. Treating
// "we could not see it" as "it permits" would assert an access edge on absent
// evidence, which is the one thing this engine must never do.
func TestBoundaryFailsClosedOnMissingEvidence(t *testing.T) {
	allow := []Grant{{Effect: "Allow", Actions: []string{"s3:*"}, Resources: []string{"*"}}}

	if !boundaryAllows("not_configured", nil, s3ReadActions, "arn:aws:s3:::b") {
		t.Error("no boundary means nothing to intersect — must permit")
	}
	if boundaryAllows("denied", allow, s3ReadActions, "arn:aws:s3:::b") {
		t.Error("unreadable boundary must fail closed even with an Allow present")
	}
	if !boundaryAllows("observed", allow, s3ReadActions, "arn:aws:s3:::b") {
		t.Error("observed boundary with a matching Allow must permit")
	}

	// A Deny using NotAction cannot be evaluated without request context.
	notAction := []Grant{{Effect: "Deny", NotActions: []string{"s3:GetObject"}}}
	if identityAllows(append(allow, notAction...), s3ReadActions, "arn:aws:s3:::b") {
		t.Error("NotAction Deny must fail closed")
	}
	// A conditional Allow is not proof either.
	conditional := []Grant{{
		Effect: "Allow", Actions: []string{"s3:*"}, Resources: []string{"*"}, Conditional: true,
	}}
	if identityAllows(conditional, s3ReadActions, "arn:aws:s3:::b") {
		t.Error("conditional Allow is not unconditional proof")
	}
}

// GrantIndex is an optimisation over a per-pair glob test; it must not change
// which grants match.
func TestGrantIndexMatchesTheSameGrants(t *testing.T) {
	grants := []string{
		"arn:aws:s3:::data-prod", "arn:aws:s3:::data-*", "arn:aws:s3:::logs-*/y=*/*",
		"arn:aws:iam::123456789012:role/app-*",
	}
	index := NewGrantIndex(grants)

	if got := index.Matches("arn:aws:s3:::data-prod"); len(got) != 2 {
		t.Errorf("data-prod should match both the literal and the glob, got %v", got)
	}
	if got := index.Matches("arn:aws:s3:::nothing"); len(got) != 0 {
		t.Errorf("unrelated bucket matched %v", got)
	}
	// The S3 object grant collapses to its bucket node by exact ARN.
	if got := index.Matches("arn:aws:s3:::logs-*"); len(got) == 0 {
		t.Error("collapsed bucket ARN of an object grant should match")
	}
	if NewGrantIndex(nil).Empty() != true {
		t.Error("empty index should report empty")
	}
	if NewGrantIndex([]string{"*"}).Matches("anything") == nil {
		t.Error("star grant should match everything")
	}
}

func TestGrantIndexResolvesExactCandidatesWithoutChangingOrder(t *testing.T) {
	g := New()
	for _, id := range []string{
		"arn:aws:s3:::first",
		"arn:aws:s3:::second",
		"arn:aws:s3:::third",
	} {
		g.AddNode(&Node{ID: id, Kind: "bucket", Properties: &Properties{}})
	}
	// A role with an identical ARN-shaped identifier must never be returned by
	// a bucket lookup. The kind check replaces the old full target-set scan.
	g.AddNode(&Node{ID: "arn:aws:iam::123:role/not-a-bucket", Kind: "role", Properties: &Properties{}})

	index := NewGrantIndex([]string{
		"arn:aws:s3:::third",
		"arn:aws:s3:::first",
		"arn:aws:iam::123:role/not-a-bucket",
	})
	matches := index.MatchNodes(g, "bucket", g.NodesOfKind("bucket"))
	if len(matches) != 2 {
		t.Fatalf("expected two bucket candidates, got %#v", matches)
	}
	if matches[0].Node.ID != "arn:aws:s3:::first" || matches[1].Node.ID != "arn:aws:s3:::third" {
		t.Fatalf("candidate order drifted from graph insertion order: %#v", matches)
	}
}

func TestTypedOutgoingEdgeIndexStaysIdempotent(t *testing.T) {
	g := New()
	g.AddEdge("a", "b", "CAN_ASSUME", map[string]interface{}{"first": true})
	g.AddEdge("a", "b", "CAN_ASSUME", map[string]interface{}{"second": true})
	g.AddEdge("a", "c", "CAN_ACCESS", nil)

	assume := g.OutEdges("a", "CAN_ASSUME")
	if len(assume) != 1 {
		t.Fatalf("duplicate edge leaked into typed index: %#v", assume)
	}
	if assume[0].Properties["first"] != true || assume[0].Properties["second"] != true {
		t.Fatalf("duplicate edge properties were not merged: %#v", assume[0].Properties)
	}
	if len(g.OutEdges("a", "CAN_ACCESS")) != 1 || len(g.OutEdges("a", "")) != 2 {
		t.Fatal("typed and unfiltered adjacency indexes disagree")
	}
}
