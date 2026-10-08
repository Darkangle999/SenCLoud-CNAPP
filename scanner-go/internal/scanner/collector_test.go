package scanner

import (
	"errors"
	"testing"
)

func newCollectorStateForTest() *Collector {
	return &Collector{
		maxItems:    defaultMaxItems,
		scopeKeys:   make(map[string]struct{}),
		resourceIDs: make(map[string]struct{}),
	}
}

func TestCompleteScopeRejectsAnyRecordedCollectionError(t *testing.T) {
	collector := newCollectorStateForTest()
	region := regionPointer("us-east-1")
	collector.addError(
		"aws.ec2.instance",
		"ec2.DescribeInstances.encode",
		region,
		errors.New("encode failure"),
	)

	if collector.completeScope(
		"aws.ec2.instance",
		"ec2.DescribeInstances",
		region,
		1,
		nil,
	) {
		t.Fatal("scope with a resource collection error was marked authoritative")
	}
	if len(collector.scopes) != 0 {
		t.Fatalf("unexpected authoritative scopes: %#v", collector.scopes)
	}
}

func TestCompleteScopeAcceptsSuccessfulCollection(t *testing.T) {
	collector := newCollectorStateForTest()
	region := regionPointer("us-east-1")

	if !collector.completeScope(
		"aws.ec2.instance",
		"ec2.DescribeInstances",
		region,
		1,
		nil,
	) {
		t.Fatal("successful scope was not marked authoritative")
	}
	if len(collector.scopes) != 1 {
		t.Fatalf("expected one authoritative scope, got %#v", collector.scopes)
	}
}

func TestCompleteScopeRejectsSafetyLimit(t *testing.T) {
	collector := newCollectorStateForTest()

	if collector.completeScope(
		"aws.iam.role",
		"iam.ListRoles",
		nil,
		defaultMaxItems,
		nil,
	) {
		t.Fatal("truncated scope was marked authoritative")
	}
	if len(collector.errors) != 1 {
		t.Fatalf("expected a truncation error, got %#v", collector.errors)
	}
}

func TestFilterExcludedRegions(t *testing.T) {
	regions := []string{"af-south-1", "ap-northeast-3", "eu-west-1", "us-east-1"}
	got := filterExcludedRegions(regions, []string{"af-south-1", "eu-west-1"})
	if len(got) != 2 || got[0] != "ap-northeast-3" || got[1] != "us-east-1" {
		t.Fatalf("got %v", got)
	}
	if got := filterExcludedRegions(regions, nil); len(got) != 4 {
		t.Fatalf("nil exclusions must not filter: %v", got)
	}
	if got := filterExcludedRegions(regions, regions); len(got) != 0 {
		t.Fatalf("excluding everything must empty the set: %v", got)
	}
}
