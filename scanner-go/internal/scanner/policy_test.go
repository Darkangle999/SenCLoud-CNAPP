package scanner

import (
	"reflect"
	"testing"
)

func TestAnalyzePolicyDocument(t *testing.T) {
	doc := map[string]any{
		"Statement": []any{
			map[string]any{
				"Effect":   "Allow",
				"Action":   []any{"iam:PassRole", "sts:AssumeRole", "s3:GetObject"},
				"Resource": []any{"arn:aws:iam::123456789012:role/deploy", "arn:aws:s3:::customer-data/*"},
			},
		},
	}
	privesc, assume, s3 := analyzePolicyDocument(doc)
	if !reflect.DeepEqual(privesc, []string{"iam:PassRole", "sts:AssumeRole"}) {
		t.Fatalf("unexpected privesc actions: %#v", privesc)
	}
	if len(assume) != 2 || len(s3) != 2 {
		t.Fatalf("expected explicit resources to be retained, assume=%#v s3=%#v", assume, s3)
	}
}

func TestConditionalResourcesAreNotClaimed(t *testing.T) {
	doc := map[string]any{
		"Statement": map[string]any{
			"Effect":    "Allow",
			"Action":    "sts:AssumeRole",
			"Resource":  "*",
			"Condition": map[string]any{"StringEquals": map[string]any{"aws:PrincipalTag/team": "security"}},
		},
	}
	_, assume, _ := analyzePolicyDocument(doc)
	if len(assume) != 0 {
		t.Fatalf("conditional grant must not become an unconditional graph edge: %#v", assume)
	}
}

func TestAnalyzeTrust(t *testing.T) {
	doc := map[string]any{
		"Statement": []any{
			map[string]any{
				"Effect":    "Allow",
				"Principal": map[string]any{"Service": "ec2.amazonaws.com"},
			},
			map[string]any{
				"Effect":    "Allow",
				"Principal": map[string]any{"AWS": "arn:aws:iam::999999999999:role/external"},
			},
		},
	}
	ec2, external, principals := analyzeTrust(doc, "123456789012")
	if !ec2 || !external || !reflect.DeepEqual(principals, []string{"arn:aws:iam::999999999999:role/external"}) {
		t.Fatalf("unexpected trust analysis: ec2=%v external=%v principals=%#v", ec2, external, principals)
	}
}
