package protocol

import (
	"encoding/json"
	"testing"
)

func TestRequestValidation(t *testing.T) {
	request := ScanRequest{
		SchemaVersion:     SchemaVersion,
		Provider:          "aws",
		AccountIdentifier: "123456789012",
		HomeRegion:        "us-east-1",
		MaxWorkers:        8,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	request.AccountIdentifier = "not-an-account"
	if request.Validate() == nil {
		t.Fatal("invalid account id was accepted")
	}
}

func TestScanRequestExcludedRegionsJSON(t *testing.T) {
	req := ScanRequest{
		SchemaVersion:     SchemaVersion,
		Provider:          "aws",
		AccountIdentifier: "123456789012",
		HomeRegion:        "us-east-1",
		ExcludedRegions:   []string{"af-south-1"},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request with excluded regions must validate: %v", err)
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ScanRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.ExcludedRegions) != 1 || back.ExcludedRegions[0] != "af-south-1" {
		t.Fatalf("excluded_regions round-trip failed: %v", back.ExcludedRegions)
	}
}
