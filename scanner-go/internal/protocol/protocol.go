package protocol

import (
	"encoding/json"
	"fmt"
)

const SchemaVersion = "1.0"

type ScanRequest struct {
	SchemaVersion     string   `json:"schema_version"`
	Provider          string   `json:"provider"`
	AccountIdentifier string   `json:"account_identifier"`
	RoleARN           string   `json:"role_arn,omitempty"`
	ExternalID        string   `json:"external_id,omitempty"`
	HomeRegion        string   `json:"home_region"`
	Regions           []string `json:"regions,omitempty"`
	// ExcludedRegions removes regions from the sweep set. Discovery still runs
	// first so the sweep covers every enabled region minus these; an operator
	// uses it for regions an SCP physically blocks, where every call would
	// fail and burn collection budget for nothing.
	ExcludedRegions []string `json:"excluded_regions,omitempty"`
	MaxWorkers      int      `json:"max_workers,omitempty"`
	MaxItems        int      `json:"max_items_per_operation,omitempty"`
	TimeoutSeconds  int      `json:"timeout_seconds,omitempty"`
}

func (r ScanRequest) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported request schema_version %q", r.SchemaVersion)
	}
	if r.Provider != "aws" {
		return fmt.Errorf("unsupported provider %q", r.Provider)
	}
	if len(r.AccountIdentifier) != 12 {
		return fmt.Errorf("account_identifier must be a 12-digit AWS account id")
	}
	for _, ch := range r.AccountIdentifier {
		if ch < '0' || ch > '9' {
			return fmt.Errorf("account_identifier must be a 12-digit AWS account id")
		}
	}
	if r.HomeRegion == "" {
		return fmt.Errorf("home_region is required")
	}
	if r.MaxWorkers < 0 || r.MaxWorkers > 64 {
		return fmt.Errorf("max_workers must be between 1 and 64")
	}
	if r.MaxItems < 0 || r.MaxItems > 100_000 {
		return fmt.Errorf("max_items_per_operation must be between 1 and 100000")
	}
	return nil
}

type RawResource struct {
	SourceType string         `json:"source_type"`
	Raw        map[string]any `json:"raw"`
}

type Scope struct {
	SourceType string  `json:"source_type"`
	Region     *string `json:"region"`
}

type CollectionError struct {
	SourceType string  `json:"source_type"`
	Operation  string  `json:"operation"`
	Message    string  `json:"message"`
	Region     *string `json:"region"`
}

type Metrics struct {
	RegionsScanned int            `json:"regions_scanned"`
	Operations     int            `json:"operations"`
	Resources      int            `json:"resources"`
	ByType         map[string]int `json:"by_type"`
	DurationMS     int64          `json:"duration_ms"`
}

type ScanResponse struct {
	SchemaVersion     string            `json:"schema_version"`
	Collector         string            `json:"collector"`
	AccountIdentifier string            `json:"account_identifier"`
	Resources         []RawResource     `json:"resources"`
	Authoritative     []Scope           `json:"authoritative_scopes"`
	Errors            []CollectionError `json:"collection_errors"`
	Metrics           Metrics           `json:"metrics"`
	FatalError        string            `json:"fatal_error,omitempty"`
}

func DecodeRequest(data []byte) (ScanRequest, error) {
	var request ScanRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return request, fmt.Errorf("decode scan request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return request, err
	}
	return request, nil
}
