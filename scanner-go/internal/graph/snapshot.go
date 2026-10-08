// Package graph is the Go attack-path engine: it assembles the security graph
// from a normalized inventory snapshot, runs the correlated path detectors, and
// scores the results.
//
// The split with Python is deliberate. Python still owns collection,
// normalization, the atomic misconfiguration rules, and the three analyzers
// whose verdicts are facts about one asset (reachability, layered reachability,
// CIEM relationships). Those verdicts arrive in the snapshot already decided.
// Go owns everything that is a function of the graph as a whole: node and edge
// derivation, the identity cross-products, traversal, scoring and dedup — which
// profiling showed to be where the work actually is.
package graph

import "encoding/json"

// SnapshotVersion is bumped when the wire contract changes shape. The engine
// refuses a version it does not know rather than silently misreading fields:
// a graph engine that quietly drops evidence produces confident wrong answers.
const SnapshotVersion = 2

// Grant is one normalized IAM policy statement. Mirrors the dicts produced by
// odineyes.inventory.iam_analysis.normalize_policy_document.
type Grant struct {
	Effect       string   `json:"effect"`
	Actions      []string `json:"actions"`
	Resources    []string `json:"resources"`
	NotActions   []string `json:"not_actions"`
	NotResources []string `json:"not_resources"`
	Conditional  bool     `json:"conditional"`
}

// TrustStatement is one statement of a role's trust policy, already reduced to
// the principals and ExternalIds it names.
type TrustStatement struct {
	Principals  []string `json:"principals"`
	ExternalIDs []string `json:"external_ids"`
}

// Asset is the subset of a NormalizedAsset the graph layer reads. Fields the
// graph never touches are not transported.
type Asset struct {
	ResourceID        string            `json:"resource_id"`
	AssetType         string            `json:"asset_type"`
	Name              string            `json:"name"`
	Region            string            `json:"region"`
	AccountIdentifier string            `json:"account_identifier"`
	IsPublic          bool              `json:"is_public"`
	Tags              map[string]string `json:"tags"`
	RiskScore         float64           `json:"risk_score"`

	// EncryptionEnabled is tri-state in Python (True/False/None) and the
	// detectors distinguish "observed unencrypted" from "not observed", so it
	// must not collapse to a bare bool.
	EncryptionEnabled *bool `json:"encryption_enabled"`
	// LastScannedAt is RFC3339; empty means never scanned, which scores as
	// full freshness exactly as Python's `not isinstance(scanned, datetime)`.
	LastScannedAt string `json:"last_scanned_at"`

	Properties    Properties     `json:"properties"`
	Relationships []Relationship `json:"relationships"`
}

// Relationship is a normalizer-declared edge candidate carried on the asset.
type Relationship struct {
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
}

// Properties is the type-specific bag. Only the keys the graph reads are typed;
// Extra preserves everything else so serialization back to the UI is lossless.
type Properties struct {
	HasAdmin                 bool             `json:"has_admin"`
	AdminReason              string           `json:"admin_reason"`
	PolicyAnalysisComplete   bool             `json:"policy_analysis_complete"`
	TrustExternal            bool             `json:"trust_external"`
	PubliclyAssumable        bool             `json:"publicly_assumable"`
	TrustPrincipals          []string         `json:"trust_principals"`
	TrustFederated           []string         `json:"trust_federated"`
	TrustStatements          []TrustStatement `json:"trust_statements"`
	S3ReadResources          []string         `json:"s3_read_resources"`
	AssumeRoleResources      []string         `json:"assume_role_resources"`
	PrivescActions           []string         `json:"privesc_actions"`
	EffectivePrivescActions  []string         `json:"effective_privesc_actions"`
	PolicyGrants             []Grant          `json:"policy_grants"`
	PermissionsBoundaryState string           `json:"permissions_boundary_state"`
	PermissionsBoundaryGrant []Grant          `json:"permissions_boundary_grants"`
	AuthorizationScope       string           `json:"authorization_scope"`
	EffectiveAccessComplete  bool             `json:"effective_access_complete"`
	IAMInstanceProfile       string           `json:"iam_instance_profile"`
	OpenPorts                []int            `json:"open_ports"`
	OpenPortLabels           []string         `json:"open_port_labels"`
	Engine                   string           `json:"engine"`
	IAMAuthEnabled           bool             `json:"iam_auth_enabled"`
	IsPublic                 bool             `json:"is_public"`
	DataSensitivityLabel     string           `json:"data_sensitivity_label"`

	// Extra carries every other property key verbatim so the serialized graph
	// the UI consumes keeps the fields Go has no opinion about.
	Extra map[string]json.RawMessage `json:"-"`
}

// CIEMRelationship is a second-order edge already derived by Python.
type CIEMRelationship struct {
	SourceID         string                 `json:"source_id"`
	TargetID         string                 `json:"target_id"`
	RelationshipType string                 `json:"relationship_type"`
	Properties       map[string]interface{} `json:"properties"`
}

// Verdict is a Python-computed reachability assessment, transported verbatim.
// Go reads Status to decide whether an EXPOSED_TO edge is warranted and passes
// the rest through as evidence without reinterpreting it.
type Verdict struct {
	Status   string                 `json:"status"`
	Evidence []map[string]string    `json:"evidence"`
	Missing  []string               `json:"missing"`
	Raw      map[string]interface{} `json:"-"`
}

// Snapshot is the full engine input for one account.
type Snapshot struct {
	Version              int                        `json:"version"`
	AccountIdentifier    string                     `json:"account_identifier"`
	ScannerPrincipalARN  string                     `json:"scanner_principal_arn"`
	AccountExternalIDs   map[string]string          `json:"account_external_ids"`
	AccountRoleARNs      map[string]string          `json:"account_role_arns"`
	Now                  string                     `json:"now"`
	Assets               []Asset                    `json:"assets"`
	NetworkVerdicts      map[string]json.RawMessage `json:"network_verdicts"`
	NetworkStatus        map[string]string          `json:"network_status"`
	LayeredReachability  map[string]json.RawMessage `json:"layered_reachability"`
	CIEM                 []CIEMRelationship         `json:"ciem_relationships"`
	InternetReachability map[string]json.RawMessage `json:"internet_reachability"`
}

// Result is the full engine output.
type Result struct {
	Version int                      `json:"version"`
	Issues  []Issue                  `json:"issues"`
	Graph   SerializedGraph          `json:"graph"`
	Paths   []map[string]interface{} `json:"paths"`
	Stats   map[string]int           `json:"stats"`
}

// Issue matches odineyes.inventory.issues.Issue.to_dict() field for field, so
// the Python side can rehydrate it without a translation layer.
type Issue struct {
	IssueType      string              `json:"issue_type"`
	Title          string              `json:"title"`
	Severity       string              `json:"severity"`
	RiskScore      float64             `json:"risk_score"`
	ResourceID     string              `json:"resource_id"`
	Why            string              `json:"why"`
	Remediation    string              `json:"remediation"`
	Path           []map[string]string `json:"path"`
	Compliance     map[string][]string `json:"compliance"`
	Related        []string            `json:"related"`
	Evidence       []map[string]string `json:"evidence"`
	Scoring        string              `json:"scoring"`
	Confidence     float64             `json:"confidence"`
	EvidenceStatus string              `json:"evidence_status"`
}

// SerializedGraph is the graph-canvas projection, matching AssetGraph.serialize.
type SerializedGraph struct {
	Nodes []map[string]interface{} `json:"nodes"`
	Edges []map[string]interface{} `json:"edges"`
}
