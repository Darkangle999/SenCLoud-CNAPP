package scanner

import (
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strings"
)

var privilegeEscalationActions = map[string]struct{}{
	"iam:CreatePolicyVersion":     {},
	"iam:SetDefaultPolicyVersion": {},
	"iam:AttachUserPolicy":        {},
	"iam:AttachGroupPolicy":       {},
	"iam:AttachRolePolicy":        {},
	"iam:PutUserPolicy":           {},
	"iam:PutGroupPolicy":          {},
	"iam:PutRolePolicy":           {},
	"iam:CreateAccessKey":         {},
	"iam:CreateLoginProfile":      {},
	"iam:UpdateLoginProfile":      {},
	"iam:UpdateAssumeRolePolicy":  {},
	"iam:PassRole":                {},
	"sts:AssumeRole":              {},
}

func decodePolicyDocument(encoded string) map[string]any {
	if encoded == "" {
		return map[string]any{}
	}
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		decoded = encoded
	}
	var doc map[string]any
	if json.Unmarshal([]byte(decoded), &doc) != nil {
		return map[string]any{}
	}
	return doc
}

func statements(doc map[string]any) []map[string]any {
	value, ok := doc["Statement"]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		return []map[string]any{typed}
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if statement, ok := item.(map[string]any); ok {
				out = append(out, statement)
			}
		}
		return out
	default:
		return nil
	}
}

func stringsFrom(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func policyMatches(candidate, pattern string) bool {
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(candidate))
	return err == nil && ok
}

func isAdminDocument(doc map[string]any) bool {
	for _, statement := range statements(doc) {
		if statement["Effect"] != "Allow" {
			continue
		}
		if contains(stringsFrom(statement["Action"]), "*") &&
			contains(stringsFrom(statement["Resource"]), "*") {
			return true
		}
	}
	return false
}

func analyzePolicyDocument(doc map[string]any) (privesc, assumeRoleResources, s3ReadResources []string) {
	privilegeSet := map[string]struct{}{}
	assumeSet := map[string]struct{}{}
	s3Set := map[string]struct{}{}
	s3Candidates := []string{
		"s3:GetObject",
		"s3:GetObjectVersion",
		"s3:GetObjectAttributes",
		"s3:SelectObjectContent",
	}

	for _, statement := range statements(doc) {
		if statement["Effect"] != "Allow" {
			continue
		}
		actions := stringsFrom(statement["Action"])
		resources := stringsFrom(statement["Resource"])
		for _, action := range actions {
			if action == "*" || action == "iam:*" || action == "sts:*" {
				privilegeSet[action] = struct{}{}
			} else if _, ok := privilegeEscalationActions[action]; ok {
				privilegeSet[action] = struct{}{}
			}
		}

		if statement["Condition"] != nil || statement["NotAction"] != nil || statement["NotResource"] != nil {
			continue
		}
		for _, action := range actions {
			if policyMatches("sts:AssumeRole", action) {
				for _, resource := range resources {
					assumeSet[resource] = struct{}{}
				}
			}
			for _, candidate := range s3Candidates {
				if policyMatches(candidate, action) {
					for _, resource := range resources {
						s3Set[resource] = struct{}{}
					}
					break
				}
			}
		}
	}
	return sortedKeys(privilegeSet), sortedKeys(assumeSet), sortedKeys(s3Set)
}

func analyzeTrust(doc map[string]any, accountID string) (bool, bool, []string) {
	assumableByEC2 := false
	external := false
	principals := map[string]struct{}{}

	for _, statement := range statements(doc) {
		if statement["Effect"] != "Allow" {
			continue
		}
		principal := statement["Principal"]
		if principal == "*" {
			external = true
			principals["*"] = struct{}{}
			continue
		}
		principalMap, ok := principal.(map[string]any)
		if !ok {
			continue
		}
		for _, service := range stringsFrom(principalMap["Service"]) {
			if service == "ec2.amazonaws.com" {
				assumableByEC2 = true
			}
		}
		for _, awsPrincipal := range stringsFrom(principalMap["AWS"]) {
			if awsPrincipal == "*" {
				external = true
				principals[awsPrincipal] = struct{}{}
				continue
			}
			if principalAccount(awsPrincipal) != "" && principalAccount(awsPrincipal) != accountID {
				external = true
				principals[awsPrincipal] = struct{}{}
			}
		}
	}
	return assumableByEC2, external, sortedKeys(principals)
}

func principalAccount(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 && parts[0] == "arn" && parts[2] == "iam" {
		return parts[4]
	}
	return ""
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
