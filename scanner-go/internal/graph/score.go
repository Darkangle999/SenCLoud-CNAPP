package graph

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Names remain a bounded ranking hint for unclassified stores. Only DSPM
// classification may promote an issue to critical.
var sensitiveName = regexp.MustCompile(
	`(?i)(data|backup|log|secret|cred|customer|cust|prod|pii|financ|private|confidential)`)

var (
	prodEnv    = regexp.MustCompile(`(?i)^(prod|production|prd|live)$`)
	nonProdEnv = regexp.MustCompile(`(?i)^(dev|development|test|testing|qa|stage|staging|sandbox|sbx|demo)$`)
)

var envTagKeys = map[string]struct{}{
	"environment": {}, "env": {}, "stage": {}, "tier": {},
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// roundTo mirrors Python's round(x, n).
//
// math.Round(value*10^n)/10^n is NOT equivalent and produced real divergence:
// a risk of 41.65 scored 41.6 in Python and 41.7 in Go. Two reasons. Scaling by
// a power of ten introduces its own representation error before rounding, and
// math.Round breaks ties away from zero while Python breaks them to even.
// strconv formats the exact binary value at the requested precision with
// round-half-to-even, which is what Python's round() does, so the two agree by
// construction rather than by luck.
func roundTo(value float64, places int) float64 {
	rounded, err := strconv.ParseFloat(
		strconv.FormatFloat(value, 'f', places, 64), 64)
	if err != nil {
		return value
	}
	return rounded
}

// freshness decays confidence by the entry asset's scan recency (1.0 -> 0.85).
func freshness(node *Node, now time.Time) float64 {
	if node == nil || node.Asset == nil || node.Asset.LastScannedAt == "" {
		return 1.0
	}
	scanned, err := parseTime(node.Asset.LastScannedAt)
	if err != nil {
		return 1.0
	}
	ageDays := now.Sub(scanned).Hours() / 24
	switch {
	case ageDays <= 1:
		return 1.0
	case ageDays <= 7:
		return 0.95
	default:
		return 0.85
	}
}

func parseTime(value string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			// A naive timestamp is treated as UTC, matching Python's
			// scanned.replace(tzinfo=timezone.utc).
			if parsed.Location() == time.UTC || !strings.ContainsAny(value, "Z+") {
				return parsed.UTC(), nil
			}
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errUnparsableTime
}

type timeError string

func (e timeError) Error() string { return string(e) }

const errUnparsableTime = timeError("unparsable timestamp")

// risk is the contextual risk model: base x exposure x blast x freshness x
// sensitivity, capped at 100.
func risk(base, exposure, blast, fresh, sensitivity float64) float64 {
	return roundTo(math.Min(base*10*exposure*blast*fresh*sensitivity, 100.0), 1)
}

// severityFor keeps the badge consistent with the number.
func severityFor(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

// dataSensitivity weights the crown jewel at the end of a path (0.6-1.0).
// Classification is authoritative. Names never receive full weight.
func dataSensitivity(node *Node) float64 {
	if node == nil {
		return 1.0
	}
	switch dataLabel(node) {
	case "CRITICAL":
		return 1.0
	case "HIGH":
		return 0.95
	case "MEDIUM":
		return 0.85
	case "LOW":
		return 0.70
	case "NONE":
		return 0.60
	}
	if sensitiveName.MatchString(node.Name) {
		return 0.75
	}
	return 0.65
}

func dataLabel(node *Node) string {
	if node == nil || node.Properties == nil || node.Properties.DataSensitivityLabel == "" {
		return "UNCLASSIFIED"
	}
	return strings.ToUpper(node.Properties.DataSensitivityLabel)
}

func classifiedSensitive(node *Node) bool {
	switch dataLabel(node) {
	case "CRITICAL", "HIGH", "MEDIUM":
		return true
	default:
		return false
	}
}

func dataEvidence(node *Node) map[string]string {
	label := dataLabel(node)
	if label == "UNCLASSIFIED" {
		return evidence(
			"dspm:classification", "sensitivity = UNCLASSIFIED",
			"name used only as a bounded ranking hint; no critical promotion",
		)
	}
	return evidence(
		"dspm:classification", "sensitivity = "+label,
		"confirmed data-impact input",
	)
}

// envWeight rescales by the path's Environment tags. A prod asset anywhere
// raises the rank; a wholly non-prod path is de-prioritised.
func envWeight(hops []*Node) float64 {
	var envs []string
	for _, hop := range hops {
		if hop == nil || hop.Asset == nil {
			continue
		}
		for key, value := range hop.Asset.Tags {
			if _, ok := envTagKeys[strings.ToLower(key)]; ok && value != "" {
				envs = append(envs, value)
			}
		}
	}
	for _, env := range envs {
		if prodEnv.MatchString(env) {
			return 1.2
		}
	}
	if len(envs) > 0 {
		allNonProd := true
		for _, env := range envs {
			if !nonProdEnv.MatchString(env) {
				allNonProd = false
				break
			}
		}
		if allNonProd {
			return 0.85
		}
	}
	return 1.0
}

// confidence is how completely the route is evidenced (0-1): freshness of the
// entry asset times the fraction of routed hops backed by a real asset.
// Internet and external pseudo-nodes are definitional rather than inferred, so
// they are excluded rather than counted against the route.
func confidence(hops []*Node, entry *Node, now time.Time) float64 {
	var routed []*Node
	for _, hop := range hops {
		if hop.Kind == "internet" || hop.Kind == "external" {
			continue
		}
		routed = append(routed, hop)
	}
	if len(routed) == 0 {
		return roundTo(freshness(entry, now), 2)
	}
	backed := 0
	for _, hop := range routed {
		if hop.Asset != nil {
			backed++
		}
	}
	return roundTo(freshness(entry, now)*float64(backed)/float64(len(routed)), 2)
}

func evidenceStatus(hops []*Node, entry *Node, now time.Time) string {
	for _, hop := range hops {
		if hop.Kind == "internet" || hop.Kind == "external" {
			continue
		}
		if hop.Asset == nil {
			return "partial"
		}
	}
	if freshness(entry, now) < 1.0 {
		return "stale"
	}
	return "confirmed"
}

// evidence builds one verifiable evidence record.
func evidence(source, observation, effect string) map[string]string {
	return map[string]string{"source": source, "observation": observation, "effect": effect}
}
