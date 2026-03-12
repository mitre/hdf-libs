package oscal

import (
	"fmt"
	"regexp"
	"strings"
)

// controlEnhancementRe matches OSCAL control IDs with enhancements like "ac-2.3".
var controlEnhancementRe = regexp.MustCompile(`^([a-z]{2}-\d+)\.(\d+)$`)

// objectiveIDRe extracts the control ID from a SAR objective ID like "ac-1.a.1_obj.1".
var objectiveIDRe = regexp.MustCompile(`^([a-z]{2}-\d+(?:\.\d+)?)`)

// ControlIDToNistTag converts an OSCAL control ID to NIST 800-53 notation.
// Examples:
//
//	"ac-1"   → "AC-1"
//	"ac-2.3" → "AC-2 (3)"
//	"si-7.1" → "SI-7 (1)"
func ControlIDToNistTag(id string) string {
	if m := controlEnhancementRe.FindStringSubmatch(id); m != nil {
		return fmt.Sprintf("%s (%s)", strings.ToUpper(m[1]), m[2])
	}
	return strings.ToUpper(id)
}

// ControlIDsToNistTags converts a slice of OSCAL control IDs to NIST tags.
func ControlIDsToNistTags(ids []string) []string {
	tags := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		tag := ControlIDToNistTag(id)
		if !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	return tags
}

// ExtractControlIDFromObjectiveID extracts the base control ID from a SAR
// objective ID. For example, "ac-1.a.1_obj.1" returns "ac-1".
// Returns the input unchanged if it doesn't match the expected pattern.
func ExtractControlIDFromObjectiveID(objectiveID string) string {
	if m := objectiveIDRe.FindStringSubmatch(objectiveID); m != nil {
		return m[1]
	}
	return objectiveID
}

// OscalStatusToHDF maps OSCAL finding/risk status strings to HDF-compatible
// status strings. Returns the mapped status and true, or ("", false) if the
// input is not recognized.
//
// OSCAL SAR statuses: "satisfied" → "passed", "not-satisfied" → "failed"
// OSCAL risk statuses: "closed" → "passed", "open" → "failed"
func OscalStatusToHDF(state string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "satisfied", "closed":
		return "passed", true
	case "not-satisfied", "open":
		return "failed", true
	default:
		return "", false
	}
}

// ExtractPropValue finds the first property with the given name and returns
// its value. If ns is non-empty, the property must also match that namespace.
// Returns ("", false) if not found.
func ExtractPropValue(props []Property, name, ns string) (string, bool) {
	for _, p := range props {
		if p.Name == name && (ns == "" || p.Ns == ns) {
			return p.Value, true
		}
	}
	return "", false
}

// ExtractAllPropValues returns all property values matching the given name.
func ExtractAllPropValues(props []Property, name, ns string) []string {
	var values []string
	for _, p := range props {
		if p.Name == name && (ns == "" || p.Ns == ns) {
			values = append(values, p.Value)
		}
	}
	return values
}

// FlattenParts recursively concatenates prose from a Part tree,
// joining with newlines. Empty prose sections are skipped.
func FlattenParts(parts []Part) string {
	var sb strings.Builder
	flattenPartsRecursive(parts, &sb)
	return strings.TrimSpace(sb.String())
}

func flattenPartsRecursive(parts []Part, sb *strings.Builder) {
	for _, p := range parts {
		if p.Prose != "" {
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(p.Prose)
		}
		if len(p.Parts) > 0 {
			flattenPartsRecursive(p.Parts, sb)
		}
	}
}

// FlattenPartsByName is like FlattenParts but only includes parts matching
// the given name. Nested parts are included regardless of their name.
func FlattenPartsByName(parts []Part, name string) string {
	var sb strings.Builder
	for _, p := range parts {
		if p.Name == name {
			if p.Prose != "" {
				if sb.Len() > 0 {
					sb.WriteString("\n")
				}
				sb.WriteString(p.Prose)
			}
			if len(p.Parts) > 0 {
				flattenPartsRecursive(p.Parts, &sb)
			}
		}
	}
	return strings.TrimSpace(sb.String())
}

// ExtractRiskSeverity extracts impact/severity from risk characterization
// facets and returns a normalized 0.0–1.0 impact value. Looks for facets
// named "impact" or "risk" in any system. Falls back to defaultImpact.
func ExtractRiskSeverity(characterizations []Characterization, defaultImpact float64) float64 {
	for _, c := range characterizations {
		for _, f := range c.Facets {
			if f.Name == "impact" || f.Name == "risk" || f.Name == "likelihood" {
				switch strings.ToLower(f.Value) {
				case "critical":
					return 0.9
				case "high":
					return 0.7
				case "moderate", "medium":
					return 0.5
				case "low":
					return 0.3
				case "info", "informational", "none":
					return 0.0
				}
			}
		}
	}
	return defaultImpact
}

// MetadataInfo holds extracted metadata common to all OSCAL documents.
type MetadataInfo struct {
	Title        string
	Version      string
	OscalVersion string
	LastModified string
}

// ExtractMetadata pulls common fields from OSCAL metadata.
func ExtractMetadata(m Metadata) MetadataInfo {
	return MetadataInfo{
		Title:        m.Title,
		Version:      m.Version,
		OscalVersion: m.OscalVersion,
		LastModified: m.LastModified,
	}
}
