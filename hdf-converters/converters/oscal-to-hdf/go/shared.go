package oscal

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

// ToKebabCase converts a title to kebab-case, truncated to 80 characters.
// Returns fallback if title is empty.
func ToKebabCase(title, fallback string) string {
	if title == "" {
		return fallback
	}
	return hdfutil.ToKebabCase(title)
}

// nistEnhancementReverseRe matches NIST tags with enhancements like "AC-2 (3)".
var nistEnhancementReverseRe = regexp.MustCompile(`^([A-Z]{2}-\d+)\s*\((\d+)\)$`)

// NistTagToControlID converts NIST 800-53 notation back to OSCAL control ID.
// Examples:
//
//	"AC-1"     → "ac-1"
//	"AC-2 (3)" → "ac-2.3"
//	"SI-7 (1)" → "si-7.1"
func NistTagToControlID(tag string) string {
	tag = strings.TrimSpace(tag)
	if m := nistEnhancementReverseRe.FindStringSubmatch(tag); m != nil {
		return fmt.Sprintf("%s.%s", strings.ToLower(m[1]), m[2])
	}
	return strings.ToLower(tag)
}

// ParseOscalDocument parses raw JSON input into an OscalDocument, performing
// size validation and type checking. Returns an error if the input is empty,
// too large, invalid JSON, or not the expected document type.
func ParseOscalDocument(input []byte, expectedType, converterName string) (*OscalDocument, error) {
	if err := shared.ValidateJSONSize(input, converterName, 0); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("%s: empty input", converterName)
	}
	var doc OscalDocument
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("%s: failed to parse JSON: %w", converterName, err)
	}
	docType := doc.DocumentType()
	if docType != expectedType {
		return nil, fmt.Errorf("%s: expected %s document, got %s", converterName, expectedType, docType)
	}
	return &doc, nil
}

// GenerateUUID creates a version-4 UUID using crypto/rand.
func GenerateUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// ImpactToSeverity converts a 0.0-1.0 impact value to an OSCAL severity string.
// This is the reverse of ExtractRiskSeverity.
func ImpactToSeverity(impact float64) string {
	switch {
	case impact >= 0.9:
		return "critical"
	case impact >= 0.7:
		return "high"
	case impact >= 0.4:
		return "moderate"
	case impact >= 0.1:
		return "low"
	default:
		return "info"
	}
}

// HDFStatusToOSCALRiskStatus maps an HDF ResultStatus to an OSCAL risk status
// string. "passed"/"notApplicable" → "closed", everything else → "open".
func HDFStatusToOSCALRiskStatus(status hdf.ResultStatus) string {
	switch status {
	case hdf.Passed, hdf.NotApplicable:
		return "closed"
	default:
		return "open"
	}
}

// OscalVersion is the OSCAL specification version used in reverse converter output documents.
const OscalVersion = "1.1.2"

// OSCALToken encodes an arbitrary identifier into OSCAL's TokenDatatype shape:
// ^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$
//
// HDF requirement ids come from whatever the source tool numbers its rules with,
// and only some of those shapes are already tokens. Measured across this
// package's converter fixtures, 46% are not (57% of the distinct ids): package-style ids
// carrying '/', CIS control numbers starting with a digit, advisory ids carrying
// ':'. Copying one of those into a token-typed OSCAL field produces a document
// the target schema rejects while the converter exits successfully.
//
// The kept set is deliberately ASCII — [A-Za-z0-9._-] — rather than the wider
// \p{L}/\p{N} the pattern permits. Delegating to each platform's Unicode tables
// looked equivalent and was not: Go's unicode package and V8's \p{L}/\p{N} are
// built from different Unicode versions, and comparing the two implementations
// across the whole code-point range turned up 4657 characters they disagree on.
// Go would emit one of those and an ajv-based OSCAL validator would reject it —
// the very defect this function exists to prevent. An explicit ASCII set has no
// such dependency and is identical in both languages by construction. It costs
// nothing on real data: no requirement id in this package's converter fixtures
// is non-ASCII, and a non-ASCII one is preserved in full by the
// caller's source-id prop regardless.
//
// Every character outside that set becomes '_', and a leading '_' is prepended
// when the result would not start with a letter or '_'. An id built only from
// the kept characters is returned unchanged; note that this is narrower than
// token shape, so a token-valid non-ASCII id such as "café" is still rewritten.
//
// Two different ids can encode to the same token ("a/b" and "a:b" both yield
// "a_b"), which is why callers must also record the source id in the emitted
// document — for SAR that is a prop on the finding, trimmed because OSCAL's
// StringDatatype forbids a padded value. No collision occurs across the distinct
// requirement ids in this package's converter fixtures, which
// TestOSCALToken_NoCollisionsAcrossRealFixtureIDs pins against the same
// composition the converter uses.
func OSCALToken(s string) string {
	if s == "" {
		return ""
	}

	keep := func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return true
		case r == '.', r == '-', r == '_':
			return true
		}
		return false
	}
	leads := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
	}

	var b strings.Builder
	b.Grow(len(s) + 1)
	for _, r := range s {
		if keep(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}

	out := b.String()
	if !leads([]rune(out)[0]) {
		return "_" + out
	}
	return out
}
