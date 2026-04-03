// Package testing provides shared utilities for Go converters.
package shared

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mitre/hdf-mappings/go/cwe"
	hdf "github.com/mitre/hdf-schema"
)

// InputChecksum computes the SHA-256 checksum of raw input bytes and returns
// it as an hdf.Checksum. Used by every input-to-HDF converter for the
// EvaluatedBaseline.ResultsChecksum field.
func InputChecksum(input []byte) *hdf.Checksum {
	hash := sha256.Sum256(input)
	return &hdf.Checksum{
		Algorithm: hdf.Sha256,
		Value:     hex.EncodeToString(hash[:]),
	}
}

// InputIntegrity computes the SHA-256 checksum of raw input bytes and returns
// it as an hdf.Integrity. Used for root-level integrity fields on document
// types (HDFBaseline, HDFSystem, HDFPlan, HDFAmendments, HDFEvidencePackage).
func InputIntegrity(input []byte) *hdf.Integrity {
	hash := sha256.Sum256(input)
	alg := hdf.Sha256
	val := hex.EncodeToString(hash[:])
	return &hdf.Integrity{
		Algorithm: &alg,
		Checksum:  &val,
	}
}

// Ptr returns a pointer to the given value. Replaces per-converter stringPtr,
// floatPtr, and ptr[T] helpers.
func Ptr[T any](v T) *T { return &v }

// Pre-compiled regexes for StripHTML — avoids per-call compilation overhead.
var (
	htmlTagRe    = regexp.MustCompile(`<[^>]*>`)
	whitespaceRe = regexp.MustCompile(`\s+`)
)

// StripHTML removes HTML tags from a string and normalizes whitespace.
// Returns the trimmed plain-text result.
func StripHTML(html string) string {
	stripped := htmlTagRe.ReplaceAllString(html, " ")
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(stripped, " "))
}

// standardSeverityMap defines the canonical severity-to-impact mappings used
// across most HDF converters, aligned with CVSS 3.x bands normalized to 0-1.
// Each value is the floor of its band: 0.9-1.0=critical, 0.7-0.8=high,
// 0.4-0.6=medium, 0.1-0.3=low, 0.0=informational.
// Case-insensitive lookup is handled by the caller.
var standardSeverityMap = map[string]float64{
	"critical":      0.9,
	"high":          0.7,
	"medium":        0.5,
	"low":           0.3,
	"info":          0.0,
	"none":          0.0,
	"informational": 0.0,
	"information":   0.0,
}

// SeverityToImpact maps a standard severity string to an HDF impact value.
// Case-insensitive. Returns defaultVal if severity is not recognized.
// Standard mappings: critical=0.9, high=0.7, medium=0.5, low=0.3,
// info/none/informational/information=0.0.
func SeverityToImpact(severity string, defaultVal float64) float64 {
	if impact, ok := standardSeverityMap[strings.ToLower(severity)]; ok {
		return impact
	}
	return defaultVal
}

// SeverityToImpactWithAliases maps severity to impact, checking custom aliases
// first, then falling back to standard mappings. Use for tools with non-standard
// severity labels (e.g., sonarqube BLOCKER, veracode numeric levels, grype
// critical=0.9). Aliases are matched case-insensitively.
func SeverityToImpactWithAliases(severity string, aliases map[string]float64, defaultVal float64) float64 {
	lower := strings.ToLower(severity)
	if impact, ok := aliases[lower]; ok {
		return impact
	}
	if impact, ok := standardSeverityMap[lower]; ok {
		return impact
	}
	return defaultVal
}

// DefaultStaticAnalysisNIST is the canonical NIST 800-53 fallback for static
// analysis and vulnerability scanning tools (SA-11: Developer Security Testing
// and Evaluation, RA-5: Vulnerability Monitoring and Scanning).
// Use when a finding has no CWE or the CWE has no NIST mapping.
var DefaultStaticAnalysisNIST = []string{"SA-11", "RA-5"}

// DefaultRemediationNIST is the canonical NIST 800-53 fallback for tools that
// identify outdated packages or flaws requiring patching (SI-2: Flaw
// Remediation, RA-5: Vulnerability Monitoring and Scanning).
var DefaultRemediationNIST = []string{"SI-2", "RA-5"}

// DefaultComponentManagementNIST is the canonical NIST 800-53 fallback for
// dependency/inventory management tools (CM-8: System Component Inventory).
var DefaultComponentManagementNIST = []string{"CM-8"}

// StringsToInterfaces converts a string slice to an interface slice.
// This is needed because Go's type system does not allow direct assignment
// of []string to []interface{} in JSON-serializable map values.
func StringsToInterfaces(ss []string) []interface{} {
	result := make([]interface{}, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// BuildNISTCCITags creates a tags map with NIST and optional CCI string slices
// converted to []interface{} for JSON serialization. If cci is empty, the "cci"
// key is omitted.
func BuildNISTCCITags(nist, cci []string) map[string]interface{} {
	tags := map[string]interface{}{
		"nist": StringsToInterfaces(nist),
	}
	if len(cci) > 0 {
		tags["cci"] = StringsToInterfaces(cci)
	}
	return tags
}

// BuildNISTCCITagsWithExtras creates a tags map with NIST, optional CCI, and
// additional key-value pairs. Extras are added after NIST/CCI so they can
// override those keys if needed.
func BuildNISTCCITagsWithExtras(nist, cci []string, extras map[string]interface{}) map[string]interface{} {
	tags := BuildNISTCCITags(nist, cci)
	for k, v := range extras {
		tags[k] = v
	}
	return tags
}

// SafeString extracts a string from an interface{} value.
// Returns the zero string if v is nil or not a string.
func SafeString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// SafeStringSlice extracts a string slice from an interface{} value.
// Returns nil if v is nil or not a []interface{} containing strings.
// Non-string elements within the slice are skipped.
func SafeStringSlice(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// DefaultMaxItems is the maximum number of items processed from any single
// input array. Truncation is silent (returns partial results with a boolean
// flag) to avoid breaking legitimate large scans while capping memory usage.
const DefaultMaxItems = 100000

// LimitSlice returns at most maxItems elements from items. The second return
// value is true if the slice was truncated. If maxItems <= 0, DefaultMaxItems
// is used.
func LimitSlice[T any](items []T, maxItems int) ([]T, bool) {
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}
	if len(items) <= maxItems {
		return items, false
	}
	return items[:maxItems], true
}

// MapCWEToNIST looks up NIST 800-53 controls for the given CWE identifiers,
// deduplicates and sorts the results, and falls back to the provided default
// when no CWE has a mapping. CWE IDs may optionally have a "CWE-" prefix
// (e.g., "CWE-79" or "79").
func MapCWEToNIST(cweIDs []string, fallback []string) []string {
	seen := make(map[string]bool)
	for _, id := range cweIDs {
		numericID := strings.TrimPrefix(id, "CWE-")
		for _, ctrl := range cwe.NISTControls(numericID) {
			seen[ctrl] = true
		}
	}
	if len(seen) == 0 {
		return fallback
	}
	result := make([]string, 0, len(seen))
	for ctrl := range seen {
		result = append(result, ctrl)
	}
	sort.Strings(result)
	return result
}

// LimitSliceWithWarning returns at most maxItems elements from items and logs
// a warning if the slice was truncated. The label parameter identifies the item
// type in the warning message (e.g., "issue", "vulnerability").
func LimitSliceWithWarning[T any](items []T, maxItems int, label string) []T {
	limited, truncated := LimitSlice(items, maxItems)
	if truncated {
		log.Printf("WARNING: Input truncated at %d %s items (original: %d)", len(limited), label, len(items))
	}
	return limited
}

// CWEPattern matches CWE identifiers like "CWE-79", "CWE 79", "cwe79".
// Pre-compiled at package level to avoid per-call overhead.
var CWEPattern = regexp.MustCompile(`(?i)CWE[- ]?(\d+)`)

// ExtractCWEIDs extracts all numeric CWE IDs from a text string.
// Returns deduplicated sorted list of numeric ID strings (e.g., ["79", "89"]).
func ExtractCWEIDs(text string) []string {
	matches := CWEPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		id := m[1]
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}

// ParseTimestamp tries multiple common timestamp formats and returns the first
// successful parse. Returns zero time if none match.
//
// Supported formats: RFC3339Nano, RFC3339, RFC1123Z, RFC1123, and the
// Nessus-specific "Mon Jan 02 15:04:05 2006" format.
func ParseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02T15:04:05",
		"Mon Jan 02 15:04:05 2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}

	return time.Time{}
}

// HDFResultsOptions configures the fields for building an HDFResults struct.
// GeneratorName and ConverterVersion are required. Tool fields are only
// included when at least one is non-empty.
type HDFResultsOptions struct {
	GeneratorName    string
	ConverterVersion string
	ToolName         string
	ToolVersion      string
	ToolFormat       string
	Baselines        []hdf.EvaluatedBaseline
	Components       []hdf.Component
	Timestamp        *time.Time
	Statistics       *hdf.Statistics
}

// BuildHDFResults assembles an HDFResults struct from the given options.
// Eliminates the repeated boilerplate of constructing Generator, Tool
// (with pointer fields), and assembling the top-level struct in every converter.
func BuildHDFResults(opts HDFResultsOptions) *hdf.HDFResults {
	result := &hdf.HDFResults{
		Baselines: opts.Baselines,
		Generator: &hdf.Generator{
			Name:    opts.GeneratorName,
			Version: opts.ConverterVersion,
		},
		Components: opts.Components,
		Timestamp:  opts.Timestamp,
		Statistics: opts.Statistics,
	}

	if opts.ToolName != "" || opts.ToolVersion != "" || opts.ToolFormat != "" {
		t := &hdf.Tool{}
		if opts.ToolName != "" {
			t.Name = &opts.ToolName
		}
		if opts.ToolVersion != "" {
			t.Version = &opts.ToolVersion
		}
		if opts.ToolFormat != "" {
			t.Format = &opts.ToolFormat
		}
		result.Tool = t
	}

	return result
}

// DefaultMaxJSONSize is the maximum allowed JSON input size (50 MB).
// This provides defense against memory exhaustion when converters are used
// as libraries outside the CLI (which has its own 50 MB input limit).
const DefaultMaxJSONSize = 50 * 1024 * 1024

// ValidateJSONSize checks that JSON input doesn't exceed the maximum allowed size.
// If maxSize <= 0, DefaultMaxJSONSize is used.
func ValidateJSONSize(input []byte, converterName string, maxSize int) error {
	if maxSize <= 0 {
		maxSize = DefaultMaxJSONSize
	}
	if len(input) > maxSize {
		return fmt.Errorf("%s: input exceeds maximum allowed size of %d bytes (%d bytes provided)", converterName, maxSize, len(input))
	}
	return nil
}

// DefaultMaxXMLSize is the maximum allowed XML input size (50 MB).
// This provides defense against entity expansion DoS when converters are used
// as libraries outside the CLI (which has its own 50 MB input limit).
const DefaultMaxXMLSize = 50 * 1024 * 1024

// ValidateXMLSize checks that XML input doesn't exceed the maximum allowed size.
// If maxSize <= 0, DefaultMaxXMLSize is used.
func ValidateXMLSize(input []byte, maxSize int) error {
	if maxSize <= 0 {
		maxSize = DefaultMaxXMLSize
	}
	if len(input) > maxSize {
		return fmt.Errorf("XML input exceeds maximum allowed size of %d bytes (%d bytes provided)", maxSize, len(input))
	}
	return nil
}

// ContainsXMLEntityDeclarations checks if XML input contains DOCTYPE entity
// declarations which could be used for entity expansion DoS attacks (billion
// laughs). Returns true if entities are found. Only inspects the first 4 KB
// of the input since DOCTYPE declarations must appear before the root element.
func ContainsXMLEntityDeclarations(input []byte) bool {
	limit := len(input)
	if limit > 4096 {
		limit = 4096
	}
	upper := bytes.ToUpper(input[:limit])
	return bytes.Contains(upper, []byte("<!ENTITY"))
}

// ValidateXMLInput performs safety checks on XML input:
//  1. Size limit check (default 50 MB)
//  2. Entity declaration detection (billion-laughs prevention)
//
// Returns nil if input passes all checks. If maxSize <= 0, DefaultMaxXMLSize
// is used.
func ValidateXMLInput(input []byte, maxSize int) error {
	if err := ValidateXMLSize(input, maxSize); err != nil {
		return err
	}
	if ContainsXMLEntityDeclarations(input) {
		return fmt.Errorf("XML input contains entity declarations which are not supported (potential entity expansion attack)")
	}
	return nil
}

// xmlRootElementRe matches an opening XML element tag, optionally namespace-prefixed.
// Captures the local name (group 1).
var xmlRootElementRe = regexp.MustCompile(`^<(?:[a-zA-Z_][\w.\-]*:)?([a-zA-Z_][\w.\-]*)`)

// ExtractXMLRootElement extracts the root element local name from an XML string.
// It skips XML processing instructions (<?...?>), comments (<!--...-->),
// and DOCTYPE declarations (<!DOCTYPE ... [...]>), and strips namespace prefixes.
// Returns "" if no element is found.
func ExtractXMLRootElement(input string) string {
	s := input
	for {
		s = strings.TrimLeft(s, " \t\n\r")
		if len(s) == 0 {
			return ""
		}
		switch {
		case strings.HasPrefix(s, "<?"):
			end := strings.Index(s, "?>")
			if end == -1 {
				return ""
			}
			s = s[end+2:]
		case strings.HasPrefix(s, "<!--"):
			end := strings.Index(s, "-->")
			if end == -1 {
				return ""
			}
			s = s[end+3:]
		case strings.HasPrefix(s, "<!DOCTYPE") || strings.HasPrefix(s, "<!doctype"):
			bracket := strings.Index(s, "[")
			gt := strings.Index(s, ">")
			if gt == -1 {
				return ""
			}
			if bracket != -1 && bracket < gt {
				endSubset := strings.Index(s, "]>")
				if endSubset == -1 {
					return ""
				}
				s = s[endSubset+2:]
			} else {
				s = s[gt+1:]
			}
		case strings.HasPrefix(s, "<!"):
			end := strings.Index(s, ">")
			if end == -1 {
				return ""
			}
			s = s[end+1:]
		default:
			m := xmlRootElementRe.FindStringSubmatch(s)
			if m == nil {
				return ""
			}
			return m[1]
		}
	}
}
