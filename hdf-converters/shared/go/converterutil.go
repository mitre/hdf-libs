// Package testing provides shared utilities for Go converters.
package testing

import (
	"crypto/sha256"
	"encoding/hex"
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

// Ptr returns a pointer to the given value. Replaces per-converter stringPtr,
// floatPtr, and ptr[T] helpers.
func Ptr[T any](v T) *T { return &v }

// StripHTML removes HTML tags from a string and normalizes whitespace.
// Returns the trimmed plain-text result.
func StripHTML(html string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	stripped := re.ReplaceAllString(html, " ")
	ws := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(ws.ReplaceAllString(stripped, " "))
}

// Severity-to-impact mapping audit (2026-02):
// Each converter defines its own severity-to-impact map because different tools
// have different severity levels (e.g. SonarQube uses BLOCKER/CRITICAL/MAJOR/
// MINOR/INFO while Grype uses Critical/High/Medium/Low/Negligible).
// Canonical reference: heimdall2 sonarqube-mapper.ts IMPACT_MAPPING.
// Grype uses critical=0.9 consistently in both Go/TS -- this is intentional,
// not a parity bug (grype's "Critical" is broader than SonarQube's "CRITICAL").

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
