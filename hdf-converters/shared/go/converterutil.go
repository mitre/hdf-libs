// Package shared provides converter-specific utilities for Go converters.
// General-purpose utilities (severity mapping, string manipulation, CWE
// extraction, etc.) live in hdfutil (github.com/mitre/hdf-libs/hdf-utilities/go/v3).
// This package contains only converter-specific logic that depends on
// hdf-schema types, hdf-mappings, or converter-domain constants.
package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

// BuildNISTCCITags creates a tags map with NIST and optional CCI string slices
// converted to []interface{} for JSON serialization. If cci is empty, the "cci"
// key is omitted.
func BuildNISTCCITags(nist, cci []string) map[string]interface{} {
	tags := map[string]interface{}{
		"nist": hdfutil.StringsToInterfaces(nist),
	}
	if len(cci) > 0 {
		tags["cci"] = hdfutil.StringsToInterfaces(cci)
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
	limited, truncated := hdfutil.LimitSlice(items, maxItems)
	if truncated {
		log.Printf("WARNING: Input truncated at %d %s items (original: %d)", len(limited), label, len(items))
	}
	return limited
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
	if hdfutil.ContainsXMLEntityDeclarations(input) {
		return fmt.Errorf("XML input contains entity declarations which are not supported (potential entity expansion attack)")
	}
	return nil
}
