// Package shared provides converter-specific utilities for Go converters.
// General-purpose utilities (severity mapping, string manipulation, CWE
// extraction, etc.) live in hdfutil (github.com/mitre/hdf-libs/hdf-utilities/go/v3).
// This package contains only converter-specific logic that depends on
// hdf-schema types, hdf-mappings, or converter-domain constants.
package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
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

// nistTagPattern matches a NIST 800-53 control identifier and captures the
// family (two letters) and the base sub-control number, ignoring enhancement
// suffixes like "(1)" or ".1". Used by DeriveControlType to classify a tag.
var nistTagPattern = regexp.MustCompile(`^([A-Z]{2})-(\d+)`)

// nistFamilyControlType maps each NIST 800-53 Rev 5 family to its HDF
// controlType per Appendix C / SP 800-53A classification. Families not in
// this map (e.g., synthetic XCCDF families like "SV") yield nil.
var nistFamilyControlType = map[string]hdf.ControlType{
	"AC": hdf.Technical,
	"AU": hdf.Operational,
	"CM": hdf.Operational,
	"CP": hdf.Operational,
	"IA": hdf.Technical,
	"IR": hdf.Operational,
	"MA": hdf.Operational,
	"MP": hdf.Operational,
	"PE": hdf.Operational,
	"PS": hdf.Operational,
	"PT": hdf.Operational,
	"AT": hdf.Operational,
	"SC": hdf.Technical,
	"SI": hdf.Technical,
	"CA": hdf.Management,
	"PL": hdf.Management,
	"PM": hdf.Management,
	"RA": hdf.Management,
	"SA": hdf.Management,
	"SR": hdf.Management,
}

// DeriveControlType returns the HDF controlType classification for a NIST
// 800-53 control identifier using a family-prefix heuristic. Returns nil when
// the family is unrecognized or the tag is not a NIST control identifier.
//
// The heuristic, drawn from NIST SP 800-53 Rev 5 Appendix C and SP 800-53A:
//
//   - Management: PM, RA, CA, PL, SA, SR families
//   - Operational: AT, AU, CM, CP, IR, MA, MP, PE, PS, PT families
//   - Technical:  AC, IA, SC, SI families
//   - Policy:     any "-1" sub-control (the per-family policy/procedure
//     document, regardless of which family it belongs to). Enhancements of
//     -1 controls (e.g., AC-1(1)) also resolve to policy.
//
// The "-1" rule takes precedence over the family rule because a per-family
// policy/procedure document is more usefully classified by its document
// nature than by the family it documents.
//
// Examples:
//
//	DeriveControlType("AC-3")      -> &Technical
//	DeriveControlType("AC-1")      -> &Policy        (any *-1 is policy)
//	DeriveControlType("AC-3(1)")   -> &Technical     (enhancement of AC-3)
//	DeriveControlType("PM-2")      -> &Management
//	DeriveControlType("SV-238196") -> nil            (not a NIST tag)
//	DeriveControlType("")          -> nil
func DeriveControlType(nistTag string) *hdf.ControlType {
	match := nistTagPattern.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(nistTag)))
	if match == nil {
		return nil
	}
	family := match[1]
	subControl := match[2]
	ct, ok := nistFamilyControlType[family]
	if !ok {
		return nil
	}
	if subControl == "1" {
		policy := hdf.Policy
		return &policy
	}
	return &ct
}

// nistFallbackBundles enumerates NIST tag sets this package uses as
// per-converter static fallbacks when no real per-finding mapping is
// available. When DeriveControlTypeFromTags sees an input that exactly
// matches one of these bundles, it returns nil — the input carries no
// real per-finding signal, and labeling every requirement with the same
// derived controlType is misleading.
//
// Keep in sync with DefaultStaticAnalysisNIST, DefaultRemediationNIST,
// DefaultComponentManagementNIST above.
var nistFallbackBundles = [][]string{
	{"RA-5", "SA-11"}, // DefaultStaticAnalysisNIST (sorted)
	{"RA-5", "SI-2"},  // DefaultRemediationNIST (sorted)
	{"CM-8"},          // DefaultComponentManagementNIST
}

// tagsMatchFallback reports whether tags exactly matches one of the known
// per-converter static fallback bundles, after sorting and deduplication.
func tagsMatchFallback(tags []string) bool {
	if len(tags) == 0 {
		return false
	}
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		seen[t] = true
	}
	sorted := make([]string, 0, len(seen))
	for t := range seen {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)
	for _, bundle := range nistFallbackBundles {
		if len(bundle) != len(sorted) {
			continue
		}
		match := true
		for i, b := range bundle {
			if b != sorted[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// DeriveControlTypeFromTags returns the controlType for a slice of NIST tags.
// Resolves each tag via DeriveControlType, then picks the most-specific class
// by precedence: technical > operational > management > policy. The rationale
// is that a control enforced via configuration (technical) is more actionable
// than the same control's management/policy framing — consumers benefit more
// from the action-oriented label.
//
// Returns nil when no tag resolves to a known classification, OR when the
// input exactly matches a converter-level static-fallback bundle (e.g. the
// DefaultStaticAnalysisNIST set). The fallback gate prevents converters that
// have no per-finding NIST signal from stamping every requirement with the
// same misleading controlType.
func DeriveControlTypeFromTags(tags []string) *hdf.ControlType {
	if tagsMatchFallback(tags) {
		return nil
	}
	rank := map[hdf.ControlType]int{
		hdf.Technical:   0,
		hdf.Operational: 1,
		hdf.Management:  2,
		hdf.Policy:      3,
		hdf.Procedure:   4,
	}
	var best *hdf.ControlType
	bestRank := len(rank) + 1
	for _, tag := range tags {
		ct := DeriveControlType(tag)
		if ct == nil {
			continue
		}
		if r, ok := rank[*ct]; ok && r < bestRank {
			bestRank = r
			best = ct
		}
	}
	return best
}

// NISTTagsFromMap returns the "nist" tag slice from a converter tags map,
// or nil when the key is absent. Converters store tags as
// map[string]interface{} so a type assertion is required. This helper
// accepts both []string (used by converters that assign tags["nist"]
// directly) and []interface{} (the JSON-marshaled form produced by
// BuildNISTCCITags via hdfutil.StringsToInterfaces) and normalizes to
// []string. An empty slice is treated as "no tags."
//
// Use with DeriveControlTypeFromTags to populate Requirement_Core.controlType
// from whatever NIST tags the converter has already resolved:
//
//	req.ControlType = shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags))
func NISTTagsFromMap(tags map[string]interface{}) []string {
	raw, present := tags["nist"]
	if !present {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		if len(v) == 0 {
			return nil
		}
		return v
	case []interface{}:
		if len(v) == 0 {
			return nil
		}
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

// BuildNoFindingsRequirement synthesizes a passed placeholder for tools that
// ran clean. Required because the HDF schema enforces requirements.minItems=1.
func BuildNoFindingsRequirement(id, codeDesc string, startTime time.Time) hdf.EvaluatedRequirement {
	title := "No findings reported"
	return hdf.EvaluatedRequirement{
		ID:    id,
		Title: &title,
		Descriptions: []hdf.Description{
			{Label: "default", Data: codeDesc},
		},
		Results: []hdf.RequirementResult{
			{
				Status:    hdf.Passed,
				CodeDesc:  codeDesc,
				StartTime: startTime,
			},
		},
		Tags:   map[string]interface{}{},
		Impact: 0,
	}
}

// DeriveVerificationMethod returns the HDF verificationMethod for a
// requirement based on whether check code is present. Returns &Automated
// when code is non-nil and non-empty (a check exists and runs without
// operator action), and nil otherwise — the converter is responsible for
// distinguishing manual-by-design (statement-form, e.g. FedRAMP 20x KSI)
// from manual-pending-automation (a check that could be automated but
// isn't yet) when it has the source-format context to do so.
func DeriveVerificationMethod(code *string) *hdf.VerificationMethodEnum {
	if code == nil || *code == "" {
		return nil
	}
	automated := hdf.VerificationMethodEnumAutomated
	return &automated
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

// purlTypeToEcosystem maps a PURL `type` segment to the AffectedPackage
// ecosystem enum. Unknown types fall back to Generic.
var purlTypeToEcosystem = map[string]hdf.Ecosystem{
	"npm":    hdf.Npm,
	"pypi":   hdf.Pypi,
	"rpm":    hdf.RPM,
	"deb":    hdf.Deb,
	"maven":  hdf.Maven,
	"gem":    hdf.Gem,
	"nuget":  hdf.Nuget,
	"golang": hdf.Go,
	"go":     hdf.Go,
	"cargo":  hdf.Cargo,
}

// EcosystemFromPurlType resolves an Ecosystem from a PURL type string.
// Returns Generic for unknown types so callers can keep the schema's
// name+version+ecosystem triple valid without inventing a synthetic
// ecosystem.
func EcosystemFromPurlType(typeStr string) hdf.Ecosystem {
	if typeStr == "" {
		return hdf.Generic
	}
	if eco, ok := purlTypeToEcosystem[strings.ToLower(typeStr)]; ok {
		return eco
	}
	return hdf.Generic
}

// AffectedPackageOptions carries the fields a converter might know about
// a package. BuildAffectedPackage uses non-empty fields to assemble an
// Affected_Package primitive.
type AffectedPackageOptions struct {
	Name           string
	Version        string
	Ecosystem      hdf.Ecosystem // empty string means "unset"
	Purl           string
	CPE            string
	FixedInVersion string
}

// BuildAffectedPackage assembles an Affected_Package primitive from the
// available identifiers. Returns nil when no identifier or full triple
// is present — callers should skip the entry rather than emit a
// schema-invalid AffectedPackage. Empty strings are treated as missing.
//
// The schema's anyOf requires at least one of:
//   - name + version + ecosystem
//   - purl alone
//   - cpe alone
func BuildAffectedPackage(opts AffectedPackageOptions) *hdf.AffectedPackage {
	pkg := &hdf.AffectedPackage{}
	if opts.Purl != "" {
		p := opts.Purl
		pkg.Purl = &p
	}
	if opts.CPE != "" {
		c := opts.CPE
		pkg.Cpe = &c
	}
	if opts.Name != "" {
		n := opts.Name
		pkg.Name = &n
	}
	if opts.Version != "" {
		v := opts.Version
		pkg.Version = &v
	}
	if opts.Ecosystem != "" {
		e := opts.Ecosystem
		pkg.Ecosystem = &e
	}
	if opts.FixedInVersion != "" {
		f := opts.FixedInVersion
		pkg.FixedInVersion = &f
	}
	hasTriple := pkg.Name != nil && pkg.Version != nil && pkg.Ecosystem != nil
	if !hasTriple && pkg.Purl == nil && pkg.Cpe == nil {
		return nil
	}
	return pkg
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

// DecodeHDF decodes an HDF document into v. It is the single ingest point for
// every HDF-consuming converter: real HDF carries zone-less timestamps (InSpec
// emits startTime with no offset), which the schema types' time.Time fields
// reject, so the bytes are normalized to canonical trimmed-UTC RFC3339 first.
// Callers keep their own error wrapping.
func DecodeHDF(input []byte, v interface{}) error {
	return json.Unmarshal(hdfutil.NormalizeHDFTimestamps(input), v)
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
