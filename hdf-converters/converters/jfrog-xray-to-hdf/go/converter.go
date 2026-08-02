package jfrogxray

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// XrayReport is the top-level JFrog Xray scan output structure.
type XrayReport struct {
	TotalCount int         `json:"total_count"`
	Data       []XrayEntry `json:"data"`
}

// XrayEntry represents a single vulnerability/issue entry from Xray output.
type XrayEntry struct {
	ID                string            `json:"id"`
	Severity          string            `json:"severity"`
	Summary           string            `json:"summary"`
	IssueType         string            `json:"issue_type"`
	Provider          string            `json:"provider"`
	Component         string            `json:"component"`
	SourceID          string            `json:"source_id"`
	SourceCompID      string            `json:"source_comp_id"`
	ComponentVersions ComponentVersions `json:"component_versions"`
	Edited            string            `json:"edited"`
}

// ComponentVersions holds version metadata for a vulnerable component.
type ComponentVersions struct {
	ID                 string      `json:"id"`
	VulnerableVersions []string    `json:"vulnerable_versions"`
	FixedVersions      []string    `json:"fixed_versions"`
	MoreDetails        MoreDetails `json:"more_details"`
}

// MoreDetails holds CVE, CWE, and description data.
type MoreDetails struct {
	CVEs        []CVEEntry `json:"cves"`
	Description string     `json:"description"`
	Provider    string     `json:"provider"`

	// CVEsRaw is the source `cves` JSON verbatim. formatDescription renders the
	// CVE list into human-readable text, and re-marshalling CVEs would invent
	// zero-valued keys the source never had.
	CVEsRaw json.RawMessage `json:"-"`
}

// UnmarshalJSON captures the raw `cves` payload alongside the decoded entries.
func (m *MoreDetails) UnmarshalJSON(data []byte) error {
	var aux struct {
		CVEs        json.RawMessage `json:"cves"`
		Description string          `json:"description"`
		Provider    string          `json:"provider"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	m.Description = aux.Description
	m.Provider = aux.Provider
	m.CVEsRaw = aux.CVEs
	m.CVEs = nil
	if len(aux.CVEs) > 0 {
		if err := json.Unmarshal(aux.CVEs, &m.CVEs); err != nil {
			return err
		}
	}
	return nil
}

// marshalPlain serializes v without Go's default HTML escaping, so `<` and `>`
// survive into human-readable text as themselves.
func marshalPlain(v interface{}) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// CVEEntry holds a single CVE entry with optional CWE mappings.
type CVEEntry struct {
	CVE    string   `json:"cve"`
	CWE    []string `json:"cwe"`
	CvssV2 string   `json:"cvss_v2"`
	CvssV3 string   `json:"cvss_v3"`
}

// hashID generates a truncated SHA-256 hash of the summary string for use as
// an ID when the entry's "id" field is empty. Truncated to 32 hex chars for
// compatibility with the original heimdall2 hash length.
func hashID(summary string) string {
	hash := sha256.Sum256([]byte(summary))
	return hex.EncodeToString(hash[:16]) // 16 bytes = 32 hex chars
}

// getEntryID returns the entry ID, falling back to a SHA-256 hash of the
// summary when the id field is empty.
func getEntryID(entry XrayEntry) string {
	if entry.ID != "" {
		return entry.ID
	}
	return hashID(entry.Summary)
}

// getImpact maps JFrog Xray severity strings to HDF impact values.
func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

// extractCWEs extracts CWE identifiers from the first CVE entry's cwe array.
func extractCWEs(entry XrayEntry) []string {
	if len(entry.ComponentVersions.MoreDetails.CVEs) == 0 {
		return nil
	}
	return entry.ComponentVersions.MoreDetails.CVEs[0].CWE
}

// formatDescription builds the description from more_details.description and
// CVE information, matching the heimdall2 formatDesc behavior.
func formatDescription(entry XrayEntry) string {
	parts := []string{}
	desc := entry.ComponentVersions.MoreDetails.Description
	if desc != "" {
		parts = append(parts, desc)
	}
	if len(entry.ComponentVersions.MoreDetails.CVEs) > 0 {
		var compact bytes.Buffer
		if err := json.Compact(&compact, entry.ComponentVersions.MoreDetails.CVEsRaw); err == nil {
			cveStr := strings.ReplaceAll(compact.String(), "\":", "\"=>")
			cveStr = strings.ReplaceAll(cveStr, ",", ", ")
			parts = append(parts, fmt.Sprintf("cves: %s", cveStr))
		}
	}
	if len(parts) == 0 {
		return entry.Summary
	}
	return strings.Join(parts, "\n")
}

// formatCodeDesc builds the code_desc string from component version metadata,
// matching the heimdall2 formatCodeDesc behavior.
func formatCodeDesc(entry XrayEntry) string {
	parts := []string{}

	parts = append(parts, fmt.Sprintf("source_comp_id : %s", entry.SourceCompID))

	if len(entry.ComponentVersions.VulnerableVersions) > 0 {
		vulnData, err := marshalPlain(entry.ComponentVersions.VulnerableVersions)
		if err == nil {
			parts = append(parts, fmt.Sprintf("vulnerable_versions : %s", vulnData))
		}
	} else {
		parts = append(parts, "vulnerable_versions : ")
	}

	if len(entry.ComponentVersions.FixedVersions) > 0 {
		fixedData, err := marshalPlain(entry.ComponentVersions.FixedVersions)
		if err == nil {
			parts = append(parts, fmt.Sprintf("fixed_versions : %s", fixedData))
		}
	} else {
		parts = append(parts, "fixed_versions : ")
	}

	parts = append(parts, fmt.Sprintf("issue_type : %s", entry.IssueType))
	parts = append(parts, fmt.Sprintf("provider : %s", entry.Provider))

	result := strings.Join(parts, "\n")
	return strings.ReplaceAll(result, ",", ", ")
}

// groupByID groups entries by their effective ID, preserving insertion order.
func groupByID(entries []XrayEntry) ([]string, map[string][]XrayEntry) {
	order := []string{}
	groups := map[string][]XrayEntry{}
	for _, entry := range entries {
		id := getEntryID(entry)
		if _, seen := groups[id]; !seen {
			order = append(order, id)
		}
		groups[id] = append(groups[id], entry)
	}
	return order, groups
}

// buildRequirement converts a group of entries sharing an ID into one
// EvaluatedRequirement with multiple results.
func buildRequirement(entryID string, entries []XrayEntry, scanTime time.Time) hdf.EvaluatedRequirement {
	rep := entries[0]

	cweIDs := extractCWEs(rep)
	nist := shared.MapCWEToNIST(cweIDs, shared.DefaultStaticAnalysisNIST)
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	if len(cweIDs) > 0 {
		extras["cweid"] = cweIDs
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	descText := formatDescription(rep)
	descriptions := []hdf.Description{
		{Label: "default", Data: descText},
	}

	results := make([]hdf.RequirementResult, len(entries))
	for i, entry := range entries {
		results[i] = hdf.RequirementResult{
			Status:    hdf.Failed,
			CodeDesc:  formatCodeDesc(entry),
			StartTime: scanTime,
		}
	}

	title := rep.Summary
	req := hdf.EvaluatedRequirement{
		ID:                 entryID,
		Title:              &title,
		Impact:             getImpact(rep.Severity),
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            results,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	if pkg := buildAffectedPackageFromEntry(rep); pkg != nil {
		req.AffectedPackages = []hdf.AffectedPackage{*pkg}
	}
	return req
}

// xraySourceComp parses an Xray source_comp_id (`<scheme>://<name>:<version>`)
// or source_id (`<scheme>://<name>`).
func xraySourceComp(s string) (scheme, name, version string, ok bool) {
	if s == "" {
		return "", "", "", false
	}
	idx := strings.Index(s, "://")
	if idx <= 0 {
		return "", "", "", false
	}
	scheme = strings.ToLower(s[:idx])
	rest := s[idx+3:]
	if colon := strings.LastIndex(rest, ":"); colon > 0 {
		return scheme, rest[:colon], rest[colon+1:], true
	}
	return scheme, rest, "", true
}

// ecosystemFromXraySource maps Xray's scheme prefix to AffectedPackage.ecosystem.
// `gav://` is Maven (group:artifact); other schemes match PURL types directly.
func ecosystemFromXraySource(scheme string) hdf.Ecosystem {
	if scheme == "gav" {
		return hdf.Maven
	}
	return shared.EcosystemFromPurlType(scheme)
}

func buildAffectedPackageFromEntry(entry XrayEntry) *hdf.AffectedPackage {
	src := entry.SourceCompID
	if src == "" {
		src = entry.SourceID
	}
	name := entry.Component
	var version string
	var ecosystem hdf.Ecosystem
	if scheme, parsedName, parsedVersion, ok := xraySourceComp(src); ok {
		if parsedName != "" {
			name = parsedName
		}
		version = parsedVersion
		ecosystem = ecosystemFromXraySource(scheme)
	}
	var fixed string
	if len(entry.ComponentVersions.FixedVersions) > 0 {
		fixed = entry.ComponentVersions.FixedVersions[0]
	}
	if ecosystem == "" && name != "" {
		ecosystem = hdf.Generic
	}
	return shared.BuildAffectedPackage(shared.AffectedPackageOptions{
		Name:           name,
		Version:        version,
		Ecosystem:      ecosystem,
		FixedInVersion: fixed,
	})
}

// ConvertJfrogXrayToHDF converts JFrog Xray JSON output to HDF format.
func ConvertJfrogXrayToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("jfrog-xray: empty input")
	}
	if err := shared.ValidateJSONSize(input, "jfrog-xray", 0); err != nil {
		return nil, fmt.Errorf("jfrog-xray: %w", err)
	}

	var report XrayReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("jfrog-xray: invalid JSON: %w", err)
	}

	checksum := shared.InputChecksum(input)

	limitedEntries := shared.LimitSliceWithWarning(report.Data, 0, "entry")

	// JFrog Xray output carries no scan-level timestamp (only per-entry `edited`
	// dates, which mark when each vuln-DB record was last edited, not when the
	// scan ran). Use a single conversion timestamp for all results, the doc
	// timestamp, and the no-findings placeholder.
	scanTime := time.Now().UTC()

	order, groups := groupByID(limitedEntries)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, entryID := range order {
		requirements[i] = buildRequirement(entryID, groups[entryID], scanTime)
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"jfrog-xray-no-findings",
				"JFrog Xray scanned the target artifact and reported zero vulnerable components.",
				scanTime,
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "JFrog Xray Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "jfrog-xray-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "JFrog Xray",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: "JFrog Xray Scan", Type: hdf.Application},
		},
		Timestamp: &scanTime,
	}), nil
}
