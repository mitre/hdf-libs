package jfrogxray

import (
	"crypto/md5" //nolint:gosec // MD5 used for ID generation (non-cryptographic), matches heimdall2 behavior
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/mitre/hdf-mappings/go/cci"
	hdf "github.com/mitre/hdf-schema"
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
}

// CVEEntry holds a single CVE entry with optional CWE mappings.
type CVEEntry struct {
	CVE    string   `json:"cve"`
	CWE    []string `json:"cwe"`
	CvssV2 string   `json:"cvss_v2"`
	CvssV3 string   `json:"cvss_v3"`
}

// hashID generates an MD5 hash of the summary string for use as an ID when
// the entry's "id" field is empty. This matches the heimdall2 behavior.
func hashID(summary string) string {
	hash := md5.Sum([]byte(summary)) //nolint:gosec // Non-cryptographic use for ID generation
	return hex.EncodeToString(hash[:])
}

// getEntryID returns the entry ID, falling back to an MD5 hash of the summary
// when the id field is empty.
func getEntryID(entry XrayEntry) string {
	if entry.ID != "" {
		return entry.ID
	}
	return hashID(entry.Summary)
}

// getImpact maps JFrog Xray severity strings to HDF impact values.
func getImpact(severity string) float64 {
	switch strings.ToLower(severity) {
	case "high":
		return 0.7
	case "medium":
		return 0.5
	case "low":
		return 0.3
	default:
		return 0.5
	}
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
		cveData, err := json.Marshal(entry.ComponentVersions.MoreDetails.CVEs)
		if err == nil {
			cveStr := strings.ReplaceAll(string(cveData), "\":", "\"=>")
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
		vulnData, err := json.Marshal(entry.ComponentVersions.VulnerableVersions)
		if err == nil {
			parts = append(parts, fmt.Sprintf("vulnerable_versions : %s", string(vulnData)))
		}
	} else {
		parts = append(parts, "vulnerable_versions : ")
	}

	if len(entry.ComponentVersions.FixedVersions) > 0 {
		fixedData, err := json.Marshal(entry.ComponentVersions.FixedVersions)
		if err == nil {
			parts = append(parts, fmt.Sprintf("fixed_versions : %s", string(fixedData)))
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
func buildRequirement(entryID string, entries []XrayEntry) hdf.EvaluatedRequirement {
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
			Status:   hdf.Failed,
			CodeDesc: formatCodeDesc(entry),
		}
	}

	title := rep.Summary
	return hdf.EvaluatedRequirement{
		ID:           entryID,
		Title:        &title,
		Impact:       getImpact(rep.Severity),
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
	}
}

// ConvertJfrogXrayToHDF converts JFrog Xray JSON output to HDF format.
func ConvertJfrogXrayToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("jfrog-xray: empty input")
	}

	var report XrayReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("jfrog-xray: invalid JSON: %w", err)
	}

	checksum := shared.InputChecksum(input)

	limitedEntries, truncated := shared.LimitSlice(report.Data, 0)
	if truncated {
		fmt.Printf("WARNING: Input truncated at %d entries (original: %d)\n", len(limitedEntries), len(report.Data))
	}

	order, groups := groupByID(limitedEntries)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, entryID := range order {
		requirements[i] = buildRequirement(entryID, groups[entryID])
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "JFrog Xray Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	toolName := "JFrog Xray"
	formatName := "JSON"
	now := time.Now().UTC()

	return &hdf.HDFResults{
		Generator: &hdf.Generator{
			Name:    "jfrog-xray-to-hdf",
			Version: converterVersion,
		},
		DataSource: &hdf.DataSource{
			Name:   &toolName,
			Format: &formatName,
		},
		Baselines: []hdf.EvaluatedBaseline{baseline},
		Targets: []hdf.Target{
			{Name: "JFrog Xray Scan", Type: hdf.Application},
		},
		Timestamp: &now,
	}, nil
}
