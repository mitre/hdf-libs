package dbprotect

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	"github.com/mitre/hdf-mappings/go/cci"
	hdf "github.com/mitre/hdf-schema"
)

// Impact mapping was formerly a local map; now uses hdfutil.SeverityToImpact.
// DBProtect uses standard severity levels: high, medium, low, informational.

// Dataset represents the root DBProtect Cognos XML dataset structure.
type Dataset struct {
	XMLName  xml.Name `xml:"dataset"`
	Metadata Metadata `xml:"metadata"`
	Data     Data     `xml:"data"`
}

// Metadata contains column definitions for the dataset.
type Metadata struct {
	Items []MetadataItem `xml:"item"`
}

// MetadataItem describes a column in the dataset.
type MetadataItem struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Data contains all the rows of the dataset.
type Data struct {
	Rows []Row `xml:"row"`
}

// Row is a single data row with ordered values.
type Row struct {
	Values []string `xml:"value"`
}

// finding represents a single compiled finding, mapping column names to values.
type finding map[string]string

// compileFindings maps metadata column names to row values by position index,
// mirroring the heimdall2 compileFindings function.
func compileFindings(ds *Dataset) []finding {
	colNames := make([]string, len(ds.Metadata.Items))
	for i, item := range ds.Metadata.Items {
		colNames[i] = item.Name
	}

	findings := make([]finding, 0, len(ds.Data.Rows))
	for _, row := range ds.Data.Rows {
		f := make(finding, len(colNames))
		for i, name := range colNames {
			if i < len(row.Values) {
				f[name] = row.Values[i]
			}
		}
		findings = append(findings, f)
	}
	return findings
}

// getStatus maps DBProtect result statuses to HDF result statuses.
func getStatus(status string) hdf.ResultStatus {
	switch status {
	case "Fact":
		return hdf.NotReviewed
	case "Failed":
		return hdf.Failed
	case "Finding":
		return hdf.Failed
	case "Not A Finding":
		return hdf.Passed
	default:
		// Includes "Skipped" and any unknown status
		return hdf.NotReviewed
	}
}

// getImpact maps DBProtect risk levels to HDF impact values.
func getImpact(riskDV string) float64 {
	return hdfutil.SeverityToImpact(riskDV, 0.5)
}

// formatDesc creates a description string from the finding's task and check category.
func formatDesc(f finding) string {
	return fmt.Sprintf("Task : %s; Check Category : %s", f["Task"], f["Check Category"])
}

// formatSummary creates a summary string from the first finding's metadata.
func formatSummary(f finding) string {
	lines := []string{
		fmt.Sprintf("Organization : %s", f["Organization"]),
		fmt.Sprintf("Asset : %s", f["Asset"]),
		fmt.Sprintf("Asset Type : %s", f["Asset Type"]),
		fmt.Sprintf("IP Address, Port, Instance : %s", f["IP Address, Port, Instance"]),
	}
	return strings.Join(lines, "\n")
}

// idToString converts a Check ID to string form.
func idToString(id string) string {
	return strings.TrimSpace(id)
}

// parseDate attempts to parse the DBProtect date format "Feb 18 2021 15:57".
func parseDate(dateStr string) time.Time {
	dateStr = strings.TrimSpace(dateStr)
	if dateStr == "" {
		return time.Time{}
	}

	formats := []string{
		"Jan 02 2006 15:04",
		"Jan 2 2006 15:04",
		"2006-01-02 15:04",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}

	return time.Time{}
}

// groupByCheckID groups findings by their Check ID, preserving insertion order.
func groupByCheckID(findings []finding) ([]string, map[string][]finding) {
	order := []string{}
	groups := map[string][]finding{}
	for _, f := range findings {
		checkID := idToString(f["Check ID"])
		if _, seen := groups[checkID]; !seen {
			order = append(order, checkID)
		}
		groups[checkID] = append(groups[checkID], f)
	}
	return order, groups
}

// hasResultStatus checks if the dataset includes a "Result Status" column.
func hasResultStatus(ds *Dataset) bool {
	for _, item := range ds.Metadata.Items {
		if item.Name == "Result Status" {
			return true
		}
	}
	return false
}

// buildRequirement converts a group of findings sharing a Check ID into one
// EvaluatedRequirement with multiple results.
func buildRequirement(checkID string, findings []finding, hasStatus bool) hdf.EvaluatedRequirement {
	rep := findings[0]

	nist := shared.DefaultStaticAnalysisNIST
	cciTags := cci.NISTToCCI(nist)
	tags := shared.BuildNISTCCITags(nist, cciTags)

	descriptions := []hdf.Description{
		{Label: "default", Data: formatDesc(rep)},
	}

	results := make([]hdf.RequirementResult, len(findings))
	for i, f := range findings {
		var status hdf.ResultStatus
		if hasStatus {
			status = getStatus(f["Result Status"])
		} else {
			// Findings Detail report: all entries are findings (failed)
			status = hdf.Failed
		}

		startTime := parseDate(f["Date"])

		results[i] = hdf.RequirementResult{
			Status:    status,
			CodeDesc:  f["Details"],
			StartTime: startTime,
		}
	}

	title := rep["Check"]
	return hdf.EvaluatedRequirement{
		ID:           checkID,
		Title:        &title,
		Impact:       getImpact(rep["Risk DV"]),
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
	}
}

// ConvertDbprotectToHDF converts DBProtect Cognos XML output to HDF format.
// Supports both "Check Results Details" (has Result Status) and "Findings Detail"
// (no Result Status; all rows are findings) report formats.
func ConvertDbprotectToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("dbprotect: empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("dbprotect: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	var ds Dataset
	if err := xml.Unmarshal(input, &ds); err != nil {
		return nil, fmt.Errorf("dbprotect: failed to parse XML: %w", err)
	}

	if len(ds.Data.Rows) == 0 {
		return nil, fmt.Errorf("dbprotect: no data rows found")
	}

	findings := compileFindings(&ds)
	limitedFindings := shared.LimitSliceWithWarning(findings, 0, "finding")
	hasStatus := hasResultStatus(&ds)

	order, groups := groupByCheckID(limitedFindings)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, checkID := range order {
		requirements[i] = buildRequirement(checkID, groups[checkID], hasStatus)
	}

	// Use first finding for metadata
	firstFinding := limitedFindings[0]
	title := firstFinding["Job Name"]
	summary := formatSummary(firstFinding)

	baseline := hdf.EvaluatedBaseline{
		Name:            "DBProtect Scan",
		Title:           &title,
		Summary:         &summary,
		ResultsChecksum: resultsChecksum,
		Requirements:    requirements,
	}

	// Extract policy info
	if policy := firstFinding["Policy"]; policy != "" {
		baseline.Version = &policy
	}

	targetName := firstFinding["Asset"]
	now := time.Now().UTC()

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "dbprotect-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "DBProtect",
		ToolFormat:       "XML",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.Host},
		},
		Timestamp: &now,
	}), nil
}
