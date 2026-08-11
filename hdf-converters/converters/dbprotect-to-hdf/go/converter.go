package dbprotect

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
				// The TS parser trims XML text nodes; surrounding whitespace in a
				// Cognos cell is layout, not data, so trim here too.
				f[name] = strings.TrimSpace(row.Values[i])
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

// getBacktrace mirrors heimdall2: a source "Failed" result carries a fixed
// marker in results[].backtrace. DBProtect ships no stacktrace, so this sentinel
// is the only backtrace signal. Keys on the literal source "Result Status", not
// the mapped HDF status, so "Finding" (also HDF-failed) and the implicit-failed
// Findings Detail rows get no marker — exactly as heimdall2 does.
func getBacktrace(resultStatus string) []string {
	if resultStatus == "Failed" {
		return []string{"DB Protect Failed Check"}
	}
	return nil
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
			return hdfutil.NormalizeTimestamp(t)
		}
	}

	return time.Time{}
}

// scanTimestamp derives the scan time for the top-level HDF timestamp from the
// source, preferring the "Start Date" column (the Findings Detail report's scan
// start) and falling back to the per-finding "Date" column present in both
// report formats. Returns the zero time when neither parses, so the caller omits
// the timestamp rather than emitting a wall-clock value (determinism).
func scanTimestamp(f finding) time.Time {
	if t := parseDate(f["Start Date"]); !t.IsZero() {
		return t
	}
	return parseDate(f["Date"])
}

// parseTarget splits DBProtect's combined "IP Address, Port, Instance" cell
// (e.g. "10.0.10.204, 1433, MSSQLSERVER") into its three parts. Any part the
// source omits comes back empty. Extra commas beyond the third field are folded
// back into the instance so an instance name containing a comma survives.
func parseTarget(s string) (ip, port, instance string) {
	parts := strings.Split(s, ",")
	if len(parts) > 0 {
		ip = strings.TrimSpace(parts[0])
	}
	if len(parts) > 1 {
		port = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		instance = strings.TrimSpace(strings.Join(parts[2:], ","))
	}
	return ip, port, instance
}

// buildScanTarget derives the scan-wide asset under test — the database — from
// the first finding's identity columns. Name prefers the instance, then IP:Port,
// then the raw asset label. Returns nil when the source carries no identity at
// all, so the caller omits components[] rather than emitting a nameless target.
func buildScanTarget(f finding) *hdf.Component {
	ip, port, instance := parseTarget(f["IP Address, Port, Instance"])
	assetType := strings.TrimSpace(f["Asset Type"])
	asset := strings.TrimSpace(f["Asset"])

	name := instance
	switch {
	case name != "":
	case ip != "" && port != "":
		name = ip + ":" + port
	case ip != "":
		name = ip
	default:
		name = asset
	}
	if name == "" {
		return nil
	}

	comp := &hdf.Component{Name: name, Type: hdf.Database}
	if ip != "" {
		comp.IPAddress = &ip
	}
	if port != "" {
		if p, err := strconv.ParseInt(port, 10, 64); err == nil {
			comp.Port = &p
		}
	}
	if assetType != "" {
		comp.Engine = &assetType
	}
	if asset != "" {
		comp.Hostname = &asset
	}
	return comp
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

// marshalFindingCode renders the finding's parsed row (column→value map) as the
// indented JSON blob carried in requirement.code — DBProtect ships no literal
// check source, so the row itself is the richest available representation.
// HTML escaping is off and encoding/json emits map keys in sorted order, so the
// bytes match the TypeScript twin's JSON.stringify over the same sorted object.
// Encoding a map[string]string cannot fail, so the error is deliberately ignored
// (no uncoverable defensive branch).
func marshalFindingCode(f finding) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(f)
	return strings.TrimSuffix(buf.String(), "\n")
}

// buildRequirement converts a group of findings sharing a Check ID into one
// EvaluatedRequirement with multiple results.
func buildRequirement(checkID string, findings []finding, hasStatus bool) hdf.EvaluatedRequirement {
	rep := findings[0]

	nist := shared.DefaultStaticAnalysisNIST
	cciTags := cci.NISTToCCI(nist)
	tags := shared.BuildNISTCCITags(nist, cciTags)

	if checkCategory := rep["Check Category"]; checkCategory != "" {
		tags["check_category"] = checkCategory
	}

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
			Backtrace: getBacktrace(f["Result Status"]),
		}
	}

	title := rep["Check"]
	code := marshalFindingCode(rep)
	return hdf.EvaluatedRequirement{
		ID:                 checkID,
		Title:              &title,
		Impact:             getImpact(rep["Risk DV"]),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		Code:               &code,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
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

	// Top-level timestamp is source-derived (Start Date, else Date) so repeated
	// conversions of the same input are byte-identical. Omit it rather than fall
	// back to now() when the source carries no parseable scan time.
	var timestamp *time.Time
	if ts := scanTimestamp(firstFinding); !ts.IsZero() {
		timestamp = &ts
	}

	var components []hdf.Component
	if target := buildScanTarget(firstFinding); target != nil {
		components = append(components, *target)
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "dbprotect-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "DBProtect",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       components,
		Timestamp:        timestamp,
	}), nil
}
