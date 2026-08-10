package hdftocsv

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ConvertHDFToCSV converts HDF JSON to CSV format
func ConvertHDFToCSV(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-csv: empty input")
	}
	if err := shared.ValidateJSONSize(input, "hdf-to-csv", 0); err != nil {
		return nil, fmt.Errorf("hdf-to-csv: %w", err)
	}

	// Parse HDF JSON
	var hdfData hdf.HDFResults
	if err := shared.DecodeHDF(input, &hdfData); err != nil {
		return nil, fmt.Errorf("invalid HDF JSON: %w", err)
	}

	// Validate structure
	if hdfData.Baselines == nil {
		return nil, fmt.Errorf("invalid HDF structure: missing baselines field")
	}

	// Build CSV rows
	rows := buildCSVRows(&hdfData)

	// If no rows, return empty string
	if len(rows) == 0 {
		return []byte{}, nil
	}

	// Write CSV
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write all rows (including header)
	if err := writer.WriteAll(rows); err != nil {
		return nil, fmt.Errorf("failed to write CSV: %w", err)
	}

	return buf.Bytes(), nil
}

// buildCSVRows constructs CSV rows from HDF data
func buildCSVRows(hdfData *hdf.HDFResults) [][]string {
	var rows [][]string

	// Add header row
	header := []string{
		"Baseline ID",
		"Baseline Version",
		"Baseline Title",
		"Target ID",
		"Target Type",
		"Requirement ID",
		"Requirement Title",
		"Description",
		"Check",
		"Fix",
		"Rationale",
		"Code",
		"References",
		"Severity",
		"Impact",
		"Status",
		"NIST Controls",
		"CCI Controls",
		"Control Type",
		"Verification Method",
		"Applicability",
		"Result Message",
		"Effective Status",
		"Effective Impact",
		"Disposition",
		"Override Reason",
		"Applied By",
		"Expires At",
		"CVSS",
		"CWE",
		"EPSS",
		"KEV",
		"Target FQDN",
		"Target IP",
	}
	rows = append(rows, header)

	// Get targets (may be nil or empty)
	targets := hdfData.Components
	if len(targets) == 0 {
		// Create single empty target entry
		targets = []hdf.Component{{Name: "", Type: hdf.TargetType("")}}
	}

	// Iterate through baselines
	for _, baseline := range hdfData.Baselines {
		// Skip baselines with no requirements
		if len(baseline.Requirements) == 0 {
			continue
		}

		// Iterate through requirements
		for _, requirement := range baseline.Requirements {
			// Create row for each target
			for _, target := range targets {
				row := createRow(&baseline, &requirement, &target)
				rows = append(rows, row)
			}
		}
	}

	// If only header row, return empty (no data rows)
	if len(rows) == 1 {
		return [][]string{}
	}

	return rows
}

// createRow creates a single CSV row
func createRow(baseline *hdf.EvaluatedBaseline, requirement *hdf.EvaluatedRequirement, target *hdf.Component) []string {
	// Get default description
	description := ""
	for _, desc := range requirement.Descriptions {
		if desc.Label == "default" {
			description = desc.Data
			break
		}
	}

	// Other conventional description labels (check/fix/rationale) — empty when absent
	check := descriptionByLabel(requirement, "check")
	fix := descriptionByLabel(requirement, "fix")
	rationale := descriptionByLabel(requirement, "rationale")
	code := ""
	if requirement.Code != nil {
		code = *requirement.Code
	}
	references := flattenRefs(requirement.Refs)

	// Get severity
	severity := getSeverity(requirement)

	// Get status from first result (required, minItems: 1)
	firstResult := requirement.Results[0]
	status := string(firstResult.Status)
	message := ""
	if firstResult.Message != nil {
		message = *firstResult.Message
	}

	// Extract NIST and CCI controls
	nistControls := extractArrayFromTags(requirement.Tags, "nist")
	cciControls := extractArrayFromTags(requirement.Tags, "cci")

	// Get baseline version and title
	version := ""
	if baseline.Version != nil {
		version = *baseline.Version
	}
	title := ""
	if baseline.Title != nil {
		title = *baseline.Title
	}

	// Get requirement title
	reqTitle := ""
	if requirement.Title != nil {
		reqTitle = *requirement.Title
	}

	// v3.2 classification fields — dereference pointers to strings
	controlType := ""
	if requirement.ControlType != nil {
		controlType = string(*requirement.ControlType)
	}
	verificationMethod := ""
	if requirement.VerificationMethod != nil {
		verificationMethod = string(*requirement.VerificationMethod)
	}
	applicability := ""
	if requirement.Applicability != nil {
		applicability = string(*requirement.Applicability)
	}

	// Post-override posture: effective columns fall back to the raw value when no
	// override governs, so the column is always populated and sortable.
	effStatus := status
	if requirement.EffectiveStatus != nil {
		effStatus = string(*requirement.EffectiveStatus)
	}
	effImpact := requirement.Impact
	if requirement.EffectiveImpact != nil {
		effImpact = *requirement.EffectiveImpact
	}
	disposition := ""
	if requirement.Disposition != nil {
		disposition = string(*requirement.Disposition)
	}

	// statusOverrides[] provenance — emit ALL overrides joined with "; ".
	overrideReason := joinOverrides(requirement.StatusOverrides, func(o hdf.StatusOverride) string { return o.Reason })
	appliedBy := joinOverrides(requirement.StatusOverrides, func(o hdf.StatusOverride) string { return o.AppliedBy.Identifier })
	expiresAt := joinOverrides(requirement.StatusOverrides, func(o hdf.StatusOverride) string {
		return o.ExpiresAt.UTC().Format(time.RFC3339Nano)
	})

	// Vulnerability metadata (CVE-scan HDFs).
	cvss := cvssScores(requirement.Cvss)
	cwe := strings.Join(requirement.Cwe, "; ")
	epss := ""
	if requirement.Epss != nil {
		epss = fmt.Sprintf("%.5f", requirement.Epss.Score)
	}
	kev := ""
	if requirement.Kev != nil {
		if requirement.Kev.InKev {
			kev = "true"
		} else {
			kev = "false"
		}
	}

	// Asset identity beyond display name.
	fqdn := ""
	if target.FQDN != nil {
		fqdn = *target.FQDN
	}
	ipAddress := ""
	if target.IPAddress != nil {
		ipAddress = *target.IPAddress
	}

	// Build row with sanitization
	return []string{
		sanitizeCSV(baseline.Name),
		sanitizeCSV(version),
		sanitizeCSV(title),
		sanitizeCSV(target.Name),
		sanitizeCSV(string(target.Type)),
		sanitizeCSV(requirement.ID),
		sanitizeCSV(reqTitle),
		sanitizeCSV(description),
		sanitizeCSV(check),
		sanitizeCSV(fix),
		sanitizeCSV(rationale),
		sanitizeCSV(code),
		sanitizeCSV(references),
		sanitizeCSV(severity),
		fmt.Sprintf("%.1f", requirement.Impact),
		sanitizeCSV(status),
		sanitizeCSV(nistControls),
		sanitizeCSV(cciControls),
		sanitizeCSV(controlType),
		sanitizeCSV(verificationMethod),
		sanitizeCSV(applicability),
		sanitizeCSV(message),
		sanitizeCSV(effStatus),
		fmt.Sprintf("%.1f", effImpact),
		sanitizeCSV(disposition),
		sanitizeCSV(overrideReason),
		sanitizeCSV(appliedBy),
		sanitizeCSV(expiresAt),
		sanitizeCSV(cvss),
		sanitizeCSV(cwe),
		sanitizeCSV(epss),
		sanitizeCSV(kev),
		sanitizeCSV(fqdn),
		sanitizeCSV(ipAddress),
	}
}

// joinOverrides applies pick to every status override and joins non-empty
// results with "; ", matching the NIST/CCI multi-value column convention.
func joinOverrides(overrides []hdf.StatusOverride, pick func(hdf.StatusOverride) string) string {
	var out []string
	for _, o := range overrides {
		if v := pick(o); v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, "; ")
}

// cvssScores renders each CVSS entry's score (computed when present, else base)
// to one decimal, joined with "; " to preserve multi-CVE findings.
func cvssScores(entries []hdf.Cvss) string {
	var out []string
	for _, c := range entries {
		switch {
		case c.ComputedScore != nil:
			out = append(out, fmt.Sprintf("%.1f", *c.ComputedScore))
		case c.BaseScore != nil:
			out = append(out, fmt.Sprintf("%.1f", *c.BaseScore))
		}
	}
	return strings.Join(out, "; ")
}

// descriptionByLabel returns the data of the first description matching a label, or "".
func descriptionByLabel(requirement *hdf.EvaluatedRequirement, label string) string {
	for _, desc := range requirement.Descriptions {
		if desc.Label == label {
			return desc.Data
		}
	}
	return ""
}

// flattenRefs renders a requirement's refs to one string: each Reference as its
// url/uri (or a string ref); array-form refs are skipped. Joined with "; " to
// match the NIST/CCI column convention.
func flattenRefs(refs []hdf.Reference) string {
	var out []string
	for _, r := range refs {
		switch {
		case r.URL != nil:
			out = append(out, *r.URL)
		case r.URI != nil:
			out = append(out, *r.URI)
		case r.Ref != nil && r.Ref.String != nil:
			out = append(out, *r.Ref.String)
		}
	}
	return strings.Join(out, "; ")
}

// getSeverity gets severity from requirement
func getSeverity(requirement *hdf.EvaluatedRequirement) string {
	// Check if severity is explicitly provided in tags
	if requirement.Tags != nil {
		if sev, ok := requirement.Tags["severity"]; ok {
			if str, ok := sev.(string); ok {
				return str
			}
			// Handle array case
			if arr, ok := sev.([]interface{}); ok && len(arr) > 0 {
				if str, ok := arr[0].(string); ok {
					return str
				}
			}
		}
	}

	// Derive from impact
	impact := requirement.Impact
	if impact >= 0.7 {
		return "high"
	}
	if impact >= 0.4 {
		return "medium"
	}
	return "low"
}

// extractArrayFromTags extracts array values from tags and joins with semicolons
func extractArrayFromTags(tags map[string]interface{}, key string) string {
	if tags == nil {
		return ""
	}

	value, ok := tags[key]
	if !ok {
		return ""
	}

	// Handle array
	arr, ok := value.([]interface{})
	if !ok {
		return ""
	}

	var items []string
	for _, item := range arr {
		if str, ok := item.(string); ok {
			items = append(items, str)
		}
	}

	return strings.Join(items, "; ")
}

// sanitizeCSV prevents CSV injection attacks
func sanitizeCSV(value string) string {
	if len(value) == 0 {
		return value
	}

	// Check if first character is a formula trigger
	firstChar := value[0]
	if firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@' || firstChar == '|' || firstChar == '%' {
		return "'" + value
	}

	return value
}
