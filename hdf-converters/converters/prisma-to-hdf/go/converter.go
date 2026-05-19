// Package prisma converts Prisma Cloud compliance scan CSV output to HDF format.
//
// Prisma Cloud exports compliance scan results as CSV with one row per finding.
// Findings are grouped by Hostname, producing one baseline per host.
// Each finding maps to a single requirement with a single failed result.
package prisma

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// prismaRecord represents a single row from the Prisma Cloud CSV export.
type prismaRecord struct {
	Hostname          string
	Distro            string
	CVEID             string
	ComplianceID      string
	Type              string
	Severity          string
	Packages          string
	Description       string
	Cause             string
	FixStatus         string
	Published         string
	VulnerabilityLink string
}

// requiredColumns are the CSV header names that must be present.
var requiredColumns = []string{"Hostname", "Compliance ID", "Severity", "Type", "Description"}

// getImpact maps Prisma Cloud severity strings to HDF impact values.
// Prisma uses "important" (0.9) and "moderate" (0.5) in addition to standard levels.

var prismaAliases = map[string]float64{
	"important": 0.9,
	"moderate":  0.5,
}

func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, prismaAliases, 0.5)
}

// nistTags returns the appropriate NIST 800-53 controls for a finding.
// CVE findings get remediation tags (SI-2, RA-5) since they represent
// known vulnerabilities requiring patching.
// Non-CVE compliance findings get static analysis tags (SA-11, RA-5).
func nistTags(cveID string) []string {
	if cveID != "" {
		return shared.DefaultRemediationNIST
	}
	return shared.DefaultStaticAnalysisNIST
}

// makeRequirementID constructs the requirement ID following the heimdall2 pattern:
// - CVE findings: "{ComplianceID}-{CVEID}"
// - Non-CVE compliance: "{ComplianceID}-{Distro}-{Severity}"
func makeRequirementID(rec prismaRecord) string {
	if rec.CVEID != "" {
		return fmt.Sprintf("%s-%s", rec.ComplianceID, rec.CVEID)
	}
	return fmt.Sprintf("%s-%s-%s", rec.ComplianceID, rec.Distro, rec.Severity)
}

// makeCodeDesc builds the code description following the heimdall2 pattern.
func makeCodeDesc(rec prismaRecord) string {
	var result string
	switch rec.Type {
	case "image":
		if rec.Packages != "" {
			result = fmt.Sprintf("Version check of package: %s", rec.Packages)
		}
	case "linux":
		if rec.Distro != "" {
			result = fmt.Sprintf("Configuration check for %s", rec.Distro)
		}
	default:
		result = fmt.Sprintf("%s check for %s", rec.Type, rec.Hostname)
	}
	if rec.Description != "" {
		result += "\n\n" + rec.Description
	}
	return result
}

// makeMessage builds the result message from Fix Status and Cause fields.
func makeMessage(rec prismaRecord) string {
	hasFixStatus := rec.FixStatus != ""
	hasCause := rec.Cause != ""

	switch {
	case hasFixStatus && hasCause:
		return fmt.Sprintf("Fix Status: %s\n\n%s", rec.FixStatus, rec.Cause)
	case hasFixStatus:
		return fmt.Sprintf("Fix Status: %s", rec.FixStatus)
	case hasCause:
		return fmt.Sprintf("Cause: %s", rec.Cause)
	default:
		return "Unknown"
	}
}

// makeTitle builds the requirement title following the heimdall2 pattern.
func makeTitle(rec prismaRecord) string {
	return fmt.Sprintf("%s-%s-%s", rec.Hostname, rec.Distro, rec.Type)
}

// parseCSV reads the Prisma CSV and returns structured records.
func parseCSV(input []byte) ([]prismaRecord, error) {
	reader := csv.NewReader(strings.NewReader(string(input)))
	reader.LazyQuotes = true

	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("prisma: failed to read CSV headers: %w", err)
	}

	// Build column index
	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[h] = i
	}

	// Validate required columns
	for _, col := range requiredColumns {
		if _, ok := colIdx[col]; !ok {
			return nil, fmt.Errorf("prisma: missing required CSV column %q", col)
		}
	}

	var records []prismaRecord
	for {
		row, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("prisma: error reading CSV row: %w", readErr)
		}

		rec := prismaRecord{
			Hostname:          safeCol(row, colIdx, "Hostname"),
			Distro:            safeCol(row, colIdx, "Distro"),
			CVEID:             safeCol(row, colIdx, "CVE ID"),
			ComplianceID:      safeCol(row, colIdx, "Compliance ID"),
			Type:              safeCol(row, colIdx, "Type"),
			Severity:          safeCol(row, colIdx, "Severity"),
			Packages:          safeCol(row, colIdx, "Packages"),
			Description:       safeCol(row, colIdx, "Description"),
			Cause:             safeCol(row, colIdx, "Cause"),
			FixStatus:         safeCol(row, colIdx, "Fix Status"),
			Published:         safeCol(row, colIdx, "Published"),
			VulnerabilityLink: safeCol(row, colIdx, "Vulnerability Link"),
		}
		records = append(records, rec)
	}

	return records, nil
}

// safeCol extracts a column value by name, returning empty string if missing.
func safeCol(row []string, colIdx map[string]int, name string) string {
	if idx, ok := colIdx[name]; ok && idx < len(row) {
		return row[idx]
	}
	return ""
}

// groupByHostname groups records by their Hostname field, preserving insertion order.
func groupByHostname(records []prismaRecord) ([]string, map[string][]prismaRecord) {
	order := []string{}
	groups := map[string][]prismaRecord{}
	for _, rec := range records {
		if _, seen := groups[rec.Hostname]; !seen {
			order = append(order, rec.Hostname)
		}
		groups[rec.Hostname] = append(groups[rec.Hostname], rec)
	}
	return order, groups
}

// buildRequirement converts a single Prisma record to an HDF requirement.
func buildRequirement(rec prismaRecord) hdf.EvaluatedRequirement {
	id := makeRequirementID(rec)
	title := makeTitle(rec)
	codeDesc := makeCodeDesc(rec)
	message := makeMessage(rec)

	nist := nistTags(rec.CVEID)
	cciTags := cci.NISTToCCI(nist)

	var extras map[string]interface{}
	if rec.CVEID != "" {
		extras = map[string]interface{}{
			"cve": hdfutil.StringsToInterfaces([]string{rec.CVEID}),
		}
	}

	var tags map[string]interface{}
	if extras != nil {
		tags = shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)
	} else {
		tags = shared.BuildNISTCCITags(nist, cciTags)
	}

	descriptions := []hdf.Description{
		{Label: "default", Data: rec.Description},
	}

	result := hdf.RequirementResult{
		Status:   hdf.Failed,
		CodeDesc: codeDesc,
		Message:  &message,
	}

	return hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              &title,
		Impact:             getImpact(rec.Severity),
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            []hdf.RequirementResult{result},
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// buildBaseline converts all records for a single host into an HDF baseline.
func buildBaseline(hostname string, records []prismaRecord, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	limitedRecords := shared.LimitSliceWithWarning(records, 0, "finding")

	requirements := make([]hdf.EvaluatedRequirement, len(limitedRecords))
	for i, rec := range limitedRecords {
		requirements[i] = buildRequirement(rec)
	}

	title := fmt.Sprintf("Prisma Cloud Scan (%s)", hostname)

	return hdf.EvaluatedBaseline{
		Name:            "Prisma Cloud Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}
}

// ConvertPrismaToHDF converts Prisma Cloud CSV compliance scan output to HDF format.
// Records are grouped by hostname, producing one baseline per host.
func ConvertPrismaToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("prisma: empty input")
	}
	if err := shared.ValidateJSONSize(input, "prisma", 0); err != nil {
		return nil, fmt.Errorf("prisma: %w", err)
	}

	records, err := parseCSV(input)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("prisma: no data rows in CSV")
	}

	checksum := shared.InputChecksum(input)
	hostOrder, hostGroups := groupByHostname(records)

	baselines := make([]hdf.EvaluatedBaseline, len(hostOrder))
	targets := make([]hdf.Component, len(hostOrder))
	for i, hostname := range hostOrder {
		baselines[i] = buildBaseline(hostname, hostGroups[hostname], checksum)
		targets[i] = hdf.Component{
			Name: hostname,
			Type: hdf.Host,
		}
	}

	now := time.Now().UTC()

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "prisma-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Prisma Cloud",
		ToolFormat:       "CSV",
		Baselines:        baselines,
		Components:       targets,
		Timestamp:        &now,
	}), nil
}
