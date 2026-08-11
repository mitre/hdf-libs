// Package prisma converts Prisma Cloud compliance scan CSV output to HDF format.
//
// Prisma Cloud exports compliance scan results as CSV with one row per finding.
// Findings are grouped by Hostname, producing one baseline per host.
// Each finding maps to a single requirement with a single failed result.
package prisma

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// prismaRecord represents a single row from the Prisma Cloud CSV export.
type prismaRecord struct {
	Hostname     string
	Distro       string
	CVEID        string
	ComplianceID string
	Type         string
	Severity     string
	Packages     string
	// SourcePackage and PackageVersion are populated when the Prisma
	// export includes the Source Package + Package Version columns
	// (newer exports). Older exports collapse the package name into
	// the Packages column without a version.
	SourcePackage     string
	PackageVersion    string
	Description       string
	Cause             string
	FixStatus         string
	Published         string
	VulnerabilityLink string
	// CVSS is the base score column (numeric, no vector). Compliance/config
	// rows carry "0.00"; only vulnerability rows carry a real score.
	CVSS string
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

// rawFindingCode renders the parsed CSV finding as the indented JSON blob
// carried in the requirement's code field (the CODE tab), so per-row source
// fields survive the conversion (heimdall2 sets code = JSON.stringify(row)).
// This is a fixed field-order projection keyed by CSV header name; HTML
// escaping is off and the trailing newline trimmed so the bytes match the TS
// twin's JSON.stringify(projection, null, 2).
func rawFindingCode(rec prismaRecord) string {
	projection := struct {
		Hostname          string `json:"Hostname"`
		Distro            string `json:"Distro"`
		CVEID             string `json:"CVE ID"`
		ComplianceID      string `json:"Compliance ID"`
		Type              string `json:"Type"`
		Severity          string `json:"Severity"`
		Packages          string `json:"Packages"`
		SourcePackage     string `json:"Source Package"`
		PackageVersion    string `json:"Package Version"`
		CVSS              string `json:"CVSS"`
		FixStatus         string `json:"Fix Status"`
		Description       string `json:"Description"`
		Cause             string `json:"Cause"`
		Published         string `json:"Published"`
		VulnerabilityLink string `json:"Vulnerability Link"`
	}{
		Hostname:          rec.Hostname,
		Distro:            rec.Distro,
		CVEID:             rec.CVEID,
		ComplianceID:      rec.ComplianceID,
		Type:              rec.Type,
		Severity:          rec.Severity,
		Packages:          rec.Packages,
		SourcePackage:     rec.SourcePackage,
		PackageVersion:    rec.PackageVersion,
		CVSS:              rec.CVSS,
		FixStatus:         rec.FixStatus,
		Description:       rec.Description,
		Cause:             rec.Cause,
		Published:         rec.Published,
		VulnerabilityLink: rec.VulnerabilityLink,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(projection); err != nil {
		return "{}"
	}
	return strings.TrimSuffix(buf.String(), "\n")
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
			SourcePackage:     safeCol(row, colIdx, "Source Package"),
			PackageVersion:    safeCol(row, colIdx, "Package Version"),
			Description:       safeCol(row, colIdx, "Description"),
			Cause:             safeCol(row, colIdx, "Cause"),
			FixStatus:         safeCol(row, colIdx, "Fix Status"),
			Published:         safeCol(row, colIdx, "Published"),
			VulnerabilityLink: safeCol(row, colIdx, "Vulnerability Link"),
			CVSS:              safeCol(row, colIdx, "CVSS"),
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
func buildRequirement(rec prismaRecord, scanTime time.Time) hdf.EvaluatedRequirement {
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
		Status:    hdf.Failed,
		CodeDesc:  codeDesc,
		Message:   &message,
		StartTime: scanTime,
	}

	req := hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              &title,
		Impact:             getImpact(rec.Severity),
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            []hdf.RequirementResult{result},
		Code:               hdfutil.Ptr(rawFindingCode(rec)),
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	if cvss := buildCvssEntries(rec); cvss != nil {
		req.Cvss = cvss
	}
	if rec.CVEID != "" {
		if pkg := buildAffectedPackageFromRecord(rec); pkg != nil {
			req.AffectedPackages = []hdf.AffectedPackage{*pkg}
		}
	}
	if refs := buildRefs(rec); refs != nil {
		req.Refs = refs
	}
	return req
}

// buildRefs maps the "Vulnerability Link" CSV column to a single external
// Reference URL. Omitted (nil) when the column is blank.
func buildRefs(rec prismaRecord) []hdf.Reference {
	url := strings.TrimSpace(rec.VulnerabilityLink)
	if url == "" {
		return nil
	}
	return []hdf.Reference{{URL: &url}}
}

// buildCvssEntries maps the CSV CVSS column to a structured cvss[] entry.
// Prisma emits a bare base score with no vector, so version defaults to 3.1
// via the shared helper. Non-vulnerability rows carry "0.00" (or blank);
// only a positive score yields an entry, and the source is the associated CVE.
func buildCvssEntries(rec prismaRecord) []hdf.Cvss {
	score, ok := parseCvssScore(rec.CVSS)
	if !ok {
		return nil
	}
	return []hdf.Cvss{
		shared.BuildCvss(shared.CvssInput{
			Version:   shared.CvssVersionFromString(""),
			BaseScore: &score,
			Source:    rec.CVEID,
		}),
	}
}

// parseCvssScore parses the CVSS column, returning ok=false for blank,
// non-numeric, or non-positive scores (the placeholder value on config rows).
func parseCvssScore(field string) (float64, bool) {
	s := strings.TrimSpace(field)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// Distro slugs in Prisma look like `redhat-RHEL7`, `debian-buster`,
// `alpine-3.14`, `ubuntu-20.04`. Only the leading vendor segment is
// mapped — unknown vendors fall back to Generic rather than guessing.
func ecosystemFromDistro(distro string) hdf.Ecosystem {
	if distro == "" {
		return hdf.Generic
	}
	head := strings.ToLower(strings.SplitN(distro, "-", 2)[0])
	switch head {
	case "redhat", "rhel", "centos", "rocky", "alma", "fedora",
		"amazon", "amazonlinux", "suse", "sles", "opensuse":
		return hdf.RPM
	case "debian", "ubuntu":
		return hdf.Deb
	default:
		return hdf.Generic
	}
}

var fixVersionPattern = regexp.MustCompile(`(?i)fixed in\s+([^\s,;]+)`)

func buildAffectedPackageFromRecord(rec prismaRecord) *hdf.AffectedPackage {
	name := rec.SourcePackage
	if name == "" {
		name = rec.Packages
	}
	if name == "" || rec.PackageVersion == "" {
		return nil
	}
	var fixed string
	if rec.FixStatus != "" {
		if m := fixVersionPattern.FindStringSubmatch(rec.FixStatus); len(m) > 1 {
			fixed = m[1]
		}
	}
	return shared.BuildAffectedPackage(shared.AffectedPackageOptions{
		Name:           name,
		Version:        rec.PackageVersion,
		Ecosystem:      ecosystemFromDistro(rec.Distro),
		FixedInVersion: fixed,
	})
}

// buildBaseline converts all records for a single host into an HDF baseline.
func buildBaseline(hostname string, records []prismaRecord, checksum *hdf.Checksum, scanTime time.Time) hdf.EvaluatedBaseline {
	limitedRecords := shared.LimitSliceWithWarning(records, 0, "finding")

	requirements := make([]hdf.EvaluatedRequirement, len(limitedRecords))
	for i, rec := range limitedRecords {
		requirements[i] = buildRequirement(rec, scanTime)
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

	checksum := shared.InputChecksum(input)
	// Prisma Cloud CSV exports carry no scan-level timestamp (the Published
	// column is a per-finding CVE publish date), so use conversion time for
	// every result, the doc timestamp, and any no-findings placeholder.
	now := time.Now().UTC()

	var baselines []hdf.EvaluatedBaseline
	var targets []hdf.Component

	if len(records) == 0 {
		title := "Prisma Cloud Scan"
		baselines = []hdf.EvaluatedBaseline{
			{
				Name:  "Prisma Cloud Scan",
				Title: &title,
				Requirements: []hdf.EvaluatedRequirement{
					shared.BuildNoFindingsRequirement(
						"prisma-no-findings",
						"Prisma Cloud scanned the workload and reported zero vulnerable components.",
						now,
					),
				},
				ResultsChecksum: checksum,
			},
		}
	} else {
		hostOrder, hostGroups := groupByHostname(records)
		baselines = make([]hdf.EvaluatedBaseline, len(hostOrder))
		targets = make([]hdf.Component, len(hostOrder))
		for i, hostname := range hostOrder {
			baselines[i] = buildBaseline(hostname, hostGroups[hostname], checksum, now)
			targets[i] = hdf.Component{
				Name: hostname,
				Type: hdf.Host,
			}
		}
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "prisma-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Prisma Cloud",
		Baselines:        baselines,
		Components:       targets,
		Timestamp:        &now,
	}), nil
}
