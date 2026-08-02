package neuvector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

var cpe23Pattern = regexp.MustCompile(`^cpe:2\.3:[aho]:`)

// whitespaceRun collapses runs of ASCII whitespace to a single space when
// building the code_desc description snippet. The class is spelled out (rather
// than \s) so Go and TS collapse identically.
var whitespaceRun = regexp.MustCompile(`[ \t\n\r]+`)

// codeDescSnippetRunes bounds the description snippet in code_desc.
const codeDescSnippetRunes = 100

// NeuVectorScan is the top-level NeuVector scan JSON output structure.
type NeuVectorScan struct {
	ErrorMessage string              `json:"error_message"`
	Report       NeuVectorScanReport `json:"report"`
}

// NeuVectorScanReport is the "report" field inside NeuVectorScan.
type NeuVectorScanReport struct {
	ImageID         string                `json:"image_id"`
	Registry        string                `json:"registry"`
	Repository      string                `json:"repository"`
	Tag             string                `json:"tag"`
	Digest          string                `json:"digest"`
	Size            int64                 `json:"size"`
	Author          string                `json:"author"`
	BaseOS          string                `json:"base_os"`
	CreatedAt       string                `json:"created_at"`
	CvedbVersion    string                `json:"cvedb_version"`
	CvedbCreateTime string                `json:"cvedb_create_time"`
	Layers          json.RawMessage       `json:"layers"`
	Vulnerabilities []NeuVectorVuln       `json:"vulnerabilities"`
	Modules         []NeuVectorScanModule `json:"modules"`
}

// NeuVectorVuln represents a single vulnerability entry from NeuVector scan output.
type NeuVectorVuln struct {
	Name                  string   `json:"name"`
	Score                 float64  `json:"score"`
	Severity              string   `json:"severity"`
	Vectors               string   `json:"vectors"`
	Description           string   `json:"description"`
	FileName              string   `json:"file_name"`
	PackageName           string   `json:"package_name"`
	PackageVersion        string   `json:"package_version"`
	FixedVersion          string   `json:"fixed_version"`
	Link                  string   `json:"link"`
	ScoreV3               float64  `json:"score_v3"`
	VectorsV3             string   `json:"vectors_v3"`
	PublishedTimestamp    int64    `json:"published_timestamp"`
	LastModifiedTimestamp int64    `json:"last_modified_timestamp"`
	Cpes                  []string `json:"cpes,omitempty"`
	Cves                  []string `json:"cves"`
	FeedRating            string   `json:"feed_rating"`
	InBaseImage           *bool    `json:"in_base_image,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
}

// NeuVectorScanModule represents a module in the NeuVector scan report.
type NeuVectorScanModule struct {
	Name    string `json:"name"`
	File    string `json:"file"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// extractCWEs parses CWE identifiers from a vulnerability description string.
// Returns CWE-prefixed IDs (e.g., ["CWE-444"]) for use in tags and MapCWEToNIST.
func extractCWEs(description string) []string {
	ids := hdfutil.ExtractCWEIDs(description)
	if len(ids) == 0 {
		return nil
	}
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = "CWE-" + id
	}
	return result
}

// extractCVEs collects the distinct CVE identifiers a vulnerability carries in
// its cves[] field, preserving first-seen order. The requirement ID is a
// name/package/version composite (not the CVE), so tags.cve is where the CVE
// list lives.
func extractCVEs(vuln NeuVectorVuln) []string {
	var out []string
	seen := map[string]bool{}
	for _, cve := range vuln.Cves {
		if cve != "" && !seen[cve] {
			seen[cve] = true
			out = append(out, cve)
		}
	}
	return out
}

// buildCvssEntries assembles the structured requirement.cvss[] from the scoring
// a vulnerability carries. NeuVector emits a CVSS v3 vector (with a
// version-prefixed string) and, separately, a legacy v2 vector (prefix-less).
// The v3 metric is preferred; the v2 metric is the fallback. A vulnerability
// with neither vector contributes no entry — its score still drives impact.
func buildCvssEntries(vuln NeuVectorVuln) []hdf.Cvss {
	if vuln.VectorsV3 != "" {
		var score *float64
		if vuln.ScoreV3 > 0 {
			s := vuln.ScoreV3
			score = &s
		}
		return []hdf.Cvss{shared.BuildCvss(shared.CvssInput{
			Version:    shared.CvssVersionFromVector(vuln.VectorsV3),
			BaseScore:  score,
			BaseVector: vuln.VectorsV3,
			Source:     "NeuVector",
		})}
	}
	if vuln.Vectors != "" {
		var score *float64
		if vuln.Score > 0 {
			s := vuln.Score
			score = &s
		}
		return []hdf.Cvss{shared.BuildCvss(shared.CvssInput{
			Version:    shared.CvssVersionFromString("2.0"),
			BaseScore:  score,
			BaseVector: vuln.Vectors,
			Source:     "NeuVector",
		})}
	}
	return nil
}

// getImpact computes the HDF impact from NeuVector CVSS scores.
// Prefers CVSS v3 score; falls back to CVSS v2 if v3 is 0.
// Impact is normalized to 0.0-1.0 by dividing by 10.
func getImpact(vuln NeuVectorVuln) float64 {
	if vuln.ScoreV3 > 0 {
		return vuln.ScoreV3 / 10
	}
	if vuln.Score > 0 {
		return vuln.Score / 10
	}
	return 0.5 // default when no score available
}

// vulnID constructs the unique ID for a NeuVector vulnerability:
// name/package_name/package_version.
func vulnID(vuln NeuVectorVuln) string {
	return fmt.Sprintf("%s/%s/%s", vuln.Name, vuln.PackageName, vuln.PackageVersion)
}

// vulnTitle generates a human-readable title for the vulnerability.
func vulnTitle(vuln NeuVectorVuln) string {
	return fmt.Sprintf("NeuVector found a vulnerability to %s in %s/%s.",
		vuln.Name, vuln.PackageName, vuln.PackageVersion)
}

// vulnMessage generates the result message describing the fix action.
func vulnMessage(vuln NeuVectorVuln) string {
	if vuln.FixedVersion == "" {
		return fmt.Sprintf("Vulnerable package %s is at version %s. No fixed version available.",
			vuln.PackageName, vuln.PackageVersion)
	}
	return fmt.Sprintf("Vulnerable package %s is at version %s. Update to fixed version %s.",
		vuln.PackageName, vuln.PackageVersion, vuln.FixedVersion)
}

// cvssScore returns the CVSS score used in code_desc: CVSS v3 preferred, else v2.
func cvssScore(vuln NeuVectorVuln) float64 {
	if vuln.ScoreV3 > 0 {
		return vuln.ScoreV3
	}
	return vuln.Score
}

// descSnippet collapses the vulnerability description to a single line and
// truncates it to codeDescSnippetRunes runes for the code_desc composite. Rune
// counting (not bytes) matches the TS twin's Array.from(...).slice().
func descSnippet(description string) string {
	collapsed := strings.TrimSpace(whitespaceRun.ReplaceAllString(description, " "))
	runes := []rune(collapsed)
	if len(runes) > codeDescSnippetRunes {
		return string(runes[:codeDescSnippetRunes]) + "…"
	}
	return collapsed
}

// buildCodeDesc builds the pipe-joined result code_desc from the fields the
// vuln carries: package@version | name | CVSS score | description snippet. Only
// parts the source actually provides are included.
func buildCodeDesc(vuln NeuVectorVuln) string {
	parts := make([]string, 0, 4)
	if vuln.PackageName != "" {
		if vuln.PackageVersion != "" {
			parts = append(parts, vuln.PackageName+"@"+vuln.PackageVersion)
		} else {
			parts = append(parts, vuln.PackageName)
		}
	}
	if vuln.Name != "" {
		parts = append(parts, vuln.Name)
	}
	if score := cvssScore(vuln); score > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %g", score))
	}
	if snippet := descSnippet(vuln.Description); snippet != "" {
		parts = append(parts, snippet)
	}
	return strings.Join(parts, " | ")
}

// marshalVulnCode renders the source vulnerability as the indented JSON blob
// carried in the requirement's code field (the CODE tab). HTML escaping is off
// so `<`, `>`, `&` in descriptions stay literal, matching the TS twin's
// JSON.stringify(vuln, null, 2).
func marshalVulnCode(vuln NeuVectorVuln) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vuln); err != nil {
		return "{}"
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// buildRequirement converts a NeuVector vulnerability to an EvaluatedRequirement.
func buildRequirement(vuln NeuVectorVuln, scanTime time.Time) hdf.EvaluatedRequirement {
	cweIDs := extractCWEs(vuln.Description)
	cveIDs := extractCVEs(vuln)
	nist := shared.MapCWEToNIST(cweIDs, shared.DefaultRemediationNIST)
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	if len(cveIDs) > 0 {
		extras["cve"] = hdfutil.StringsToInterfaces(cveIDs)
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	descriptions := []hdf.Description{
		{Label: "default", Data: vuln.Description},
	}

	msg := vulnMessage(vuln)
	results := []hdf.RequirementResult{
		{
			Status:    hdf.Failed,
			CodeDesc:  buildCodeDesc(vuln),
			Message:   &msg,
			StartTime: scanTime,
		},
	}

	title := vulnTitle(vuln)
	req := hdf.EvaluatedRequirement{
		ID:                 vulnID(vuln),
		Title:              &title,
		Impact:             getImpact(vuln),
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            results,
		Code:               hdfutil.Ptr(marshalVulnCode(vuln)),
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	if len(cweIDs) > 0 {
		req.Cwe = cweIDs
	}
	if cvss := buildCvssEntries(vuln); len(cvss) > 0 {
		req.Cvss = cvss
	}

	// NeuVector scans container images; the package ecosystem isn't
	// disambiguated by the source format, so record `generic`.
	// NeuVector emits CPE 2.2 URIs (`cpe:/...`); the schema requires
	// CPE 2.3, so only the first 2.3-shaped entry is carried through.
	var firstCPE string
	for _, c := range vuln.Cpes {
		if cpe23Pattern.MatchString(c) {
			firstCPE = c
			break
		}
	}
	var ecosystem hdf.Ecosystem
	if vuln.PackageName != "" && vuln.PackageVersion != "" {
		ecosystem = hdf.Generic
	}
	if pkg := shared.BuildAffectedPackage(shared.AffectedPackageOptions{
		Name:           vuln.PackageName,
		Version:        vuln.PackageVersion,
		Ecosystem:      ecosystem,
		CPE:            firstCPE,
		FixedInVersion: vuln.FixedVersion,
	}); pkg != nil {
		req.AffectedPackages = []hdf.AffectedPackage{*pkg}
	}
	return req
}

// imageTitle constructs the baseline title from the image metadata.
func imageTitle(report NeuVectorScanReport) string {
	return fmt.Sprintf("%s/%s:%s - Digest: %s - Image ID: %s",
		report.Registry, report.Repository, report.Tag,
		report.Digest, report.ImageID)
}

// targetName constructs the target name from the image metadata.
func targetName(report NeuVectorScanReport) string {
	return fmt.Sprintf("%s/%s:%s",
		report.Registry, report.Repository, report.Tag)
}

// ConvertNeuVectorToHDF converts NeuVector container vulnerability scan JSON output
// to HDF format. Each vulnerability becomes a separate requirement with a unique
// ID of name/package_name/package_version.
func ConvertNeuVectorToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("neuvector: empty input")
	}
	if err := shared.ValidateJSONSize(input, "neuvector", 0); err != nil {
		return nil, fmt.Errorf("neuvector: %w", err)
	}

	var scan NeuVectorScan
	if err := json.Unmarshal(input, &scan); err != nil {
		return nil, fmt.Errorf("neuvector: invalid JSON: %w", err)
	}

	checksum := shared.InputChecksum(input)

	vulns := shared.LimitSliceWithWarning(scan.Report.Vulnerabilities, 0, "vulnerability")

	// NeuVector reports carry image build time (created_at) and CVE-DB version
	// time (cvedb_create_time), but neither is the scan time, so use conversion
	// time as the single timestamp shared by every result.
	now := time.Now().UTC()

	// Each vulnerability is unique by name/package_name/package_version,
	// so no grouping is needed (unlike Snyk which groups by vuln ID).
	// However, we still deduplicate by the composite ID in case the input
	// has exact duplicates.
	seen := make(map[string]bool)
	requirements := make([]hdf.EvaluatedRequirement, 0, len(vulns))
	for _, vuln := range vulns {
		id := vulnID(vuln)
		if seen[id] {
			log.Printf("WARNING: Duplicate vulnerability ID %s skipped", id)
			continue
		}
		seen[id] = true
		requirements = append(requirements, buildRequirement(vuln, now))
	}

	target := targetName(scan.Report)
	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"neuvector-no-findings",
				fmt.Sprintf("NeuVector scanned %s and reported zero vulnerable components.", target),
				now,
			),
		}
	}

	title := imageTitle(scan.Report)
	baseline := hdf.EvaluatedBaseline{
		Name:            "NeuVector Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
		Title:           &title,
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "neuvector-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "NeuVector",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{
				Name: targetName(scan.Report),
				Type: hdf.ContainerImage,
				Labels: map[string]string{
					"image":    fmt.Sprintf("%s/%s:%s", scan.Report.Registry, scan.Report.Repository, scan.Report.Tag),
					"registry": scan.Report.Registry,
				},
			},
		},
		Timestamp: &now,
	}), nil
}
