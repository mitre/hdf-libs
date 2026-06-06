package neuvector

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

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
	Cpes                  []string `json:"cpes"`
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

// buildRequirement converts a NeuVector vulnerability to an EvaluatedRequirement.
func buildRequirement(vuln NeuVectorVuln) hdf.EvaluatedRequirement {
	cweIDs := extractCWEs(vuln.Description)
	nist := shared.MapCWEToNIST(cweIDs, shared.DefaultRemediationNIST)
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	if len(cweIDs) > 0 {
		extras["cwe"] = hdfutil.StringsToInterfaces(cweIDs)
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	descriptions := []hdf.Description{
		{Label: "default", Data: vuln.Description},
	}

	msg := vulnMessage(vuln)
	results := []hdf.RequirementResult{
		{
			Status:   hdf.Failed,
			CodeDesc: "",
			Message:  &msg,
		},
	}

	title := vulnTitle(vuln)
	return hdf.EvaluatedRequirement{
		ID:                 vulnID(vuln),
		Title:              &title,
		Impact:             getImpact(vuln),
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            results,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
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
		requirements = append(requirements, buildRequirement(vuln))
	}

	now := time.Now().UTC()
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
		ToolFormat:       "JSON",
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
