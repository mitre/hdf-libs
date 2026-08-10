package deptrack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// DeptrackReport is the top-level Dependency-Track Finding Packaging Format (FPF) structure.
type DeptrackReport struct {
	Version  string            `json:"version"`
	Meta     DeptrackMeta      `json:"meta"`
	Project  DeptrackProject   `json:"project"`
	Findings []DeptrackFinding `json:"findings"`
}

// DeptrackMeta holds metadata about the Dependency-Track instance.
type DeptrackMeta struct {
	Application string `json:"application"`
	Version     string `json:"version"`
	Timestamp   string `json:"timestamp"`
	BaseURL     string `json:"baseUrl"`
}

// DeptrackProject holds project identification.
type DeptrackProject struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// DeptrackFinding represents a single finding from Dependency-Track.
type DeptrackFinding struct {
	Component     DeptrackComponent     `json:"component"`
	Vulnerability DeptrackVulnerability `json:"vulnerability"`
	Analysis      DeptrackAnalysis      `json:"analysis"`
	Attribution   *DeptrackAttribution  `json:"attribution,omitempty"`
	Matrix        string                `json:"matrix"`

	// raw is the finding exactly as Dependency-Track emitted it. It carries no
	// literal source snippet, so requirement.code is the whole finding re-indented
	// in place — preserving source key order and every field the typed struct does
	// not model (aliases, epssScore, source, vulnId), so the output is
	// byte-identical to the TypeScript twin's JSON.stringify(finding, null, 2).
	raw json.RawMessage
}

func (f *DeptrackFinding) UnmarshalJSON(data []byte) error {
	type plain DeptrackFinding
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*f = DeptrackFinding(p)
	f.raw = append(json.RawMessage(nil), data...)
	return nil
}

// DeptrackComponent identifies the affected software component.
type DeptrackComponent struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Purl          string `json:"purl"`
	LatestVersion string `json:"latestVersion"`
	Group         string `json:"group"`
	Project       string `json:"project"`
	Cpe           string `json:"cpe"`
}

// DeptrackVulnerability holds vulnerability details.
type DeptrackVulnerability struct {
	UUID           string          `json:"uuid"`
	Source         string          `json:"source"`
	VulnID         string          `json:"vulnId"`
	Title          string          `json:"title"`
	Subtitle       string          `json:"subtitle"`
	Severity       string          `json:"severity"`
	SeverityRank   int             `json:"severityRank"`
	CweID          int             `json:"cweId"`
	CweName        string          `json:"cweName"`
	Cwes           []DeptrackCwe   `json:"cwes"`
	Description    string          `json:"description"`
	Recommendation string          `json:"recommendation"`
	Aliases        []DeptrackAlias `json:"aliases"`
	CvssV2Base     float64         `json:"cvssV2BaseScore"`
	CvssV3Base     float64         `json:"cvssV3BaseScore"`
	EpssScore      float64         `json:"epssScore"`
	EpssPercentile float64         `json:"epssPercentile"`
}

// DeptrackAlias is a cross-reference to the same vulnerability under another
// naming scheme. Dependency-Track's finding.id is a UUID composite (matrix), not
// the CVE, so aliases[].cveId is where the CVE identifier lives.
type DeptrackAlias struct {
	CveID string `json:"cveId"`
}

// DeptrackCwe represents a CWE entry.
type DeptrackCwe struct {
	CweID int    `json:"cweId"`
	Name  string `json:"name"`
}

// DeptrackAnalysis holds analysis state.
type DeptrackAnalysis struct {
	State        string `json:"state"`
	IsSuppressed bool   `json:"isSuppressed"`
}

// DeptrackAttribution holds attribution details.
type DeptrackAttribution struct {
	AnalyzerIdentity    string `json:"analyzerIdentity"`
	AttributedOn        string `json:"attributedOn"`
	AlternateIdentifier string `json:"alternateIdentifier"`
	ReferenceURL        string `json:"referenceUrl"`
}

// getImpact maps Dependency-Track severity strings to HDF impact values.
// Uses the same mapping as the heimdall2 dependency-track-mapper:
// critical=0.9, high=0.7, medium=0.5, low=0.3, info=0, unassigned=0.5

var deptrackAliases = map[string]float64{
	"critical": 0.9,
}

func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, deptrackAliases, 0.5)
}

// getTitle builds the requirement title from component purl and vulnerability title,
// matching the heimdall2 pattern: "{purl} - {title}" or just "{purl}" if no title.
func getTitle(finding DeptrackFinding) string {
	purl := finding.Component.Purl
	title := finding.Vulnerability.Title
	if title != "" {
		return fmt.Sprintf("%s - %s", purl, title)
	}
	return purl
}

// getCweIDs extracts numeric CWE IDs as strings with "CWE-" prefix from the cwes array.
func getCweIDs(cwes []DeptrackCwe) []string {
	if len(cwes) == 0 {
		return nil
	}
	ids := make([]string, len(cwes))
	for i, cwe := range cwes {
		ids[i] = "CWE-" + strconv.Itoa(cwe.CweID)
	}
	return ids
}

// getCVEs collects CVE identifiers from vulnerability.aliases[].cveId, deduped in
// first-seen order. The finding.id is a UUID composite, so the CVE has no other
// home; it goes to tags.cve (interim, pending an identifiers[] schema field).
func getCVEs(vuln DeptrackVulnerability) []string {
	var out []string
	seen := map[string]bool{}
	for _, alias := range vuln.Aliases {
		if alias.CveID != "" && !seen[alias.CveID] {
			seen[alias.CveID] = true
			out = append(out, alias.CveID)
		}
	}
	return out
}

// buildFindingCode renders the raw Dependency-Track finding as indented JSON for
// requirement.code (the Heimdall CODE tab). json.Indent reformats the original
// bytes in place, preserving source key order so the output is byte-identical to
// the TypeScript twin's JSON.stringify(finding, null, 2).
func buildFindingCode(finding DeptrackFinding) string {
	if len(finding.raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, finding.raw, "", "  "); err != nil {
		return "{}"
	}
	return buf.String()
}

// buildRequirement converts a Dependency-Track finding into an EvaluatedRequirement.
func buildRequirement(finding DeptrackFinding, timestamp string) hdf.EvaluatedRequirement {
	cweIDs := getCweIDs(finding.Vulnerability.Cwes)
	cveIDs := getCVEs(finding.Vulnerability)
	nist := shared.MapCWEToNIST(cweIDs, shared.DefaultStaticAnalysisNIST)
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	if len(cveIDs) > 0 {
		extras["cve"] = hdfutil.StringsToInterfaces(cveIDs)
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	// Build descriptions: check (description), fix (recommendation), default (description fallback)
	descriptions := []hdf.Description{
		{Label: "default", Data: finding.Vulnerability.Description},
	}
	if finding.Vulnerability.Description != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "check",
			Data:  finding.Vulnerability.Description,
		})
	}
	if finding.Vulnerability.Recommendation != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  finding.Vulnerability.Recommendation,
		})
	}

	// Build result: all findings are Failed
	codeDesc := finding.Vulnerability.Recommendation
	if codeDesc == "" {
		codeDesc = "No recommendation available"
	}

	results := []hdf.RequirementResult{
		{
			Status:   hdf.Failed,
			CodeDesc: codeDesc,
		},
	}

	// Add startTime from meta.timestamp if available
	if timestamp != "" {
		t := hdfutil.ParseTimestamp(timestamp)
		if !t.IsZero() {
			results[0].StartTime = t
		}
	}

	title := getTitle(finding)
	req := hdf.EvaluatedRequirement{
		ID:                 finding.Matrix,
		Title:              &title,
		Code:               hdfutil.Ptr(buildFindingCode(finding)),
		Impact:             getImpact(finding.Vulnerability.Severity),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	if len(cweIDs) > 0 {
		req.Cwe = cweIDs
	}
	if pkg := buildAffectedPackageFromComponent(finding.Component); pkg != nil {
		req.AffectedPackages = []hdf.AffectedPackage{*pkg}
	}
	return req
}

// buildAffectedPackageFromComponent builds an Affected_Package from a
// Dependency-Track component. Prefers the rich identifiers
// Dependency-Track already exposes (purl, cpe) and augments with
// name/version/ecosystem when available.
func buildAffectedPackageFromComponent(c DeptrackComponent) *hdf.AffectedPackage {
	var ecosystem hdf.Ecosystem
	if c.Purl != "" {
		if parsed := hdfutil.ParsePurl(c.Purl); parsed != nil {
			ecosystem = shared.EcosystemFromPurlType(parsed.Type)
		} else {
			ecosystem = hdf.Generic
		}
	} else if c.Name != "" && c.Version != "" {
		ecosystem = hdf.Generic
	}
	return shared.BuildAffectedPackage(shared.AffectedPackageOptions{
		Name:           c.Name,
		Version:        c.Version,
		Ecosystem:      ecosystem,
		Purl:           c.Purl,
		CPE:            c.Cpe,
		FixedInVersion: c.LatestVersion,
	})
}

// ConvertDeptrackToHDF converts a Dependency-Track FPF JSON report to HDF format.
func ConvertDeptrackToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("deptrack: empty input")
	}
	if err := shared.ValidateJSONSize(input, "deptrack", 0); err != nil {
		return nil, fmt.Errorf("deptrack: %w", err)
	}

	var report DeptrackReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("deptrack: invalid JSON: %w", err)
	}

	// Validate it looks like a Dependency-Track report
	if report.Findings == nil && report.Project.UUID == "" && report.Meta.Application == "" {
		return nil, fmt.Errorf("deptrack: input does not appear to be a Dependency-Track report")
	}

	checksum := shared.InputChecksum(input)

	limitedFindings := shared.LimitSliceWithWarning(report.Findings, 0, "finding")
	requirements := make([]hdf.EvaluatedRequirement, len(limitedFindings))
	for i, finding := range limitedFindings {
		requirements[i] = buildRequirement(finding, report.Meta.Timestamp)
	}

	if len(requirements) == 0 {
		projectName := report.Project.Name
		if projectName == "" {
			projectName = report.Project.UUID
		}
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"deptrack-no-findings",
				fmt.Sprintf("Dependency-Track analyzed %s and reported zero vulnerable components.", projectName),
				time.Now().UTC(),
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Dependency-Track Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	title := fmt.Sprintf("Dependency-Track: %s %s", report.Project.Name, report.Project.Version)
	baseline.Title = &title

	if report.Project.Description != "" {
		baseline.Summary = &report.Project.Description
	}

	targetName := report.Project.Name
	if targetName == "" {
		targetName = report.Project.UUID
	}

	// Top-level timestamp is the scan time from meta.timestamp (source-derived, so
	// converting the same input twice is deterministic). Fall back to wall-clock
	// only when the source omits it or it is unparseable.
	docTimestamp := time.Now().UTC()
	if report.Meta.Timestamp != "" {
		if t := hdfutil.ParseTimestamp(report.Meta.Timestamp); !t.IsZero() {
			docTimestamp = t
		}
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "deptrack-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Dependency-Track",
		ToolFormat:       "FPF",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.Application},
		},
		Timestamp: &docTimestamp,
	}), nil
}
