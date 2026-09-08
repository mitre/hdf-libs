package snyk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// SnykReport is the top-level Snyk test JSON output structure.
type SnykReport struct {
	OK              bool       `json:"ok"`
	Vulnerabilities []SnykVuln `json:"vulnerabilities"`
	DependencyCount int        `json:"dependencyCount"`
	Org             string     `json:"org"`
	PackageManager  string     `json:"packageManager"`
	Summary         string     `json:"summary"`
	ProjectName     string     `json:"projectName"`
	Path            string     `json:"path"`
}

// SnykVuln represents a single vulnerability entry from Snyk output. Structured
// slices of it map into dedicated HDF fields (impact, cvss, cwe, refs, tags,
// affectedPackages, descriptions); every field the converter parses is also
// re-serialized verbatim into requirement.code as the raw-finding passthrough,
// so fields with no structured HDF home (exploit, language, semver, functions,
// disclosure/publication times, …) are not lost. The struct field ORDER is the
// requirement.code field order and must stay byte-identical to the TS
// projection — do not reorder without updating typescript/converter.ts.
type SnykVuln struct {
	ID                   string          `json:"id,omitempty"`
	Title                string          `json:"title,omitempty"`
	Description          string          `json:"description,omitempty"`
	Severity             string          `json:"severity,omitempty"`
	SeverityWithCritical string          `json:"severityWithCritical,omitempty"`
	Language             string          `json:"language,omitempty"`
	PackageName          string          `json:"packageName,omitempty"`
	ModuleName           string          `json:"moduleName,omitempty"`
	Name                 string          `json:"name,omitempty"`
	Version              string          `json:"version,omitempty"`
	PackageManager       string          `json:"packageManager,omitempty"`
	CvssScore            float64         `json:"cvssScore,omitempty"`
	CVSSv3               string          `json:"CVSSv3,omitempty"`
	Exploit              string          `json:"exploit,omitempty"`
	Malicious            bool            `json:"malicious,omitempty"`
	Proprietary          bool            `json:"proprietary,omitempty"`
	SocialTrendAlert     bool            `json:"socialTrendAlert,omitempty"`
	IsUpgradable         bool            `json:"isUpgradable,omitempty"`
	IsPatchable          bool            `json:"isPatchable,omitempty"`
	Semver               *SnykSemver     `json:"semver,omitempty"`
	Functions            []SnykFunction  `json:"functions,omitempty"`
	FunctionsNew         []SnykFunction  `json:"functions_new,omitempty"`
	FixedIn              []string        `json:"fixedIn,omitempty"`
	Patches              []SnykPatch     `json:"patches,omitempty"`
	DisclosureTime       string          `json:"disclosureTime,omitempty"`
	PublicationTime      string          `json:"publicationTime,omitempty"`
	CreationTime         string          `json:"creationTime,omitempty"`
	ModificationTime     string          `json:"modificationTime,omitempty"`
	Credit               []string        `json:"credit,omitempty"`
	AlternativeIds       []string        `json:"alternativeIds,omitempty"`
	Identifiers          SnykIdentifiers `json:"identifiers"`
	References           []SnykReference `json:"references,omitempty"`
	From                 []string        `json:"from,omitempty"`
	UpgradePath          []interface{}   `json:"upgradePath,omitempty"`
}

// SnykReference is an external link Snyk attaches to a vulnerability. Only the
// url carries into HDF (Reference.url) as structured data; both title and url
// are preserved verbatim in the requirement.code passthrough.
type SnykReference struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
}

// SnykIdentifiers holds the CVE, CWE, and GHSA identifiers for a vulnerability.
type SnykIdentifiers struct {
	CVE  []string `json:"CVE,omitempty"`
	CWE  []string `json:"CWE,omitempty"`
	GHSA []string `json:"GHSA,omitempty"`
}

// SnykSemver captures Snyk's affected-version-range object. Only `vulnerable`
// is modeled (the only shape present across our corpus); other keys are dropped
// from the passthrough rather than risking a Go/TS serialization divergence.
type SnykSemver struct {
	Vulnerable []string `json:"vulnerable,omitempty"`
}

// SnykFunctionID names the affected function within a source file.
type SnykFunctionID struct {
	ClassName    *string `json:"className,omitempty"`
	FilePath     string  `json:"filePath,omitempty"`
	FunctionName string  `json:"functionName,omitempty"`
}

// SnykFunction is one affected-function entry (backs both `functions` and
// `functions_new`).
type SnykFunction struct {
	FunctionID *SnykFunctionID `json:"functionId,omitempty"`
	Version    []string        `json:"version,omitempty"`
}

// SnykPatch is a Snyk-published patch descriptor for a vulnerability.
type SnykPatch struct {
	Comments         []string `json:"comments,omitempty"`
	ID               string   `json:"id,omitempty"`
	ModificationTime string   `json:"modificationTime,omitempty"`
	URLs             []string `json:"urls,omitempty"`
	Version          string   `json:"version,omitempty"`
}

// buildVulnCode re-serializes the parsed vulnerability into indented JSON for
// requirement.code (the raw-finding passthrough, Heimdall's CODE tab). It is
// byte-identical to the TS projection: json.Encoder with HTML escaping disabled
// and a two-space indent matches JSON.stringify(vuln, null, 2). The encoder
// appends a trailing newline that JSON.stringify does not, so it is trimmed.
func buildVulnCode(v SnykVuln) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimRight(buf.String(), "\n")
}

// getImpact maps Snyk severity strings to HDF impact values.
func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

// formatDependencyPath formats the "from" array as a human-readable dependency path.
func formatDependencyPath(from []string) string {
	if len(from) == 0 {
		return "Unknown dependency path"
	}
	return fmt.Sprintf("From: [ %s ]", strings.Join(from, ", "))
}

// groupByID caps a project's vulnerabilities and groups them by ID, preserving
// insertion order. It is the single definition of the input-to-requirement
// relation within a project: the conversion builds requirements from it and
// ExpectedRequirementCount counts it.
func groupByID(vulns []SnykVuln) ([]string, map[string][]SnykVuln) {
	order := []string{}
	groups := map[string][]SnykVuln{}
	for _, vuln := range shared.LimitSliceWithWarning(vulns, 0, "vulnerability") {
		if _, seen := groups[vuln.ID]; !seen {
			order = append(order, vuln.ID)
		}
		groups[vuln.ID] = append(groups[vuln.ID], vuln)
	}
	return order, groups
}

// ecosystemFromSnykPackageManager maps Snyk's `packageManager` field to an
// Affected_Package ecosystem. Snyk values don't always match PURL types
// one-to-one (pip → pypi, rubygems → gem, yarn → npm).
func ecosystemFromSnykPackageManager(pm string) hdf.Ecosystem {
	switch strings.ToLower(pm) {
	case "":
		return hdf.Generic
	case "pip", "pip3":
		return hdf.Pypi
	case "rubygems", "bundler":
		return hdf.Gem
	case "yarn", "npm":
		return hdf.Npm
	default:
		return shared.EcosystemFromPurlType(pm)
	}
}

// synthesizeSnykPurl builds a `pkg:<type>/<name>@<version>` PURL when the
// ecosystem maps cleanly. Returns "" for `generic` so we don't emit a fake
// `pkg:generic/...` purl that downstream tools can't dereference.
func synthesizeSnykPurl(ecosystem hdf.Ecosystem, name, version string) string {
	if ecosystem == hdf.Generic {
		return ""
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, name, version)
}

// buildSnykCvss assembles the structured cvss[] entry for a Snyk vulnerability
// from its cvssScore (base score) and CVSSv3 (base vector, carrying a CVSS:3.1/
// prefix). Returns nil when the source carries neither so the field is omitted.
func buildSnykCvss(v SnykVuln) []hdf.Cvss {
	if v.CvssScore == 0 && v.CVSSv3 == "" {
		return nil
	}
	var scorePtr *float64
	if v.CvssScore != 0 {
		s := v.CvssScore
		scorePtr = &s
	}
	return []hdf.Cvss{shared.BuildCvss(shared.CvssInput{
		Version:    shared.CvssVersionFromVector(v.CVSSv3),
		BaseScore:  scorePtr,
		BaseVector: v.CVSSv3,
	})}
}

// buildSnykRefs emits one hdf.Reference{URL} per source reference that carries
// a URL. Returns nil when the vulnerability carries no linkable references so
// the refs[] field is omitted.
func buildSnykRefs(refs []SnykReference) []hdf.Reference {
	var out []hdf.Reference
	for _, r := range refs {
		if r.URL == "" {
			continue
		}
		url := r.URL
		out = append(out, hdf.Reference{URL: &url})
	}
	return out
}

// formatUpgradePath renders Snyk's upgradePath into readable remediation text.
// The array leads with a boolean (whether the top-level dependency itself is
// upgradable) followed by the `pkg@version` chain to upgrade to. Only the
// string chain is meaningful; returns "" when it carries no package steps.
func formatUpgradePath(path []interface{}) string {
	var steps []string
	for _, elem := range path {
		if s, ok := elem.(string); ok && s != "" {
			steps = append(steps, s)
		}
	}
	if len(steps) == 0 {
		return ""
	}
	return strings.Join(steps, " > ")
}

// buildRequirement converts a group of vulnerabilities sharing an ID into one
// EvaluatedRequirement with multiple results.
func buildRequirement(vulnID string, vulns []SnykVuln, now time.Time, packageManager string) hdf.EvaluatedRequirement {
	rep := vulns[0]

	nist := shared.MapCWEToNIST(rep.Identifiers.CWE, shared.DefaultStaticAnalysisNIST)
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	// requirement.id is a SNYK/npm advisory id, not the CVE, so tags.cve is the
	// CVE's home. (Interim pending an identifiers[] schema field.)
	if len(rep.Identifiers.CVE) > 0 {
		extras["cve"] = rep.Identifiers.CVE
	}
	if len(rep.Identifiers.GHSA) > 0 {
		extras["ghsaid"] = rep.Identifiers.GHSA
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)
	shared.MarkUnratedSeverity(tags, rep.Severity)

	descriptions := []hdf.Description{
		{Label: "default", Data: rep.Description},
	}
	if upgrade := formatUpgradePath(rep.UpgradePath); upgrade != "" {
		descriptions = append(descriptions, hdf.Description{Label: "upgradePath", Data: upgrade})
	}

	results := make([]hdf.RequirementResult, len(vulns))
	for i, vuln := range vulns {
		results[i] = hdf.RequirementResult{
			Status:    hdf.Failed,
			CodeDesc:  formatDependencyPath(vuln.From),
			StartTime: now,
		}
	}

	title := rep.Title
	req := hdf.EvaluatedRequirement{
		ID:                 vulnID,
		Title:              &title,
		Impact:             getImpact(rep.Severity),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	if code := buildVulnCode(rep); code != "" {
		req.Code = &code
	}

	if cvss := buildSnykCvss(rep); len(cvss) > 0 {
		req.Cvss = cvss
	}
	if len(rep.Identifiers.CWE) > 0 {
		req.Cwe = rep.Identifiers.CWE
	}
	if refs := buildSnykRefs(rep.References); len(refs) > 0 {
		req.Refs = refs
	}

	name := rep.PackageName
	if name == "" {
		name = rep.ModuleName
	}
	if name != "" && rep.Version != "" {
		ecosystem := ecosystemFromSnykPackageManager(packageManager)
		var fixed string
		if len(rep.FixedIn) > 0 {
			fixed = rep.FixedIn[0]
		}
		if pkg := shared.BuildAffectedPackage(shared.AffectedPackageOptions{
			Name:           name,
			Version:        rep.Version,
			Ecosystem:      ecosystem,
			Purl:           synthesizeSnykPurl(ecosystem, name, rep.Version),
			FixedInVersion: fixed,
		}); pkg != nil {
			req.AffectedPackages = []hdf.AffectedPackage{*pkg}
		}
	}
	return req
}

// convertSingleProject converts a single Snyk project report to an HDF baseline.
func convertSingleProject(report SnykReport, checksum *hdf.Checksum, now time.Time) hdf.EvaluatedBaseline {
	order, groups := groupByID(report.Vulnerabilities)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, vulnID := range order {
		requirements[i] = buildRequirement(vulnID, groups[vulnID], now, report.PackageManager)
	}

	if len(requirements) == 0 {
		target := report.ProjectName
		if target == "" {
			target = report.Path
		}
		if target == "" {
			target = "project"
		}
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"snyk-no-findings",
				fmt.Sprintf("Snyk scanned %s and reported zero vulnerable components.", target),
				now,
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Snyk Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	title := fmt.Sprintf("Snyk Project: %s Snyk Path: %s", report.ProjectName, report.Path)
	baseline.Title = &title

	if report.Summary != "" {
		baseline.Summary = &report.Summary
	}

	return baseline
}

// ConvertSnykToHDF converts Snyk output to HDF format.
// Accepts both native Snyk JSON and SARIF format — SARIF input is detected
// automatically and delegated to the shared SARIF converter.
// Handles both single-project (object) and multi-project (array) input.
func ConvertSnykToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	reports, multi, isSarif, err := parseReports(input)
	if err != nil {
		return nil, err
	}
	if isSarif {
		return sarif.ConvertSarifToHDF(input, converterVersion)
	}

	checksum := shared.InputChecksum(input)

	if multi {
		return convertMultiProject(reports, checksum, converterVersion)
	}
	report := reports[0]

	now := time.Now().UTC()

	baseline := convertSingleProject(report, checksum, now)

	targetName := report.ProjectName
	if targetName == "" {
		targetName = report.Path
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "snyk-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Snyk",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.Application},
		},
		Timestamp: &now,
	}), nil
}

func convertMultiProject(reports []SnykReport, checksum *hdf.Checksum, converterVersion string) (*hdf.HDFResults, error) {
	now := time.Now().UTC()

	limitedReports := projectReports(reports, true)
	baselines := make([]hdf.EvaluatedBaseline, len(limitedReports))
	for i, report := range limitedReports {
		baselines[i] = convertSingleProject(report, checksum, now)
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "snyk-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Snyk",
		Baselines:        baselines,
		Timestamp:        &now,
	}), nil
}

// parseReports applies the converter's input guards and decodes the Snyk
// output. isSarif reports a SARIF-shaped input, which the converter delegates;
// multi reports an array of projects (one baseline each), otherwise reports
// holds the single project. ConvertSnykToHDF and ExpectedRequirementCount
// share it so they accept and reject exactly the same inputs.
func parseReports(input []byte) (reports []SnykReport, multi, isSarif bool, err error) {
	if len(input) == 0 {
		return nil, false, false, fmt.Errorf("snyk: empty input")
	}
	if sizeErr := shared.ValidateJSONSize(input, "snyk", 0); sizeErr != nil {
		return nil, false, false, fmt.Errorf("snyk: %w", sizeErr)
	}
	if result := registry.DetectConverter(input); result != nil && result.Fingerprint.ID == "sarif-to-hdf" {
		return nil, false, true, nil
	}

	// Try single project first
	var report SnykReport
	if objErr := json.Unmarshal(input, &report); objErr != nil {
		// Try array of projects
		if arrErr := json.Unmarshal(input, &reports); arrErr != nil {
			return nil, false, false, fmt.Errorf("snyk: invalid JSON: %w", objErr)
		}
		return reports, true, false, nil
	}

	// Validate structure — must have vulnerabilities field
	// (json.Unmarshal succeeds on any JSON; check for expected content)
	if report.Vulnerabilities == nil {
		// Re-check: maybe it was actually an array
		if arrErr := json.Unmarshal(input, &reports); arrErr == nil && len(reports) > 0 {
			return reports, true, false, nil
		}
		// Default to empty vulnerabilities — Snyk output for clean projects
		// has "vulnerabilities": [] which parses as nil slice vs null
	}
	return []SnykReport{report}, false, false, nil
}

// projectReports returns the reports the conversion builds one baseline from
// each: the capped array for multi-project input, the single report otherwise.
func projectReports(reports []SnykReport, multi bool) []SnykReport {
	if multi {
		return shared.LimitSliceWithWarning(reports, 0, "project")
	}
	return reports
}

// ExpectedRequirementCount states how many requirements the input must convert
// to: per project, one per distinct vulnerability id or one no-findings
// requirement when the project carries none, summed across the (capped)
// projects. SARIF-shaped input defers to the SARIF converter's own relation,
// as the conversion does.
func ExpectedRequirementCount(input []byte) (int, string, error) {
	const unit = "distinct Snyk vulnerability ids per project"
	reports, multi, isSarif, err := parseReports(input)
	if err != nil {
		return 0, unit, err
	}
	if isSarif {
		return sarif.ExpectedRequirementCount(input)
	}
	count := 0
	for _, report := range projectReports(reports, multi) {
		order, _ := groupByID(report.Vulnerabilities)
		if len(order) == 0 {
			count++
			continue
		}
		count += len(order)
	}
	return count, unit, nil
}
