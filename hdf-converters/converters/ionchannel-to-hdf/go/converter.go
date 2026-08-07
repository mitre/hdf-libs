package ionchannel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// IonChannelAnalysis is the top-level Ion Channel analysis JSON structure
// from the /v1/report/getAnalysis API endpoint.
type IonChannelAnalysis struct {
	ID            string        `json:"id"`
	AnalysisID    string        `json:"analysis_id"`
	TeamID        string        `json:"team_id"`
	ProjectID     string        `json:"project_id"`
	Name          string        `json:"name"`
	Text          string        `json:"text"`
	Type          string        `json:"type"`
	Source        string        `json:"source"`
	Branch        string        `json:"branch"`
	Description   string        `json:"description"`
	Risk          string        `json:"risk"`
	Summary       string        `json:"summary"`
	Passed        bool          `json:"passed"`
	RulesetID     string        `json:"ruleset_id"`
	RulesetName   string        `json:"ruleset_name"`
	Status        string        `json:"status"`
	CreatedAt     string        `json:"created_at"`
	UpdatedAt     string        `json:"updated_at"`
	Duration      float64       `json:"duration"`
	TriggerHash   string        `json:"trigger_hash"`
	TriggerText   string        `json:"trigger_text"`
	TriggerAuthor string        `json:"trigger_author"`
	Trigger       string        `json:"trigger"`
	Public        bool          `json:"public"`
	ScanSummaries []ScanSummary `json:"scan_summaries"`
}

// ScanSummary represents a single scan within an Ion Channel analysis.
type ScanSummary struct {
	ID          string      `json:"id"`
	TeamID      string      `json:"team_id"`
	ProjectID   string      `json:"project_id"`
	AnalysisID  string      `json:"analysis_id"`
	Summary     string      `json:"summary"`
	Results     ScanResults `json:"results"`
	CreatedAt   string      `json:"created_at"`
	UpdatedAt   string      `json:"updated_at"`
	Duration    float64     `json:"duration"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
}

// ScanResults wraps the type and data of a scan result. Data is kept raw so that
// non-dependency scan types (community, vulnerability, license, virus, …) — whose
// data shape is not the dependency tree — are preserved verbatim rather than
// dropped by a dependency-only struct.
type ScanResults struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// ScanData holds the dependency data from a dependency scan.
type ScanData struct {
	Dependencies []Dependency `json:"dependencies"`
}

// Dependency represents a single dependency entry, which may contain nested sub-dependencies.
type Dependency struct {
	LatestVersion   string          `json:"latest_version"`
	Org             string          `json:"org"`
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	Package         string          `json:"package"`
	Version         string          `json:"version"`
	Scope           string          `json:"scope"`
	Requirement     string          `json:"requirement"`
	File            string          `json:"file"`
	OutdatedVersion OutdatedVersion `json:"outdated_version"`
	Dependencies    []Dependency    `json:"dependencies"`
}

// OutdatedVersion tracks how far behind a dependency is from its latest version.
type OutdatedVersion struct {
	MajorBehind int `json:"major_behind"`
	MinorBehind int `json:"minor_behind"`
	PatchBehind int `json:"patch_behind"`
}

// contextualizedDependency is a dependency with its parent relationship info.
type contextualizedDependency struct {
	Dependency
	ParentDependencies []string `json:"parentDependencies"`
}

// extractAllDependencies recursively flattens a dependency tree.
func extractAllDependencies(dep Dependency) []contextualizedDependency {
	result := []contextualizedDependency{
		{Dependency: dep, ParentDependencies: []string{}},
	}
	for _, sub := range dep.Dependencies {
		result = append(result, extractAllDependencies(sub)...)
	}
	return result
}

// buildDependencyGraph flattens the dependency tree and associates parent relationships.
func buildDependencyGraph(deps []Dependency) []contextualizedDependency {
	graph := make(map[string]*contextualizedDependency)
	// Insertion order tracking for deterministic output
	var insertionOrder []string

	// Flatten all dependencies
	for _, topLevel := range deps {
		for _, flat := range extractAllDependencies(topLevel) {
			key := flat.Org + "/" + flat.Name
			if _, exists := graph[key]; !exists {
				cp := flat
				graph[key] = &cp
				insertionOrder = append(insertionOrder, key)
			}
		}
	}

	// Associate parent relationships
	for _, dep := range graph {
		for _, sub := range dep.Dependencies {
			subKey := sub.Org + "/" + sub.Name
			if child, ok := graph[subKey]; ok {
				parentKey := dep.Org + "/" + dep.Name
				child.ParentDependencies = append(child.ParentDependencies, parentKey)
			}
		}
	}

	// Return in insertion order
	result := make([]contextualizedDependency, 0, len(insertionOrder))
	for _, key := range insertionOrder {
		result = append(result, *graph[key])
	}
	return result
}

// buildTitle builds the human-readable title for a dependency requirement.
func buildTitle(dep Dependency) string {
	// Python editable install special case
	if dep.Type == "pypi" && dep.Package == "egg" && dep.Name == "-e" {
		return "Python requirements file " + dep.File
	}

	title := "Dependency " + dep.Name + " "
	if dep.Org != "" && !strings.EqualFold(dep.Org, "n/a") {
		title += "from " + dep.Org + " "
	}
	if dep.Version != "" && !strings.EqualFold(dep.Version, "n/a") {
		title += "@ " + dep.Version + " "
	}
	if dep.Requirement != "" && !strings.EqualFold(dep.Requirement, "n/a") {
		title += "(Required " + dep.Requirement + ") "
	}
	return strings.TrimSpace(title)
}

// analysisTags returns the analysis-level verdict metadata attached to every
// requirement built from the analysis. risk/ruleset_name/ruleset_id are omitted
// when the source leaves them empty; passed is always present as its native
// boolean (distinct from the string form carried in the baseline labels).
func analysisTags(a IonChannelAnalysis) map[string]interface{} {
	tags := map[string]interface{}{"passed": a.Passed}
	if a.Risk != "" {
		tags["risk"] = a.Risk
	}
	if a.RulesetName != "" {
		tags["ruleset_name"] = a.RulesetName
	}
	if a.RulesetID != "" {
		tags["ruleset_id"] = a.RulesetID
	}
	return tags
}

// buildTags builds the tags map for a dependency requirement.
func buildTags(dep contextualizedDependency, analysis IonChannelAnalysis) map[string]interface{} {
	nist := shared.DefaultComponentManagementNIST
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{
		"org":            dep.Org,
		"name":           dep.Name,
		"type":           dep.Type,
		"version":        dep.Version,
		"latest_version": dep.LatestVersion,
		"scope":          dep.Scope,
		"requirement":    dep.Requirement,
		"file":           dep.File,
	}

	if len(dep.Dependencies) > 0 {
		subNames := make([]string, len(dep.Dependencies))
		for i, sub := range dep.Dependencies {
			subNames[i] = sub.Name
		}
		extras["dependencies"] = subNames
	}

	if len(dep.ParentDependencies) > 0 {
		extras["parentDependencies"] = dep.ParentDependencies
	}

	for k, v := range analysisTags(analysis) {
		extras[k] = v
	}

	return shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)
}

// marshalDependencyCode renders a dependency as the JSON blob carried in the
// requirement's code field. HTML escaping is off so a version requirement like
// ">=0.5.0" is not mangled into a unicode escape inside the embedded blob.
func marshalDependencyCode(dep Dependency) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(dep); err != nil {
		return "{}"
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// buildScanCode renders a non-dependency scan's raw result data as the indented
// JSON blob carried in the requirement's code field. json.Indent re-formats the
// original bytes in place, preserving the source key order so the output is
// byte-identical to the TypeScript twin's JSON.stringify(data, null, 2).
func buildScanCode(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return "{}"
	}
	return buf.String()
}

// titleCaseFirst upper-cases the first rune of s (ASCII only), leaving the rest.
func titleCaseFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// scanStartTime returns a scan summary's start time: created_at (when the scan
// began), falling back to updated_at, then the zero sentinel when the source
// carries neither. Zero mirrors the TS `new Date('0001-01-01T00:00:00Z')`
// sentinel so both languages emit the same startTime on a timeless scan.
func scanStartTime(scan ScanSummary) time.Time {
	if t := hdfutil.ParseTimestamp(scan.CreatedAt); !t.IsZero() {
		return t
	}
	if t := hdfutil.ParseTimestamp(scan.UpdatedAt); !t.IsZero() {
		return t
	}
	return time.Time{}
}

// analysisTimestamp returns the document timestamp: the analysis updated_at
// (completion / last-update time), falling back to created_at, then wall-clock
// now() when the source carries no parseable analysis time. Source-derived so
// converting the same input twice yields the same top-level timestamp.
func analysisTimestamp(a IonChannelAnalysis) time.Time {
	if t := hdfutil.ParseTimestamp(a.UpdatedAt); !t.IsZero() {
		return t
	}
	if t := hdfutil.ParseTimestamp(a.CreatedAt); !t.IsZero() {
		return t
	}
	return time.Now()
}

// buildScanRequirement builds the single inventory requirement emitted for a
// non-dependency scan summary. The scan's serializable result data is preserved
// in the code field (the ionchannel dependency pattern), and scan identity lands
// in tags.
func buildScanRequirement(scan ScanSummary, analysis IonChannelAnalysis) hdf.EvaluatedRequirement {
	title := scan.Description
	if title == "" {
		title = titleCaseFirst(scan.Name) + " scan"
	}

	desc := scan.Summary
	if desc == "" {
		desc = titleCaseFirst(scan.Name) + " scan summary"
	}

	tags := map[string]interface{}{
		"name": scan.Name,
		"type": scan.Results.Type,
	}
	for k, v := range analysisTags(analysis) {
		tags[k] = v
	}

	return hdf.EvaluatedRequirement{
		ID:    "scan-" + scan.Name,
		Title: hdfutil.Ptr(title),
		Descriptions: []hdf.Description{
			{Label: "default", Data: desc},
		},
		Impact: 0.0,
		Tags:   tags,
		Code:   hdfutil.Ptr(buildScanCode(scan.Results.Data)),
		Results: []hdf.RequirementResult{
			{
				Status:    hdf.NotReviewed,
				CodeDesc:  scan.Name + " scan summary",
				StartTime: scanStartTime(scan),
			},
		},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// verdictDescription renders the analysis-level ruleset verdict as prose.
func verdictDescription(a IonChannelAnalysis) string {
	outcome := "PASSED"
	if !a.Passed {
		outcome = "FAILED"
	}
	desc := fmt.Sprintf("Ion Channel analysis verdict: %s", outcome)
	if a.Risk != "" {
		desc += fmt.Sprintf(" (risk: %s)", a.Risk)
	}
	if a.RulesetName != "" {
		desc += fmt.Sprintf(". Ruleset: %s", a.RulesetName)
		if a.RulesetID != "" {
			desc += fmt.Sprintf(" (%s)", a.RulesetID)
		}
	}
	return desc + "."
}

// verdictLabels surfaces the structured analysis-level verdict fields as
// queryable baseline labels (well-known-key grouping map). Values are strings;
// only non-empty fields are included, and passed is always present.
func verdictLabels(a IonChannelAnalysis) map[string]string {
	labels := map[string]string{"passed": strconv.FormatBool(a.Passed)}
	if a.Risk != "" {
		labels["risk"] = a.Risk
	}
	if a.RulesetName != "" {
		labels["ruleset_name"] = a.RulesetName
	}
	if a.RulesetID != "" {
		labels["ruleset_id"] = a.RulesetID
	}
	return labels
}

// ConvertIonChannelToHDF converts Ion Channel analysis JSON to HDF format.
func ConvertIonChannelToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if err := shared.ValidateJSONSize(input, "ionchannel", 0); err != nil {
		return nil, fmt.Errorf("ionchannel: %w", err)
	}

	var analysis IonChannelAnalysis
	if err := json.Unmarshal(input, &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse Ion Channel JSON: %w", err)
	}

	if analysis.ScanSummaries == nil {
		return nil, fmt.Errorf("ion channel: scan_summaries is missing")
	}

	// Extract dependencies from the dependency scan summary; collect every other
	// scan summary for its own baseline.
	var allDeps []Dependency
	var nonDepScans []ScanSummary
	foundDep := false
	for _, scan := range analysis.ScanSummaries {
		if scan.Name == "dependency" && !foundDep {
			var data ScanData
			if err := json.Unmarshal(scan.Results.Data, &data); err != nil {
				return nil, fmt.Errorf("ion channel: invalid dependency scan data: %w", err)
			}
			allDeps = data.Dependencies
			foundDep = true
			continue
		}
		nonDepScans = append(nonDepScans, scan)
	}

	// Flatten and contextualize
	contextDeps := buildDependencyGraph(allDeps)

	// Build requirements
	requirements := make([]hdf.EvaluatedRequirement, len(contextDeps))
	for i, dep := range contextDeps {
		depID := fmt.Sprintf("dependency-%s/%s", dep.Org, dep.Name)
		title := buildTitle(dep.Dependency)
		tags := buildTags(dep, analysis)

		code := marshalDependencyCode(dep.Dependency)

		desc := fmt.Sprintf("Dependency %s/%s", dep.Org, dep.Name)

		requirements[i] = hdf.EvaluatedRequirement{
			ID:    depID,
			Title: hdfutil.Ptr(title),
			Descriptions: []hdf.Description{
				{Label: "default", Data: desc},
			},
			Impact:      0.0,
			Tags:        tags,
			ControlType: shared.DeriveControlTypeFromTags(shared.DefaultComponentManagementNIST),
			Code:        hdfutil.Ptr(code),
			Results: []hdf.RequirementResult{
				{
					Status:    hdf.NotReviewed,
					CodeDesc:  "Dependency inventory item",
					StartTime: time.Time{},
				},
			},
			VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		}
	}

	integrity := shared.InputIntegrity(input)
	baselineTitle := "Ion Channel Analysis of " + analysis.Source

	baseline := hdf.EvaluatedBaseline{
		Name:         "Ion Channel SBOM Analysis",
		Title:        hdfutil.Ptr(baselineTitle),
		Summary:      hdfutil.Ptr(analysis.Summary),
		Description:  hdfutil.Ptr(verdictDescription(analysis)),
		Labels:       verdictLabels(analysis),
		Maintainer:   hdfutil.Ptr("saf@groups.mitre.org"),
		Supports:     []hdf.SupportedPlatform{},
		Groups:       []hdf.RequirementGroup{},
		Requirements: requirements,
		Integrity:    integrity,
		Status:       hdfutil.Ptr("loaded"),
	}

	baselines := []hdf.EvaluatedBaseline{baseline}

	// One baseline per non-dependency scan summary, grouped by scan-summary name.
	for _, scan := range nonDepScans {
		baselines = append(baselines, hdf.EvaluatedBaseline{
			Name:         "Ion Channel " + scan.Name + " Scan",
			Title:        hdfutil.Ptr(baselineTitle),
			Summary:      hdfutil.Ptr(scan.Summary),
			Maintainer:   hdfutil.Ptr("saf@groups.mitre.org"),
			Supports:     []hdf.SupportedPlatform{},
			Groups:       []hdf.RequirementGroup{},
			Requirements: []hdf.EvaluatedRequirement{buildScanRequirement(scan, analysis)},
			Integrity:    integrity,
			Status:       hdfutil.Ptr("loaded"),
		})
	}

	ts := analysisTimestamp(analysis)

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "ionchannel-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Ion Channel",
		Baselines:        baselines,
		Timestamp:        &ts,
	}), nil
}
