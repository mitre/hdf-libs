package ionchannel

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// ScanResults wraps the type and data of a scan result.
type ScanResults struct {
	Type string   `json:"type"`
	Data ScanData `json:"data"`
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

// buildTags builds the tags map for a dependency requirement.
func buildTags(dep contextualizedDependency) map[string]interface{} {
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

	// Extract dependencies from the dependency scan summary
	var allDeps []Dependency
	for _, scan := range analysis.ScanSummaries {
		if scan.Name == "dependency" {
			allDeps = scan.Results.Data.Dependencies
			break
		}
	}

	// Flatten and contextualize
	contextDeps := buildDependencyGraph(allDeps)

	// Build requirements
	requirements := make([]hdf.EvaluatedRequirement, len(contextDeps))
	for i, dep := range contextDeps {
		depID := fmt.Sprintf("dependency-%s/%s", dep.Org, dep.Name)
		title := buildTitle(dep.Dependency)
		tags := buildTags(dep)

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
		Maintainer:   hdfutil.Ptr("saf@groups.mitre.org"),
		Supports:     []hdf.SupportedPlatform{},
		Groups:       []hdf.RequirementGroup{},
		Requirements: requirements,
		Integrity:    integrity,
		Status:       hdfutil.Ptr("loaded"),
	}

	now := time.Now()

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "ionchannel-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Ion Channel",
		ToolFormat:       "JSON",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &now,
	}), nil
}
