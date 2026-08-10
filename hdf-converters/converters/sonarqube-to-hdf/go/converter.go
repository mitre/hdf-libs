package sonarqube

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// IssuesResponse is the SonarQube /api/issues/search response structure.
// ServerVersion is populated by the fetcher from /api/server/version and
// travels with the data so the converter can include it in the HDF output.
type IssuesResponse struct {
	Total         int         `json:"total"`
	Page          int         `json:"p"`
	PageSize      int         `json:"ps"`
	Paging        Paging      `json:"paging"`
	Issues        []Issue     `json:"issues"`
	Components    []Component `json:"components,omitempty"`
	Rules         []Rule      `json:"rules,omitempty"`
	ServerVersion string      `json:"serverVersion,omitempty"`
}

type Paging struct {
	PageIndex int `json:"pageIndex"`
	PageSize  int `json:"pageSize"`
	Total     int `json:"total"`
}

type Issue struct {
	Key       string     `json:"key"`
	Rule      string     `json:"rule"`
	Severity  string     `json:"severity"`
	Component string     `json:"component"`
	Project   string     `json:"project"`
	Line      *int       `json:"line,omitempty"`
	Hash      string     `json:"hash,omitempty"`
	TextRange *TextRange `json:"textRange,omitempty"`
	Flows     []Flow     `json:"flows,omitempty"`
	Status    string     `json:"status"`
	Message   string     `json:"message"`
	Effort    string     `json:"effort,omitempty"`
	Debt      string     `json:"debt,omitempty"`
	Author    string     `json:"author,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	// Impacts carries the Multi-Quality-Rule (Clean Code) software-quality
	// severities. Present only when the server is in MQR mode, where SonarQube
	// treats these — not the deprecated top-level Severity — as authoritative.
	Impacts                    []Impact `json:"impacts,omitempty"`
	CleanCodeAttribute         string   `json:"cleanCodeAttribute,omitempty"`
	CleanCodeAttributeCategory string   `json:"cleanCodeAttributeCategory,omitempty"`
	CreationDate               string   `json:"creationDate"`
	UpdateDate                 string   `json:"updateDate"`
	Type                       string   `json:"type"`
}

// Impact is one MQR software-quality severity: SonarQube rates an issue
// independently per quality (SECURITY, RELIABILITY, MAINTAINABILITY).
type Impact struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}

type TextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartOffset int `json:"startOffset"`
	EndOffset   int `json:"endOffset"`
}

type Flow struct {
	Locations []Location `json:"locations"`
}

type Location struct {
	Component string     `json:"component"`
	TextRange *TextRange `json:"textRange,omitempty"`
	Msg       string     `json:"msg,omitempty"`
}

type Component struct {
	Key       string `json:"key"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Qualifier string `json:"qualifier,omitempty"`
	Name      string `json:"name,omitempty"`
	LongName  string `json:"longName,omitempty"`
	Path      string `json:"path,omitempty"`
}

type Rule struct {
	Key                 string               `json:"key"`
	Name                string               `json:"name"`
	Status              string               `json:"status,omitempty"`
	Lang                string               `json:"lang,omitempty"`
	LangName            string               `json:"langName,omitempty"`
	HTMLDesc            string               `json:"htmlDesc,omitempty"`
	MDDesc              string               `json:"mdDesc,omitempty"`
	Severity            string               `json:"severity,omitempty"`
	Type                string               `json:"type,omitempty"`
	Tags                []string             `json:"tags,omitempty"`
	SysTags             []string             `json:"sysTags,omitempty"`
	Scope               string               `json:"scope,omitempty"`
	DescriptionSections []DescriptionSection `json:"descriptionSections,omitempty"`
}

// DescriptionSection represents a section of a SonarQube rule description.
// SonarQube 26+ returns rule descriptions as structured sections instead of
// monolithic htmlDesc/mdDesc fields.
type DescriptionSection struct {
	Key     string `json:"key"`
	Content string `json:"content"`
}

// sonarqubeAliases maps SonarQube's deprecated legacy severity labels to HDF
// impact scores. Canonical reference: heimdall2 sonarqube-mapper.ts IMPACT_MAPPING.
// Keys must be lowercase for use with SeverityToImpactWithAliases.
// Note: SonarQube "CRITICAL" maps to 0.7, not the standard 1.0.
var sonarqubeAliases = map[string]float64{
	"blocker":  1.0,
	"critical": 0.7,
	"major":    0.5,
	"minor":    0.3,
}

// mqrAliases covers the one MQR severity the standard map lacks; HIGH/MEDIUM/
// LOW/INFO already resolve to 0.7/0.5/0.3/0.0 via SeverityToImpactWithAliases.
var mqrAliases = map[string]float64{
	"blocker": 1.0,
}

// mqrSeverityRank orders MQR software-quality severities weakest to strongest.
var mqrSeverityRank = map[string]int{
	"info":    0,
	"low":     1,
	"medium":  2,
	"high":    3,
	"blocker": 4,
}

// Which severity axis drove a requirement's severity/impact. Emitted as the
// severitySource tag so downstream gates can pin the meaning of severity.
const (
	severitySourceMQR    = "mqr"
	severitySourceLegacy = "legacy"
)

// maxImpact returns the highest-severity impact. An issue is rated per software
// quality, so the worst rating governs — matching how the SonarQube UI buckets it.
func maxImpact(impacts []Impact) (Impact, bool) {
	var best Impact
	found := false
	for _, imp := range impacts {
		if !found || mqrSeverityRank[strings.ToLower(imp.Severity)] > mqrSeverityRank[strings.ToLower(best.Severity)] {
			best = imp
			found = true
		}
	}
	return best, found
}

// selectSeverity picks the authoritative severity axis for an issue. In MQR mode
// SonarQube deprecates the top-level severity and the UI reports impacts[], so
// impacts[] wins whenever present; pre-MQR servers fall back to the legacy field.
// The legacy→MQR relationship is per-rule, not a constant offset, so the legacy
// value can never be relabelled into the MQR axis after the fact.
func selectSeverity(issue Issue) (severity, source string) {
	if imp, ok := maxImpact(issue.Impacts); ok {
		return imp.Severity, severitySourceMQR
	}
	return issue.Severity, severitySourceLegacy
}

// severityToImpactScore converts a severity to an HDF impact using the scale that
// belongs to its axis — the two axes share labels (BLOCKER) but not meaning.
func severityToImpactScore(severity, source string) float64 {
	if source == severitySourceMQR {
		return hdfutil.SeverityToImpactWithAliases(severity, mqrAliases, 0.5)
	}
	return hdfutil.SeverityToImpactWithAliases(severity, sonarqubeAliases, 0.5)
}

// defaultNistTag is the fallback NIST control for SonarQube findings without
// CWE mappings. SA-11 (Developer Security Testing and Evaluation) applies to
// all SonarQube issue types — security findings without CWEs are rare, and
// SonarQube is fundamentally a static analysis tool. Matches heimdall2.
const defaultNistTag = "SA-11"

// sonarTimestampFormat matches the SonarQube API date format "2006-01-02T15:04:05+0000".
// SonarQube omits the colon in the timezone offset, so time.RFC3339 does not parse it.
const sonarTimestampFormat = "2006-01-02T15:04:05-0700"

// ConvertSonarqubeToHDF converts SonarQube issues JSON to HDF format
func ConvertSonarqubeToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("sonarqube: empty input")
	}
	if err := shared.ValidateJSONSize(input, "sonarqube", 0); err != nil {
		return nil, fmt.Errorf("sonarqube: %w", err)
	}

	// Calculate checksum of source scan data
	resultsChecksum := shared.InputChecksum(input)

	var sonarData IssuesResponse
	if err := json.Unmarshal(input, &sonarData); err != nil {
		return nil, fmt.Errorf("invalid SonarQube JSON: %w", err)
	}

	if sonarData.Issues == nil {
		return nil, fmt.Errorf("invalid SonarQube structure: missing or invalid issues field")
	}

	// Create lookup maps for components and rules
	componentMap := make(map[string]Component)
	for _, component := range sonarData.Components {
		componentMap[component.Key] = component
	}

	ruleMap := make(map[string]Rule)
	for _, rule := range sonarData.Rules {
		ruleMap[rule.Key] = rule
	}

	// Group issues by project
	limitedIssues := shared.LimitSliceWithWarning(sonarData.Issues, 0, "issue")
	issuesByProject := make(map[string][]Issue)
	for _, issue := range limitedIssues {
		projectKey := issue.Project
		issuesByProject[projectKey] = append(issuesByProject[projectKey], issue)
	}

	// Sorted project keys keep baselines and targets in a stable order across runs.
	projectKeys := make([]string, 0, len(issuesByProject))
	for projectKey := range issuesByProject {
		projectKeys = append(projectKeys, projectKey)
	}
	sort.Strings(projectKeys)

	// Convert each project to a baseline
	baselines := make([]hdf.EvaluatedBaseline, 0, len(issuesByProject))
	targets := make([]hdf.Component, 0, len(issuesByProject))
	for _, projectKey := range projectKeys {
		baseline := convertProjectToBaseline(projectKey, issuesByProject[projectKey], componentMap, ruleMap, resultsChecksum)
		baselines = append(baselines, baseline)
		targets = append(targets, hdf.Component{
			Name: projectKey,
			Type: hdf.Application,
		})
	}

	if len(baselines) == 0 {
		targetName := deriveEmptyScanTarget(sonarData.Components)
		title := fmt.Sprintf("SonarQube Analysis for %s", targetName)
		baselines = []hdf.EvaluatedBaseline{{
			Name:  targetName,
			Title: &title,
			Requirements: []hdf.EvaluatedRequirement{
				shared.BuildNoFindingsRequirement(
					"sonarqube-no-findings",
					fmt.Sprintf("SonarQube scanned %s and reported zero findings.", targetName),
					time.Now().UTC(),
				),
			},
			ResultsChecksum: resultsChecksum,
		}}
		targets = []hdf.Component{{
			Name: targetName,
			Type: hdf.Application,
		}}
	}

	// Build HDF
	timestamp := time.Now().UTC()

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "sonarqube-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "SonarQube",
		ToolVersion:      sonarData.ServerVersion,
		Baselines:        baselines,
		Components:       targets,
		Timestamp:        &timestamp,
	}), nil
}

func deriveEmptyScanTarget(components []Component) string {
	for _, c := range components {
		if c.Qualifier == "TRK" {
			return c.Key
		}
	}
	for _, c := range components {
		return c.Key
	}
	return "the SonarQube project"
}

func convertProjectToBaseline(
	projectKey string,
	issues []Issue,
	componentMap map[string]Component,
	ruleMap map[string]Rule,
	resultsChecksum *hdf.Checksum,
) hdf.EvaluatedBaseline {
	// Group issues by rule
	issuesByRule := make(map[string][]Issue)
	for _, issue := range issues {
		ruleKey := issue.Rule
		issuesByRule[ruleKey] = append(issuesByRule[ruleKey], issue)
	}

	// Convert each rule to a requirement. Iterate rule keys in sorted order —
	// ranging a map directly would emit requirements in a random order each run.
	ruleKeys := make([]string, 0, len(issuesByRule))
	for ruleKey := range issuesByRule {
		ruleKeys = append(ruleKeys, ruleKey)
	}
	sort.Strings(ruleKeys)

	requirements := make([]hdf.EvaluatedRequirement, 0, len(issuesByRule))
	for _, ruleKey := range ruleKeys {
		requirement := convertRuleToRequirement(ruleKey, issuesByRule[ruleKey], componentMap, ruleMap)
		requirements = append(requirements, requirement)
	}

	return hdf.EvaluatedBaseline{
		Name:            projectKey,
		Title:           hdfutil.Ptr(fmt.Sprintf("SonarQube Analysis for %s", projectKey)),
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}
}

func convertRuleToRequirement(
	ruleKey string,
	issues []Issue,
	componentMap map[string]Component,
	ruleMap map[string]Rule,
) hdf.EvaluatedRequirement {
	rule, hasRule := ruleMap[ruleKey]

	// Extract rule name and description
	title := ruleKey
	if hasRule {
		title = rule.Name
	}
	description := extractDescription(&rule, hasRule)

	// Severity is a property of the rule, so the first issue speaks for the group.
	firstIssue := issues[0]
	severity, severitySource := selectSeverity(firstIssue)
	impact := severityToImpactScore(severity, severitySource)

	// Extract tags and mappings
	cweIds, owaspTags, allTags := extractTags(&rule, hasRule, issues)
	nistControls := shared.MapCWEToNIST(cweIds, []string{defaultNistTag})
	cciControls := cci.NISTToCCI(nistControls)

	// Create results for each issue
	results := make([]hdf.RequirementResult, 0, len(issues))
	for _, issue := range issues {
		result := createResultFromIssue(issue, componentMap)
		results = append(results, result)
	}

	// Get source location from first issue with a line number
	var sourceLocation *hdf.SourceLocation
	for _, issue := range issues {
		if issue.Line != nil {
			sourceLocation = extractSourceLocation(issue, componentMap)
			break
		}
	}

	// Create descriptions
	descriptions := []hdf.Description{
		{
			Data:  description,
			Label: "default",
		},
	}

	// Build tags
	tags := make(map[string]interface{})
	tags["severity"] = strings.ToLower(severity)
	tags["severitySource"] = severitySource
	tags["type"] = strings.ToLower(firstIssue.Type)
	tags["cwe"] = cweIds
	tags["owasp"] = owaspTags
	tags["nist"] = nistControls
	tags["cci"] = cciControls
	// Per-issue metadata SonarQube carries on every mode. Omitted when empty so
	// the golden stays clean rather than pinning "".
	if firstIssue.Effort != "" {
		tags["effort"] = firstIssue.Effort
	}
	if firstIssue.Debt != "" {
		tags["debt"] = firstIssue.Debt
	}
	if firstIssue.Author != "" {
		tags["author"] = firstIssue.Author
	}
	// Language is a property of the rule, not the issue.
	if hasRule {
		if rule.Lang != "" {
			tags["lang"] = rule.Lang
		}
		if rule.LangName != "" {
			tags["langName"] = rule.LangName
		}
	}
	// Keep both axes available in MQR mode so consumers can select. In legacy
	// mode tags.severity already is the legacy axis, so repeating it adds nothing.
	if severitySource == severitySourceMQR {
		tags["legacySeverity"] = strings.ToLower(firstIssue.Severity)
		tags["impacts"] = firstIssue.Impacts
		if firstIssue.CleanCodeAttribute != "" {
			tags["cleanCodeAttribute"] = firstIssue.CleanCodeAttribute
		}
		if firstIssue.CleanCodeAttributeCategory != "" {
			tags["cleanCodeAttributeCategory"] = firstIssue.CleanCodeAttributeCategory
		}
	}
	for k, v := range allTags {
		tags[k] = v
	}

	req := hdf.EvaluatedRequirement{
		ID:                 ruleKey,
		Title:              &title,
		Descriptions:       descriptions,
		Impact:             impact,
		Results:            results,
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nistControls),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	if sourceLocation != nil {
		req.SourceLocation = sourceLocation
	}

	return req
}

func extractDescription(rule *Rule, hasRule bool) string {
	if !hasRule || rule == nil {
		return ""
	}

	// Prefer markdown description
	if rule.MDDesc != "" {
		return rule.MDDesc
	}

	// Strip HTML tags for plain text description
	if rule.HTMLDesc != "" {
		return hdfutil.StripHTML(rule.HTMLDesc)
	}

	// Fall back to descriptionSections (SonarQube 26+ format)
	if len(rule.DescriptionSections) > 0 {
		// Prefer root_cause section (closest to the old monolithic description)
		for _, section := range rule.DescriptionSections {
			if section.Key == "root_cause" {
				return hdfutil.StripHTML(section.Content)
			}
		}
		// If no root_cause, concatenate all sections
		var parts []string
		for _, section := range rule.DescriptionSections {
			stripped := hdfutil.StripHTML(section.Content)
			if stripped != "" {
				parts = append(parts, stripped)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n\n")
		}
	}

	return rule.Name
}

func extractTags(rule *Rule, hasRule bool, issues []Issue) ([]string, []string, map[string][]string) {
	cweSet := make(map[string]bool)
	owaspSet := make(map[string]bool)
	allTagsMap := make(map[string]map[string]bool)

	// Extract from rule tags
	if hasRule && rule != nil {
		ruleTags := make([]string, 0, len(rule.Tags)+len(rule.SysTags))
		ruleTags = append(ruleTags, rule.Tags...)
		ruleTags = append(ruleTags, rule.SysTags...)

		for _, tag := range ruleTags {
			lowerTag := strings.ToLower(tag)

			// Check for CWE tags
			if strings.HasPrefix(lowerTag, "cwe-") || strings.Contains(lowerTag, "cwe") {
				if match := hdfutil.CWEPattern.FindStringSubmatch(tag); match != nil {
					cweSet[fmt.Sprintf("CWE-%s", match[1])] = true
				}
			}

			// Check for OWASP tags
			if strings.Contains(lowerTag, "owasp") {
				owaspSet[tag] = true
			}

			// Collect other tags by category
			parts := strings.Split(tag, ":")
			if len(parts) == 2 {
				category := parts[0]
				value := parts[1]
				if allTagsMap[category] == nil {
					allTagsMap[category] = make(map[string]bool)
				}
				allTagsMap[category][value] = true
			}
		}
	}

	// Extract from issue tags
	for _, issue := range issues {
		for _, tag := range issue.Tags {
			lowerTag := strings.ToLower(tag)

			if strings.HasPrefix(lowerTag, "cwe-") {
				if match := hdfutil.CWEPattern.FindStringSubmatch(tag); match != nil {
					cweSet[fmt.Sprintf("CWE-%s", match[1])] = true
				}
			}

			if strings.Contains(lowerTag, "owasp") {
				owaspSet[tag] = true
			}
		}
	}

	// Parse CWE from rule description (htmlDesc / mdDesc)
	if hasRule && rule != nil {
		desc := rule.HTMLDesc + rule.MDDesc
		matches := hdfutil.CWEPattern.FindAllStringSubmatch(desc, -1)
		for _, match := range matches {
			cweSet[fmt.Sprintf("CWE-%s", match[1])] = true
		}
	}

	// Parse CWE from descriptionSections (SonarQube 26+ format)
	if hasRule && rule != nil {
		for _, section := range rule.DescriptionSections {
			matches := hdfutil.CWEPattern.FindAllStringSubmatch(section.Content, -1)
			for _, match := range matches {
				cweSet[fmt.Sprintf("CWE-%s", match[1])] = true
			}
		}
	}

	// Convert sets to sorted slices
	cweIds := make([]string, 0, len(cweSet))
	for cweID := range cweSet {
		cweIds = append(cweIds, cweID)
	}
	sort.Strings(cweIds)

	owaspTags := make([]string, 0, len(owaspSet))
	for owasp := range owaspSet {
		owaspTags = append(owaspTags, owasp)
	}
	sort.Strings(owaspTags)

	allTags := make(map[string][]string)
	for category, values := range allTagsMap {
		valueSlice := make([]string, 0, len(values))
		for value := range values {
			valueSlice = append(valueSlice, value)
		}
		sort.Strings(valueSlice)
		allTags[category] = valueSlice
	}

	return cweIds, owaspTags, allTags
}

func createResultFromIssue(issue Issue, componentMap map[string]Component) hdf.RequirementResult {
	status := hdf.Failed
	if issue.Status == "RESOLVED" || issue.Status == "CLOSED" {
		status = hdf.Passed
	}

	component, hasComponent := componentMap[issue.Component]
	componentPath := issue.Component
	if hasComponent {
		if component.Path != "" {
			componentPath = component.Path
		} else if component.LongName != "" {
			componentPath = component.LongName
		}
	}

	codeDesc := componentPath
	if issue.Line != nil {
		codeDesc = fmt.Sprintf("%s LINE : %d", componentPath, *issue.Line)
	}

	creationTime, _ := time.Parse(sonarTimestampFormat, issue.CreationDate)
	creationTime = hdfutil.NormalizeTimestamp(creationTime)

	return hdf.RequirementResult{
		Status:    status,
		Message:   &issue.Message,
		CodeDesc:  codeDesc,
		StartTime: creationTime,
		Backtrace: []string{},
	}
}

func extractSourceLocation(issue Issue, componentMap map[string]Component) *hdf.SourceLocation {
	if issue.Line == nil {
		return nil
	}

	component, hasComponent := componentMap[issue.Component]
	ref := issue.Component
	if hasComponent {
		if component.Path != "" {
			ref = component.Path
		} else {
			ref = component.Key
		}
	}

	lineFloat := float64(*issue.Line)

	return &hdf.SourceLocation{
		Ref:  &ref,
		Line: &lineFloat,
	}
}
