package sonarqube

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-schema"
)

// SonarQube /api/issues/search response structure
type IssuesResponse struct {
	Total      int          `json:"total"`
	Page       int          `json:"p"`
	PageSize   int          `json:"ps"`
	Paging     Paging       `json:"paging"`
	Issues     []Issue      `json:"issues"`
	Components []Component  `json:"components,omitempty"`
	Rules      []Rule       `json:"rules,omitempty"`
}

type Paging struct {
	PageIndex int `json:"pageIndex"`
	PageSize  int `json:"pageSize"`
	Total     int `json:"total"`
}

type Issue struct {
	Key          string     `json:"key"`
	Rule         string     `json:"rule"`
	Severity     string     `json:"severity"`
	Component    string     `json:"component"`
	Project      string     `json:"project"`
	Line         *int       `json:"line,omitempty"`
	Hash         string     `json:"hash,omitempty"`
	TextRange    *TextRange `json:"textRange,omitempty"`
	Flows        []Flow     `json:"flows,omitempty"`
	Status       string     `json:"status"`
	Message      string     `json:"message"`
	Effort       string     `json:"effort,omitempty"`
	Debt         string     `json:"debt,omitempty"`
	Author       string     `json:"author,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	CreationDate string     `json:"creationDate"`
	UpdateDate   string     `json:"updateDate"`
	Type         string     `json:"type"`
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
	Key      string   `json:"key"`
	Name     string   `json:"name"`
	Status   string   `json:"status,omitempty"`
	Lang     string   `json:"lang,omitempty"`
	LangName string   `json:"langName,omitempty"`
	HTMLDesc string   `json:"htmlDesc,omitempty"`
	MDDesc   string   `json:"mdDesc,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Type     string   `json:"type,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	SysTags  []string `json:"sysTags,omitempty"`
	Scope    string   `json:"scope,omitempty"`
}

var severityImpactMapping = map[string]float64{
	"BLOCKER":  1.0,
	"CRITICAL": 0.9,
	"MAJOR":    0.7,
	"MINOR":    0.5,
	"INFO":     0.3,
}

const defaultCodeQualityNistTag = "SA-11"
const defaultSecurityNistTag = "SI-10"

// ConvertSonarqubeToHDF converts SonarQube issues JSON to HDF format
func ConvertSonarqubeToHDF(input []byte) ([]byte, error) {
	// Calculate checksum of source scan data
	hash := sha256.Sum256(input)
	resultsChecksum := &hdf.Checksum{
		Algorithm: hdf.Sha256,
		Value:     hex.EncodeToString(hash[:]),
	}

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
	issuesByProject := make(map[string][]Issue)
	for _, issue := range sonarData.Issues {
		projectKey := issue.Project
		issuesByProject[projectKey] = append(issuesByProject[projectKey], issue)
	}

	// Convert each project to a baseline
	baselines := make([]hdf.EvaluatedBaseline, 0, len(issuesByProject))
	for projectKey, issues := range issuesByProject {
		baseline := convertProjectToBaseline(projectKey, issues, componentMap, ruleMap, resultsChecksum)
		baselines = append(baselines, baseline)
	}

	// Build HDF
	timestamp := time.Now()
	hdfResult := hdf.HDFResults{
		Timestamp: &timestamp,
		Baselines: baselines,
		Targets:   []hdf.Target{},
		Generator: &hdf.Generator{
			Name:    "sonarqube-to-hdf",
			Version: "1.0.0",
		},
	}

	output, err := json.MarshalIndent(hdfResult, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HDF JSON: %w", err)
	}

	return output, nil
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

	// Convert each rule to a requirement
	requirements := make([]hdf.EvaluatedRequirement, 0, len(issuesByRule))
	for ruleKey, ruleIssues := range issuesByRule {
		requirement := convertRuleToRequirement(ruleKey, ruleIssues, componentMap, ruleMap)
		requirements = append(requirements, requirement)
	}

	return hdf.EvaluatedBaseline{
		Name:            projectKey,
		Title:           stringPtr(fmt.Sprintf("SonarQube Analysis for %s", projectKey)),
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

	// Get impact from first issue
	firstIssue := issues[0]
	impact, ok := severityImpactMapping[firstIssue.Severity]
	if !ok {
		impact = 0.5
	}

	// Extract tags and mappings
	cweIds, owaspTags, allTags := extractTags(&rule, hasRule, issues)
	nistControls := mapToNist(cweIds, owaspTags, firstIssue.Type)
	cciControls := mapNistToCCI(nistControls)

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
	tags["severity"] = strings.ToLower(firstIssue.Severity)
	tags["type"] = strings.ToLower(firstIssue.Type)
	tags["cwe"] = cweIds
	tags["owasp"] = owaspTags
	tags["nist"] = nistControls
	tags["cci"] = cciControls
	for k, v := range allTags {
		tags[k] = v
	}

	req := hdf.EvaluatedRequirement{
		ID:             ruleKey,
		Title:          &title,
		Descriptions:   descriptions,
		Impact:         impact,
		Results:        results,
		Tags:           tags,
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
		re := regexp.MustCompile(`<[^>]*>`)
		stripped := re.ReplaceAllString(rule.HTMLDesc, " ")
		re = regexp.MustCompile(`\s+`)
		return strings.TrimSpace(re.ReplaceAllString(stripped, " "))
	}

	return rule.Name
}

func extractTags(rule *Rule, hasRule bool, issues []Issue) ([]string, []string, map[string][]string) {
	cweSet := make(map[string]bool)
	owaspSet := make(map[string]bool)
	allTagsMap := make(map[string]map[string]bool)

	// Extract from rule tags
	if hasRule && rule != nil {
		ruleTags := append(rule.Tags, rule.SysTags...)

		for _, tag := range ruleTags {
			lowerTag := strings.ToLower(tag)

			// Check for CWE tags
			if strings.HasPrefix(lowerTag, "cwe-") || strings.Contains(lowerTag, "cwe") {
				cwePattern := regexp.MustCompile(`(?i)cwe[- ]?(\d+)`)
				if match := cwePattern.FindStringSubmatch(tag); match != nil {
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
				cwePattern := regexp.MustCompile(`(?i)cwe[- ]?(\d+)`)
				if match := cwePattern.FindStringSubmatch(tag); match != nil {
					cweSet[fmt.Sprintf("CWE-%s", match[1])] = true
				}
			}

			if strings.Contains(lowerTag, "owasp") {
				owaspSet[tag] = true
			}
		}
	}

	// Parse CWE from rule description
	if hasRule && rule != nil {
		desc := rule.HTMLDesc + rule.MDDesc
		cwePattern := regexp.MustCompile(`(?i)CWE[- ]?(\d+)`)
		matches := cwePattern.FindAllStringSubmatch(desc, -1)
		for _, match := range matches {
			cweSet[fmt.Sprintf("CWE-%s", match[1])] = true
		}
	}

	// Convert sets to sorted slices
	cweIds := make([]string, 0, len(cweSet))
	for cwe := range cweSet {
		cweIds = append(cweIds, cwe)
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

func mapToNist(cweIds []string, owaspTags []string, issueType string) []string {
	nistSet := make(map[string]bool)

	// Map CWE to NIST (simplified - in real implementation, use CWE→NIST mapping table)
	for _, cweId := range cweIds {
		// Extract numeric part
		numStr := strings.TrimPrefix(cweId, "CWE-")
		if num, err := strconv.Atoi(numStr); err == nil {
			// Simplified mapping - real implementation should use hdf-mappings
			if nist := getCweNistMapping(num); nist != "" {
				nistSet[nist] = true
			}
		}
	}

	// If no NIST mappings found, use default based on issue type
	if len(nistSet) == 0 {
		if issueType == "VULNERABILITY" || issueType == "SECURITY_HOTSPOT" {
			return []string{defaultSecurityNistTag}
		}
		return []string{defaultCodeQualityNistTag}
	}

	// Convert to sorted slice
	nistControls := make([]string, 0, len(nistSet))
	for nist := range nistSet {
		nistControls = append(nistControls, nist)
	}
	sort.Strings(nistControls)

	return nistControls
}

// Simplified CWE to NIST mapping - should use hdf-mappings in production
func getCweNistMapping(cweNum int) string {
	mappings := map[int]string{
		20:  "SI-10", // Improper Input Validation
		79:  "SI-10", // XSS
		89:  "SI-10", // SQL Injection
		119: "SI-16", // Buffer overflow
		120: "SI-16", // Buffer Copy without Checking Size
		190: "SI-10", // Integer Overflow
		200: "SC-28", // Information Exposure
		284: "AC-3",  // Improper Access Control
		287: "IA-2",  // Improper Authentication
		311: "SC-13", // Missing Encryption
		352: "SC-23", // CSRF
		476: "SI-11", // NULL Pointer Dereference
		502: "SI-10", // Deserialization of Untrusted Data
		787: "SI-16", // Out-of-bounds Write
	}

	if nist, ok := mappings[cweNum]; ok {
		return nist
	}
	return ""
}

func mapNistToCCI(nistControls []string) []string {
	// Simplified CCI mapping - should use hdf-mappings in production
	cciSet := make(map[string]bool)

	for _, nist := range nistControls {
		// Simple mapping for common controls
		switch nist {
		case "SI-10":
			cciSet["CCI-001310"] = true
		case "AC-3":
			cciSet["CCI-000213"] = true
		case "IA-2":
			cciSet["CCI-000764"] = true
		case "SC-13":
			cciSet["CCI-002450"] = true
		}
	}

	cciControls := make([]string, 0, len(cciSet))
	for cci := range cciSet {
		cciControls = append(cciControls, cci)
	}
	sort.Strings(cciControls)

	return cciControls
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

	creationTime, _ := time.Parse(time.RFC3339, issue.CreationDate)

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

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func floatPtr(f float64) *float64 {
	return &f
}
