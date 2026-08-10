package sarif

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// --- SARIF 2.1.0 struct definitions ---

// SarifFile is the top-level SARIF log object.
type SarifFile struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

// SarifRun represents a single analysis run.
type SarifRun struct {
	Tool       *SarifTool      `json:"tool"`
	Results    []SarifResult   `json:"results"`
	Taxonomies []SarifTaxonomy `json:"taxonomies,omitempty"`
}

// SarifTool wraps the driver (and optional extensions).
type SarifTool struct {
	Driver *SarifDriver `json:"driver"`
}

// SarifDriver describes the analysis tool.
type SarifDriver struct {
	Name           string                `json:"name"`
	Version        string                `json:"version"`
	InformationURI string                `json:"informationUri"`
	Rules          []ReportingDescriptor `json:"rules,omitempty"`
}

// ReportingDescriptor is a rule or taxonomy entry definition.
type ReportingDescriptor struct {
	ID                   string                        `json:"id"`
	Name                 string                        `json:"name,omitempty"`
	ShortDescription     *MultiformatMessage           `json:"shortDescription,omitempty"`
	FullDescription      *MultiformatMessage           `json:"fullDescription,omitempty"`
	HelpURI              string                        `json:"helpUri,omitempty"`
	Help                 *MultiformatMessage           `json:"help,omitempty"`
	DefaultConfiguration *ReportingConfiguration       `json:"defaultConfiguration,omitempty"`
	Relationships        []ReportingDescriptorRelation `json:"relationships,omitempty"`
	Properties           map[string]interface{}        `json:"properties,omitempty"`
	MessageStrings       map[string]MultiformatMessage `json:"messageStrings,omitempty"`
}

// MultiformatMessage carries text and optional markdown.
type MultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// ReportingConfiguration holds default severity for a rule.
type ReportingConfiguration struct {
	Level string `json:"level,omitempty"` // error, warning, note, none
}

// ReportingDescriptorRelation links a rule to a taxonomy entry.
type ReportingDescriptorRelation struct {
	Target DescriptorReference `json:"target"`
	Kinds  []string            `json:"kinds,omitempty"`
}

// DescriptorReference identifies a rule or taxon in a tool component.
type DescriptorReference struct {
	ID            string                  `json:"id"`
	GUID          string                  `json:"guid,omitempty"`
	ToolComponent *ToolComponentReference `json:"toolComponent,omitempty"`
}

// ToolComponentReference names a tool component (e.g. "CWE").
type ToolComponentReference struct {
	Name string `json:"name"`
	GUID string `json:"guid,omitempty"`
}

// SarifTaxonomy declares a taxonomy such as CWE.
type SarifTaxonomy struct {
	Name         string                `json:"name"`
	Version      string                `json:"version,omitempty"`
	Organization string                `json:"organization,omitempty"`
	Taxa         []ReportingDescriptor `json:"taxa,omitempty"`
}

// SarifResult is a single finding.
type SarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex,omitempty"`
	Kind                string            `json:"kind,omitempty"`
	Level               string            `json:"level,omitempty"`
	Message             SarifMessage      `json:"message"`
	Locations           []SarifLocation   `json:"locations,omitempty"`
	RelatedLocations    []SarifLocation   `json:"relatedLocations,omitempty"`
	Suppressions        []Suppression     `json:"suppressions,omitempty"`
	Fixes               []Fix             `json:"fixes,omitempty"`
	CodeFlows           []CodeFlow        `json:"codeFlows,omitempty"`
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	// Properties is the SCA-SARIF property bag that carries package
	// identity for SCA-class results (Grype, Trivy, Dependency-Check).
	// SAST results leave this empty.
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SarifMessage carries the human-readable message.
type SarifMessage struct {
	Text      string   `json:"text,omitempty"`
	ID        string   `json:"id,omitempty"`
	Arguments []string `json:"arguments,omitempty"`
}

// Suppression records a suppression on a result.
type Suppression struct {
	Kind          string `json:"kind"`             // "inSource" or "external"
	Status        string `json:"status,omitempty"` // "accepted", "underReview", "rejected"
	Justification string `json:"justification,omitempty"`
}

// Fix describes a proposed remediation.
type Fix struct {
	Description SarifMessage `json:"description,omitempty"`
}

// CodeFlow traces data flow through a program.
type CodeFlow struct {
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

// ThreadFlow is a sequence of code locations forming a trace.
type ThreadFlow struct {
	Locations []ThreadFlowLocation `json:"locations"`
}

// ThreadFlowLocation is a single step in a thread flow.
type ThreadFlowLocation struct {
	Location   SarifLocation `json:"location"`
	Importance string        `json:"importance,omitempty"`
}

// SarifLocation describes a location in source code.
type SarifLocation struct {
	ID               *int              `json:"id,omitempty"`
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *SarifMessage     `json:"message,omitempty"`
}

// PhysicalLocation points to a file and region.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation"`
	Region           *Region           `json:"region"`
}

// ArtifactLocation identifies a file.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region identifies a span within a file.
type Region struct {
	StartLine   int              `json:"startLine"`
	StartColumn int              `json:"startColumn"`
	EndLine     int              `json:"endLine,omitempty"`
	EndColumn   int              `json:"endColumn,omitempty"`
	Snippet     *ArtifactContent `json:"snippet,omitempty"`
}

// ArtifactContent holds inline text content.
type ArtifactContent struct {
	Text string `json:"text"`
}

// --- Impact mapping ---
// SARIF uses "error"/"warning"/"note" levels, not standard severity labels.
// These are used as aliases; unknown levels fall through to 0.0 (then bumped
// to 0.1 at the call site).

var sarifAliases = map[string]float64{
	"error":   0.7,
	"warning": 0.5,
	"note":    0.3,
}

// --- Conversion entry point ---

// ConvertSarifToHDF converts SARIF JSON to HDF format.
// ConvertSarifToHDF converts SARIF input to HDF Results.
// The optional inputVersion parameter specifies the SARIF schema version
// (e.g. "2.0.0", "2.1.0"). When omitted or empty, the version is read from
// the input's "version" field. SARIF 2.0 input is normalized to 2.1 structure
// before processing.
func ConvertSarifToHDF(input []byte, converterVersion string, inputVersion ...string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("sarif: empty input")
	}
	if err := shared.ValidateJSONSize(input, "sarif", 0); err != nil {
		return nil, fmt.Errorf("sarif: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	// Determine effective input version from parameter or input
	effectiveVersion := ""
	if len(inputVersion) > 0 && inputVersion[0] != "" {
		effectiveVersion = inputVersion[0]
	}

	// Normalize SARIF 2.0 → 2.1 structure if needed
	normalized, err := normalizeSarifVersion(input, effectiveVersion)
	if err != nil {
		return nil, err
	}

	var sarif SarifFile
	if err := json.Unmarshal(normalized, &sarif); err != nil {
		return nil, fmt.Errorf("invalid SARIF JSON: %w", err)
	}

	if len(sarif.Runs) == 0 {
		return nil, fmt.Errorf("invalid SARIF structure: missing or empty runs field")
	}

	timestamp := time.Now()

	limitedRuns := shared.LimitSliceWithWarning(sarif.Runs, 0, "run")
	baselines := make([]hdf.EvaluatedBaseline, 0, len(limitedRuns))

	for _, run := range limitedRuns {
		baseline := convertRun(run, sarif.Version, timestamp, resultsChecksum)
		baselines = append(baselines, baseline)
	}

	toolName := ""
	toolVersion := ""
	if len(sarif.Runs) > 0 && sarif.Runs[0].Tool != nil && sarif.Runs[0].Tool.Driver != nil {
		driver := sarif.Runs[0].Tool.Driver
		toolName = driver.Name
		toolVersion = driver.Version
	}

	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "sarif-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         toolName,
		ToolVersion:      toolVersion,
		ToolFormat:       "SARIF",
		Baselines:        baselines,
		Components:       []hdf.Component{},
		Timestamp:        &timestamp,
	})

	return hdfResult, nil
}

// normalizeSarifVersion handles structural differences between SARIF versions.
// SARIF 2.0 uses "resources.rules" instead of "tool.driver.rules"; this function
// rewrites 2.0 structure to 2.1 layout so the converter logic can be unified.
// If the version is not 2.0 or if the input already has 2.1 structure, the
// input is returned unchanged.
func normalizeSarifVersion(input []byte, explicitVersion string) ([]byte, error) {
	// Quick check: only normalize if version indicates 2.0
	if !isSarif20(input, explicitVersion) {
		return input, nil
	}

	// Parse into a generic map for structural rewriting
	var doc map[string]any
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("invalid SARIF JSON: %w", err)
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		return input, nil
	}

	modified := false
	for _, runRaw := range runs {
		run, ok := runRaw.(map[string]any)
		if !ok {
			continue
		}

		// SARIF 2.0: "resources" → { "rules": [...] }
		// SARIF 2.1: "tool" → { "driver": { "rules": [...] } }
		resources, hasResources := run["resources"].(map[string]any)
		if !hasResources {
			continue
		}

		rules, hasRules := resources["rules"]
		if !hasRules {
			continue
		}

		// Move resources.rules → tool.driver.rules (only if tool.driver exists
		// and doesn't already have rules)
		tool, _ := run["tool"].(map[string]any)
		if tool == nil {
			continue
		}
		driver, _ := tool["driver"].(map[string]any)
		if driver == nil {
			continue
		}
		if _, alreadyHasRules := driver["rules"]; !alreadyHasRules {
			driver["rules"] = rules
			modified = true
		}

		// Clean up the resources field
		delete(run, "resources")
	}

	// Update version to 2.1.0 so downstream code doesn't re-normalize
	if modified {
		doc["version"] = "2.1.0"
		return json.Marshal(doc)
	}

	return input, nil
}

// isSarif20 checks if the input is SARIF 2.0 based on the explicit version
// parameter or the version field in the document. When an explicit version is
// provided, it takes precedence over the document's version field.
func isSarif20(input []byte, explicitVersion string) bool {
	if explicitVersion != "" {
		return strings.HasPrefix(explicitVersion, "2.0")
	}
	// No explicit version — check the document's version field
	var peek struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(input, &peek); err != nil {
		return false
	}
	return strings.HasPrefix(peek.Version, "2.0")
}

// --- Run-level conversion ---

func convertRun(run SarifRun, version string, timestamp time.Time, resultsChecksum *hdf.Checksum) hdf.EvaluatedBaseline {
	// Build rule lookup by ID
	ruleMap := buildRuleMap(run)

	// Group SARIF results by ruleId — each group becomes one EvaluatedRequirement.
	// When ruleId is absent, fall back to message text as the grouping key.
	type resultGroup struct {
		ruleID  string
		rule    *ReportingDescriptor
		results []SarifResult
	}
	limitedResults := shared.LimitSliceWithWarning(run.Results, 0, "result")
	groupOrder := []string{}
	groupMap := make(map[string]*resultGroup)
	for _, result := range limitedResults {
		groupKey := result.RuleID
		if groupKey == "" {
			groupKey = resolveMessageText(result.Message, nil)
		}
		g, exists := groupMap[groupKey]
		if !exists {
			rule := lookupRule(ruleMap, result)
			g = &resultGroup{ruleID: groupKey, rule: rule}
			groupMap[groupKey] = g
			groupOrder = append(groupOrder, groupKey)
		}
		g.results = append(g.results, result)
	}

	requirements := make([]hdf.EvaluatedRequirement, 0, len(groupOrder))
	for _, ruleID := range groupOrder {
		g := groupMap[ruleID]
		req := convertResultGroup(g.ruleID, g.rule, g.results, timestamp)
		requirements = append(requirements, req)
	}

	// Use tool name for baseline name if available
	baselineName := "SARIF"
	var maintainer *string
	if run.Tool != nil && run.Tool.Driver != nil {
		if run.Tool.Driver.Name != "" {
			baselineName = run.Tool.Driver.Name
		}
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			synthesizeNoFindingsRequirement(run, timestamp),
		}
	}

	return hdf.EvaluatedBaseline{
		Name:            baselineName,
		Version:         &version,
		Title:           hdfutil.Ptr("Static Analysis Results Interchange Format"),
		Maintainer:      maintainer,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}
}

// HDF requires requirements.minItems=1; per SARIF v2.1.0 §3.7.2 an empty
// results array means the analyzer ran clean, so emit one passed placeholder
// per run-baseline. ID/target derive from run.tool.driver.name so downstream
// converters that delegate to SARIF (msft-defender-devops, etc.) can identify
// and override the placeholder when needed.
func synthesizeNoFindingsRequirement(run SarifRun, timestamp time.Time) hdf.EvaluatedRequirement {
	target := "SARIF analyzer"
	idPrefix := "sarif"
	if run.Tool != nil && run.Tool.Driver != nil && run.Tool.Driver.Name != "" {
		target = run.Tool.Driver.Name
		idPrefix = run.Tool.Driver.Name
	}
	return shared.BuildNoFindingsRequirement(
		idPrefix+"-no-findings",
		fmt.Sprintf("%s ran and reported zero findings.", target),
		timestamp,
	)
}

func buildRuleMap(run SarifRun) map[string]ReportingDescriptor {
	ruleMap := make(map[string]ReportingDescriptor)
	if run.Tool != nil && run.Tool.Driver != nil {
		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = rule
		}
	}
	return ruleMap
}

func lookupRule(ruleMap map[string]ReportingDescriptor, result SarifResult) *ReportingDescriptor {
	if rule, ok := ruleMap[result.RuleID]; ok {
		return &rule
	}
	return nil
}

// --- Result-group conversion (one EvaluatedRequirement per ruleId) ---

func convertResultGroup(ruleID string, rule *ReportingDescriptor, sarifResults []SarifResult, timestamp time.Time) hdf.EvaluatedRequirement {
	// Derive requirement-level metadata from the rule and first result
	firstResult := sarifResults[0]
	title, description := deriveMetadata(firstResult, rule)

	// Extract CWE IDs from rule (or first result message as fallback)
	cweIds := extractCweFromRule(rule)
	if len(cweIds) == 0 {
		cweIds = extractCweIds(resolveMessageText(firstResult.Message, rule))
	}

	nistControls := shared.MapCWEToNIST(cweIds, shared.DefaultStaticAnalysisNIST)
	cciControls := cci.NISTToCCI(nistControls)

	// Determine requirement-level impact from the rule's inherent severity.
	// Use the rule's defaultConfiguration.level, falling back to the first result's level,
	// then to the SARIF default "warning".
	ruleLevel := resolveRuleLevel(rule, sarifResults)
	impact := hdfutil.SeverityToImpactWithAliases(ruleLevel, sarifAliases, 0.0)
	if impact == 0 {
		impact = 0.1
	}

	// Source location from first result's first location
	var sourceLocationPtr *hdf.SourceLocation
	if len(firstResult.Locations) > 0 {
		sourceLocation := extractSourceLocation(firstResult.Locations[0])
		if sourceLocation.Ref != nil || sourceLocation.Line != nil {
			sourceLocationPtr = &sourceLocation
		}
	}

	// requirement.code = raw source snippet (region.snippet.text) so Heimdall's
	// CODE tab is populated. Only set when a primary location carries a snippet —
	// never fabricated.
	var codePtr *string
	for _, loc := range firstResult.Locations {
		if snippet := extractSnippet(loc); snippet != "" {
			codePtr = &snippet
			break
		}
	}

	// Convert each SARIF result into RequirementResult(s)
	var results []hdf.RequirementResult
	for _, sr := range sarifResults {
		results = append(results, convertSarifResultToHDFResults(sr, rule, timestamp)...)
	}

	// Build descriptions from rule metadata and first result
	descriptions := buildDescriptions(description, rule, firstResult)

	// Aggregate every suppression across the grouped results so the suppressions
	// tag is a lossless record (the tag is requirement-level; a group can hold
	// suppressed and unsuppressed results).
	var allSuppressions []Suppression
	for _, sr := range sarifResults {
		allSuppressions = append(allSuppressions, sr.Suppressions...)
	}

	// Build tags — rule-level severity, fingerprints from first result, and the
	// full group suppression record.
	tags := buildTags(firstResult, rule, ruleLevel, cweIds, nistControls, cciControls, allSuppressions)

	req := hdf.EvaluatedRequirement{
		ID:                 ruleID,
		Title:              &title,
		Descriptions:       descriptions,
		Impact:             impact,
		Tags:               tags,
		Results:            results,
		Code:               codePtr,
		SourceLocation:     sourceLocationPtr,
		ControlType:        shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	// SCA-shaped SARIF carries package identity in result.properties.
	// Pure SAST results leave properties empty → no affectedPackage.
	seen := map[string]bool{}
	var packages []hdf.AffectedPackage
	for _, sr := range sarifResults {
		pkg := packageFromSarifProperties(sr.Properties)
		if pkg == nil {
			continue
		}
		var key string
		switch {
		case pkg.Purl != nil:
			key = "purl:" + *pkg.Purl
		case pkg.Cpe != nil:
			key = "cpe:" + *pkg.Cpe
		default:
			n, v := "", ""
			if pkg.Name != nil {
				n = *pkg.Name
			}
			if pkg.Version != nil {
				v = *pkg.Version
			}
			key = "nv:" + n + "@" + v
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, *pkg)
	}
	if len(packages) > 0 {
		req.AffectedPackages = packages
	}

	// Reconstruct structured status overrides from accepted suppressions. Each
	// accepted suppression across the grouped results becomes an attributed,
	// expiring override; effectiveStatus/disposition are set only when the
	// overrides actually change the requirement's rolled-up status (an unsuppressed
	// sibling failure keeps the requirement effectively failed).
	var overrides []hdf.StatusOverride
	rawStatuses := make([]hdf.ResultStatus, 0, len(sarifResults))
	effStatuses := make([]hdf.ResultStatus, 0, len(sarifResults))
	for _, sr := range sarifResults {
		raw := mapKindToStatus(sr.Kind)
		rawStatuses = append(rawStatuses, raw)
		if raw == hdf.Failed || raw == hdf.Passed {
			if ov, eff, ok := buildSuppressionOverride(sr, timestamp); ok {
				overrides = append(overrides, ov)
				effStatuses = append(effStatuses, eff)
				continue
			}
		}
		effStatuses = append(effStatuses, raw)
	}
	if len(overrides) > 0 {
		req.StatusOverrides = overrides
		if eff, rawRoll := rollupStatus(effStatuses), rollupStatus(rawStatuses); eff != rawRoll {
			req.EffectiveStatus = &eff
			disp := governingDisposition(overrides, eff)
			req.Disposition = &disp
		}
	}
	return req
}

// packageFromSarifProperties extracts an Affected_Package from a SARIF
// result.properties bag. Returns nil for SAST results that lack any
// package identity.
func packageFromSarifProperties(props map[string]interface{}) *hdf.AffectedPackage {
	if props == nil {
		return nil
	}
	str := func(k string) string {
		if v, ok := props[k].(string); ok {
			return v
		}
		return ""
	}
	name := str("packageName")
	if name == "" {
		name = str("name")
	}
	version := str("packageVersion")
	if version == "" {
		version = str("version")
	}
	purl := str("purl")
	cpe := str("cpe")
	fixed := str("fixedInVersion")
	ecoStr := str("ecosystem")

	var ecosystem hdf.Ecosystem
	switch {
	case purl != "":
		if parsed := hdfutil.ParsePurl(purl); parsed != nil {
			ecosystem = shared.EcosystemFromPurlType(parsed.Type)
		} else {
			ecosystem = hdf.Generic
		}
	case ecoStr != "":
		ecosystem = shared.EcosystemFromPurlType(ecoStr)
	case name != "" && version != "":
		ecosystem = hdf.Generic
	}
	return shared.BuildAffectedPackage(shared.AffectedPackageOptions{
		Name:           name,
		Version:        version,
		Ecosystem:      ecosystem,
		Purl:           purl,
		CPE:            cpe,
		FixedInVersion: fixed,
	})
}

// resolveRuleLevel determines the inherent severity level for a rule, independent of
// per-result kind overrides. Priority: rule.defaultConfiguration.level > first fail-kind
// result's level > SARIF default "warning".
func resolveRuleLevel(rule *ReportingDescriptor, results []SarifResult) string {
	if rule != nil && rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
		return rule.DefaultConfiguration.Level
	}
	// Find first result that represents a failure (kind="" or "fail") with an explicit level
	for _, r := range results {
		if r.Kind == "" || r.Kind == "fail" {
			if r.Level != "" {
				return r.Level
			}
		}
	}
	return "warning"
}

// convertSarifResultToHDFResults converts a single SARIF result into one or more HDF RequirementResults.
func convertSarifResultToHDFResults(result SarifResult, rule *ReportingDescriptor, timestamp time.Time) []hdf.RequirementResult {
	// Map kind to HDF status. The raw status stays the tool's — an accepted
	// suppression becomes a structured, attributed override on the requirement
	// (see convertResultGroup), not a laundered notReviewed status.
	status := mapKindToStatus(result.Kind)

	// Surface an accepted suppression's justification as an informative per-result
	// message; the requirement's Status_Override carries the authoritative record.
	suppressionJustification := ""
	if status == hdf.Failed || status == hdf.Passed {
		suppressionJustification = acceptedSuppressionReason(result.Suppressions)
	}

	// Build backtrace from code flows
	backtrace := extractBacktrace(result.CodeFlows)

	// Create results for each location
	var results []hdf.RequirementResult
	for _, loc := range result.Locations {
		if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil {
			res := createHDFResult(loc, status, timestamp, backtrace)
			results = append(results, res)
		}
	}

	// If no locations, create a location-less result so the finding isn't silently dropped
	if len(results) == 0 {
		results = append(results, hdf.RequirementResult{
			Status:    status,
			CodeDesc:  "No source location",
			StartTime: timestamp,
			Backtrace: backtrace,
		})
	}

	// Add suppression justification as message on results
	if suppressionJustification != "" {
		for i := range results {
			msg := fmt.Sprintf("Suppressed: %s", suppressionJustification)
			results[i].Message = &msg
		}
	}

	return results
}

// --- Message resolution ---

// resolveMessageText resolves a SARIF message to its text content.
// Priority: message.text > rule.messageStrings[message.id] with argument substitution.
func resolveMessageText(msg SarifMessage, rule *ReportingDescriptor) string {
	if msg.Text != "" {
		return msg.Text
	}
	if msg.ID != "" && rule != nil {
		if tmpl, ok := rule.MessageStrings[msg.ID]; ok {
			text := tmpl.Text
			for i, arg := range msg.Arguments {
				text = strings.ReplaceAll(text, fmt.Sprintf("{%d}", i), arg)
			}
			return text
		}
	}
	return ""
}

// --- Metadata derivation ---

// deriveMetadata determines title and description from rule metadata or message text.
func deriveMetadata(result SarifResult, rule *ReportingDescriptor) (string, string) {
	messageText := resolveMessageText(result.Message, rule)
	if rule != nil && rule.Name != "" {
		return rule.Name, messageText
	}
	// If rule has shortDescription, use it as title and message as description
	if rule != nil && rule.ShortDescription != nil && rule.ShortDescription.Text != "" {
		return rule.ShortDescription.Text, messageText
	}
	return parseMessage(messageText)
}

func parseMessage(text string) (string, string) {
	colonIndex := strings.Index(text, ":")
	if colonIndex == -1 {
		return text, ""
	}
	return strings.TrimSpace(text[:colonIndex]), strings.TrimSpace(text[colonIndex+1:])
}

// --- CWE extraction with priority ---

// extractCweFromRule extracts CWE IDs from rule relationships and properties.
// Returns nil if no CWEs found (caller should fall back to message regex).
func extractCweFromRule(rule *ReportingDescriptor) []string {
	if rule == nil {
		return nil
	}

	// Priority 1: rule.relationships where toolComponent.name == "CWE"
	var cweIds []string
	for _, rel := range rule.Relationships {
		if rel.Target.ToolComponent != nil && strings.EqualFold(rel.Target.ToolComponent.Name, "CWE") {
			id := rel.Target.ID
			if !strings.HasPrefix(id, "CWE-") {
				id = "CWE-" + id
			}
			cweIds = append(cweIds, id)
		}
	}
	if len(cweIds) > 0 {
		return cweIds
	}

	// Priority 2: rule.properties.tags containing CWE-\d+ patterns
	if tags, ok := rule.Properties["tags"]; ok {
		if tagSlice, ok := tags.([]interface{}); ok {
			for _, tag := range tagSlice {
				if tagStr, ok := tag.(string); ok {
					if ids := hdfutil.ExtractCWEIDs(tagStr); len(ids) > 0 {
						for _, id := range ids {
							cweIds = append(cweIds, "CWE-"+id)
						}
					}
				}
			}
		}
	}
	if len(cweIds) > 0 {
		return cweIds
	}

	return nil
}

func extractCweIds(text string) []string {
	ids := hdfutil.ExtractCWEIDs(text)
	if len(ids) == 0 {
		return []string{}
	}
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = "CWE-" + id
	}
	return result
}

// --- Kind → Status mapping ---

// mapKindToStatus maps SARIF result.kind to HDF ResultStatus.
func mapKindToStatus(kind string) hdf.ResultStatus {
	switch kind {
	case "pass":
		return hdf.Passed
	case "open":
		return hdf.Failed
	case "review":
		return hdf.NotReviewed
	case "informational":
		return hdf.NotApplicable
	case "notApplicable":
		return hdf.NotApplicable
	default: // "fail" or empty (SARIF default is "fail")
		return hdf.Failed
	}
}

// --- Suppression handling ---

// defaultSuppressionReason is the fallback Reason for an accepted suppression
// that carries no justification text (Reason is REQUIRED on a Status_Override).
const defaultSuppressionReason = "Suppressed in SARIF source"

// acceptedSuppressions returns the suppressions whose status is "accepted".
// underReview and rejected suppressions are NOT overrides — an underReview
// decision is not final and a rejected one was declined.
func acceptedSuppressions(suppressions []Suppression) []Suppression {
	var out []Suppression
	for _, s := range suppressions {
		if s.Status == "accepted" {
			out = append(out, s)
		}
	}
	return out
}

// acceptedSuppressionReason joins the justifications of a result's accepted
// suppressions, falling back to a constant when none carry text. Empty when the
// result has no accepted suppression.
func acceptedSuppressionReason(suppressions []Suppression) string {
	accepted := acceptedSuppressions(suppressions)
	if len(accepted) == 0 {
		return ""
	}
	var justifications []string
	for _, s := range accepted {
		if s.Justification != "" {
			justifications = append(justifications, s.Justification)
		}
	}
	if len(justifications) == 0 {
		return defaultSuppressionReason
	}
	return strings.Join(justifications, "; ")
}

// justificationIndicatesFalsePositive reports whether a suppression justification
// reads as a false-positive determination rather than a risk-accepted waiver.
func justificationIndicatesFalsePositive(justification string) bool {
	lower := strings.ToLower(justification)
	return strings.Contains(lower, "false positive") || strings.Contains(lower, "false-positive")
}

// buildSuppressionOverride turns a result's accepted suppression(s) into an HDF
// Status_Override. SARIF carries no owner or decision date, so appliedBy is an
// honest system identity and appliedAt is the run/conversion time (expiresAt +1yr).
// A justification that reads as a false positive maps to falsePositive →
// notApplicable (SARIF is a vuln/SAST format); otherwise a risk-accepted waiver →
// passed. Returns (override, implied effective status, true) when an accepted
// suppression exists; otherwise ok=false.
func buildSuppressionOverride(result SarifResult, timestamp time.Time) (hdf.StatusOverride, hdf.ResultStatus, bool) {
	accepted := acceptedSuppressions(result.Suppressions)
	if len(accepted) == 0 {
		return hdf.StatusOverride{}, "", false
	}
	isFalsePositive := false
	for _, s := range accepted {
		if justificationIndicatesFalsePositive(s.Justification) {
			isFalsePositive = true
			break
		}
	}
	overrideType := hdf.OverrideTypeWaiver
	effective := hdf.Passed
	if isFalsePositive {
		overrideType = hdf.FalsePositive
		effective = hdf.NotApplicable
	}
	override := hdf.StatusOverride{
		Type:      overrideType,
		Status:    &effective,
		Reason:    acceptedSuppressionReason(result.Suppressions),
		AppliedBy: hdf.Identity{Type: hdf.IdentityTypeOther, Identifier: "sarif suppression"},
		AppliedAt: timestamp,
		ExpiresAt: timestamp.AddDate(1, 0, 0),
	}
	return override, effective, true
}

// statusSeverityRank orders result statuses for requirement-level rollup
// (higher = worse). Used to decide whether accepted suppressions actually change
// the requirement's effective status.
func statusSeverityRank(s hdf.ResultStatus) int {
	switch s {
	case hdf.Failed:
		return 5
	case hdf.Error:
		return 4
	case hdf.NotReviewed:
		return 3
	case hdf.Passed:
		return 2
	case hdf.NotApplicable:
		return 1
	default:
		return 0
	}
}

// rollupStatus returns the worst status in the set — the requirement-level status.
func rollupStatus(statuses []hdf.ResultStatus) hdf.ResultStatus {
	worst := hdf.ResultStatus("")
	worstRank := -1
	for _, s := range statuses {
		if r := statusSeverityRank(s); r > worstRank {
			worstRank = r
			worst = s
		}
	}
	return worst
}

// governingDisposition picks the override type that produced the effective
// rollup status (the governing override); falls back to the first override.
func governingDisposition(overrides []hdf.StatusOverride, effective hdf.ResultStatus) hdf.OverrideType {
	for _, ov := range overrides {
		if ov.Status != nil && *ov.Status == effective {
			return ov.Type
		}
	}
	return overrides[0].Type
}

// --- Code flow → backtrace ---

func extractBacktrace(codeFlows []CodeFlow) []string {
	if len(codeFlows) == 0 {
		return []string{}
	}

	var backtrace []string
	for _, cf := range codeFlows {
		for _, tf := range cf.ThreadFlows {
			for _, tfl := range tf.Locations {
				loc := tfl.Location
				uri := ""
				line := 0
				msg := ""

				if loc.PhysicalLocation != nil {
					if loc.PhysicalLocation.ArtifactLocation != nil {
						uri = loc.PhysicalLocation.ArtifactLocation.URI
					}
					if loc.PhysicalLocation.Region != nil {
						line = loc.PhysicalLocation.Region.StartLine
					}
				}
				if loc.Message != nil {
					msg = loc.Message.Text
				}

				entry := fmt.Sprintf("%s:%d", uri, line)
				if msg != "" {
					entry = fmt.Sprintf("%s:%d - %s", uri, line, msg)
				}
				backtrace = append(backtrace, entry)
			}
		}
	}

	return backtrace
}

// --- Description building ---

func buildDescriptions(defaultDesc string, rule *ReportingDescriptor, result SarifResult) []hdf.Description {
	descriptions := []hdf.Description{
		{Label: "default", Data: defaultDesc},
	}

	if rule != nil {
		// Add rule description as enrichment
		if rule.FullDescription != nil && rule.FullDescription.Text != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: "rationale",
				Data:  rule.FullDescription.Text,
			})
		} else if rule.ShortDescription != nil && rule.ShortDescription.Text != "" && defaultDesc == "" {
			// If no default description from message, use shortDescription
			descriptions[0].Data = rule.ShortDescription.Text
		}

		// Rule help → "check" description
		if rule.Help != nil && rule.Help.Text != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: "check",
				Data:  rule.Help.Text,
			})
		}
	}

	// Fix → "fix" description
	if len(result.Fixes) > 0 && result.Fixes[0].Description.Text != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  result.Fixes[0].Description.Text,
		})
	}

	return descriptions
}

// --- Tag building ---

func buildTags(result SarifResult, rule *ReportingDescriptor, resolvedLevel string, cweIds, nistControls, cciControls []string, allSuppressions []Suppression) map[string]interface{} {
	tags := make(map[string]interface{})

	tags["severity"] = resolvedLevel
	tags["cwe"] = cweIds
	tags["nist"] = nistControls
	tags["cci"] = cciControls

	if result.Kind != "" {
		tags["kind"] = result.Kind
	}

	if rule != nil && rule.HelpURI != "" {
		tags["helpUri"] = rule.HelpURI
	}

	// Store EVERY suppression across the grouped results — accepted, underReview,
	// AND rejected — losslessly. Only accepted ones drive a statusOverride; the
	// non-accepted records must still survive here so no source data is dropped.
	if len(allSuppressions) > 0 {
		supps := make([]map[string]string, 0, len(allSuppressions))
		for _, s := range allSuppressions {
			entry := map[string]string{"kind": s.Kind}
			if s.Status != "" {
				entry["status"] = s.Status
			}
			if s.Justification != "" {
				entry["justification"] = s.Justification
			}
			supps = append(supps, entry)
		}
		tags["suppressions"] = supps
	}

	// Store fingerprints
	if len(result.Fingerprints) > 0 || len(result.PartialFingerprints) > 0 {
		fp := make(map[string]interface{})
		if len(result.Fingerprints) > 0 {
			fp["fingerprints"] = result.Fingerprints
		}
		if len(result.PartialFingerprints) > 0 {
			fp["partialFingerprints"] = result.PartialFingerprints
		}
		tags["fingerprints"] = fp
	}

	return tags
}

// --- Location helpers ---

func extractSourceLocation(location SarifLocation) hdf.SourceLocation {
	sourceLocation := hdf.SourceLocation{}

	if location.PhysicalLocation == nil || location.PhysicalLocation.ArtifactLocation == nil {
		return sourceLocation
	}

	uri := location.PhysicalLocation.ArtifactLocation.URI
	line := 0
	if location.PhysicalLocation.Region != nil {
		line = location.PhysicalLocation.Region.StartLine
	}

	if uri != "" {
		sourceLocation.Ref = &uri
	}
	if line != 0 {
		lineFloat := float64(line)
		sourceLocation.Line = &lineFloat
	}

	return sourceLocation
}

// extractSnippet returns the raw source text at a location's region, or "" when absent.
func extractSnippet(location SarifLocation) string {
	if location.PhysicalLocation != nil &&
		location.PhysicalLocation.Region != nil &&
		location.PhysicalLocation.Region.Snippet != nil {
		return location.PhysicalLocation.Region.Snippet.Text
	}
	return ""
}

func createHDFResult(location SarifLocation, status hdf.ResultStatus, timestamp time.Time, backtrace []string) hdf.RequirementResult {
	uri := ""
	line := 0
	column := 0
	snippet := ""

	if location.PhysicalLocation != nil {
		if location.PhysicalLocation.ArtifactLocation != nil {
			uri = location.PhysicalLocation.ArtifactLocation.URI
		}
		if location.PhysicalLocation.Region != nil {
			line = location.PhysicalLocation.Region.StartLine
			column = location.PhysicalLocation.Region.StartColumn
			if location.PhysicalLocation.Region.Snippet != nil {
				snippet = location.PhysicalLocation.Region.Snippet.Text
			}
		}
	}

	codeDesc := fmt.Sprintf("URL : %s LINE : %d COLUMN : %d", uri, line, column)
	if snippet != "" {
		codeDesc = fmt.Sprintf("%s\n%s", codeDesc, snippet)
	}

	return hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		StartTime: timestamp,
		Backtrace: backtrace,
	}
}
