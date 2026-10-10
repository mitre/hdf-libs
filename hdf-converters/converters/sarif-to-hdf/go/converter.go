package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
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
	Tool *SarifTool `json:"tool"`
	// Pointer, not a plain slice: a plain slice decodes null and [] alike, and
	// §3.14.23 gives them opposite meanings — nothing was analyzed, versus a scan
	// that ran and found nothing.
	Results *[]SarifResult `json:"results"`
	// RawResults is the same array left unparsed, so rawSourceRecord can carry a
	// result's every property rather than only the ones SarifResult declares.
	// Parallel to Results; json.Unmarshal fills both from the same input.
	RawResults *[]json.RawMessage `json:"-"`
	Taxonomies []SarifTaxonomy    `json:"taxonomies,omitempty"`
}

// UnmarshalJSON decodes a run twice: once into the typed shape the converter maps
// from, and once leaving results unparsed so rawSourceRecord can carry a result's
// every property. Without the second pass a record would be re-marshalled from
// SarifResult and silently lose every SARIF field this converter does not declare.
func (r *SarifRun) UnmarshalJSON(data []byte) error {
	// alias drops the methods, so unmarshalling it does not recurse into this one.
	type alias SarifRun
	var typed alias
	if err := json.Unmarshal(data, &typed); err != nil {
		return err
	}
	*r = SarifRun(typed)

	var probe struct {
		Results *[]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	r.RawResults = probe.Results
	return nil
}

// analyzed reports whether the run carries a result set at all. False means absent
// or null — the tool did not analyze; true with an empty slice means it ran and
// found nothing.
func (r SarifRun) analyzed() bool { return r.Results != nil }

// rawList is resultList's unparsed twin; indices line up with resultList.
func (r SarifRun) rawList() []json.RawMessage {
	if r.RawResults == nil {
		return nil
	}
	return *r.RawResults
}

// resultList is the run's results, empty when it did not analyze.
func (r SarifRun) resultList() []SarifResult {
	if r.Results == nil {
		return nil
	}
	return *r.Results
}

// SarifTool wraps the driver and any extensions. Rules may be defined on either:
// modern CodeQL leaves tool.driver.rules empty and puts every rule on an
// extension, so a driver-only reader resolves none of them.
type SarifTool struct {
	Driver     *SarifDriver  `json:"driver"`
	Extensions []SarifDriver `json:"extensions,omitempty"`
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

// LevelNone is SARIF's "severity does not apply" level (§3.27.10), distinct from an
// absent level, which defaults to warning.
const LevelNone = "none"

// Where a requirement's impact came from, recorded in tags so a consumer can tell a
// vendor convention from a spec field from a fallback.
const (
	severitySourceSecuritySeverity = "security-severity"
	severitySourceResultLevel      = "result-level"
	severitySourceRuleDefault      = "rule-default"
	severitySourceFallback         = "fallback"
)

// --- Impact mapping ---
// SARIF uses "error"/"warning"/"note" levels, not standard severity labels. These are
// used as aliases; unknown levels fall through to 0.0 and are then bumped to 0.1 at
// the call site. An explicit "none" is exempt from that floor, because §3.27.10 means
// severity genuinely does not apply. This table is the FALLBACK — a rule carrying a
// usable security-severity outranks it; see securitySeverityImpact.
//
// SARIF 2.2 (committee draft) renames that property to securitySeverity on a 0-100
// scale rather than 0-10; nothing here reads that key, so a 2.2 producer falls back to
// the level mapping.

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
	resultsChecksum := shared.InputChecksum(input)

	sarif, err := parseSarif(input, inputVersion...)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now()

	limitedRuns := shared.LimitSliceWithWarning(sarif.Runs, 0, "run")
	baselines := make([]hdf.EvaluatedBaseline, 0, len(limitedRuns))

	for runIdx, run := range limitedRuns {
		baseline := convertRun(runIdx, run, sarif.Version, timestamp, resultsChecksum)
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

func convertRun(runIdx int, run SarifRun, version string, timestamp time.Time, resultsChecksum *hdf.Checksum) hdf.EvaluatedBaseline {
	// Build rule lookup by ID
	ruleMap := buildRuleMap(run)

	groupOrder, groupMap := groupResults(run, ruleMap)

	requirements := make([]hdf.EvaluatedRequirement, 0, len(groupOrder))
	for _, ruleID := range groupOrder {
		g := groupMap[ruleID]
		req := convertResultGroup(runIdx, g.ruleID, g.rule, g.results, g.indices, g.raws, timestamp)
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
			synthesizeEmptyRunRequirement(run, timestamp),
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

// HDF requires requirements.minItems=1, so a run contributing no requirements
// still needs one. Which placeholder depends on whether the tool analyzed at
// all: §3.14.23 distinguishes an absent or null results array, which analyzed
// nothing, from [], which ran and found nothing. ID/target derive from
// run.tool.driver.name so downstream converters that delegate to SARIF can
// identify and override the placeholder.
func synthesizeEmptyRunRequirement(run SarifRun, timestamp time.Time) hdf.EvaluatedRequirement {
	target := "SARIF analyzer"
	idPrefix := "sarif"
	if run.Tool != nil && run.Tool.Driver != nil && run.Tool.Driver.Name != "" {
		target = run.Tool.Driver.Name
		idPrefix = run.Tool.Driver.Name
	}
	if !run.analyzed() {
		return shared.BuildNotAnalyzedRequirement(
			idPrefix+"-not-analyzed",
			fmt.Sprintf("%s reported no result set; the run did not analyze.", target),
			timestamp,
		)
	}
	return shared.BuildNoFindingsRequirement(
		idPrefix+"-no-findings",
		fmt.Sprintf("%s ran and reported zero findings.", target),
		timestamp,
	)
}

// buildRuleMap indexes every rule a run defines, from the driver and from any
// extensions. Extensions are seeded first so the driver overwrites them: SARIF
// permits the same rule id on both, the driver is the primary tool component, and
// an extension must never silently shadow the tool's own definition. Seeding in a
// fixed order also keeps the outcome independent of map iteration order.
func buildRuleMap(run SarifRun) map[string]ReportingDescriptor {
	ruleMap := make(map[string]ReportingDescriptor)
	if run.Tool == nil {
		return ruleMap
	}
	for _, ext := range run.Tool.Extensions {
		for _, rule := range ext.Rules {
			ruleMap[rule.ID] = rule
		}
	}
	if run.Tool.Driver != nil {
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

func convertResultGroup(runIdx int, ruleID string, rule *ReportingDescriptor, sarifResults []SarifResult, sourceIndices []int, raws []json.RawMessage, timestamp time.Time) hdf.EvaluatedRequirement {
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

	// Determine requirement-level impact from the rule group's resolved level.
	ruleLevel, severitySource := resolveRuleLevel(rule, sarifResults)
	// security-severity is a GitHub Code Scanning convention, NOT a SARIF one: the
	// string appears nowhere in the OASIS 2.1.0 specification or its schema. It
	// currently OUTRANKS level because it is a 0-10 score rather than one of four
	// buckets, so it carries severity spread that level cannot, and it is how the
	// scanners emitting it expect to be read. Whether a vendor convention should
	// outrank a spec field is an open question recorded on this converter's card.
	impact, fromSecuritySeverity := securitySeverityImpact(rule)
	if fromSecuritySeverity {
		severitySource = severitySourceSecuritySeverity
	} else {
		impact = hdfutil.SeverityToImpactWithAliases(ruleLevel, sarifAliases, 0.0)
	}
	// Impact 0 is floored so an unrecognized level does not read as "not
	// applicable", which is what the effective-status ladder makes of it. An
	// explicit "none" is exempt: §3.27.10 means severity genuinely does not apply
	// there, so 0 is the honest value rather than an absent mapping.
	if impact == 0 && ruleLevel != LevelNone {
		impact = 0.1
	}
	// severity is a schema field consumers read directly, so the converter records
	// the band it already knows rather than leaving every consumer to re-derive it.
	// (The threshold engine is not one of them — it falls back to impact when
	// severity is absent — so this changes what is published, not what gates.)
	severity := hdf.Severity(hdfutil.ImpactToSeverity(impact))

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

	// Convert each SARIF result into RequirementResult(s), and give every one the
	// native record it came from. §3.27.12 says the locations array is not a list of
	// distinct occurrences, yet one HDF result per location is what a consumer can
	// act on, so the expansion stays and the source cardinality is published instead
	// (see the sarif-source-result-count tag below). All results expanded from one
	// SARIF result share its record and its pointer, because they share its source.
	var results []hdf.RequirementResult
	perResult := make([]map[string]interface{}, 0, len(sarifResults))
	for i, sr := range sarifResults {
		expanded := convertSarifResultToHDFResults(sr, rule, timestamp)
		srcIdx := i
		if i < len(sourceIndices) {
			srcIdx = sourceIndices[i]
		}
		var record *hdf.RawSourceRecord
		if i < len(raws) && raws[i] != nil {
			record = rawSourceRecordFor(raws[i], runIdx, srcIdx)
		}
		for j := range expanded {
			expanded[j].RawSourceRecord = record
			perResult = append(perResult, perResultTagEntry(sr))
		}
		results = append(results, expanded...)
	}

	// Title, descriptions, sourceLocation, code and fixes are deliberately derived
	// from the FIRST result and are a requirement-level SUMMARY, not a per-result
	// record. HDF scopes these to the requirement — one thing being checked, with a
	// name, a description and a place it is defined — while SARIF scopes them to each
	// finding. Synthesizing a merged title or concatenating every snippet would
	// invent a requirement no tool reported. The per-result detail is not lost: each
	// HDF result carries its own rawSourceRecord, so a consumer that wants the second
	// result's own message, location or snippet reads it there.
	// Build descriptions from rule metadata and first result
	descriptions := buildDescriptions(description, rule, firstResult)

	// Aggregate every suppression across the grouped results so the suppressions
	// tag is a lossless record (the tag is requirement-level; a group can hold
	// suppressed and unsuppressed results).
	var allSuppressions []Suppression
	for _, sr := range sarifResults {
		allSuppressions = append(allSuppressions, sr.Suppressions...)
	}

	// Build tags — rule-level severity, the full group suppression record, and the
	// per-result entries that carry what a requirement-level summary cannot.
	tags := buildTags(firstResult, rule, ruleLevel, severitySource, cweIds, nistControls, cciControls, allSuppressions)
	tags["sarif-results"] = perResult
	tags["sarif-source-result-count"] = len(sarifResults)
	// An aggregate kind is published only when the group agrees on one. Taking the
	// first result's kind made a group holding a pass and a fail report just one.
	if k, uniform := uniformKind(sarifResults); uniform {
		tags["kind"] = k
	} else {
		delete(tags, "kind")
	}

	req := hdf.EvaluatedRequirement{
		ID:                 ruleID,
		Title:              &title,
		Descriptions:       descriptions,
		Impact:             impact,
		Severity:           &severity,
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

// decimalScore matches the plain decimal forms a CVSS score is written in. It
// exists to keep Go and TypeScript agreeing on what parses: strconv.ParseFloat
// accepts Go's hex-float literals ("0x1p3") while JavaScript's Number() accepts
// "0x8" and "0b101", so each language would otherwise take a value the other
// rejects. Neither form is a CVSS score, so both languages reject both.
var decimalScore = regexp.MustCompile(`^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$`)

// securitySeverityImpact reads the rule's security-severity property — a GitHub Code
// Scanning convention for carrying a CVSS base score, absent from the OASIS SARIF
// 2.1.0 specification and its schema — and scales it to an HDF impact. Reports false when the property is absent
// or is not a finite score within 0.0-10.0, so the caller falls back to the level
// mapping rather than deriving an impact from an unusable value. Producers emit
// the score as a string; a JSON number is accepted too.
func securitySeverityImpact(rule *ReportingDescriptor) (float64, bool) {
	if rule == nil {
		return 0, false
	}
	raw, ok := rule.Properties["security-severity"]
	if !ok {
		return 0, false
	}
	var score float64
	switch v := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if !decimalScore.MatchString(trimmed) {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		score = parsed
	case float64:
		score = v
	default:
		return 0, false
	}
	// score <= 0, not < 0: GitHub documents 0.0 and out-of-range values alike as
	// carrying no security severity, so both fall through to the level mapping.
	if math.IsNaN(score) || math.IsInf(score, 0) || score <= 0 || score > 10 {
		return 0, false
	}
	return hdfutil.RoundImpact(score / 10), true
}

// levelRank orders the SARIF level enum by severity so a rule group reports its
// worst member. "none" is outside the order: §3.27.10 defines it as severity not
// applying, so it never competes with a real level.
var levelRank = map[string]int{"note": 1, "warning": 2, "error": 3}

// isFailing reports whether a result represents a failure. §3.27.9 defaults an absent
// kind to "fail", so an omitted kind is a failure.
func isFailing(r SarifResult) bool { return r.Kind == "" || r.Kind == "fail" }

// resolveRuleLevel determines a rule group's level and where it came from.
//
// §3.27.10 resolves a level only for a result whose kind is "fail" (§3.27.9 defaults
// an absent kind to "fail"), in the order: the result's own level, then
// invocation.ruleConfigurationOverrides, then rule.defaultConfiguration.level, then
// "warning". The override branch is deliberately not implemented — it needs
// run.invocations and result.provenance, neither of which is parsed yet.
//
// Only a failing result's level is ranked, and a "none" is never ranked at all.
// §3.27.10 defines "none" as "the concept of severity does not apply to this result
// because the kind property has a value other than fail", and §3.27.9 requires that
// any level other than "none" accompany kind "fail". So "none" is not a severity a
// producer can assert about a failure: on a conformant document it appears only on a
// non-failing result, where it is the spec-mandated value and carries no information
// beyond "severity does not apply". A "none" on a failing result contradicts the
// spec's own definition, so it is ignored rather than honoured — honouring it would
// put a reported FAILURE at impact 0, which the effective-status ladder reads as
// notApplicable, dropping a real finding out of the compliance denominator.
//
// A group's level is its WORST failing member, not its first. SARIF scopes severity
// to the result; HDF scopes it to the requirement, and a result says only that a
// requirement of that severity is in some state. That difference is deliberate on
// both sides, so the per-result level is summarized onto the requirement rather than
// HDF's model being bent to mirror SARIF's. Worst-wins is the only summary that
// cannot under-report: taking the first would let a note listed ahead of an error
// present the whole group as a note.
func resolveRuleLevel(rule *ReportingDescriptor, results []SarifResult) (string, string) {
	worst, found, sawNone := "", false, false
	for _, r := range results {
		if r.Level == LevelNone {
			// Only meaningful on a non-failing result, which is the conformant case.
			if !isFailing(r) {
				sawNone = true
			}
			continue
		}
		if r.Level == "" || !isFailing(r) {
			continue
		}
		if !found || levelRank[r.Level] > levelRank[worst] {
			worst, found = r.Level, true
		}
	}
	switch {
	case found:
		return worst, severitySourceResultLevel
	case rule != nil && rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "":
		return rule.DefaultConfiguration.Level, severitySourceRuleDefault
	case sawNone:
		return LevelNone, severitySourceResultLevel
	default:
		return "warning", severitySourceFallback
	}
}

// rawSourceRecordFor carries one SARIF result verbatim on the HDF result(s) it
// produced. ADR-0017 scoped this to the result deliberately: records merged onto the
// requirement collide, and merging entries that share an id has to discard one, which
// is exactly how the non-first result's metadata used to be lost. Encoding is utf-8
// rather than base64 because a SARIF result is JSON and therefore valid UTF-8 text;
// base64 would inflate it by a third and make it unreadable for no gain.
func rawSourceRecordFor(raw json.RawMessage, runIdx, resultIdx int) *hdf.RawSourceRecord {
	// Re-marshalled from the UNTYPED result, not from SarifResult: marshalling the
	// struct would emit only the fields it declares, silently dropping every SARIF
	// property this converter does not model — the opposite of a verbatim record.
	// Keys come out sorted because Go sorts map keys, and the TypeScript peer sorts
	// to match, so the two languages agree byte for byte. Original key order and
	// whitespace are therefore not preserved; the content is complete, not byte-exact.
	var untyped interface{}
	if err := json.Unmarshal(raw, &untyped); err != nil {
		return nil
	}
	// exportmap's canonical encoder, not json.Marshal: Go HTML-escapes <, > and & by
	// default while JavaScript's JSON.stringify does not, so a record holding a C
	// snippet with an ampersand would differ byte for byte between the two languages.
	// It also escapes U+2028/U+2029 and normalizes negative zero, which are the other
	// three places the two disagree.
	encoded, err := exportmap.EncodeLine(untyped)
	if err != nil {
		return nil
	}
	content := bytes.TrimRight(encoded, "\n")
	pointer := fmt.Sprintf("/runs/%d/results/%d", runIdx, resultIdx)
	return &hdf.RawSourceRecord{
		Content:   string(content),
		Encoding:  hdf.UTF8,
		MediaType: "application/json",
		Pointer:   &pointer,
	}
}

// perResultTagEntry is the queryable half of per-result carriage. rawSourceRecord
// holds the whole record but as an opaque string, so nothing can filter on what is
// inside it; fingerprints exist for cross-run correlation, which needs them
// addressable. Only fields a requirement-level summary cannot represent go here.
func perResultTagEntry(result SarifResult) map[string]interface{} {
	entry := map[string]interface{}{}
	// The EFFECTIVE kind: §3.27.9 defaults an absent kind to "fail". This is a new
	// key, so applying the default here invents no history; tags["kind"] stays
	// verbatim for the same reason.
	if result.Kind != "" {
		entry["kind"] = result.Kind
	} else {
		entry["kind"] = "fail"
	}
	if result.Level != "" {
		entry["level"] = result.Level
	}
	if len(result.Fingerprints) > 0 {
		entry["fingerprints"] = result.Fingerprints
	}
	if len(result.PartialFingerprints) > 0 {
		entry["partialFingerprints"] = result.PartialFingerprints
	}
	return entry
}

// uniformKind reports the kind every result in the group STATED, and false when they
// disagree or when any of them omitted it. Deliberately not defaulting an absent kind
// to "fail" here, even though §3.27.9 does: tags["kind"] carries what the tool wrote,
// the way tags["sarif-level"] carries the level verbatim, so publishing a spec-derived
// value under the same key would silently change what the tag means. The effective
// kind, with the §3.27.9 default applied, is in the per-result entries instead.
func uniformKind(results []SarifResult) (string, bool) {
	kind := ""
	for i, r := range results {
		if r.Kind == "" {
			return "", false
		}
		if i == 0 {
			kind = r.Kind
			continue
		}
		if r.Kind != kind {
			return "", false
		}
	}
	return kind, kind != ""
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

// acceptedSuppressions returns the suppressions in force: status "accepted" or
// absent — SARIF 2.1.0 treats a suppression without status as effective, and
// real producers (CodeQL, semgrep) commonly emit only {"kind": ...}. underReview
// and rejected suppressions are NOT overrides — an underReview decision is not
// final and a rejected one was declined.
func acceptedSuppressions(suppressions []Suppression) []Suppression {
	var out []Suppression
	for _, s := range suppressions {
		if s.Status == "accepted" || s.Status == "" {
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
		ExpiresAt: shared.DefaultOverrideExpiry(timestamp),
	}
	return override, effective, true
}

// rollupStatus returns the worst status in the set per the canonical worst-wins
// ordering (hdfutil.StatusSeverityOrder) — the requirement-level status.
func rollupStatus(statuses []hdf.ResultStatus) hdf.ResultStatus {
	strs := make([]string, len(statuses))
	for i, s := range statuses {
		strs[i] = string(s)
	}
	return hdf.ResultStatus(hdfutil.WorstStatus(strs))
}

// governingDisposition is the type of the override that explains the
// requirement's effective status: the one asserting that status, else the
// governing (most recently applied non-expired) one.
//
// It previously scanned for an override whose status matched the effective
// rollup and fell back to overrides[0]. That missed entirely when the governing
// override carried only an impact — the canonical riskAdjustment shape, which
// sets no status — and the fallback read array position as recency, which it is
// not: nothing sorts these and this repo's writers append.
func governingDisposition(overrides []hdf.StatusOverride, effective hdf.ResultStatus) hdf.OverrideType {
	// Every override this converter creates carries the same appliedAt (the run
	// timestamp), so recency cannot tell them apart — but they may differ in type
	// (waiver vs falsePositive) and in the status they assert. The override whose
	// status produced the rollup is the one that explains it, so that match stays
	// the primary rule here. Recency is only the tie-break beneath it.
	for _, ov := range overrides {
		if ov.Status != nil && *ov.Status == effective {
			return ov.Type
		}
	}
	// No override asserts the effective status — the governing one carries only an
	// impact, say. Fall back to the shared rule rather than to array position.
	if o := shared.GoverningOverride(overrides, time.Time{}); o != nil {
		return o.Type
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

func buildTags(result SarifResult, rule *ReportingDescriptor, resolvedLevel, severitySource string, cweIds, nistControls, cciControls []string, allSuppressions []Suppression) map[string]interface{} {
	tags := make(map[string]interface{})

	// The SARIF level verbatim. Not "severity": impact may derive from GitHub's
	// security-severity instead, so one name would carry two different values.
	tags["sarif-level"] = resolvedLevel
	tags["sarif-severity-source"] = severitySource
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

// parseSarif applies the converter's input guards, normalizes SARIF 2.0 to
// 2.1, and decodes. ConvertSarifToHDF and ExpectedRequirementCount share it so
// they accept and reject exactly the same inputs.
func parseSarif(input []byte, inputVersion ...string) (*SarifFile, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("sarif: empty input")
	}
	if err := shared.ValidateJSONSize(input, "sarif", 0); err != nil {
		return nil, fmt.Errorf("sarif: %w", err)
	}
	effectiveVersion := ""
	if len(inputVersion) > 0 && inputVersion[0] != "" {
		effectiveVersion = inputVersion[0]
	}
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
	return &sarif, nil
}

// resultGroup is one requirement's worth of SARIF results: every result that
// shares a ruleId (or, when ruleId is absent, the same message text).
type resultGroup struct {
	ruleID string
	rule   *ReportingDescriptor
	// results and indices are parallel: indices[i] is results[i]'s position in
	// run.results, which rawSourceRecord.pointer needs to address the source record.
	results []SarifResult
	indices []int
	raws    []json.RawMessage
}

// groupResults groups a run's results into requirements, in first-seen order.
// It is the single definition of the input-to-requirement relation: the
// conversion builds requirements from it and ExpectedRequirementCount counts it.
func groupResults(run SarifRun, ruleMap map[string]ReportingDescriptor) ([]string, map[string]*resultGroup) {
	limitedResults := shared.LimitSliceWithWarning(run.resultList(), 0, "result")
	groupOrder := []string{}
	groupMap := make(map[string]*resultGroup)
	rawResults := run.rawList()
	for srcIdx, result := range limitedResults {
		groupKey := result.RuleID
		if groupKey == "" {
			groupKey = resolveMessageText(result.Message, nil)
		}
		g, exists := groupMap[groupKey]
		if !exists {
			g = &resultGroup{ruleID: groupKey, rule: lookupRule(ruleMap, result)}
			groupMap[groupKey] = g
			groupOrder = append(groupOrder, groupKey)
		}
		g.results = append(g.results, result)
		g.indices = append(g.indices, srcIdx)
		if srcIdx < len(rawResults) {
			g.raws = append(g.raws, rawResults[srcIdx])
		} else {
			g.raws = append(g.raws, nil)
		}
	}
	return groupOrder, groupMap
}

// ExpectedRequirementCount states how many requirements the input must convert
// to: one per distinct rule in each run (message text standing in for a
// missing ruleId), and one no-findings requirement for a run with no results.
// Computed from the input alone, through the same grouping the conversion uses.
func ExpectedRequirementCount(input []byte, inputVersion ...string) (int, string, error) {
	const unit = "distinct SARIF rules"
	sarif, err := parseSarif(input, inputVersion...)
	if err != nil {
		return 0, unit, err
	}
	count := 0
	for _, run := range shared.LimitSliceWithWarning(sarif.Runs, 0, "run") {
		order, _ := groupResults(run, buildRuleMap(run))
		if len(order) == 0 {
			count++
			continue
		}
		count += len(order)
	}
	return count, unit, nil
}
