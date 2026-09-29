package hdfengine

import (
	"fmt"
	"math"
	"time"

	"gopkg.in/yaml.v3"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// Threshold status-key constants used in the threshold spec and violation
// messages (SAF CLI-compatible keys).
const (
	ThresholdPassed   = "passed"
	ThresholdFailed   = "failed"
	ThresholdSkipped  = "skipped"
	ThresholdError    = "error"
	ThresholdNoImpact = "no_impact"
)

// legacyInformationalKey is the name the informational severity bucket had
// before 3.7.0 renamed it. Accepted on input and echoed back in violations
// written with it, never emitted by generate.
const legacyInformationalKey = "none"

// SeverityCounts holds counts broken down by severity level.
type SeverityCounts struct {
	Critical int `yaml:"critical,omitempty" json:"critical,omitempty"`
	High     int `yaml:"high,omitempty" json:"high,omitempty"`
	Medium   int `yaml:"medium,omitempty" json:"medium,omitempty"`
	Low      int `yaml:"low,omitempty" json:"low,omitempty"`
	// Informational is the schema's fifth severity. It also absorbs a severity
	// that cannot be derived or is not in the enum at all.
	Informational int `yaml:"informational,omitempty" json:"informational,omitempty"`
	Total         int `yaml:"total" json:"total"`
}

// StatusCounts holds per-status severity breakdowns.
type StatusCounts struct {
	Passed   SeverityCounts `yaml:"passed" json:"passed"`
	Failed   SeverityCounts `yaml:"failed" json:"failed"`
	Skipped  SeverityCounts `yaml:"skipped" json:"skipped"`
	Error    SeverityCounts `yaml:"error" json:"error"`
	NoImpact SeverityCounts `yaml:"no_impact" json:"no_impact"`
}

// ControlIDMapping maps a control ID to its observed status and severity.
type ControlIDMapping struct {
	ID     string
	Status string // "passed", "failed", "skipped", "error", "no_impact"
	// Severity is the counting BUCKET, not the requirement's raw severity
	// string: it is always one of "critical", "high", "medium", "low",
	// "informational", having gone through SeverityBucket. Anything else would
	// name a bucket the counts do not have, and a bound listing the control
	// would report a mismatch against the bucket that control was counted in.
	Severity string
	// Title is the requirement's title when it has one, carried so a breached
	// count bound can name its offenders the way a rule violation does. A reader
	// should not have to know which kind of bound produced a line to know whether
	// it will be readable.
	Title string
}

// ThresholdBound is a min/max/controls bound on a single count.
type ThresholdBound struct {
	Min      *int     `yaml:"min,omitempty" json:"min,omitempty"`
	Max      *int     `yaml:"max,omitempty" json:"max,omitempty"`
	Controls []string `yaml:"controls,omitempty" json:"controls,omitempty"`
}

// ThresholdSeverity holds per-severity bounds within a status category.
type ThresholdSeverity struct {
	Critical      *ThresholdBound `yaml:"critical,omitempty" json:"critical,omitempty"`
	High          *ThresholdBound `yaml:"high,omitempty" json:"high,omitempty"`
	Medium        *ThresholdBound `yaml:"medium,omitempty" json:"medium,omitempty"`
	Low           *ThresholdBound `yaml:"low,omitempty" json:"low,omitempty"`
	Informational *ThresholdBound `yaml:"informational,omitempty" json:"informational,omitempty"`
	// None is the name Informational replaced in 3.7.0, accepted so templates
	// this tool generated before the rename still parse. Resolved into
	// Informational by resolveLegacySeverity; never written.
	None  *ThresholdBound `yaml:"none,omitempty" json:"none,omitempty"`
	Total *ThresholdBound `yaml:"total,omitempty" json:"total,omitempty"`
}

// UnmarshalYAML accepts the two shapes a SAF CLI threshold file uses for a count
// bound: the object form ({min, max}) and a bare scalar. A scalar means EXACTLY
// that count — measured in SAF's own validate-threshold command, which guards the
// scalar path with `typeof !== 'object'` and then fails on inequality — so it
// expands to min == max rather than to a minimum.
//
// Four of SAF's seven published sample thresholds use the scalar form, so
// rejecting it means rejecting real SAF specs. Unknown keys inside the object
// form are still refused — by the key loop below, NOT by the decoder, whose
// KnownFields setting a custom unmarshaller does not inherit.
func (b *ThresholdBound) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		// The tag, not the destination type: node.Decode into an int accepts a
		// !!float and TRUNCATES it, so without this `total: 1.5` would become a
		// bound of 1 the author never wrote. A count is a whole number or it is a
		// mistake. (Before this method existed a float was a hard parse error, as
		// every scalar was — the truncation is a hazard this shorthand INTRODUCES,
		// not one it inherited.)
		if node.Tag != "!!int" {
			return fmt.Errorf("a bound written as a bare value must be a whole number of controls, got %q", node.Value)
		}
		var exact int
		if err := node.Decode(&exact); err != nil {
			return fmt.Errorf("a bound written as a bare value must be a whole number of controls: %w", err)
		}
		b.Min = &exact
		b.Max = &exact
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("a bound must be a whole number of controls or a min/max mapping, got a %s", nodeKindName(node.Kind))
	}

	// The keys are checked here rather than by the decoder's KnownFields setting,
	// which a custom unmarshaller does not inherit: yaml.Node.Decode carries none
	// of the parent decoder's strictness, so delegating would have accepted a typo
	// inside a bound as a bound nobody wrote.
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		switch key.Value {
		case "min", "max", "controls":
		case "<<":
			// go-yaml expands a merge key before the value reaches the struct, so
			// refusing it here would reject legitimate YAML — and a repetitive
			// threshold file is exactly where an author reaches for one.
		default:
			return fmt.Errorf("line %d: field %s is not a known bound", key.Line, key.Value)
		}
	}

	// A distinct type, not ThresholdBound, or this method would recurse.
	type bound struct {
		Min      *int     `yaml:"min,omitempty"`
		Max      *int     `yaml:"max,omitempty"`
		Controls []string `yaml:"controls,omitempty"`
	}
	var decoded bound
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	b.Min, b.Max, b.Controls = decoded.Min, decoded.Max, decoded.Controls
	return nil
}

func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.SequenceNode:
		return "list"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "value"
	case yaml.AliasNode:
		return "alias"
	case yaml.DocumentNode:
		return "document"
	default:
		return "unknown node"
	}
}

// ComplianceBound is a min/max bound on the compliance percentage.
type ComplianceBound struct {
	Min *float64 `yaml:"min,omitempty" json:"min,omitempty"`
	Max *float64 `yaml:"max,omitempty" json:"max,omitempty"`
}

// ThresholdConfig is a full threshold specification.
type ThresholdConfig struct {
	Compliance *ComplianceBound   `yaml:"compliance,omitempty" json:"compliance,omitempty"`
	Passed     *ThresholdSeverity `yaml:"passed,omitempty" json:"passed,omitempty"`
	Failed     *ThresholdSeverity `yaml:"failed,omitempty" json:"failed,omitempty"`
	Skipped    *ThresholdSeverity `yaml:"skipped,omitempty" json:"skipped,omitempty"`
	Error      *ThresholdSeverity `yaml:"error,omitempty" json:"error,omitempty"`
	NoImpact   *ThresholdSeverity `yaml:"no_impact,omitempty" json:"no_impact,omitempty"`
	// Rules are the additive half: a filter predicate plus a bound, for the
	// policies the fixed grid above cannot express. See rules.go.
	Rules []ThresholdRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// CountControlsByStatusSeverity counts a result set's requirements by their
// overall status and severity. Reads each requirement's OWN impact and raw
// result statuses by design: this is the no-override-awareness twin of
// CountControlsByStatus, which is its purpose, not an oversight.
func CountControlsByStatusSeverity(results hdf.HDFResults) *StatusCounts {
	counts := &StatusCounts{}
	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			status := overallStatus(req.Results)
			sev := DeriveSeverity(req.Impact, req.Severity)
			addCount(counts, status, sev)
		}
	}
	return counts
}

// CountControlsByStatus counts a result set's requirements by a caller-resolved
// status — the injected-resolver twin of CountControlsByStatusSeverity (which
// counts raw result statuses with no override awareness). statusOf returns each
// requirement's status in the schema vocabulary (passed/failed/notApplicable/
// notReviewed/error); an empty or unrecognized value is counted as skipped, and
// a nil resolver yields all-skipped. Callers use this to build effective-status
// rollups — e.g. compliance with and without agent-attributed overrides — without
// the engine binding to any one status convention (the same injection pattern as
// Filter's StatusOf).
func CountControlsByStatus(results hdf.HDFResults, statusOf func(hdf.EvaluatedRequirement) string) *StatusCounts {
	counts := &StatusCounts{}
	for _, baseline := range results.Baselines {
		for i := range baseline.Requirements {
			req := baseline.Requirements[i]
			status := ""
			if statusOf != nil {
				status = statusOf(req)
			}
			// Effective impact, so a governing riskAdjustment moves the
			// requirement into the band it was re-scored into. This function
			// already resolves STATUS through the injected resolver; deriving
			// severity from the raw impact counted one post-adjudication and the
			// other pre-adjudication.
			addCount(counts, hdf.ResultStatus(status), DeriveSeverity(EffectiveImpactOf(req, time.Time{}), req.Severity))
		}
	}
	return counts
}

// AgentOverrideCount counts the status overrides across a result set whose
// applied-by identity type is "agent" — the §3 detective count. Deterministic
// from_vex / system overrides (appliedBy.type == "system") are deliberately
// excluded: keeping non-judgment overrides out of the count is what makes an
// agent-attributed count a meaningful AI-scrutiny signal for auditors.
func AgentOverrideCount(results hdf.HDFResults) int {
	count := 0
	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			for _, o := range req.StatusOverrides {
				if o.AppliedBy.Type == hdf.Agent {
					count++
				}
			}
		}
	}
	return count
}

// MapControlIDs builds control ID → status/severity mappings from a result set.
func MapControlIDs(results hdf.HDFResults) []ControlIDMapping {
	var mappings []ControlIDMapping
	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			status := overallStatus(req.Results)
			sev := DeriveSeverity(req.Impact, req.Severity)
			mappings = append(mappings, ControlIDMapping{
				ID:       req.ID,
				Status:   statusToThresholdKey(status),
				Severity: SeverityBucket(sev),
				Title:    requirementTitle(req),
			})
		}
	}
	return mappings
}

// MapControlIDsByStatus builds control ID → status/severity mappings using a
// caller-resolved status — the injected-resolver twin of MapControlIDs (which
// maps raw result statuses). statusOf returns each requirement's status in the
// schema vocabulary; an empty or unrecognized value maps to skipped, and a nil
// resolver yields all-skipped. Callers use this for effective-status control
// listings (the same injection pattern as CountControlsByStatus).
func MapControlIDsByStatus(results hdf.HDFResults, statusOf func(hdf.EvaluatedRequirement) string) []ControlIDMapping {
	var mappings []ControlIDMapping
	for _, baseline := range results.Baselines {
		for i := range baseline.Requirements {
			req := baseline.Requirements[i]
			status := ""
			if statusOf != nil {
				status = statusOf(req)
			}
			mappings = append(mappings, ControlIDMapping{
				ID:     req.ID,
				Status: statusToThresholdKey(hdf.ResultStatus(status)),
				// Effective impact, matching CountControlsByStatus, so a control
				// listing and the counts it is listed alongside cannot disagree.
				Severity: SeverityBucket(DeriveSeverity(EffectiveImpactOf(req, time.Time{}), req.Severity)),
				Title:    requirementTitle(req),
			})
		}
	}
	return mappings
}

// requirementTitle is the requirement's title, or empty when it has none —
// title is optional on the schema.
func requirementTitle(req hdf.EvaluatedRequirement) string {
	if req.Title == nil {
		return ""
	}
	return *req.Title
}

// thresholdKeyToStatus is statusToThresholdKey's inverse, for reporting a
// requirement found via the control map. A finding line describes the
// REQUIREMENT, so it names the requirement's own status — which is also the only
// vocabulary `hdf query --status` accepts, so a reader can paste the value
// straight into a query. The threshold key is a bucket name and is refused there.
func thresholdKeyToStatus(key string) string {
	switch key {
	case ThresholdPassed:
		return string(hdf.Passed)
	case ThresholdFailed:
		return string(hdf.Failed)
	case ThresholdSkipped:
		return string(hdf.NotReviewed)
	case ThresholdError:
		return string(hdf.Error)
	case ThresholdNoImpact:
		return string(hdf.NotApplicable)
	default:
		return key
	}
}

// statusToThresholdKey converts a ResultStatus to the threshold key name.
func statusToThresholdKey(status hdf.ResultStatus) string {
	switch status {
	case hdf.Passed:
		return ThresholdPassed
	case hdf.Failed:
		return ThresholdFailed
	case hdf.NotReviewed:
		return ThresholdSkipped
	case hdf.Error:
		return ThresholdError
	case hdf.NotApplicable:
		return ThresholdNoImpact
	default:
		return ThresholdSkipped
	}
}

// overallStatus determines the aggregate status of a requirement from its
// individual test results. It is the canonical worst-wins roll-up, delegated to
// hdfutil.WorstStatus (error > failed > passed > notApplicable > notReviewed;
// empty → notReviewed) — no local rank switch. This folds in the former CLI
// overallStatus duplicate (supersedes hdf-libs-ixhx).
func overallStatus(results []hdf.RequirementResult) hdf.ResultStatus {
	statuses := make([]string, len(results))
	for i, r := range results {
		statuses[i] = string(r.Status)
	}
	return hdf.ResultStatus(hdfutil.WorstStatus(statuses))
}

// DeriveSeverity determines the severity string from impact and optional
// explicit severity, importing hdfutil.ImpactToSeverity for the impact-based
// mapping. Both paths yield a value from the schema's severity enum: an
// explicit informational and an impact-derived one are the same thing and must
// not land in different buckets.
func DeriveSeverity(impact float64, severity *hdf.Severity) string {
	if severity != nil {
		return string(*severity)
	}
	return hdfutil.ImpactToSeverity(impact)
}

// SeverityBucket folds a severity string into the bucket the threshold grid
// counts it in. The schema's four named levels pass through; informational and
// anything outside the enum land in informational, so a malformed severity is
// counted rather than dropped and a document still gates.
//
// It is exported because ControlIDMapping.Severity is the bucket, not the raw
// string: a caller assembling its own control map has to apply the same rule or
// its listing and its counts will disagree about where a requirement went.
func SeverityBucket(severity string) string {
	switch severity {
	case string(hdf.SeverityCritical), string(hdf.SeverityHigh), string(hdf.SeverityMedium), string(hdf.SeverityLow):
		return severity
	default:
		return string(hdf.Informational)
	}
}

// addCount increments the appropriate severity bucket for the given status.
func addCount(counts *StatusCounts, status hdf.ResultStatus, severity string) {
	var sc *SeverityCounts
	switch status {
	case hdf.Passed:
		sc = &counts.Passed
	case hdf.Failed:
		sc = &counts.Failed
	case hdf.NotReviewed:
		sc = &counts.Skipped
	case hdf.Error:
		sc = &counts.Error
	case hdf.NotApplicable:
		sc = &counts.NoImpact
	default:
		sc = &counts.Skipped
	}

	sc.Total++
	switch SeverityBucket(severity) {
	case string(hdf.SeverityCritical):
		sc.Critical++
	case string(hdf.SeverityHigh):
		sc.High++
	case string(hdf.SeverityMedium):
		sc.Medium++
	case string(hdf.SeverityLow):
		sc.Low++
	default:
		sc.Informational++
	}
}

// CalculateCompliance returns the compliance percentage, rounded to two decimals.
// compliance = passed / (passed + failed + skipped + error) * 100; notApplicable
// (no_impact) requirements are excluded.
func CalculateCompliance(counts *StatusCounts) float64 {
	relevant := counts.Passed.Total + counts.Failed.Total + counts.Skipped.Total + counts.Error.Total
	if relevant == 0 {
		return 0.0
	}
	pct := float64(counts.Passed.Total) / float64(relevant) * 100.0
	return math.Round(pct*100) / 100
}

// ValidateThresholds checks all threshold bounds against observed counts and
// compliance, returning a list of human-readable violation messages (empty when
// all pass).
func ValidateThresholds(config *ThresholdConfig, counts *StatusCounts, compliance float64, controlMap []ControlIDMapping) []string {
	violations := ViolationMessages(validateGrid(config, counts, compliance, controlMap))
	// A config carrying rules cannot be judged by the grid alone. Returning the
	// grid's verdict as though the rules were satisfied would report a passing
	// gate over policy nobody applied, so the caller is told to use Evaluate
	// rather than quietly getting half an answer.
	if config != nil && len(config.Rules) > 0 {
		violations = append(violations, ruleRefusal(len(config.Rules)))
	}
	return violations
}

// validateGrid is the status × severity half of a policy, shared by
// ValidateThresholds and Evaluate.
func validateGrid(config *ThresholdConfig, counts *StatusCounts, compliance float64, controlMap []ControlIDMapping) []Violation {
	var violations []Violation

	// Every construction path lands here, so the former name is resolved once
	// rather than in each of the file, inline and MCP callers. Resolved
	// before the compliance bounds so a refusal is reported ahead of them.
	sections := []resolvedSection{
		{name: ThresholdPassed, threshold: config.Passed, counts: &counts.Passed},
		{name: ThresholdFailed, threshold: config.Failed, counts: &counts.Failed},
		{name: ThresholdSkipped, threshold: config.Skipped, counts: &counts.Skipped},
		{name: ThresholdError, threshold: config.Error, counts: &counts.Error},
		{name: ThresholdNoImpact, threshold: config.NoImpact, counts: &counts.NoImpact},
	}
	for i := range sections {
		resolved, wroteNone, refusal := resolveLegacySeverity(sections[i].name, sections[i].threshold)
		if refusal != "" {
			violations = append(violations, Violation{Message: refusal})
		}
		sections[i].threshold = resolved
		sections[i].wroteNone = wroteNone
	}

	actualControls := make(map[string]ControlIDMapping)
	for _, m := range controlMap {
		actualControls[m.ID] = m
	}

	if config.Compliance != nil {
		// No Findings: a compliance percentage is a property of the whole
		// document, so there is no offending requirement to name.
		if config.Compliance.Min != nil && compliance < *config.Compliance.Min {
			violations = append(violations, Violation{Message: fmt.Sprintf(
				"compliance %.2f%% is below minimum %.2f%%", compliance, *config.Compliance.Min)})
		}
		if config.Compliance.Max != nil && compliance > *config.Compliance.Max {
			violations = append(violations, Violation{Message: fmt.Sprintf(
				"compliance %.2f%% exceeds maximum %.2f%%", compliance, *config.Compliance.Max)})
		}
	}

	for _, s := range sections {
		violations = append(violations, checkSeverityThreshold(s.name, s.threshold, s.counts, actualControls, s.wroteNone, controlMap)...)
	}

	return violations
}

// resolvedSection is one status category of a spec after the former severity
// name has been resolved, paired with the counts it is checked against.
type resolvedSection struct {
	name      string
	threshold *ThresholdSeverity
	counts    *SeverityCounts
	wroteNone bool
}

// resolveLegacySeverity folds a section's pre-3.7 "none" key into
// "informational", reporting whether the bound was written that way so a
// violation can name the key the author will find in their own file. A spec
// setting both is refused rather than resolved: 3.7.0 renamed the bucket, so
// the two name one thing and silently honouring one would drop a bound the
// author wrote.
//
// The caller's section is COPIED, never rewritten. Folding in place made the
// name a one-shot property of the config object: the same spec reported the
// author's key on its first validate pass and the canonical one on every pass
// after, which is the confusion naming the author's key exists to remove.
func resolveLegacySeverity(name string, ts *ThresholdSeverity) (*ThresholdSeverity, bool, string) {
	if ts == nil || ts.None == nil {
		return ts, false, ""
	}
	if ts.Informational != nil {
		return ts, false, fmt.Sprintf(
			"%s: both 'none' and 'informational' are set; 'informational' replaced 'none' in 3.7.0 and both name the same bucket", name)
	}
	resolved := *ts
	resolved.Informational = ts.None
	resolved.None = nil
	return &resolved, true, ""
}

// checkSeverityThreshold validates all severity bounds within a status category.
func checkSeverityThreshold(status string, threshold *ThresholdSeverity, actual *SeverityCounts, actualControls map[string]ControlIDMapping, wroteNone bool, controlMap []ControlIDMapping) []Violation {
	if threshold == nil {
		return nil
	}

	// The path names the key the author wrote; the comparison below keeps
	// the canonical bucket name, because informational is where the control was
	// actually counted. Reporting "expected no_impact/none" would name a bucket
	// that does not exist.
	pathLabel := func(label string) string {
		if wroteNone && label == string(hdf.Informational) {
			return legacyInformationalKey
		}
		return label
	}

	// The requirements a count bound counted, so a breached bound can name them.
	// "total" is the whole status bucket; a severity label narrows it further.
	inBucket := func(label string) []Match {
		var found []Match
		for _, m := range controlMap {
			if m.Status != status {
				continue
			}
			if label != "total" && m.Severity != label {
				continue
			}
			found = append(found, Match{ID: m.ID, Title: m.Title, Status: thresholdKeyToStatus(m.Status), Severity: m.Severity})
		}
		return found
	}

	var violations []Violation
	check := func(label string, bound *ThresholdBound, actualCount int) {
		if bound == nil {
			return
		}
		path := status + "." + pathLabel(label)
		if bound.Min != nil && actualCount < *bound.Min {
			violations = append(violations, Violation{
				Message:  fmt.Sprintf("%s: %d is below minimum %d", path, actualCount, *bound.Min),
				Findings: inBucket(label),
			})
		}
		if bound.Max != nil && actualCount > *bound.Max {
			violations = append(violations, Violation{
				Message:  fmt.Sprintf("%s: %d exceeds maximum %d", path, actualCount, *bound.Max),
				Findings: inBucket(label),
			})
		}
		for _, expectedID := range bound.Controls {
			// A controls list already names its requirement in the message, so
			// these carry no Findings: repeating the id underneath would say the
			// same thing twice.
			ac, found := actualControls[expectedID]
			if !found {
				violations = append(violations, Violation{Message: fmt.Sprintf(
					"%s: expected control %s not found in results", path, expectedID)})
			} else if ac.Status != status || ac.Severity != label {
				violations = append(violations, Violation{Message: fmt.Sprintf(
					"%s: control %s expected %s/%s but found %s/%s",
					path, expectedID, status, label, ac.Status, ac.Severity)})
			}
		}
	}

	check("critical", threshold.Critical, actual.Critical)
	check("high", threshold.High, actual.High)
	check("medium", threshold.Medium, actual.Medium)
	check("low", threshold.Low, actual.Low)
	check("informational", threshold.Informational, actual.Informational)
	check("total", threshold.Total, actual.Total)

	return violations
}
