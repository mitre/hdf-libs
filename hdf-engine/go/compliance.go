package hdfengine

import (
	"fmt"
	"math"

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

// SeverityCounts holds counts broken down by severity level.
type SeverityCounts struct {
	Critical int `yaml:"critical,omitempty" json:"critical,omitempty"`
	High     int `yaml:"high,omitempty" json:"high,omitempty"`
	Medium   int `yaml:"medium,omitempty" json:"medium,omitempty"`
	Low      int `yaml:"low,omitempty" json:"low,omitempty"`
	None     int `yaml:"none,omitempty" json:"none,omitempty"`
	Total    int `yaml:"total" json:"total"`
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
	ID       string
	Status   string // "passed", "failed", "skipped", "error", "no_impact"
	Severity string // "critical", "high", "medium", "low", "none"
}

// ThresholdBound is a min/max/controls bound on a single count.
type ThresholdBound struct {
	Min      *int     `yaml:"min,omitempty" json:"min,omitempty"`
	Max      *int     `yaml:"max,omitempty" json:"max,omitempty"`
	Controls []string `yaml:"controls,omitempty" json:"controls,omitempty"`
}

// ThresholdSeverity holds per-severity bounds within a status category.
type ThresholdSeverity struct {
	Critical *ThresholdBound `yaml:"critical,omitempty" json:"critical,omitempty"`
	High     *ThresholdBound `yaml:"high,omitempty" json:"high,omitempty"`
	Medium   *ThresholdBound `yaml:"medium,omitempty" json:"medium,omitempty"`
	Low      *ThresholdBound `yaml:"low,omitempty" json:"low,omitempty"`
	None     *ThresholdBound `yaml:"none,omitempty" json:"none,omitempty"`
	Total    *ThresholdBound `yaml:"total,omitempty" json:"total,omitempty"`
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
}

// CountControlsByStatusSeverity counts a result set's requirements by their
// overall status and severity.
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
			addCount(counts, hdf.ResultStatus(status), DeriveSeverity(req.Impact, req.Severity))
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
				Severity: sev,
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
				ID:       req.ID,
				Status:   statusToThresholdKey(hdf.ResultStatus(status)),
				Severity: DeriveSeverity(req.Impact, req.Severity),
			})
		}
	}
	return mappings
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
// mapping. Maps "informational" to "none" for SAF CLI threshold compatibility.
func DeriveSeverity(impact float64, severity *hdf.Severity) string {
	if severity != nil {
		return string(*severity)
	}
	sev := hdfutil.ImpactToSeverity(impact)
	if sev == "informational" {
		return "none"
	}
	return sev
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
	switch severity {
	case string(hdf.SeverityCritical):
		sc.Critical++
	case string(hdf.SeverityHigh):
		sc.High++
	case string(hdf.SeverityMedium):
		sc.Medium++
	case string(hdf.SeverityLow):
		sc.Low++
	default:
		sc.None++
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
	var violations []string

	actualControls := make(map[string]ControlIDMapping)
	for _, m := range controlMap {
		actualControls[m.ID] = m
	}

	if config.Compliance != nil {
		if config.Compliance.Min != nil && compliance < *config.Compliance.Min {
			violations = append(violations, fmt.Sprintf(
				"compliance %.2f%% is below minimum %.2f%%", compliance, *config.Compliance.Min))
		}
		if config.Compliance.Max != nil && compliance > *config.Compliance.Max {
			violations = append(violations, fmt.Sprintf(
				"compliance %.2f%% exceeds maximum %.2f%%", compliance, *config.Compliance.Max))
		}
	}

	violations = append(violations, checkSeverityThreshold(ThresholdPassed, config.Passed, &counts.Passed, actualControls)...)
	violations = append(violations, checkSeverityThreshold(ThresholdFailed, config.Failed, &counts.Failed, actualControls)...)
	violations = append(violations, checkSeverityThreshold(ThresholdSkipped, config.Skipped, &counts.Skipped, actualControls)...)
	violations = append(violations, checkSeverityThreshold(ThresholdError, config.Error, &counts.Error, actualControls)...)
	violations = append(violations, checkSeverityThreshold(ThresholdNoImpact, config.NoImpact, &counts.NoImpact, actualControls)...)

	return violations
}

// checkSeverityThreshold validates all severity bounds within a status category.
func checkSeverityThreshold(status string, threshold *ThresholdSeverity, actual *SeverityCounts, actualControls map[string]ControlIDMapping) []string {
	if threshold == nil {
		return nil
	}

	var violations []string
	check := func(label string, bound *ThresholdBound, actualCount int) {
		if bound == nil {
			return
		}
		path := status + "." + label
		if bound.Min != nil && actualCount < *bound.Min {
			violations = append(violations, fmt.Sprintf("%s: %d is below minimum %d", path, actualCount, *bound.Min))
		}
		if bound.Max != nil && actualCount > *bound.Max {
			violations = append(violations, fmt.Sprintf("%s: %d exceeds maximum %d", path, actualCount, *bound.Max))
		}
		for _, expectedID := range bound.Controls {
			ac, found := actualControls[expectedID]
			if !found {
				violations = append(violations, fmt.Sprintf("%s: expected control %s not found in results", path, expectedID))
			} else if ac.Status != status || ac.Severity != label {
				violations = append(violations, fmt.Sprintf(
					"%s: control %s expected %s/%s but found %s/%s",
					path, expectedID, status, label, ac.Status, ac.Severity))
			}
		}
	}

	check("critical", threshold.Critical, actual.Critical)
	check("high", threshold.High, actual.High)
	check("medium", threshold.Medium, actual.Medium)
	check("low", threshold.Low, actual.Low)
	check("none", threshold.None, actual.None)
	check("total", threshold.Total, actual.Total)

	return violations
}
