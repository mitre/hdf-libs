package cmd

import (
	"encoding/json"
	"fmt"
	"math"

	hdf "github.com/mitre/hdf-schema"
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

// countControlsByStatusSeverity parses HDF results JSON and counts
// requirements by their overall status and severity.
func countControlsByStatusSeverity(data []byte) (*StatusCounts, error) {
	var results hdf.HDFResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to parse HDF results: %w", err)
	}

	counts := &StatusCounts{}

	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			status := overallStatus(req.Results)
			sev := deriveSeverity(req.Impact, req.Severity)

			addCount(counts, status, sev)
		}
	}

	return counts, nil
}

// ControlIDMapping maps a control ID to its observed status and severity.
type ControlIDMapping struct {
	ID       string
	Status   string // "passed", "failed", "skipped", "error", "no_impact"
	Severity string // "critical", "high", "medium", "low", "none"
}

// mapControlIDs builds a list of control ID → status/severity mappings
// from HDF results.
func mapControlIDs(data []byte) ([]ControlIDMapping, error) {
	var results hdf.HDFResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to parse HDF results: %w", err)
	}

	var mappings []ControlIDMapping
	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			status := overallStatus(req.Results)
			sev := deriveSeverity(req.Impact, req.Severity)

			statusName := statusToThresholdKey(status)
			mappings = append(mappings, ControlIDMapping{
				ID:       req.ID,
				Status:   statusName,
				Severity: sev,
			})
		}
	}

	return mappings, nil
}

// Threshold status key constants used in YAML output and validation.
const (
	thresholdPassed   = "passed"
	thresholdFailed   = "failed"
	thresholdSkipped  = "skipped"
	thresholdError    = "error"
	thresholdNoImpact = "no_impact"
)

// statusToThresholdKey converts a ResultStatus to the threshold YAML key name.
func statusToThresholdKey(status hdf.ResultStatus) string {
	switch status {
	case hdf.Passed:
		return thresholdPassed
	case hdf.Failed:
		return thresholdFailed
	case hdf.NotReviewed:
		return thresholdSkipped
	case hdf.Error:
		return thresholdError
	case hdf.NotApplicable:
		return thresholdNoImpact
	default:
		return thresholdSkipped
	}
}

// overallStatus determines the aggregate status of a requirement from its
// individual test results. Follows InSpec convention:
//   - Any error → error
//   - Any failed → failed
//   - All passed → passed
//   - All notApplicable → notApplicable
//   - Otherwise → notReviewed (skipped)
func overallStatus(results []hdf.RequirementResult) hdf.ResultStatus {
	if len(results) == 0 {
		return hdf.NotReviewed
	}

	hasError := false
	hasFailed := false
	hasPassed := false
	hasNA := false

	for _, r := range results {
		switch r.Status {
		case hdf.Error:
			hasError = true
		case hdf.Failed:
			hasFailed = true
		case hdf.Passed:
			hasPassed = true
		case hdf.NotApplicable:
			hasNA = true
		case hdf.NotReviewed:
			// counted as skipped via default in overall status
		}
	}

	switch {
	case hasError:
		return hdf.Error
	case hasFailed:
		return hdf.Failed
	case hasPassed:
		return hdf.Passed
	case hasNA:
		return hdf.NotApplicable
	default:
		return hdf.NotReviewed
	}
}

// deriveSeverity determines the severity string from impact and optional
// explicit severity. Delegates to impactToSeverity (query.go) for the
// impact-based mapping, with an override when explicit severity is provided.
// Maps "informational" to "none" for SAF CLI threshold YAML compatibility.
func deriveSeverity(impact float64, severity *hdf.Severity) string {
	if severity != nil {
		return string(*severity)
	}
	sev := impactToSeverity(impact)
	if sev == SeverityInformational {
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
	case string(hdf.Critical):
		sc.Critical++
	case string(hdf.SeverityHigh):
		sc.High++
	case string(hdf.Medium):
		sc.Medium++
	case string(hdf.SeverityLow):
		sc.Low++
	default:
		sc.None++
	}
}

// calculateCompliance returns the compliance percentage.
// compliance = passed / (passed + failed + skipped + error) * 100
// notApplicable controls are excluded from the calculation.
func calculateCompliance(counts *StatusCounts) float64 {
	relevant := counts.Passed.Total + counts.Failed.Total + counts.Skipped.Total + counts.Error.Total
	if relevant == 0 {
		return 0.0
	}
	pct := float64(counts.Passed.Total) / float64(relevant) * 100.0
	return math.Round(pct*100) / 100 // round to 2 decimal places
}
