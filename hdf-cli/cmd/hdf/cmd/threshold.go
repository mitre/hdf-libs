package cmd

import (
	"fmt"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
)

// The compliance/threshold types and status-key constants now live in the shared
// hdf-engine library. These aliases let the CLI's threshold parsing/template code
// reference them without a second definition (an alias is not a copy).
type (
	StatusCounts      = hdfengine.StatusCounts
	SeverityCounts    = hdfengine.SeverityCounts
	ControlIDMapping  = hdfengine.ControlIDMapping
	ThresholdConfig   = hdfengine.ThresholdConfig
	ThresholdSeverity = hdfengine.ThresholdSeverity
	ThresholdBound    = hdfengine.ThresholdBound
	ComplianceBound   = hdfengine.ComplianceBound
)

const (
	thresholdPassed   = hdfengine.ThresholdPassed
	thresholdFailed   = hdfengine.ThresholdFailed
	thresholdSkipped  = hdfengine.ThresholdSkipped
	thresholdError    = hdfengine.ThresholdError
	thresholdNoImpact = hdfengine.ThresholdNoImpact
)

// countControlsByStatusSeverity parses HDF results JSON and counts requirements
// by their overall status and severity, delegating the counting to the shared
// hdf-engine library. Input parsing stays here (the CLI's gated pipeline).
func countControlsByStatusSeverity(data []byte) (*hdfengine.StatusCounts, error) {
	results, err := parseHDFResults(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HDF results: %w", err)
	}
	return hdfengine.CountControlsByStatusSeverity(results), nil
}

// mapControlIDs builds control ID → status/severity mappings from HDF results,
// delegating to the shared hdf-engine library.
func mapControlIDs(data []byte) ([]hdfengine.ControlIDMapping, error) {
	results, err := parseHDFResults(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HDF results: %w", err)
	}
	return hdfengine.MapControlIDs(results), nil
}
