package cmd

import (
	"fmt"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

// effectiveStatus resolves a requirement's canonical effective status (impact==0
// → notApplicable, non-expired overrides honored, worst-wins) in the schema
// vocabulary. Threshold gating counts by this — the same rule HDF's read tools
// use — so a CLI gate agrees with hdf_compliance and never keeps Not Applicable
// controls (impact==0) in the compliance denominator.
func effectiveStatus(req hdf.EvaluatedRequirement) string {
	return hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(req), time.Time{})
}

// countControlsByStatusSeverity parses HDF results JSON and counts requirements
// by their effective status and severity, delegating to the shared hdf-engine
// library via the effective-status resolver. Input parsing stays here (the CLI's
// gated pipeline).
func countControlsByStatusSeverity(data []byte) (*hdfengine.StatusCounts, error) {
	results, err := parseHDFResults(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HDF results: %w", err)
	}
	return hdfengine.CountControlsByStatus(results, effectiveStatus), nil
}

// mapControlIDs builds control ID → effective-status/severity mappings from HDF
// results, delegating to the shared hdf-engine library. Uses the same
// effective-status resolver as the counts so per-control listings and the
// aggregate counts stay consistent.
func mapControlIDs(data []byte) ([]hdfengine.ControlIDMapping, error) {
	results, err := parseHDFResults(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HDF results: %w", err)
	}
	return hdfengine.MapControlIDsByStatus(results, effectiveStatus), nil
}
