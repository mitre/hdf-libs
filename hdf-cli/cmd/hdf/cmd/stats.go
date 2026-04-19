package cmd

import (
	hdf "github.com/mitre/hdf-schema"
)

// determineControlStatus derives a display status string from a requirement's
// results using InSpec precedence: error > failed > passed > notApplicable > notReviewed.
// Used by list, diff, and query commands.
func determineControlStatus(control hdf.EvaluatedRequirement) string {
	// If effectiveStatus is set, use the shared schema→display mapping
	if control.EffectiveStatus != nil {
		return SchemaStatusToDisplay(*control.EffectiveStatus)
	}

	// Otherwise, derive from results
	if len(control.Results) == 0 {
		// No results - check impact for not_applicable
		if control.Impact == 0 {
			return StatusNotApplicable
		}
		return StatusNotReviewed
	}

	// Apply InSpec precedence: error > failed > passed > notApplicable > notReviewed
	// Fail-fast on error (highest precedence). Collect flags for the rest.
	hasFailed := false
	hasPassed := false
	hasNotApplicable := false

	for _, result := range control.Results {
		switch result.Status {
		case hdf.Error:
			return StatusError // highest precedence — no need to scan further
		case hdf.Failed:
			hasFailed = true
		case hdf.Passed:
			hasPassed = true
		case hdf.NotApplicable:
			hasNotApplicable = true
		case hdf.NotReviewed:
			// lowest precedence — only returned if nothing else matches
		}
	}

	if hasFailed {
		return StatusFailed
	}
	if hasPassed {
		return StatusPassed
	}
	if hasNotApplicable {
		return StatusNotApplicable
	}

	return StatusNotReviewed
}
