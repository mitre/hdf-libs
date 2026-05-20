package cmd

import (
	schema "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// baselineToEvalReqs converts BaselineRequirements to EvaluatedRequirements for matching.
func baselineToEvalReqs(reqs []schema.BaselineRequirement) []schema.EvaluatedRequirement {
	result := make([]schema.EvaluatedRequirement, len(reqs))
	for i, r := range reqs {
		result[i] = schema.EvaluatedRequirement{
			ID:           r.ID,
			Title:        r.Title,
			Impact:       r.Impact,
			Tags:         r.Tags,
			Descriptions: r.Descriptions,
			Code:         r.Code,
		}
	}
	return result
}

// computePotentialMismatch determines if a match is a potential mismatch based on
// the strategy used and confidence level.
func computePotentialMismatch(strategy, relationship string, confidence float64) bool {
	if relationship != "primary" {
		return false
	}
	switch strategy {
	case "srgDeterministic", "exactId":
		return false
	case "srgCciTiebreak":
		return confidence < 0.5
	case "vendorFuzzyTitle":
		return confidence < 0.9
	default:
		return confidence < 0.8
	}
}
