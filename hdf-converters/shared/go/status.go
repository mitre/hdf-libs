package shared

import (
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// StatusOverrideInputs maps schema status overrides onto the canonical
// effective-status helper's neutral shape (hdf-utilities).
func StatusOverrideInputs(overrides []hdf.StatusOverride) []hdfutil.StatusOverrideInput {
	inputs := make([]hdfutil.StatusOverrideInput, len(overrides))
	for i, o := range overrides {
		inputs[i] = hdfutil.StatusOverrideInput{AppliedAt: o.AppliedAt, ExpiresAt: o.ExpiresAt}
		if o.Status != nil {
			inputs[i].Status = string(*o.Status)
		}
	}
	return inputs
}

// RequirementStatusInput maps a requirement onto the canonical
// effective-status helper's input shape (hdf-utilities), so every consumer
// computes status through the single shared implementation.
func RequirementStatusInput(r hdf.EvaluatedRequirement) hdfutil.EffectiveStatusInput {
	input := hdfutil.EffectiveStatusInput{
		Impact:    r.Impact,
		Overrides: StatusOverrideInputs(r.StatusOverrides),
	}
	if r.EffectiveStatus != nil {
		input.EffectiveStatus = string(*r.EffectiveStatus)
	}
	for _, res := range r.Results {
		input.ResultStatuses = append(input.ResultStatuses, string(res.Status))
	}
	return input
}
