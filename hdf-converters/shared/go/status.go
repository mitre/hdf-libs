package shared

import (
	"time"

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
		if o.Impact != nil {
			// Carried so effective IMPACT can be resolved from the same
			// overrides; eligibility is per-field, so an override may govern one
			// and not the other.
			value := o.Impact.Value
			inputs[i].Impact = &value
		}
	}
	return inputs
}

// GoverningOverrideIndex returns the index of the override that governs a
// requirement — the most recently applied non-expired one, whatever it carries —
// or -1 when none does. A zero ref means now.
//
// Resolution is by appliedAt, never by array position. The schema's description
// says the most recent override "should be first in array", but nothing in this
// repo sorts and both writers append (hdf-diff amend, enrich_stix), so on a
// document our own tooling amended twice the newest override is LAST. Selecting
// by position therefore reads the oldest.
func GoverningOverrideIndex(overrides []hdf.StatusOverride, ref time.Time) int {
	anyOverride := func(int) bool { return true }
	return hdfutil.GoverningOverrideIndex(StatusOverrideInputs(overrides), anyOverride, ref)
}

// GoverningOverride returns the override that governs a requirement, or nil when
// none does. The pointer aliases the caller's slice; do not retain it past the
// slice's lifetime.
func GoverningOverride(overrides []hdf.StatusOverride, ref time.Time) *hdf.StatusOverride {
	if i := GoverningOverrideIndex(overrides, ref); i >= 0 {
		return &overrides[i]
	}
	return nil
}

// RequirementDisposition is the type of the override that governs a requirement,
// or "" when none does — the disposition twin of RequirementEffectiveStatus and
// RequirementEffectiveImpact. A zero ref means now.
//
// Whenever the requirement carries overrides, they decide: the stored
// disposition field is an output cache that can disagree with them, or be stale,
// and it is not read.
//
// The one exception is a requirement carrying NO overrides at all. There the
// stored field is the only evidence in the document — nothing can contradict it,
// so passing it through preserves information an export would otherwise drop,
// and an exporter that dropped it would lose the disposition of every document
// whose producer recorded the verdict without the override detail. That is why
// it is a fallback and not a source.
//
// Note hdf-engine's filter does NOT take this fallback: it returns no
// disposition for such a requirement. The asymmetry is deliberate for now —
// a filter that matched on an unprovenanced value would select requirements it
// cannot justify, where an export is only restating what it was given.
//
// A second, related asymmetry: this reads statusOverrides only. hdf-engine's
// filter and hdf-diff's checksum fold poams[] into the same governing set and
// report "poam" when a plan governs; an export does not, because the exporters
// carry the plan separately and a disposition of "poam" would duplicate it in
// a column that names an override type. Pinned by
// TestRequirementDisposition_DoesNotReadPoams.
func RequirementDisposition(r hdf.EvaluatedRequirement, ref time.Time) string {
	if o := GoverningOverride(r.StatusOverrides, ref); o != nil {
		return string(o.Type)
	}
	if len(r.StatusOverrides) == 0 && r.Disposition != nil {
		return string(*r.Disposition)
	}
	return ""
}

// RequirementStatusInput maps a requirement onto the canonical
// effective-status helper's input shape (hdf-utilities), so every consumer
// computes status through the single shared implementation.
func RequirementStatusInput(r hdf.EvaluatedRequirement) hdfutil.EffectiveStatusInput {
	input := hdfutil.EffectiveStatusInput{
		Impact:    r.Impact,
		Overrides: StatusOverrideInputs(r.StatusOverrides),
	}
	for _, res := range r.Results {
		input.ResultStatuses = append(input.ResultStatuses, string(res.Status))
	}
	return input
}

// RequirementEffectiveImpact is the requirement's canonical effective impact via
// the shared ladder: the governing non-expired impact override's value, else the
// requirement's own. The stored effectiveImpact field is an output cache and is
// never read, exactly as effectiveStatus is not.
func RequirementEffectiveImpact(r hdf.EvaluatedRequirement) float64 {
	return hdfutil.ComputeEffectiveImpact(RequirementStatusInput(r), time.Time{})
}

// RequirementEffectiveStatus is the requirement's canonical effective status
// via the shared ladder, judged against the clock (twin of
// requirementEffectiveStatus in status.ts).
func RequirementEffectiveStatus(r hdf.EvaluatedRequirement) string {
	return hdfutil.ComputeEffectiveStatus(RequirementStatusInput(r), time.Time{})
}
