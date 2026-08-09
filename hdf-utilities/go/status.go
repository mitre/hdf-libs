package hdfutil

import "time"

// StatusSeverityOrder is the canonical worst-wins ordering of HDF result
// statuses, worst first, per the published precedence rules
// (site/docs/architecture/status-determination.md). Every status roll-up in
// hdf-libs derives from this single ordering; do not re-implement it.
var StatusSeverityOrder = []string{"error", "failed", "passed", "notApplicable", "notReviewed"}

// StatusRank returns the severity rank of a status: higher = worse. Unknown
// statuses rank -1 (below every known status).
func StatusRank(status string) int {
	for i, s := range StatusSeverityOrder {
		if s == status {
			return len(StatusSeverityOrder) - 1 - i
		}
	}
	return -1
}

// WorstStatus rolls a list of result statuses up to the worst one. An empty
// list (or a list of only unknown statuses) rolls up to "notReviewed".
func WorstStatus(statuses []string) string {
	worst := "notReviewed"
	worstRank := -1
	for _, s := range statuses {
		if r := StatusRank(s); r > worstRank {
			worstRank = r
			worst = s
		}
	}
	return worst
}

// StatusOverrideInput is the neutral shape of a status override for
// effective-status computation. Callers map their concrete types (schema
// structs or raw JSON) onto it.
type StatusOverrideInput struct {
	// Status is the override's target status; empty means the override does
	// not carry a status and can never govern.
	Status    string
	AppliedAt time.Time
	// ExpiresAt zero means the override never expires.
	ExpiresAt time.Time
}

func (o StatusOverrideInput) expired(ref time.Time) bool {
	return !o.ExpiresAt.IsZero() && !o.ExpiresAt.After(ref)
}

// GoverningOverrideIndex returns the index of the most recently applied (by
// AppliedAt) non-expired override among those for which eligible returns true,
// or -1 when none qualifies. It generalizes governing-override selection to
// per-field eligibility: the schema defines effectiveStatus, effectiveImpact,
// and disposition each as "the most recent non-expired override" carrying the
// relevant field, so callers pass the field-presence check as the predicate.
// A zero ref time means "now".
func GoverningOverrideIndex(overrides []StatusOverrideInput, eligible func(int) bool, ref time.Time) int {
	if ref.IsZero() {
		ref = time.Now()
	}
	governing := -1
	for i := range overrides {
		o := &overrides[i]
		if !eligible(i) || o.expired(ref) {
			continue
		}
		if governing == -1 || o.AppliedAt.After(overrides[governing].AppliedAt) {
			governing = i
		}
	}
	return governing
}

// GoverningStatusOverrideIndex returns the index of the override that governs
// a requirement: the most recently applied (by AppliedAt) non-expired override
// that carries a status — matching the schema's definition of disposition
// ("the most recent non-expired override"). Returns -1 when no override
// governs. Callers holding richer concrete override types use the index to
// recover their own object.
func GoverningStatusOverrideIndex(overrides []StatusOverrideInput, ref time.Time) int {
	return GoverningOverrideIndex(overrides, func(i int) bool { return overrides[i].Status != "" }, ref)
}

// GoverningStatusOverride is GoverningStatusOverrideIndex returning the
// override itself, or nil when none governs.
func GoverningStatusOverride(overrides []StatusOverrideInput, ref time.Time) *StatusOverrideInput {
	if i := GoverningStatusOverrideIndex(overrides, ref); i >= 0 {
		return &overrides[i]
	}
	return nil
}

// EffectiveStatusInput is the neutral shape of a requirement for
// effective-status computation.
type EffectiveStatusInput struct {
	Impact float64
	// EffectiveStatus is the requirement's stored effectiveStatus field;
	// empty means unset.
	EffectiveStatus string
	ResultStatuses  []string
	Overrides       []StatusOverrideInput
}

// ComputeEffectiveStatus determines a requirement's effective status. This is
// the single canonical implementation of the precedence in
// status-determination.md:
//
//  1. impact == 0 -> "notApplicable", regardless of results or overrides
//  2. the governing (most recent non-expired) status override's status
//  3. the stored effectiveStatus, honored only when NO overrides are present —
//     effectiveStatus is state derived from overrides, so when every override
//     has expired it is stale and the result roll-up wins
//  4. worst-wins roll-up of the result statuses
//  5. no results -> "notReviewed"
//
// A zero ref time means "now".
func ComputeEffectiveStatus(input EffectiveStatusInput, ref time.Time) string {
	if input.Impact == 0 {
		return "notApplicable"
	}
	if len(input.Overrides) > 0 {
		if governing := GoverningStatusOverride(input.Overrides, ref); governing != nil {
			return governing.Status
		}
		return WorstStatus(input.ResultStatuses)
	}
	if input.EffectiveStatus != "" {
		return input.EffectiveStatus
	}
	return WorstStatus(input.ResultStatuses)
}
