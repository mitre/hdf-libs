// Package diff provides functions for computing effective requirement statuses,
// classifying change reasons between evaluations, and determining diff states.
// It is a direct port of the TypeScript implementation in hdf-diff/src/status.ts.
package diff

import (
	"reflect"
	"sort"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// passingStatuses are statuses that count as "passing" for fixed/regressed classification.
var passingStatuses = map[string]bool{
	"passed": true,
}

// failingStatuses are statuses that count as "failing" for fixed/regressed classification.
var failingStatuses = map[string]bool{
	"failed":      true,
	"error":       true,
	"notReviewed": true,
}

// ComputeEffectiveStatus determines the effective status of a requirement
// from its results and overrides, delegating to the canonical shared
// implementation in hdf-utilities (see status-determination.md):
//
//  1. impact == 0 -> "notApplicable" (regardless of results)
//  2. the governing (most recent non-expired) status override's status
//  3. effectiveStatus field set (and no statusOverrides) -> use it
//  4. Aggregate results using worst-wins
//  5. Empty results -> "notReviewed"
func ComputeEffectiveStatus(req hdf.EvaluatedRequirement, referenceTimestamp string) string {
	// ParseTimestamp keeps zone-less inputs host-independent (repo timestamp
	// convention); a zero result means "now" to the shared helper.
	ref := hdfutil.ParseTimestamp(referenceTimestamp)

	input := hdfutil.EffectiveStatusInput{Impact: req.Impact}
	if req.EffectiveStatus != nil {
		input.EffectiveStatus = string(*req.EffectiveStatus)
	}
	for _, result := range req.Results {
		input.ResultStatuses = append(input.ResultStatuses, string(result.Status))
	}
	for _, override := range req.StatusOverrides {
		in := hdfutil.StatusOverrideInput{
			AppliedAt: override.AppliedAt,
			ExpiresAt: override.ExpiresAt,
		}
		if override.Status != nil {
			in.Status = string(*override.Status)
		}
		input.Overrides = append(input.Overrides, in)
	}
	return hdfutil.ComputeEffectiveStatus(input, ref)
}

// ClassifyChangeReasons classifies why the status changed between two requirements.
// Returns a slice of change reasons (a status change can have multiple causes).
func ClassifyChangeReasons(
	oldReq, newReq hdf.EvaluatedRequirement,
	oldTimestamp, newTimestamp string,
) []ChangeReason {
	reasons := []ChangeReason{}

	// Check result status changes
	oldResultStatuses := extractSortedStatuses(oldReq.Results)
	newResultStatuses := extractSortedStatuses(newReq.Results)
	if !stringSlicesEqual(oldResultStatuses, newResultStatuses) {
		reasons = append(reasons, ReasonResultChanged)
	}

	// Check override changes
	oldOverrideCount := len(oldReq.StatusOverrides)
	newOverrideCount := len(newReq.StatusOverrides)

	if newOverrideCount > oldOverrideCount {
		reasons = append(reasons, ReasonOverrideAdded)
	} else if newOverrideCount < oldOverrideCount {
		reasons = append(reasons, ReasonOverrideRemoved)
	}

	// Check for override expiration between scans. ParseTimestamp keeps
	// zone-less scan timestamps host-independent (repo timestamp convention);
	// a zero result means unparseable, so the check is skipped.
	if oldTimestamp != "" && newTimestamp != "" && oldOverrideCount > 0 {
		oldTime := hdfutil.ParseTimestamp(oldTimestamp)
		newTime := hdfutil.ParseTimestamp(newTimestamp)
		if !oldTime.IsZero() && !newTime.IsZero() {
			for _, override := range oldReq.StatusOverrides {
				expiresAt := override.ExpiresAt
				if expiresAt.After(oldTime) && !expiresAt.After(newTime) {
					reasons = append(reasons, ReasonOverrideExpired)
					break // Only report once
				}
			}
		}
	}

	// Check impact changes
	if oldReq.Impact != newReq.Impact {
		reasons = append(reasons, ReasonImpactChanged)
	}

	// Check disposition changes
	if dispositionChanged(oldReq, newReq) {
		reasons = append(reasons, ReasonDispositionChanged)
	}

	// Check effectiveImpact changes
	if effectiveImpactChanged(oldReq, newReq) {
		reasons = append(reasons, ReasonEffectiveImpactChanged)
	}

	// Check baseline metadata changes (tags, descriptions, title)
	tagsChanged := !reflect.DeepEqual(oldReq.Tags, newReq.Tags)
	descsChanged := !reflect.DeepEqual(oldReq.Descriptions, newReq.Descriptions)

	oldTitle := ""
	if oldReq.Title != nil {
		oldTitle = *oldReq.Title
	}
	newTitle := ""
	if newReq.Title != nil {
		newTitle = *newReq.Title
	}

	if tagsChanged || descsChanged || oldTitle != newTitle {
		reasons = append(reasons, ReasonMetadataChanged)
	}

	return reasons
}

// ClassifyDiffStatus classifies the overall diff status based on old and new effective statuses.
//
//   - If old is failing and new is passing -> "fixed"
//   - If old is passing and new is failing -> "regressed"
//   - If statuses are equal -> "unchanged"
//   - Otherwise -> "updated"
func ClassifyDiffStatus(oldEffectiveStatus, newEffectiveStatus string) RequirementState {
	if oldEffectiveStatus == newEffectiveStatus {
		return StateUnchanged
	}

	oldIsFailing := failingStatuses[oldEffectiveStatus]
	newIsPassing := passingStatuses[newEffectiveStatus]
	oldIsPassing := passingStatuses[oldEffectiveStatus]
	newIsFailing := failingStatuses[newEffectiveStatus]

	if oldIsFailing && newIsPassing {
		return StateFixed
	}
	if oldIsPassing && newIsFailing {
		return StateRegressed
	}

	return StateUpdated
}

// dispositionChanged returns true if the disposition differs between old and new requirements.
func dispositionChanged(oldReq, newReq hdf.EvaluatedRequirement) bool {
	oldDisp := ""
	if oldReq.Disposition != nil {
		oldDisp = string(*oldReq.Disposition)
	}
	newDisp := ""
	if newReq.Disposition != nil {
		newDisp = string(*newReq.Disposition)
	}
	return oldDisp != newDisp
}

// effectiveImpactChanged returns true if the effectiveImpact differs between old and new requirements.
func effectiveImpactChanged(oldReq, newReq hdf.EvaluatedRequirement) bool {
	switch {
	case oldReq.EffectiveImpact == nil && newReq.EffectiveImpact == nil:
		return false
	case oldReq.EffectiveImpact == nil || newReq.EffectiveImpact == nil:
		return true
	default:
		return *oldReq.EffectiveImpact != *newReq.EffectiveImpact
	}
}

// extractSortedStatuses extracts status strings from results and returns them sorted.
func extractSortedStatuses(results []hdf.RequirementResult) []string {
	statuses := make([]string, 0, len(results))
	for _, r := range results {
		statuses = append(statuses, string(r.Status))
	}
	sort.Strings(statuses)
	return statuses
}

// stringSlicesEqual returns true if two string slices have the same contents.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
