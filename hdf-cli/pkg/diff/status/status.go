// Package status provides functions for computing effective requirement statuses,
// classifying change reasons between evaluations, and determining diff states.
// It is a direct port of the TypeScript implementation in hdf-diff/src/status.ts.
package status

import (
	"reflect"
	"sort"
	"time"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// statusSeverity defines the severity ranking of statuses.
// Higher index = worse status.
var statusSeverity = []string{
	"notApplicable",
	"notReviewed",
	"passed",
	"failed",
	"error",
}

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

// severityIndex returns the index of a status in the severity ranking, or -1 if not found.
func severityIndex(status string) int {
	for i, s := range statusSeverity {
		if s == status {
			return i
		}
	}
	return -1
}

// ComputeEffectiveStatus determines the effective status of a requirement from
// its results and overrides.
//
// Priority:
//  1. impact == 0 -> "notApplicable" (regardless of results)
//  2. Non-expired statusOverrides -> use first non-expired override's status
//  3. effectiveStatus field set (and no statusOverrides) -> use it
//  4. Aggregate results using worst-wins
//  5. Empty results -> "notReviewed"
func ComputeEffectiveStatus(req hdf.EvaluatedRequirement, referenceTimestamp string) string {
	// 1. impact == 0 -> notApplicable
	if req.Impact == 0 {
		return "notApplicable"
	}

	// 2. Non-expired statusOverrides
	if len(req.StatusOverrides) > 0 {
		var refTime time.Time
		if referenceTimestamp != "" {
			parsed, err := time.Parse(time.RFC3339, referenceTimestamp)
			if err == nil {
				refTime = parsed
			} else {
				refTime = time.Now()
			}
		} else {
			refTime = time.Now()
		}

		for _, override := range req.StatusOverrides {
			if override.ExpiresAt.After(refTime) && override.Status != nil {
				return string(*override.Status)
			}
		}
		// All overrides expired — fall through to results
	}

	// 3. effectiveStatus field set and no overrides
	if req.EffectiveStatus != nil && len(req.StatusOverrides) == 0 {
		return string(*req.EffectiveStatus)
	}

	// 4. Aggregate results using worst-wins
	if len(req.Results) == 0 {
		return "notReviewed"
	}

	worstIndex := -1
	worstStatus := "notReviewed"
	for _, result := range req.Results {
		if result.Status == nil {
			continue
		}
		idx := severityIndex(string(*result.Status))
		if idx > worstIndex {
			worstIndex = idx
			worstStatus = string(*result.Status)
		}
	}

	return worstStatus
}

// ClassifyChangeReasons classifies why the status changed between two requirements.
// Returns a slice of change reasons (a status change can have multiple causes).
func ClassifyChangeReasons(
	oldReq, newReq hdf.EvaluatedRequirement,
	oldTimestamp, newTimestamp string,
) []types.ChangeReason {
	reasons := []types.ChangeReason{}

	// Check result status changes
	oldResultStatuses := extractSortedStatuses(oldReq.Results)
	newResultStatuses := extractSortedStatuses(newReq.Results)
	if !stringSlicesEqual(oldResultStatuses, newResultStatuses) {
		reasons = append(reasons, types.ReasonResultChanged)
	}

	// Check override changes
	oldOverrideCount := len(oldReq.StatusOverrides)
	newOverrideCount := len(newReq.StatusOverrides)

	if newOverrideCount > oldOverrideCount {
		reasons = append(reasons, types.ReasonOverrideAdded)
	} else if newOverrideCount < oldOverrideCount {
		reasons = append(reasons, types.ReasonOverrideRemoved)
	}

	// Check for override expiration between scans
	if oldTimestamp != "" && newTimestamp != "" && oldOverrideCount > 0 {
		oldTime, errOld := time.Parse(time.RFC3339, oldTimestamp)
		newTime, errNew := time.Parse(time.RFC3339, newTimestamp)
		if errOld == nil && errNew == nil {
			for _, override := range oldReq.StatusOverrides {
				expiresAt := override.ExpiresAt
				if expiresAt.After(oldTime) && !expiresAt.After(newTime) {
					reasons = append(reasons, types.ReasonOverrideExpired)
					break // Only report once
				}
			}
		}
	}

	// Check impact changes
	if oldReq.Impact != newReq.Impact {
		reasons = append(reasons, types.ReasonImpactChanged)
	}

	// Check disposition changes
	if dispositionChanged(oldReq, newReq) {
		reasons = append(reasons, types.ReasonDispositionChanged)
	}

	// Check effectiveImpact changes
	if effectiveImpactChanged(oldReq, newReq) {
		reasons = append(reasons, types.ReasonEffectiveImpactChanged)
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
		reasons = append(reasons, types.ReasonMetadataChanged)
	}

	return reasons
}

// ClassifyDiffStatus classifies the overall diff status based on old and new effective statuses.
//
//   - If old is failing and new is passing -> "fixed"
//   - If old is passing and new is failing -> "regressed"
//   - If statuses are equal -> "unchanged"
//   - Otherwise -> "updated"
func ClassifyDiffStatus(oldEffectiveStatus, newEffectiveStatus string) types.RequirementState {
	if oldEffectiveStatus == newEffectiveStatus {
		return types.StateUnchanged
	}

	oldIsFailing := failingStatuses[oldEffectiveStatus]
	newIsPassing := passingStatuses[newEffectiveStatus]
	oldIsPassing := passingStatuses[oldEffectiveStatus]
	newIsFailing := failingStatuses[newEffectiveStatus]

	if oldIsFailing && newIsPassing {
		return types.StateFixed
	}
	if oldIsPassing && newIsFailing {
		return types.StateRegressed
	}

	return types.StateUpdated
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
		if r.Status != nil {
			statuses = append(statuses, string(*r.Status))
		}
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
