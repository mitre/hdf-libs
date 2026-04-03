package engine

import (
	"encoding/json"
	"sort"
	"time"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
)

// systemTrackedFields are the component-level fields tracked for field changes.
var systemTrackedFields = []string{"type", "description", "baselineRefs", "inputOverrides", "sbomRef", "targetSelector"}

// systemTopLevelFields are the system-level fields tracked for field changes.
var systemTopLevelFields = []string{"authorizationStatus", "categorizationLevel", "description"}

// DiffSystems compares two HDF system documents (as generic maps) and produces
// a structured comparison showing component-level changes between system versions.
//
// Components are matched by exact name. Top-level system fields
// (authorizationStatus, categorizationLevel, description) are also compared.
func DiffSystems(oldSystem, newSystem map[string]any) (types.HdfComparison, error) {
	oldComponents := extractComponents(oldSystem)
	newComponents := extractComponents(newSystem)

	// Build maps by component name
	oldMap := make(map[string]map[string]any)
	for _, c := range oldComponents {
		name, _ := c["name"].(string)
		if name != "" {
			oldMap[name] = c
		}
	}
	newMap := make(map[string]map[string]any)
	for _, c := range newComponents {
		name, _ := c["name"].(string)
		if name != "" {
			newMap[name] = c
		}
	}

	// Collect all component names
	allNames := make(map[string]bool)
	for name := range oldMap {
		allNames[name] = true
	}
	for name := range newMap {
		allNames[name] = true
	}

	var componentDiffs []types.ComponentDiff

	for name := range allNames {
		oldComp, oldExists := oldMap[name]
		newComp, newExists := newMap[name]

		switch {
		case oldExists && newExists:
			fieldChanges := computeMapFieldChanges(oldComp, newComp, systemTrackedFields)
			state := types.StateUnchanged
			if len(fieldChanges) > 0 {
				state = types.StateUpdated
			}
			componentDiffs = append(componentDiffs, types.ComponentDiff{
				Name:         name,
				State:        state,
				Before:       oldComp,
				After:        newComp,
				FieldChanges: fieldChanges,
			})
		case oldExists:
			componentDiffs = append(componentDiffs, types.ComponentDiff{
				Name:         name,
				State:        types.StateAbsent,
				Before:       oldComp,
				After:        nil,
				FieldChanges: []types.FieldChange{},
			})
		case newExists:
			componentDiffs = append(componentDiffs, types.ComponentDiff{
				Name:         name,
				State:        types.StateNew,
				Before:       nil,
				After:        newComp,
				FieldChanges: []types.FieldChange{},
			})
		}
	}

	// Sort by name
	sort.Slice(componentDiffs, func(i, j int) bool {
		return componentDiffs[i].Name < componentDiffs[j].Name
	})

	// Compare top-level system fields
	systemFieldChanges := computeMapFieldChanges(oldSystem, newSystem, systemTopLevelFields)

	// Build summary counts
	counts := map[string]int{"new": 0, "absent": 0, "unchanged": 0, "updated": 0}
	for _, cd := range componentDiffs {
		counts[string(cd.State)]++
	}

	oldName, _ := oldSystem["name"].(string)
	newName, _ := newSystem["name"].(string)
	systemName := newName
	if systemName == "" {
		systemName = oldName
	}

	oldLabel := "Old system"
	newLabel := "New system"
	if systemName != "" {
		oldLabel = systemName + " (old)"
		newLabel = systemName + " (new)"
	}

	sources := []types.Source{
		{Role: types.RoleOld, Label: oldLabel},
		{Role: types.RoleNew, Label: newLabel},
	}

	result := types.HdfComparison{
		FormatVersion:  "1.0.0",
		ComparisonMode: types.ModeSystemDrift,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Sources:        sources,
		Summary: types.ComparisonSummary{
			Total:             len(allNames),
			MatchedCount:      counts["unchanged"] + counts["updated"],
			UnmatchedOldCount: counts["absent"],
			UnmatchedNewCount: counts["new"],
			New:               counts["new"],
			Absent:            counts["absent"],
			Unchanged:         counts["unchanged"],
			Updated:           counts["updated"],
			Fixed:             0,
			Regressed:         0,
		},
		BaselineDiffs:    []types.BaselineDiff{},
		RequirementDiffs: []types.RequirementDiff{},
		ComponentDiffs:   componentDiffs,
	}

	// Attach system-level field changes as extensions if present
	if len(systemFieldChanges) > 0 {
		result.Extensions = map[string]any{
			"systemFieldChanges": systemFieldChanges,
		}
	}

	return result, nil
}

// extractComponents extracts the components array from a system document.
func extractComponents(system map[string]any) []map[string]any {
	raw, ok := system["components"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		// Try typed slice
		if typed, ok2 := raw.([]map[string]any); ok2 {
			return typed
		}
		return nil
	}
	result := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

// computeMapFieldChanges computes field-level changes between two maps
// for the specified tracked fields.
func computeMapFieldChanges(oldObj, newObj map[string]any, trackedFields []string) []types.FieldChange {
	var changes []types.FieldChange

	for _, field := range trackedFields {
		oldVal, oldExists := oldObj[field]
		newVal, newExists := newObj[field]

		if !jsonEqual(oldVal, newVal) {
			switch {
			case !oldExists && newExists:
				changes = append(changes, types.FieldChange{
					Op:       types.OpAdd,
					Path:     field,
					NewValue: newVal,
				})
			case oldExists && !newExists:
				changes = append(changes, types.FieldChange{
					Op:       types.OpRemove,
					Path:     field,
					OldValue: oldVal,
				})
			default:
				changes = append(changes, types.FieldChange{
					Op:       types.OpReplace,
					Path:     field,
					OldValue: oldVal,
					NewValue: newVal,
				})
			}
		}
	}

	return changes
}

// jsonEqual compares two values by their JSON serialization.
func jsonEqual(a, b any) bool {
	aj, errA := json.Marshal(a)
	bj, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(aj) == string(bj)
}
