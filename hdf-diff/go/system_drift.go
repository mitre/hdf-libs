package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// systemTrackedFields are the component-level fields tracked for field changes.
var systemTrackedFields = []string{"type", "description", "baselineRefs", "inputOverrides", "boms", "targetSelector"}

// systemTopLevelFields are the system-level fields tracked for field changes.
var systemTopLevelFields = []string{"authorizationStatus", "categorizationLevel", "description"}

// DataFlowChange represents a change to a data flow between system versions.
type DataFlowChange struct {
	State string         `json:"state"` // "added", "removed", "updated"
	Flow  map[string]any `json:"flow"`
}

// DiffSystems compares two HDF system documents (as generic maps) and produces
// a structured comparison showing component-level changes between system versions.
//
// Components are matched by componentId first, then by name (2-pass matching).
// Top-level system fields (authorizationStatus, categorizationLevel, description)
// and data flows are also compared.
//
//nolint:revive // matches TypeScript export name
func DiffSystems(oldSystem, newSystem map[string]any) (HdfComparison, error) {
	oldComponents := extractComponents(oldSystem)
	newComponents := extractComponents(newSystem)

	// Match components: componentId first, then name
	pairs := matchComponents(oldComponents, newComponents)

	var componentDiffs []ComponentDiff
	for _, p := range pairs {
		switch {
		case p.oldComp != nil && p.newComp != nil:
			fieldChanges := computeMapFieldChanges(p.oldComp, p.newComp, systemTrackedFields)
			state := StateUnchanged
			if len(fieldChanges) > 0 {
				state = StateUpdated
			}
			componentDiffs = append(componentDiffs, ComponentDiff{
				Name:         p.name,
				State:        state,
				Before:       p.oldComp,
				After:        p.newComp,
				FieldChanges: fieldChanges,
			})
		case p.oldComp != nil:
			componentDiffs = append(componentDiffs, ComponentDiff{
				Name:         p.name,
				State:        StateAbsent,
				Before:       p.oldComp,
				After:        nil,
				FieldChanges: []FieldChange{},
			})
		case p.newComp != nil:
			componentDiffs = append(componentDiffs, ComponentDiff{
				Name:         p.name,
				State:        StateNew,
				Before:       nil,
				After:        p.newComp,
				FieldChanges: []FieldChange{},
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

	sources := []Source{
		{Role: RoleOld, Label: oldLabel},
		{Role: RoleNew, Label: newLabel},
	}

	result := HdfComparison{
		FormatVersion:  "1.0.0",
		ComparisonMode: ModeSystemDrift,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Sources:        sources,
		Summary: ComparisonSummary{
			Total:             len(componentDiffs),
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
		BaselineDiffs:    []BaselineDiff{},
		RequirementDiffs: []RequirementDiff{},
		ComponentDiffs:   componentDiffs,
	}

	// Build extensions map for system-level changes and data flow changes
	extensions := map[string]any{}

	if len(systemFieldChanges) > 0 {
		extensions["systemFieldChanges"] = systemFieldChanges
	}

	dataFlowChanges := diffDataFlows(oldSystem, newSystem)
	if len(dataFlowChanges) > 0 {
		extensions["dataFlowChanges"] = dataFlowChanges
	}

	if len(extensions) > 0 {
		result.Extensions = extensions
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
func computeMapFieldChanges(oldObj, newObj map[string]any, trackedFields []string) []FieldChange {
	var changes []FieldChange

	for _, field := range trackedFields {
		oldVal, oldExists := oldObj[field]
		newVal, newExists := newObj[field]

		if !jsonEqual(oldVal, newVal) {
			switch {
			case !oldExists && newExists:
				changes = append(changes, FieldChange{
					Op:       OpAdd,
					Path:     field,
					NewValue: newVal,
				})
			case oldExists && !newExists:
				changes = append(changes, FieldChange{
					Op:       OpRemove,
					Path:     field,
					OldValue: oldVal,
				})
			default:
				changes = append(changes, FieldChange{
					Op:       OpReplace,
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

// componentPair holds a matched pair of old/new components.
type componentPair struct {
	name    string
	oldComp map[string]any
	newComp map[string]any
}

// matchComponents matches components by componentId first, then by name.
// This 2-pass strategy handles renamed components that retain their UUID.
func matchComponents(oldComponents, newComponents []map[string]any) []componentPair {
	oldMatched := make(map[int]bool)
	newMatched := make(map[int]bool)
	var pairs []componentPair

	matchComponentsByID(oldComponents, newComponents, &pairs, oldMatched, newMatched)
	matchComponentsByName(oldComponents, newComponents, &pairs, oldMatched, newMatched)
	collectUnmatchedComponents(oldComponents, newComponents, &pairs, oldMatched, newMatched)

	return pairs
}

// matchComponentsByID matches old and new components by their componentId field.
func matchComponentsByID(
	oldComponents, newComponents []map[string]any,
	pairs *[]componentPair, oldMatched, newMatched map[int]bool,
) {
	newByID := make(map[string]int)
	for i, c := range newComponents {
		if id, ok := c["componentId"].(string); ok && id != "" {
			newByID[id] = i
		}
	}
	for i, oldC := range oldComponents {
		oldID, _ := oldC["componentId"].(string)
		if oldID == "" {
			continue
		}
		if ni, ok := newByID[oldID]; ok {
			newC := newComponents[ni]
			name, _ := newC["name"].(string)
			if name == "" {
				name, _ = oldC["name"].(string)
			}
			if name == "" {
				name = oldID
			}
			*pairs = append(*pairs, componentPair{name: name, oldComp: oldC, newComp: newC})
			oldMatched[i] = true
			newMatched[ni] = true
		}
	}
}

// matchComponentsByName matches remaining unmatched components by name.
func matchComponentsByName(
	oldComponents, newComponents []map[string]any,
	pairs *[]componentPair, oldMatched, newMatched map[int]bool,
) {
	newByName := make(map[string]int)
	for i, c := range newComponents {
		if newMatched[i] {
			continue
		}
		if name, ok := c["name"].(string); ok && name != "" {
			newByName[name] = i
		}
	}
	for i, oldC := range oldComponents {
		if oldMatched[i] {
			continue
		}
		name, _ := oldC["name"].(string)
		if name == "" {
			continue
		}
		if ni, ok := newByName[name]; ok {
			*pairs = append(*pairs, componentPair{name: name, oldComp: oldC, newComp: newComponents[ni]})
			oldMatched[i] = true
			newMatched[ni] = true
			delete(newByName, name)
		}
	}
}

// collectUnmatchedComponents adds unmatched old components (absent) and new components (new).
func collectUnmatchedComponents(
	oldComponents, newComponents []map[string]any,
	pairs *[]componentPair, oldMatched, newMatched map[int]bool,
) {
	for i, oldC := range oldComponents {
		if oldMatched[i] {
			continue
		}
		name, _ := oldC["name"].(string)
		if name == "" {
			name = fmt.Sprintf("component-%d", i)
		}
		*pairs = append(*pairs, componentPair{name: name, oldComp: oldC})
	}
	for i, newC := range newComponents {
		if newMatched[i] {
			continue
		}
		name, _ := newC["name"].(string)
		if name == "" {
			name = fmt.Sprintf("component-%d", i)
		}
		*pairs = append(*pairs, componentPair{name: name, newComp: newC})
	}
}

// diffDataFlows compares data flows between two system documents.
// Flows are keyed by from→to for matching.
func diffDataFlows(oldSys, newSys map[string]any) []DataFlowChange {
	oldFlowMaps := extractMapSlice(oldSys["dataFlows"])
	newFlowMaps := extractMapSlice(newSys["dataFlows"])

	if len(oldFlowMaps) == 0 && len(newFlowMaps) == 0 {
		return nil
	}

	flowKey := func(f map[string]any) string {
		from, _ := f["from"].(string)
		to, _ := f["to"].(string)
		if to == "" {
			toJSON, _ := json.Marshal(f["to"])
			to = string(toJSON)
		}
		return from + "→" + to
	}

	oldMap := make(map[string]map[string]any)
	for _, f := range oldFlowMaps {
		oldMap[flowKey(f)] = f
	}
	newMap := make(map[string]map[string]any)
	for _, f := range newFlowMaps {
		newMap[flowKey(f)] = f
	}

	allKeys := make(map[string]bool)
	for k := range oldMap {
		allKeys[k] = true
	}
	for k := range newMap {
		allKeys[k] = true
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	var changes []DataFlowChange
	for _, key := range sortedKeys {
		oldF, inOld := oldMap[key]
		newF, inNew := newMap[key]

		switch {
		case inOld && inNew:
			if !jsonEqual(oldF, newF) {
				changes = append(changes, DataFlowChange{State: "updated", Flow: newF})
			}
		case inOld:
			changes = append(changes, DataFlowChange{State: "removed", Flow: oldF})
		case inNew:
			changes = append(changes, DataFlowChange{State: "added", Flow: newF})
		}
	}

	return changes
}

// extractMapSlice safely converts an any to []map[string]any.
func extractMapSlice(v any) []map[string]any {
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		if typed, ok2 := v.([]map[string]any); ok2 {
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
