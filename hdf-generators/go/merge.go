package generators

import (
	"encoding/json"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// MergeRequirement performs a smart merge of current and upstream requirements.
//
// Default (prefer ""):
//   - ID: always upstream
//   - Scalars (title, impact, severity): upstream wins
//   - Tags: union, upstream wins key conflicts
//   - Descriptions: union by label, upstream wins on same label
//   - Code: current (preserve tests)
//   - Refs: union (deduplicated)
//   - SourceLocation: upstream
//
// prefer "current": scalars from current, current wins tag/desc conflicts, code from current
// prefer "upstream": everything from upstream (full replacement)
func MergeRequirement(current, upstream hdf.BaselineRequirement, prefer string) hdf.BaselineRequirement {
	merged := hdf.BaselineRequirement{
		// ID always comes from upstream (target version)
		ID: upstream.ID,
	}

	// Scalars: title, impact, severity
	switch prefer {
	case "current":
		merged.Title = current.Title
		merged.Impact = current.Impact
		merged.Severity = current.Severity
	default: // "" (smart merge) or "upstream"
		merged.Title = upstream.Title
		merged.Impact = upstream.Impact
		merged.Severity = upstream.Severity
	}

	// Tags
	merged.Tags = MergeTags(current.Tags, upstream.Tags, prefer)

	// Descriptions
	merged.Descriptions = MergeDescriptions(current.Descriptions, upstream.Descriptions, prefer)

	// Code: current by default, upstream only with --prefer upstream
	switch prefer {
	case "upstream":
		merged.Code = upstream.Code
	default: // "" or "current"
		if current.Code != nil {
			merged.Code = current.Code
		} else {
			merged.Code = upstream.Code
		}
	}

	// Refs
	merged.Refs = MergeRefs(current.Refs, upstream.Refs, prefer)

	// SourceLocation: follows same pattern as scalars
	switch prefer {
	case "current":
		merged.SourceLocation = current.SourceLocation
	default:
		merged.SourceLocation = upstream.SourceLocation
	}

	return merged
}

// MergeTags merges two tag maps.
//
// Default: union of keys; upstream wins on key conflicts.
// prefer "current": union; current wins on key conflicts.
// prefer "upstream": upstream replaces all.
func MergeTags(current, upstream map[string]any, prefer string) map[string]any {
	if prefer == "upstream" {
		return copyTags(upstream)
	}

	merged := make(map[string]any)

	// Start with current
	for k, v := range current {
		merged[k] = v
	}

	// Apply upstream
	for k, v := range upstream {
		if prefer == "current" {
			// Only add if not already present from current
			if _, exists := merged[k]; !exists {
				merged[k] = v
			}
		} else {
			// Default: upstream wins on conflict
			merged[k] = v
		}
	}

	return merged
}

// MergeDescriptions merges two description arrays by label.
//
// Default: union by label; upstream wins on label conflicts.
// prefer "current": union; current wins on label conflicts.
// prefer "upstream": upstream replaces all.
func MergeDescriptions(current, upstream []hdf.Description, prefer string) []hdf.Description {
	if prefer == "upstream" {
		result := make([]hdf.Description, len(upstream))
		copy(result, upstream)
		return result
	}

	// Build a map by label, preserving order
	byLabel := make(map[string]hdf.Description)
	var order []string

	// Start with current
	for _, d := range current {
		byLabel[d.Label] = d
		order = append(order, d.Label)
	}

	// Apply upstream
	for _, d := range upstream {
		if _, exists := byLabel[d.Label]; exists {
			if prefer != "current" {
				// Default: upstream wins
				byLabel[d.Label] = d
			}
		} else {
			byLabel[d.Label] = d
			order = append(order, d.Label)
		}
	}

	result := make([]hdf.Description, 0, len(order))
	for _, label := range order {
		result = append(result, byLabel[label])
	}
	return result
}

// MergeRefs merges two reference arrays.
//
// Default: union, deduplicated by serialized JSON key.
// prefer "current": current only.
// prefer "upstream": upstream only.
func MergeRefs(current, upstream []hdf.Reference, prefer string) []hdf.Reference {
	switch prefer {
	case "current":
		if current == nil {
			return nil
		}
		result := make([]hdf.Reference, len(current))
		copy(result, current)
		return result
	case "upstream":
		if upstream == nil {
			return nil
		}
		result := make([]hdf.Reference, len(upstream))
		copy(result, upstream)
		return result
	default:
		// Union, deduplicated
		return unionRefs(current, upstream)
	}
}

func unionRefs(current, upstream []hdf.Reference) []hdf.Reference {
	seen := make(map[string]bool)
	var result []hdf.Reference

	addRef := func(r hdf.Reference) {
		key := refKey(r)
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}

	for _, r := range current {
		addRef(r)
	}
	for _, r := range upstream {
		addRef(r)
	}
	return result
}

func refKey(r hdf.Reference) string {
	data, _ := json.Marshal(r)
	return string(data)
}

func copyTags(tags map[string]any) map[string]any {
	if tags == nil {
		return map[string]any{}
	}
	result := make(map[string]any, len(tags))
	for k, v := range tags {
		result[k] = v
	}
	return result
}
