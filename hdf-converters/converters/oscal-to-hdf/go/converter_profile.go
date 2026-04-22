package oscal

import (
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// ConvertProfileToHDF resolves an OSCAL Profile against a provided catalog and
// converts the result to an HDFBaseline. The profile's import directives select
// which controls from the catalog to include.
//
// This handles:
//   - A single catalog import
//   - include-controls with with-ids filtering
//   - alter directives (add/remove parts and props on controls)
//   - set-parameters from modify section
//   - merge as-is (preserve catalog structure)
//
// It does NOT handle:
//   - Multiple imports (returns an error with guidance)
//   - Nested profile imports (profile importing another profile)
//   - Complex merge strategies
//
// For full profile resolution, use NIST's oscal-cli or pre-resolved catalogs.
func ConvertProfileToHDF(profileInput, catalogInput []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	profileDoc, err := ParseOscalDocument(profileInput, "profile", "oscal-profile")
	if err != nil {
		return nil, err
	}
	profile := profileDoc.Profile

	catalogDoc, err := ParseOscalDocument(catalogInput, "catalog", "oscal-profile-catalog")
	if err != nil {
		return nil, err
	}
	catalog := catalogDoc.Catalog

	// Validate: single import only
	if len(profile.Imports) == 0 {
		return nil, fmt.Errorf("oscal-profile: profile has no imports")
	}
	if len(profile.Imports) > 1 {
		return nil, fmt.Errorf("oscal-profile: profile has %d imports — this converter only supports single-catalog imports. Use NIST's oscal-cli to resolve complex profiles, or use a pre-resolved catalog", len(profile.Imports))
	}

	// Collect included control IDs
	imp := profile.Imports[0]
	includedIDs := collectIncludedIDs(imp)

	// Collect excluded control IDs
	excludedIDs := collectExcludedIDs(imp)

	// Filter catalog
	resolvedCatalog := filterCatalog(catalog, includedIDs, excludedIDs)

	// Apply alter directives (add/remove parts and props on controls)
	if profile.Modify != nil && len(profile.Modify.Alters) > 0 {
		applyAlters(resolvedCatalog, profile.Modify.Alters)
	}

	// Apply parameter overrides from the profile's modify section
	if profile.Modify != nil {
		applyParameterOverrides(resolvedCatalog, profile.Modify.SetParameters)
	}

	// Resolve any remaining {{ insert: param }} placeholders using the
	// catalog's own parameter definitions (select choices, labels).
	resolveDefaultParams(resolvedCatalog)

	// Override metadata from profile (the resolved catalog should carry
	// the profile's metadata, not the source catalog's)
	resolvedCatalog.Metadata = profile.Metadata
	resolvedCatalog.UUID = profile.UUID

	// Compute checksum from the profile input (the profile is the authoritative
	// document; the catalog is a dependency)
	integrity := shared.InputIntegrity(profileInput)

	baseline, err := catalogToBaseline(resolvedCatalog, profileInput, converterVersion)
	if err != nil {
		return nil, fmt.Errorf("oscal-profile: %w", err)
	}

	// Override the integrity to be based on the profile input
	baseline.Integrity = integrity

	return baseline, nil
}

// collectIncludedIDs extracts all control IDs from an import's include-controls.
// Returns nil if no include-controls are specified (meaning include all).
func collectIncludedIDs(imp Import) map[string]bool {
	if len(imp.IncludeControls) == 0 {
		return nil // include all
	}

	ids := make(map[string]bool)
	for _, ic := range imp.IncludeControls {
		for _, id := range ic.WithIDs {
			ids[id] = true
		}
	}
	return ids
}

// collectExcludedIDs extracts all control IDs from an import's exclude-controls.
func collectExcludedIDs(imp Import) map[string]bool {
	if len(imp.ExcludeControls) == 0 {
		return nil
	}

	ids := make(map[string]bool)
	for _, ec := range imp.ExcludeControls {
		for _, id := range ec.WithIDs {
			ids[id] = true
		}
	}
	return ids
}

// filterCatalog creates a new catalog containing only the controls
// matching the include/exclude filters. If includedIDs is nil, all
// controls are included (minus any excludedIDs).
func filterCatalog(catalog *Catalog, includedIDs, excludedIDs map[string]bool) *Catalog {
	includeAll := includedIDs == nil

	result := &Catalog{
		UUID:       catalog.UUID,
		Metadata:   catalog.Metadata,
		BackMatter: catalog.BackMatter,
	}

	for _, group := range catalog.Groups {
		filtered := filterGroupControls(group, includedIDs, excludedIDs, includeAll)
		if len(filtered.Controls) > 0 {
			result.Groups = append(result.Groups, filtered)
		}
	}

	for _, ctrl := range catalog.Controls {
		if shouldIncludeControl(ctrl.ID, includedIDs, excludedIDs, includeAll) {
			filteredCtrl := filterControlEnhancements(ctrl, includedIDs, excludedIDs, includeAll)
			result.Controls = append(result.Controls, filteredCtrl)
		}
	}

	return result
}

// filterGroupControls filters controls within a group.
func filterGroupControls(group Group, includedIDs, excludedIDs map[string]bool, includeAll bool) Group {
	filtered := Group{
		ID:    group.ID,
		Class: group.Class,
		Title: group.Title,
		Props: group.Props,
		Parts: group.Parts,
	}

	for _, ctrl := range group.Controls {
		if shouldIncludeControl(ctrl.ID, includedIDs, excludedIDs, includeAll) {
			filteredCtrl := filterControlEnhancements(ctrl, includedIDs, excludedIDs, includeAll)
			filtered.Controls = append(filtered.Controls, filteredCtrl)
		}
	}

	return filtered
}

// filterControlEnhancements filters nested control enhancements.
func filterControlEnhancements(ctrl Control, includedIDs, excludedIDs map[string]bool, includeAll bool) Control {
	result := Control{
		ID:     ctrl.ID,
		Class:  ctrl.Class,
		Title:  ctrl.Title,
		Params: ctrl.Params,
		Props:  ctrl.Props,
		Links:  ctrl.Links,
		Parts:  ctrl.Parts,
	}

	for _, enh := range ctrl.Controls {
		if shouldIncludeControl(enh.ID, includedIDs, excludedIDs, includeAll) {
			result.Controls = append(result.Controls, enh)
		}
	}

	return result
}

// shouldIncludeControl determines if a control should be included based on
// include/exclude filters.
func shouldIncludeControl(id string, includedIDs, excludedIDs map[string]bool, includeAll bool) bool {
	if excludedIDs != nil && excludedIDs[id] {
		return false
	}
	if includeAll {
		return true
	}
	return includedIDs[id]
}

// applyParameterOverrides applies set-parameters from the profile's modify
// section to the resolved catalog's controls.
func applyParameterOverrides(catalog *Catalog, setParams []SetParameter) {
	if len(setParams) == 0 {
		return
	}

	// Build a param-id → values lookup
	overrides := make(map[string][]string, len(setParams))
	for _, sp := range setParams {
		overrides[sp.ParamID] = sp.Values
	}

	// Apply to all controls in groups
	for i := range catalog.Groups {
		for j := range catalog.Groups[i].Controls {
			applyParamOverridesToControl(&catalog.Groups[i].Controls[j], overrides)
			for k := range catalog.Groups[i].Controls[j].Controls {
				applyParamOverridesToControl(&catalog.Groups[i].Controls[j].Controls[k], overrides)
			}
		}
	}

	// Apply to top-level controls
	for i := range catalog.Controls {
		applyParamOverridesToControl(&catalog.Controls[i], overrides)
		for j := range catalog.Controls[i].Controls {
			applyParamOverridesToControl(&catalog.Controls[i].Controls[j], overrides)
		}
	}
}

// applyParamOverridesToControl replaces parameter prose with override values
// in the control's parts. Parameter references in OSCAL prose look like
// {{ insert: param, param-id }}. We replace these with the override values.
func applyParamOverridesToControl(ctrl *Control, overrides map[string][]string) {
	for i, param := range ctrl.Params {
		if values, ok := overrides[param.ID]; ok {
			// Update the param's label/guidelines to reflect the override
			ctrl.Params[i].Label = strings.Join(values, ", ")
		}
	}

	// Replace parameter insertions in prose
	for i := range ctrl.Parts {
		replaceParamInsertions(&ctrl.Parts[i], overrides)
	}
}

// replaceParamInsertions replaces {{ insert: param, <id> }} patterns in prose
// with the override values.
func replaceParamInsertions(part *Part, overrides map[string][]string) {
	if part.Prose != "" {
		part.Prose = substituteParams(part.Prose, overrides)
	}
	for i := range part.Parts {
		replaceParamInsertions(&part.Parts[i], overrides)
	}
}

// substituteParams replaces OSCAL parameter insertion patterns in text.
// Pattern: {{ insert: param, <param-id> }}
func substituteParams(text string, overrides map[string][]string) string {
	result := text
	for paramID, values := range overrides {
		// OSCAL uses {{ insert: param, param-id }} syntax
		placeholder := fmt.Sprintf("{{ insert: param, %s }}", paramID)
		replacement := strings.Join(values, ", ")
		result = strings.ReplaceAll(result, placeholder, replacement)
	}
	return result
}

// applyAlters applies alter directives to a resolved catalog.
// Each alter targets a control by ID and can add or remove parts and props.
func applyAlters(catalog *Catalog, alters []Alter) {
	for _, alter := range alters {
		ctrl := findControl(catalog, alter.ControlID)
		if ctrl == nil {
			continue // control not in resolved catalog (filtered out)
		}

		// Apply removes first (OSCAL processing order)
		for _, remove := range alter.Removes {
			if remove.ByID != "" {
				ctrl.Parts = removePartByID(ctrl.Parts, remove.ByID)
			}
			if remove.ByName != "" {
				ctrl.Props = removePropByName(ctrl.Props, remove.ByName)
			}
		}

		// Apply adds
		for _, add := range alter.Adds {
			if len(add.Props) > 0 {
				ctrl.Props = append(ctrl.Props, add.Props...)
			}
			if len(add.Parts) > 0 {
				if add.ByID != "" {
					// Add to a specific part identified by by-id
					addPartsToTarget(&ctrl.Parts, add.ByID, add.Parts, add.Position)
				} else {
					// Add directly to the control's parts
					ctrl.Parts = addPartsAtPosition(ctrl.Parts, add.Parts, add.Position)
				}
			}
		}
	}
}

// findControl locates a control by ID in the catalog (groups + top-level).
func findControl(catalog *Catalog, id string) *Control {
	for i := range catalog.Groups {
		for j := range catalog.Groups[i].Controls {
			if catalog.Groups[i].Controls[j].ID == id {
				return &catalog.Groups[i].Controls[j]
			}
			// Check enhancements
			for k := range catalog.Groups[i].Controls[j].Controls {
				if catalog.Groups[i].Controls[j].Controls[k].ID == id {
					return &catalog.Groups[i].Controls[j].Controls[k]
				}
			}
		}
	}
	for i := range catalog.Controls {
		if catalog.Controls[i].ID == id {
			return &catalog.Controls[i]
		}
		for j := range catalog.Controls[i].Controls {
			if catalog.Controls[i].Controls[j].ID == id {
				return &catalog.Controls[i].Controls[j]
			}
		}
	}
	return nil
}

// removePartByID removes a part (and its children) by ID from a parts tree.
func removePartByID(parts []Part, id string) []Part {
	var result []Part
	for _, p := range parts {
		if p.ID == id {
			continue // remove this part
		}
		p.Parts = removePartByID(p.Parts, id) // recurse into children
		result = append(result, p)
	}
	return result
}

// removePropByName removes all props matching a name.
func removePropByName(props []Property, name string) []Property {
	var result []Property
	for _, p := range props {
		if p.Name != name {
			result = append(result, p)
		}
	}
	return result
}

// addPartsToTarget finds a part by ID in the tree and adds child parts to it.
func addPartsToTarget(parts *[]Part, targetID string, newParts []Part, position string) {
	for i := range *parts {
		if (*parts)[i].ID == targetID {
			(*parts)[i].Parts = addPartsAtPosition((*parts)[i].Parts, newParts, position)
			return
		}
		// Recurse
		addPartsToTarget(&(*parts)[i].Parts, targetID, newParts, position)
	}
}

// resolveDefaultParams substitutes remaining {{ insert: param, X }} placeholders
// using the catalog's own parameter definitions. For params with select choices,
// produces "[Selection: <how-many>: choice1; choice2]". For params with only a
// label, produces "[Assignment: <label>]".
func resolveDefaultParams(catalog *Catalog) {
	defaults := collectParamDefaults(catalog)
	if len(defaults) == 0 {
		return
	}
	// Apply defaults to all controls (same walk as applyParameterOverrides)
	for i := range catalog.Groups {
		for j := range catalog.Groups[i].Controls {
			applyParamOverridesToControl(&catalog.Groups[i].Controls[j], defaults)
			for k := range catalog.Groups[i].Controls[j].Controls {
				applyParamOverridesToControl(&catalog.Groups[i].Controls[j].Controls[k], defaults)
			}
		}
	}
	for i := range catalog.Controls {
		applyParamOverridesToControl(&catalog.Controls[i], defaults)
		for j := range catalog.Controls[i].Controls {
			applyParamOverridesToControl(&catalog.Controls[i].Controls[j], defaults)
		}
	}
}

// collectParamDefaults builds a param-id → fallback-values map from the catalog's
// own parameter definitions. Profile set-parameters take precedence (applied first).
func collectParamDefaults(catalog *Catalog) map[string][]string {
	defaults := make(map[string][]string)
	var collectFromControls func(controls []Control)
	collectFromControls = func(controls []Control) {
		for _, ctrl := range controls {
			for _, param := range ctrl.Params {
				if param.Select != nil && len(param.Select.Choice) > 0 {
					howMany := param.Select.HowMany
					if howMany == "" {
						howMany = "one or more"
					}
					fallback := fmt.Sprintf("[Selection (%s): %s]", howMany, strings.Join(param.Select.Choice, "; "))
					defaults[param.ID] = []string{fallback}
				} else if param.Label != "" {
					defaults[param.ID] = []string{fmt.Sprintf("[Assignment: %s]", param.Label)}
				}
			}
			collectFromControls(ctrl.Controls)
		}
	}
	for _, group := range catalog.Groups {
		collectFromControls(group.Controls)
	}
	collectFromControls(catalog.Controls)
	return defaults
}

// addPartsAtPosition inserts parts at the specified position.
func addPartsAtPosition(existing, newParts []Part, position string) []Part {
	switch position {
	case "starting":
		return append(newParts, existing...)
	case "before":
		return append(newParts, existing...)
	case "ending", "":
		return append(existing, newParts...)
	case "after":
		return append(existing, newParts...)
	default:
		return append(existing, newParts...)
	}
}
