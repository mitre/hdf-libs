package oscal

import (
	"encoding/json"
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
)

// ConvertProfileToHDF resolves an OSCAL Profile against a provided catalog and
// converts the result to an HDFBaseline. The profile's import directives select
// which controls from the catalog to include.
//
// This implements the "simple resolver" — it handles:
//   - A single catalog import
//   - include-controls with with-ids filtering
//   - set-parameters from modify section
//   - merge as-is (preserve catalog structure)
//
// It does NOT handle:
//   - Multiple imports (returns an error with guidance)
//   - Nested profile imports (profile importing another profile)
//   - alter directives (add/remove parts or props)
//   - Complex merge strategies
//
// For full profile resolution, use NIST's oscal-cli or pre-resolved catalogs.
func ConvertProfileToHDF(profileInput, catalogInput []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	if len(profileInput) == 0 {
		return nil, fmt.Errorf("empty profile input")
	}
	if len(catalogInput) == 0 {
		return nil, fmt.Errorf("empty catalog input")
	}

	// Parse profile
	var profileDoc OscalDocument
	if err := json.Unmarshal(profileInput, &profileDoc); err != nil {
		return nil, fmt.Errorf("oscal-profile: failed to parse profile JSON: %w", err)
	}
	if profileDoc.Profile == nil {
		return nil, fmt.Errorf("oscal-profile: input is not a profile document (root key is not 'profile')")
	}
	profile := profileDoc.Profile

	// Parse catalog
	var catalogDoc OscalDocument
	if err := json.Unmarshal(catalogInput, &catalogDoc); err != nil {
		return nil, fmt.Errorf("oscal-profile: failed to parse catalog JSON: %w", err)
	}
	if catalogDoc.Catalog == nil {
		return nil, fmt.Errorf("oscal-profile: catalog input is not a catalog document (root key is not 'catalog')")
	}
	catalog := catalogDoc.Catalog

	// Validate: single import only
	if len(profile.Imports) == 0 {
		return nil, fmt.Errorf("oscal-profile: profile has no imports")
	}
	if len(profile.Imports) > 1 {
		return nil, fmt.Errorf("oscal-profile: profile has %d imports — this converter only supports single-catalog imports. Use NIST's oscal-cli to resolve complex profiles, or use a pre-resolved catalog", len(profile.Imports))
	}

	// Validate: no alter directives
	if profile.Modify != nil && len(profile.Modify.Alters) > 0 {
		return nil, fmt.Errorf("oscal-profile: profile contains %d alter directives — this converter only supports parameter overrides. Use NIST's oscal-cli to resolve profiles with alter directives, or use a pre-resolved catalog", len(profile.Modify.Alters))
	}

	// Collect included control IDs
	imp := profile.Imports[0]
	includedIDs := collectIncludedIDs(imp)

	// Collect excluded control IDs
	excludedIDs := collectExcludedIDs(imp)

	// Filter catalog
	resolvedCatalog := filterCatalog(catalog, includedIDs, excludedIDs)

	// Apply parameter overrides
	if profile.Modify != nil {
		applyParameterOverrides(resolvedCatalog, profile.Modify.SetParameters)
	}

	// Override metadata from profile (the resolved catalog should carry
	// the profile's metadata, not the source catalog's)
	resolvedCatalog.Metadata = profile.Metadata
	resolvedCatalog.UUID = profile.UUID

	// Compute checksum from the profile input (the profile is the authoritative
	// document; the catalog is a dependency)
	checksum := shared.InputChecksum(profileInput)

	baseline, err := catalogToBaseline(resolvedCatalog, profileInput, converterVersion)
	if err != nil {
		return nil, fmt.Errorf("oscal-profile: %w", err)
	}

	// Override the checksum to be based on the profile input
	baseline.Checksum = checksum

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
