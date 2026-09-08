package oscal

import (
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertCatalogToHDF converts an OSCAL Catalog document to an HDFBaseline.
// Each control (including enhancements) becomes a BaselineRequirement.
// Groups map to RequirementGroups.
func ConvertCatalogToHDF(input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	doc, err := ParseOscalDocument(input, "catalog", "oscal-catalog")
	if err != nil {
		return nil, err
	}

	return catalogToBaseline(doc.Catalog, input, converterVersion)
}

// ExpectedCatalogRequirementCount states how many requirements a catalog must
// convert to: every control in a group and every top-level control, each with
// its direct enhancements, within the per-group control cap. Computed from the
// input alone, through the same selection the conversion uses.
func ExpectedCatalogRequirementCount(input []byte) (int, string, error) {
	const unit = "OSCAL catalog controls at depth two"
	doc, err := ParseOscalDocument(input, "catalog", "oscal-catalog")
	if err != nil {
		return 0, unit, err
	}
	return selectCatalogControls(doc.Catalog).count(), unit, nil
}

// groupSelection is one group's selected controls, each parent immediately
// followed by its direct enhancements.
type groupSelection struct {
	group    *Group
	controls []*Control
}

// catalogSelection is the set of catalog controls that become requirements.
type catalogSelection struct {
	groups   []groupSelection
	topLevel []*Control
}

func (s catalogSelection) count() int {
	n := len(s.topLevel)
	for _, g := range s.groups {
		n += len(g.controls)
	}
	return n
}

// withEnhancements lists a control followed by its direct enhancements only:
// the conversion does not recurse deeper.
func withEnhancements(ctrl *Control) []*Control {
	out := []*Control{ctrl}
	for k := range ctrl.Controls {
		out = append(out, &ctrl.Controls[k])
	}
	return out
}

// selectCatalogControls is the single definition of the catalog's
// input-to-requirement relation: the conversion builds requirements from it
// and ExpectedCatalogRequirementCount counts it.
func selectCatalogControls(catalog *Catalog) catalogSelection {
	var sel catalogSelection
	for i := range catalog.Groups {
		group := &catalog.Groups[i]
		gs := groupSelection{group: group}
		limitedControls := shared.LimitSliceWithWarning(group.Controls, 0, "control")
		for j := range limitedControls {
			gs.controls = append(gs.controls, withEnhancements(&limitedControls[j])...)
		}
		sel.groups = append(sel.groups, gs)
	}
	for i := range catalog.Controls {
		sel.topLevel = append(sel.topLevel, withEnhancements(&catalog.Controls[i])...)
	}
	return sel
}

// catalogToBaseline converts a parsed Catalog to HDFBaseline.
// This is the shared logic used by both the catalog converter and the profile
// resolver (which builds a filtered catalog first, then calls this).
func catalogToBaseline(catalog *Catalog, rawInput []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	integrity := shared.InputIntegrity(rawInput)
	meta := ExtractMetadata(catalog.Metadata)

	var requirements []hdf.BaselineRequirement
	var groups []hdf.RequirementGroup

	sel := selectCatalogControls(catalog)
	for _, gs := range sel.groups {
		var reqIDs []string
		for _, ctrl := range gs.controls {
			req := controlToBaselineRequirement(ctrl)
			requirements = append(requirements, req)
			reqIDs = append(reqIDs, req.ID)
		}

		if len(reqIDs) > 0 {
			groups = append(groups, hdf.RequirementGroup{
				ID:           gs.group.ID,
				Title:        hdfutil.Ptr(gs.group.Title),
				Requirements: reqIDs,
			})
		}
	}

	// Top-level controls (outside groups)
	for _, ctrl := range sel.topLevel {
		requirements = append(requirements, controlToBaselineRequirement(ctrl))
	}

	status := "loaded"

	baseline := &hdf.HDFBaseline{
		Name:         ToKebabCase(catalog.Metadata.Title, "oscal-catalog"),
		Title:        hdfutil.Ptr(meta.Title),
		Version:      hdfutil.Ptr(meta.Version),
		Status:       &status,
		Integrity:    integrity,
		Requirements: requirements,
		Groups:       groups,
		Generator: &hdf.Generator{
			Name:    "oscal-catalog-to-hdf",
			Version: converterVersion,
		},
	}

	return baseline, nil
}

// controlToBaselineRequirement converts a single OSCAL Control to an HDF
// BaselineRequirement.
func controlToBaselineRequirement(ctrl *Control) hdf.BaselineRequirement {
	nistTag := ControlIDToNistTag(ctrl.ID)
	descriptions := buildCatalogDescriptions(ctrl)
	tags := buildCatalogTags(ctrl)

	// Determine severity/impact from props
	impact := catalogControlImpact(ctrl)

	req := hdf.BaselineRequirement{
		ID:           nistTag,
		Title:        hdfutil.Ptr(ctrl.Title),
		Impact:       impact,
		Descriptions: descriptions,
		Tags:         tags,
		ControlType:  shared.DeriveControlTypeFromTags([]string{nistTag}),
	}

	// FedRAMP rev5 marks mandatory controls in a baseline with prop[name=CORE,value=true].
	// Catalogs typically don't carry CORE props, but resolved profiles (distributed by
	// FedRAMP as catalogs) do. When present, map CORE=true to applicability=required.
	// Absence is intentionally left undefined; consumers may interpret omitted as required
	// by convention. We do NOT map non-CORE to "optional" because catalog-only inputs
	// omit the prop entirely on all controls, which would be misleading.
	if val, ok := ExtractPropValue(ctrl.Props, "CORE", ""); ok && val == "true" {
		req.Applicability = hdfutil.Ptr(hdf.Required)
	}

	return req
}

// buildCatalogDescriptions creates HDF Description entries from control parts.
func buildCatalogDescriptions(ctrl *Control) []hdf.Description {
	var descriptions []hdf.Description

	// Statement → default description
	statement := FlattenPartsByName(ctrl.Parts, "statement")
	if statement != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  statement,
		})
	} else {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  "",
		})
	}

	// Guidance → rationale
	guidance := FlattenPartsByName(ctrl.Parts, "guidance")
	if guidance != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "rationale",
			Data:  guidance,
		})
	}

	// Assessment objective → check
	check := FlattenPartsByName(ctrl.Parts, "assessment-objective")
	if check != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "check",
			Data:  check,
		})
	}

	return descriptions
}

// buildCatalogTags builds the tags map for an OSCAL catalog control.
func buildCatalogTags(ctrl *Control) map[string]interface{} {
	tags := make(map[string]interface{})

	nistTag := ControlIDToNistTag(ctrl.ID)
	tags["nist"] = []string{nistTag}

	if label, ok := ExtractPropValue(ctrl.Props, "label", ""); ok {
		tags["label"] = label
	}

	if sortID, ok := ExtractPropValue(ctrl.Props, "sort-id", ""); ok {
		tags["sort-id"] = sortID
	}

	return tags
}

// catalogControlImpact returns an impact value for a catalog control.
// Catalog controls don't inherently have severity, so we default to 0.5
// (medium). If a "priority" or "baselines" prop exists, we could derive
// impact, but the standard catalog doesn't carry this.
func catalogControlImpact(_ *Control) float64 {
	return 0.5
}
