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

// catalogToBaseline converts a parsed Catalog to HDFBaseline.
// This is the shared logic used by both the catalog converter and the profile
// resolver (which builds a filtered catalog first, then calls this).
func catalogToBaseline(catalog *Catalog, rawInput []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	integrity := shared.InputIntegrity(rawInput)
	meta := ExtractMetadata(catalog.Metadata)

	var requirements []hdf.BaselineRequirement
	var groups []hdf.RequirementGroup

	for i := range catalog.Groups {
		group := &catalog.Groups[i]
		var reqIDs []string

		limitedControls := shared.LimitSliceWithWarning(group.Controls, 0, "control")
		for j := range limitedControls {
			ctrl := &limitedControls[j]
			req := controlToBaselineRequirement(ctrl)
			requirements = append(requirements, req)
			reqIDs = append(reqIDs, req.ID)

			// Include control enhancements
			for k := range ctrl.Controls {
				enh := &ctrl.Controls[k]
				enhReq := controlToBaselineRequirement(enh)
				requirements = append(requirements, enhReq)
				reqIDs = append(reqIDs, enhReq.ID)
			}
		}

		if len(reqIDs) > 0 {
			groups = append(groups, hdf.RequirementGroup{
				ID:           group.ID,
				Title:        hdfutil.Ptr(group.Title),
				Requirements: reqIDs,
			})
		}
	}

	// Top-level controls (outside groups)
	for i := range catalog.Controls {
		ctrl := &catalog.Controls[i]
		req := controlToBaselineRequirement(ctrl)
		requirements = append(requirements, req)

		for j := range ctrl.Controls {
			enh := &ctrl.Controls[j]
			enhReq := controlToBaselineRequirement(enh)
			requirements = append(requirements, enhReq)
		}
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
			Name:    "hdf-converters",
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

	return hdf.BaselineRequirement{
		ID:           nistTag,
		Title:        hdfutil.Ptr(ctrl.Title),
		Impact:       impact,
		Descriptions: descriptions,
		Tags:         tags,
	}
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
