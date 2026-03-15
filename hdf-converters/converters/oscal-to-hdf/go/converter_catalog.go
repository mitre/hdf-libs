package oscal

import (
	"encoding/json"
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
)

// ConvertCatalogToHDF converts an OSCAL Catalog document to an HDFBaseline.
// Each control (including enhancements) becomes a BaselineRequirement.
// Groups map to RequirementGroups.
func ConvertCatalogToHDF(input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	var doc OscalDocument
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("oscal-catalog: failed to parse JSON: %w", err)
	}
	if doc.Catalog == nil {
		return nil, fmt.Errorf("oscal-catalog: input is not a catalog document (root key is not 'catalog')")
	}

	return catalogToBaseline(doc.Catalog, input, converterVersion)
}

// catalogToBaseline converts a parsed Catalog to HDFBaseline.
// This is the shared logic used by both the catalog converter and the profile
// resolver (which builds a filtered catalog first, then calls this).
func catalogToBaseline(catalog *Catalog, rawInput []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	checksum := shared.InputChecksum(rawInput)
	meta := ExtractMetadata(catalog.Metadata)

	var requirements []hdf.BaselineRequirement
	var groups []hdf.RequirementGroup

	for i := range catalog.Groups {
		group := &catalog.Groups[i]
		var reqIDs []string

		for j := range group.Controls {
			ctrl := &group.Controls[j]
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
				Title:        shared.Ptr(group.Title),
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
		Name:         catalogBaselineName(catalog),
		Title:        shared.Ptr(meta.Title),
		Version:      shared.Ptr(meta.Version),
		Status:       &status,
		Checksum:     checksum,
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
		Title:        shared.Ptr(ctrl.Title),
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

// catalogBaselineName derives a baseline name from catalog metadata.
func catalogBaselineName(catalog *Catalog) string {
	title := catalog.Metadata.Title
	if title == "" {
		return "oscal-catalog"
	}
	// Use a simplified kebab-case of the title
	name := strings.ToLower(title)
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, name)
	// Collapse consecutive dashes and trim
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}
