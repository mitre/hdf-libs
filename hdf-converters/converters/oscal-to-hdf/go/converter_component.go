package oscal

import (
	"fmt"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	hdf "github.com/mitre/hdf-schema"
)

// ConvertComponentDefinitionToHDF converts an OSCAL Component Definition document
// to an HDFBaseline. Each component's implemented-requirements become
// BaselineRequirements. If the document contains multiple components, only the
// first component is used for the baseline (components are grouped by name).
func ConvertComponentDefinitionToHDF(input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	doc, err := ParseOscalDocument(input, "component-definition", "oscal-component-definition")
	if err != nil {
		return nil, err
	}

	compDef := doc.ComponentDefinition

	if len(compDef.Components) == 0 {
		return nil, fmt.Errorf("oscal-component-definition: document contains no components")
	}

	integrity := shared.InputIntegrity(input)
	meta := ExtractMetadata(compDef.Metadata)

	// Use the first component to build the baseline
	comp := compDef.Components[0]

	var requirements []hdf.BaselineRequirement

	for _, ci := range comp.ControlImplementations {
		limitedIR := shared.LimitSliceWithWarning(ci.ImplementedRequirements, 0, "implemented requirement")
		for _, ir := range limitedIR {
			req := implementedRequirementToBaselineRequirement(&ir)
			requirements = append(requirements, req)
		}
	}

	name := comp.Title
	if name == "" {
		name = compDef.Metadata.Title
	}
	baselineName := ToKebabCase(name, "oscal-component-definition")
	status := "loaded"

	baseline := &hdf.HDFBaseline{
		Name:         baselineName,
		Title:        hdfutil.Ptr(meta.Title),
		Version:      hdfutil.Ptr(meta.Version),
		Status:       &status,
		Integrity:    integrity,
		Requirements: requirements,
		Generator: &hdf.Generator{
			Name:    "hdf-converters",
			Version: converterVersion,
		},
	}

	return baseline, nil
}

// implementedRequirementToBaselineRequirement converts a single OSCAL
// ImplementedRequirement to an HDF BaselineRequirement.
func implementedRequirementToBaselineRequirement(ir *ImplementedRequirement) hdf.BaselineRequirement {
	nistTag := ControlIDToNistTag(ir.ControlID)

	var descriptions []hdf.Description

	// Primary description from the implemented-requirement
	if ir.Description != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  ir.Description,
		})
	} else {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  "",
		})
	}

	// Add statement prose as additional descriptions
	for _, stmt := range ir.Statements {
		if stmt.Description != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: stmt.StatementID,
				Data:  stmt.Description,
			})
		}
		if stmt.Remarks != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: stmt.StatementID + "-remarks",
				Data:  stmt.Remarks,
			})
		}
	}

	tags := map[string]interface{}{
		"nist": []string{nistTag},
	}

	return hdf.BaselineRequirement{
		ID:           nistTag,
		Title:        hdfutil.Ptr(nistTag),
		Impact:       0.5,
		Descriptions: descriptions,
		Tags:         tags,
	}
}
