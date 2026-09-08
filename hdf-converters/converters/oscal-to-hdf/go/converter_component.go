package oscal

import (
	"fmt"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertComponentDefinitionToHDF converts an OSCAL Component Definition document
// to an HDFBaseline. Each component's implemented-requirements become
// BaselineRequirements. If the document contains multiple components, only the
// first component is used for the baseline (components are grouped by name).
func ConvertComponentDefinitionToHDF(input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	compDef, comp, err := parseComponentDefinition(input)
	if err != nil {
		return nil, err
	}

	integrity := shared.InputIntegrity(input)
	meta := ExtractMetadata(compDef.Metadata)

	var requirements []hdf.BaselineRequirement
	for _, ir := range componentImplementedRequirements(comp) {
		requirements = append(requirements, implementedRequirementToBaselineRequirement(ir))
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
			Name:    "oscal-component-to-hdf",
			Version: converterVersion,
		},
	}

	return baseline, nil
}

// parseComponentDefinition applies the converter's guards and selects the
// component the baseline is built from: the first one. ConvertComponentDefinitionToHDF
// and ExpectedComponentDefinitionRequirementCount share it so they accept and
// reject exactly the same inputs.
func parseComponentDefinition(input []byte) (*ComponentDefinition, *Component, error) {
	doc, err := ParseOscalDocument(input, "component-definition", "oscal-component-definition")
	if err != nil {
		return nil, nil, err
	}
	compDef := doc.ComponentDefinition
	if len(compDef.Components) == 0 {
		return nil, nil, fmt.Errorf("oscal-component-definition: document contains no components")
	}
	return compDef, &compDef.Components[0], nil
}

// componentImplementedRequirements lists a component's implemented
// requirements across its control implementations, within the per-implementation
// cap. It is the single definition of the input-to-requirement relation: the
// conversion builds requirements from it and
// ExpectedComponentDefinitionRequirementCount counts it.
func componentImplementedRequirements(comp *Component) []*ImplementedRequirement {
	var out []*ImplementedRequirement
	for i := range comp.ControlImplementations {
		limitedIR := shared.LimitSliceWithWarning(comp.ControlImplementations[i].ImplementedRequirements, 0, "implemented requirement")
		for j := range limitedIR {
			out = append(out, &limitedIR[j])
		}
	}
	return out
}

// ExpectedComponentDefinitionRequirementCount states how many requirements a
// component definition must convert to: one per implemented requirement of the
// first component only, which is the component the conversion reads. Computed
// from the input alone, through the same selection the conversion uses.
func ExpectedComponentDefinitionRequirementCount(input []byte) (int, string, error) {
	const unit = "OSCAL implemented-requirements of the first component"
	_, comp, err := parseComponentDefinition(input)
	if err != nil {
		return 0, unit, err
	}
	return len(componentImplementedRequirements(comp)), unit, nil
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
