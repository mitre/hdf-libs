package oscal

import (
	"fmt"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertComponentDefinitionToHDF converts an OSCAL Component Definition document
// to an HDFBaseline. Every component's implemented-requirements become
// BaselineRequirements, in document order.
func ConvertComponentDefinitionToHDF(input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	compDef, err := parseComponentDefinition(input)
	if err != nil {
		return nil, err
	}

	integrity := shared.InputIntegrity(input)
	meta := ExtractMetadata(compDef.Metadata)

	var requirements []hdf.BaselineRequirement
	for _, ir := range definitionImplementedRequirements(compDef) {
		requirements = append(requirements, implementedRequirementToBaselineRequirement(ir))
	}

	// A single-component definition is named for its component; a multi-component
	// one for the definition itself.
	name := compDef.Metadata.Title
	if len(compDef.Components) == 1 && compDef.Components[0].Title != "" {
		name = compDef.Components[0].Title
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

// parseComponentDefinition applies the converter's guards.
// ConvertComponentDefinitionToHDF and ExpectedComponentDefinitionRequirementCount
// share it so they accept and reject exactly the same inputs.
func parseComponentDefinition(input []byte) (*ComponentDefinition, error) {
	doc, err := ParseOscalDocument(input, "component-definition", "oscal-component-definition")
	if err != nil {
		return nil, err
	}
	compDef := doc.ComponentDefinition
	if len(compDef.Components) == 0 {
		return nil, fmt.Errorf("oscal-component-definition: document contains no components")
	}
	return compDef, nil
}

// definitionImplementedRequirements lists every component's implemented
// requirements across its control implementations, in document order and within
// the per-implementation cap. It is the single definition of the
// input-to-requirement relation: the conversion builds requirements from it and
// ExpectedComponentDefinitionRequirementCount counts it.
func definitionImplementedRequirements(compDef *ComponentDefinition) []*ImplementedRequirement {
	var out []*ImplementedRequirement
	for c := range compDef.Components {
		comp := &compDef.Components[c]
		for i := range comp.ControlImplementations {
			limitedIR := shared.LimitSliceWithWarning(comp.ControlImplementations[i].ImplementedRequirements, 0, "implemented requirement")
			for j := range limitedIR {
				out = append(out, &limitedIR[j])
			}
		}
	}
	return out
}

// ExpectedComponentDefinitionRequirementCount states how many requirements a
// component definition must convert to: one per implemented requirement across
// every component. Computed from the input alone, through the same walk the
// conversion uses.
func ExpectedComponentDefinitionRequirementCount(input []byte) (int, string, error) {
	const unit = "OSCAL implemented-requirements across all components"
	compDef, err := parseComponentDefinition(input)
	if err != nil {
		return 0, unit, err
	}
	return len(definitionImplementedRequirements(compDef)), unit, nil
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
