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
	for _, cr := range definitionImplementedRequirements(compDef) {
		requirements = append(requirements, implementedRequirementToBaselineRequirement(cr.Requirement, cr.Component))
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
// componentRequirement pairs an implemented requirement with the component that
// declares it. Two components may implement the same control, so the component
// is what keeps the resulting requirement IDs distinct.
type componentRequirement struct {
	Component   *Component
	Requirement *ImplementedRequirement
}

func definitionImplementedRequirements(compDef *ComponentDefinition) []componentRequirement {
	var out []componentRequirement
	for c := range compDef.Components {
		comp := &compDef.Components[c]
		for i := range comp.ControlImplementations {
			limitedIR := shared.LimitSliceWithWarning(comp.ControlImplementations[i].ImplementedRequirements, 0, "implemented requirement")
			for j := range limitedIR {
				out = append(out, componentRequirement{Component: comp, Requirement: &limitedIR[j]})
			}
		}
	}
	return out
}

// requirementID qualifies the control with the component's UUID. OSCAL requires
// both a uuid and a title on every component but only guarantees the uuid is
// unique, so a title would still collide when one product appears twice — which
// is the duplicate-ID defect this qualification exists to prevent. The title
// rides in a tag instead, so a reader still sees which component this is.
func requirementID(comp *Component, nistTag string) string {
	if comp == nil || comp.UUID == "" {
		return nistTag
	}
	return comp.UUID + "/" + nistTag
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
func implementedRequirementToBaselineRequirement(ir *ImplementedRequirement, comp *Component) hdf.BaselineRequirement {
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
	// The ID is component-qualified, so carry the component here too: the tag is
	// what a report shows, and it saves a consumer parsing the ID.
	if comp != nil {
		if comp.Title != "" {
			tags["component"] = comp.Title
		}
		if comp.UUID != "" {
			tags["componentUuid"] = comp.UUID
		}
	}

	return hdf.BaselineRequirement{
		ID:           requirementID(comp, nistTag),
		Title:        hdfutil.Ptr(nistTag),
		Impact:       0.5,
		Descriptions: descriptions,
		Tags:         tags,
	}
}
