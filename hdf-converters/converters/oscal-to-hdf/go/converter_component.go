package oscal

import (
	"encoding/json"
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
)

// ConvertComponentDefinitionToHDF converts an OSCAL Component Definition document
// to an HDFBaseline. Each component's implemented-requirements become
// BaselineRequirements. If the document contains multiple components, only the
// first component is used for the baseline (components are grouped by name).
func ConvertComponentDefinitionToHDF(input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	var doc OscalDocument
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("oscal-component-definition: failed to parse JSON: %w", err)
	}
	if doc.ComponentDefinition == nil {
		return nil, fmt.Errorf("oscal-component-definition: input is not a component-definition document (root key is not 'component-definition')")
	}

	compDef := doc.ComponentDefinition

	if len(compDef.Components) == 0 {
		return nil, fmt.Errorf("oscal-component-definition: document contains no components")
	}

	checksum := shared.InputChecksum(input)
	meta := ExtractMetadata(compDef.Metadata)

	// Use the first component to build the baseline
	comp := compDef.Components[0]

	var requirements []hdf.BaselineRequirement

	for _, ci := range comp.ControlImplementations {
		for _, ir := range ci.ImplementedRequirements {
			req := implementedRequirementToBaselineRequirement(&ir)
			requirements = append(requirements, req)
		}
	}

	baselineName := componentBaselineName(comp, compDef)
	status := "loaded"

	baseline := &hdf.HDFBaseline{
		Name:         baselineName,
		Title:        shared.Ptr(meta.Title),
		Version:      shared.Ptr(meta.Version),
		Status:       &status,
		Checksum:     checksum,
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
		Title:        shared.Ptr(nistTag),
		Impact:       0.5,
		Descriptions: descriptions,
		Tags:         tags,
	}
}

// componentBaselineName derives a baseline name from the component or
// component-definition metadata.
func componentBaselineName(comp Component, compDef *ComponentDefinition) string {
	name := comp.Title
	if name == "" {
		name = compDef.Metadata.Title
	}
	if name == "" {
		return "oscal-component-definition"
	}

	// Use a simplified kebab-case of the name
	result := strings.ToLower(name)
	result = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, result)
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	result = strings.Trim(result, "-")
	if len(result) > 80 {
		result = result[:80]
	}
	return result
}
