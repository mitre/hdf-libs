// Package hdfdoc holds small, cobra-free HDF-document mutation helpers shared by
// the CLI commands (package cmd) and the MCP server (internal/mcp) — both Go
// artifacts in this module. They live here, not in package cmd, so the MCP can
// reuse them without importing the cobra command surface (ADR-0007 §7). These
// are doc-type-agnostic map mutations on already-parsed HDF JSON; they are not
// converters and carry no cross-language parity obligation.
package hdfdoc

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// ApplyLabels merges the given labels into the "labels" field of every component
// in the HDF JSON document. With no labels, or no components array, the input is
// returned unchanged (not an error). Input is not schema-validated here — callers
// validate downstream — so a non-HDF-shaped doc passes through untouched.
func ApplyLabels(data []byte, labels map[string]string) ([]byte, error) {
	if len(labels) == 0 {
		return data, nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse JSON for label application: %w", err)
	}

	targetsRaw, ok := doc["components"]
	if !ok {
		return data, nil
	}

	targets, ok := targetsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("targets field is not an array")
	}

	for i, tRaw := range targets {
		target, ok := tRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("target at index %d is not an object", i)
		}

		existing := make(map[string]interface{})
		if labelsRaw, ok := target["labels"]; ok {
			if labelsMap, ok := labelsRaw.(map[string]interface{}); ok {
				existing = labelsMap
			}
		}

		for k, v := range labels {
			existing[k] = v
		}
		target["labels"] = existing
	}

	return json.MarshalIndent(doc, "", "  ")
}

// ValidateComponentID rejects an id the schema's `format: uuid` would reject.
func ValidateComponentID(id string) error {
	if !validators.IsUUID(id) {
		return fmt.Errorf("componentId %q is not a valid UUID (RFC 4122, e.g. 3f2504e0-4f89-11d3-9a0c-0305e82c3301)", id)
	}
	return nil
}

// ApplyComponentID sets componentId on every component in the HDF JSON document:
// a fresh UUID per component when generate is true, otherwise the fixedID (when
// non-empty). A fixedID that is not a UUID is an error; no components array is a
// no-op.
func ApplyComponentID(data []byte, fixedID string, generate bool) ([]byte, error) {
	if !generate && fixedID != "" {
		if err := ValidateComponentID(fixedID); err != nil {
			return nil, err
		}
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	componentsRaw, ok := doc["components"]
	if !ok {
		return data, nil
	}
	components, ok := componentsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("components field is not an array")
	}

	for _, cRaw := range components {
		comp, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if generate {
			comp["componentId"] = uuid.New().String()
		} else if fixedID != "" {
			comp["componentId"] = fixedID
		}
	}

	return json.MarshalIndent(doc, "", "  ")
}

// ApplyExternalIDs merges ids into the "externalIds" map of every component, or of
// the components named componentName when it is non-empty. Unlike ApplyLabels it
// fails when there is nothing to write on — a document with no components, or no
// component by that name — so a caller cannot report an identifier as attached
// when it was not.
func ApplyExternalIDs(data []byte, ids map[string]string, componentName string) ([]byte, error) {
	if len(ids) == 0 {
		return data, nil
	}

	doc, components, err := parseComponents(data)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("document has no components to set external IDs on")
	}

	selected, err := selectComponents(components, componentName)
	if err != nil {
		return nil, err
	}
	for _, comp := range selected {
		existing, ok := comp["externalIds"].(map[string]interface{})
		if !ok {
			existing = make(map[string]interface{}, len(ids))
		}
		for scheme, value := range ids {
			existing[scheme] = value
		}
		comp["externalIds"] = existing
	}

	return json.MarshalIndent(doc, "", "  ")
}

// RemoveExternalIDs deletes the given schemes from "externalIds" on every
// component, or on the components named componentName. A scheme a component does
// not carry is ignored; a map left empty is dropped.
func RemoveExternalIDs(data []byte, schemes []string, componentName string) ([]byte, error) {
	if len(schemes) == 0 {
		return data, nil
	}

	doc, components, err := parseComponents(data)
	if err != nil {
		return nil, err
	}
	if components == nil {
		return data, nil
	}

	selected, err := selectComponents(components, componentName)
	if err != nil {
		return nil, err
	}
	for _, comp := range selected {
		existing, ok := comp["externalIds"].(map[string]interface{})
		if !ok {
			continue
		}
		for _, scheme := range schemes {
			delete(existing, scheme)
		}
		if len(existing) == 0 {
			delete(comp, "externalIds")
		}
	}

	return json.MarshalIndent(doc, "", "  ")
}

// parseComponents decodes the document and its components array. components is
// nil when the document has no "components" field.
func parseComponents(data []byte) (doc map[string]interface{}, components []map[string]interface{}, err error) {
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	raw, ok := doc["components"]
	if !ok {
		return doc, nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("components field is not an array")
	}

	components = make([]map[string]interface{}, len(list))
	for i, cRaw := range list {
		comp, ok := cRaw.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("component at index %d is not an object", i)
		}
		components[i] = comp
	}
	return doc, components, nil
}

// selectComponents returns every component when name is empty, otherwise the
// components with that name, and an error when none has it.
func selectComponents(components []map[string]interface{}, name string) ([]map[string]interface{}, error) {
	if name == "" {
		return components, nil
	}

	var selected []map[string]interface{}
	for _, comp := range components {
		if n, _ := comp["name"].(string); n == name {
			selected = append(selected, comp)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no component named %q in the document", name)
	}
	return selected, nil
}
