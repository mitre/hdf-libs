// Package hdfdoc holds small, cobra-free HDF-document mutation helpers shared by
// the CLI commands (package cmd) and the MCP server (internal/mcp) — both Go
// artifacts in this module. They live here, not in package cmd, so the MCP can
// reuse them without importing the cobra command surface (ADR-0007 §7). These
// are doc-type-agnostic map mutations on already-parsed HDF JSON; they are not
// converters and carry no cross-language parity obligation.
package hdfdoc

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// ErrNoComponents reports a document with no component to write the requested
// field on. It is wrapped as the PREFIX of the message naming the field, so
// every such refusal reads as one sentence; callers for which a componentless
// document is legitimate (a converter whose source names no target) match on it
// to warn instead of failing.
var ErrNoComponents = errors.New("document has no components")

// ApplyLabels merges the given labels into the "labels" field of every component
// in the HDF JSON document. With no labels, or no components array, the input is
// returned unchanged (not an error). Input is not schema-validated here — callers
// validate downstream — so a non-HDF-shaped doc passes through untouched.
func ApplyLabels(data []byte, labels map[string]string) ([]byte, error) {
	if len(labels) == 0 {
		return data, nil
	}

	doc, components, err := parseComponents(data)
	if err != nil {
		return nil, err
	}
	if components == nil {
		return data, nil
	}

	for _, target := range components {
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
// non-empty). A fixedID that is not a UUID is an error, and so is a document with
// no component to stamp — returning the input unchanged would report an id as
// attached when it was not. Asking for neither is a no-op on any document.
func ApplyComponentID(data []byte, fixedID string, generate bool) ([]byte, error) {
	if !generate && fixedID == "" {
		return data, nil
	}
	if !generate {
		if err := ValidateComponentID(fixedID); err != nil {
			return nil, err
		}
	}

	doc, components, err := parseComponents(data)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("%w to set componentId on", ErrNoComponents)
	}

	for _, comp := range components {
		if generate {
			comp["componentId"] = uuid.New().String()
		} else {
			comp["componentId"] = fixedID
		}
	}

	return json.MarshalIndent(doc, "", "  ")
}

// ApplyExternalIDs merges ids into the "externalIds" map of every component, or of
// the one component named componentName when it is non-empty. Unlike ApplyLabels it
// fails when there is nothing unambiguous to write on — a document with no
// components, or a name no component has or several share — so a caller cannot
// report an identifier as attached when it was not, or attach it more widely than
// it asked.
func ApplyExternalIDs(data []byte, ids map[string]string, componentName string) ([]byte, error) {
	if len(ids) == 0 {
		return data, nil
	}

	doc, components, err := parseComponents(data)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("%w to set external IDs on", ErrNoComponents)
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
// component, or on the one component named componentName. A scheme a component
// does not carry is ignored; a map left empty is dropped.
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

	components, err = ComponentMaps(list)
	if err != nil {
		return nil, nil, err
	}
	return doc, components, nil
}

// ComponentMaps types a document's decoded components array for the selector.
// The maps alias the array's own objects, so a caller that mutates one mutates
// the document.
func ComponentMaps(list []interface{}) ([]map[string]interface{}, error) {
	components := make([]map[string]interface{}, len(list))
	for i, cRaw := range list {
		comp, ok := cRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("component at index %d is not an object", i)
		}
		components[i] = comp
	}
	return components, nil
}

// NoSuchComponentError reports a component name no component in the document
// carries. It is typed so a command can add its own remedy to the message
// without re-implementing the match.
type NoSuchComponentError struct{ Name string }

func (e *NoSuchComponentError) Error() string {
	return fmt.Sprintf("no component named %q in the document", e.Name)
}

// SelectComponentByName returns the one component named name. A name no
// component has, or one several share, is an error: a name is a label and
// componentId is identity, so a repeated name names no single component and
// picking the first would act on a component the caller did not choose. Every
// command that selects a component by name goes through here, so they cannot
// drift into disagreeing about what an ambiguous name means.
func SelectComponentByName(components []map[string]interface{}, name string) (map[string]interface{}, error) {
	var selected []map[string]interface{}
	for _, comp := range components {
		if n, _ := comp["name"].(string); n == name {
			selected = append(selected, comp)
		}
	}
	if len(selected) == 0 {
		return nil, &NoSuchComponentError{Name: name}
	}
	if len(selected) > 1 {
		return nil, fmt.Errorf("component name %q matches %d components; it must match exactly one", name, len(selected))
	}
	return selected[0], nil
}

// selectComponents returns every component when name is empty, otherwise the one
// component with that name.
func selectComponents(components []map[string]interface{}, name string) ([]map[string]interface{}, error) {
	if name == "" {
		return components, nil
	}
	selected, err := SelectComponentByName(components, name)
	if err != nil {
		return nil, err
	}
	return []map[string]interface{}{selected}, nil
}
