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

// ApplyComponentID sets componentId on every component in the HDF JSON document:
// a fresh UUID per component when generate is true, otherwise the fixedID (when
// non-empty). No components array is a no-op.
func ApplyComponentID(data []byte, fixedID string, generate bool) ([]byte, error) {
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
