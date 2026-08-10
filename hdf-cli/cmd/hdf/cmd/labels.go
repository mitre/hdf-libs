package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseLabelsFlag parses a slice of "key=value" strings into a map.
// Returns an error if any entry does not contain an "=" sign.
func parseLabelsFlag(pairs []string) (map[string]string, error) {
	labels := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid label %q: must be in key=value format", pair)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("invalid label %q: key must not be empty", pair)
		}
		labels[key] = value
	}
	return labels, nil
}

// removeLabels removes the specified keys from the "labels" field of every
// target in the HDF JSON document. Missing keys are silently ignored.
func removeLabels(data []byte, keys []string) ([]byte, error) {
	if len(keys) == 0 {
		return data, nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse JSON for label removal: %w", err)
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

		labelsRaw, ok := target["labels"]
		if !ok {
			continue
		}
		labelsMap, ok := labelsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for _, key := range keys {
			delete(labelsMap, key)
		}
		target["labels"] = labelsMap
	}

	return json.MarshalIndent(doc, "", "  ")
}

// extractComponentLabels extracts component names, types, and labels from an HDF
// JSON document. Returns a slice of component summaries for display.
type componentLabelInfo struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

func extractComponentLabels(data []byte) ([]componentLabelInfo, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	componentsRaw, ok := doc["components"]
	if !ok {
		return nil, nil
	}

	components, ok := componentsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("components field is not an array")
	}

	result := make([]componentLabelInfo, 0, len(components))
	for i, cRaw := range components {
		comp, ok := cRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("component at index %d is not an object", i)
		}

		info := componentLabelInfo{
			Labels: make(map[string]string),
		}

		if name, ok := comp["name"].(string); ok {
			info.Name = name
		}
		if typ, ok := comp["type"].(string); ok {
			info.Type = typ
		}

		if labelsRaw, ok := comp["labels"]; ok {
			if labelsMap, ok := labelsRaw.(map[string]interface{}); ok {
				for k, v := range labelsMap {
					if vs, ok := v.(string); ok {
						info.Labels[k] = vs
					} else {
						info.Labels[k] = fmt.Sprintf("%v", v)
					}
				}
			}
		}

		result = append(result, info)
	}

	return result, nil
}
