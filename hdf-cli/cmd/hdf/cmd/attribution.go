package cmd

import (
	"encoding/json"
	"fmt"
)

// attributionInputObject reads the JSON object to write from exactly one of
// --data (inline) or --file (path), shared by `hdf target set` and
// `hdf passthrough set`. The value must be a JSON object (the elements these
// commands manage are objects), never an array or scalar.
func attributionInputObject(dataFlag, fileFlag string) (map[string]any, error) {
	switch {
	case dataFlag != "" && fileFlag != "":
		return nil, fmt.Errorf("provide only one of --data or --file, not both")
	case dataFlag == "" && fileFlag == "":
		return nil, fmt.Errorf("provide the content with --data '<json>' or --file <path>")
	}

	raw := []byte(dataFlag)
	if fileFlag != "" {
		b, err := readInputFile(fileFlag) // size-guarded like every other read
		if err != nil {
			return nil, fmt.Errorf("failed to read --file: %w", err)
		}
		raw = b
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("content must be a JSON object: %w", err)
	}
	return obj, nil
}

// extractSubMap navigates a chain of object keys in the document bytes and
// returns the final nested object, or nil if any key along the path is absent
// or not an object. Read-only; used by the attribution get commands.
func extractSubMap(data []byte, keys ...string) (map[string]any, error) {
	var cur map[string]any
	if err := json.Unmarshal(data, &cur); err != nil {
		return nil, fmt.Errorf("input is not a JSON object: %w", err)
	}
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, nil
		}
		cur = next
	}
	return cur, nil
}
