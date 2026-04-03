package cmd

import (
	"encoding/json"
	"fmt"
	"os"
)

// runGenericDocSet is a shared implementation for set commands across document types.
// It reads a JSON document, applies field updates, processes --unset flags,
// and writes the result back.
func runGenericDocSet(inputPath, outputPath string, unsetFields []string, requiredFields map[string]bool, updates map[string]string) error {
	data, err := os.ReadFile(inputPath) //nolint:gosec // CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read document: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse document: %w", err)
	}

	// Apply updates (skip empty values)
	for key, val := range updates {
		if val != "" {
			doc[key] = val
		}
	}

	// Process --unset flags (after sets, so --unset wins if both specified)
	for _, field := range unsetFields {
		if requiredFields[field] {
			return fmt.Errorf("cannot unset required field %q", field)
		}
		delete(doc, field)
	}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize document: %w", err)
	}

	target := inputPath
	if outputPath != "" {
		target = outputPath
	}

	if err := os.WriteFile(target, output, 0o600); err != nil {
		return fmt.Errorf("failed to write document: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Updated %s\n", target)
	return nil
}
