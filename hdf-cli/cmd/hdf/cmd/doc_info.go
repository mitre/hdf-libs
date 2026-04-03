package cmd

import (
	"encoding/json"
	"fmt"
)

// runDocInfo reads a JSON document, validates its type against allowedTypes,
// and either outputs it as JSON or calls the provided humanOutput function.
// This eliminates code duplication across system, plan, and evidence info commands.
func runDocInfo(filename, cmdName string, allowedTypes []string, humanOutput func(map[string]interface{}) error) error {
	data, err := readInputFile(filename)
	if err != nil {
		printError(err.Error())
		return err
	}

	if _, typeErr := requireDocumentType(data, allowedTypes, cmdName); typeErr != nil {
		return typeErr
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		printError(fmt.Sprintf("Failed to parse JSON: %v", err))
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	if jsonOutput {
		output, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(output))
		return nil
	}

	return humanOutput(doc)
}
