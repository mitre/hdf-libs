package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/atomicfile"
)

// stdinInput is the positional spelling that reads a document from stdin.
const stdinInput = "-"

// stdinNeedsOutput names what -o must give: <file>, or <dir> for a multi-file writer.
func stdinNeedsOutput(noun, operand string) error {
	return fmt.Errorf("reading the %s from stdin requires -o %s", noun, operand)
}

// requireOutputForStdin refuses to write a document read from stdin anywhere but -o: the
// positional would otherwise become the write target, a regular file literally named "-".
func requireOutputForStdin(input, output, noun string) error {
	if input == stdinInput && output == "" {
		return stdinNeedsOutput(noun, "<file>")
	}
	return nil
}

// runGenericDocSet is a shared implementation for set commands across document
// types. It reads a JSON document, schema-validates against the caller-declared
// expectedDocType ("plan", "evidence-package", "amendments", "system"), applies
// field updates, processes --unset flags, and writes the result back.
func runGenericDocSet(inputPath, outputPath, expectedDocType string, unsetFields []string, requiredFields map[string]bool, updates map[string]string) error {
	if err := requireOutputForStdin(inputPath, outputPath, "document"); err != nil {
		return err
	}
	data, err := readInputFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read document: %w", err)
	}

	doc, err := loadAndValidateHDFDoc(data, expectedDocType)
	if err != nil {
		return fmt.Errorf("document %s: %w", inputPath, err)
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

	if err := validateHDFDocument(output); err != nil {
		return fmt.Errorf("document failed validation before write: %w", err)
	}

	target := inputPath
	if outputPath != "" {
		target = outputPath
	}

	if err := atomicfile.WriteFile(target, output, 0o600); err != nil {
		return fmt.Errorf("failed to write document: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Updated %s\n", target)
	return nil
}
