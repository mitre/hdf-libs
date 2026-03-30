package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newPlanSetCmd() *cobra.Command {
	var (
		name        string
		description string
		planID      string
		systemRef   string
		planVersion string
		outputPath  string
		unsetFields []string
	)

	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Set, update, or unset top-level fields on an HDF plan document",
		Long: `Set, update, or remove top-level metadata fields on an existing HDF plan document.
Reads the file, applies the specified changes, and writes it back (or to -o).

Use --unset to remove optional fields. Required fields (name, assessments) cannot be unset.

Examples:
  hdf plan set plan.json --name "Q2 Assessment"
  hdf plan set plan.json --description "Monthly compliance scan"
  hdf plan set plan.json --plan-id "550e8400-e29b-41d4-a716-446655440000"
  hdf plan set plan.json --system-ref portal-prod.hdf-system.json
  hdf plan set plan.json --unset description --version "2.0.0"
  hdf plan set plan.json --name "New Name" -o updated.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if name == "" && description == "" && planID == "" && systemRef == "" && planVersion == "" && len(unsetFields) == 0 {
				return fmt.Errorf("at least one field flag is required (--name, --description, --plan-id, --system-ref, --version, --unset)")
			}
			return runPlanSet(args[0], outputPath, name, description, planID, systemRef, planVersion, unsetFields)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Plan name")
	cmd.Flags().StringVar(&description, "description", "", "Plan description")
	cmd.Flags().StringVar(&planID, "plan-id", "", "Plan UUID")
	cmd.Flags().StringVar(&systemRef, "system-ref", "", "URI to the target HDF system document")
	cmd.Flags().StringVar(&planVersion, "version", "", "Plan document version")
	cmd.Flags().StringArrayVar(&unsetFields, "unset", nil, "Remove a field (repeatable; e.g. --unset description)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
}

// requiredPlanFields cannot be removed with --unset.
var requiredPlanFields = map[string]bool{
	"name":        true,
	"assessments": true,
}

func runPlanSet(inputPath, outputPath, name, description, planID, systemRef, planVersion string, unsetFields []string) error {
	data, err := os.ReadFile(inputPath) //nolint:gosec // CLI reads user-provided file path
	if err != nil {
		return fmt.Errorf("failed to read plan document: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse plan document: %w", err)
	}

	if name != "" {
		doc["name"] = name
	}
	if description != "" {
		doc["description"] = description
	}
	if planID != "" {
		doc["planId"] = planID
	}
	if systemRef != "" {
		doc["systemRef"] = systemRef
	}
	if planVersion != "" {
		doc["version"] = planVersion
	}

	// Process --unset flags (after sets, so --unset wins if both specified)
	for _, field := range unsetFields {
		if requiredPlanFields[field] {
			return fmt.Errorf("cannot unset required field %q", field)
		}
		delete(doc, field)
	}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize plan document: %w", err)
	}

	target := inputPath
	if outputPath != "" {
		target = outputPath
	}

	if err := os.WriteFile(target, output, 0o600); err != nil {
		return fmt.Errorf("failed to write plan document: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Updated %s\n", target)
	return nil
}
