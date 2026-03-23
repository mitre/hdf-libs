package cmd

import (
	"encoding/json"
	"fmt"

	validators "github.com/mitre/hdf-validators/go"
	"github.com/spf13/cobra"
)

// Global flag variables for validate command (used by runValidate).
var (
	schemaType string // "results", "baseline", "comparison", "system", "plan", or "amendments"
	quiet      bool
)

// NewValidateCmd creates a new validate command with fresh state.
func NewValidateCmd() *cobra.Command { //nolint:dupl // Cobra command setup; flags and args differ per command
	// Local flag variables for this command instance
	var (
		localSchemaType string
		localQuiet      bool
	)

	cmd := &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate an HDF file against the schema",
		Long: `Validate an HDF document against its JSON schema.

Supported types: results, baseline, comparison, system, plan, amendments.

Reads from stdin if file is '-' or omitted.

Examples:
  hdf validate results.json
  hdf validate baseline.json --type baseline
  hdf validate my-system.json --type system
  hdf validate scan-plan.json --type plan
  hdf validate waivers.json --type amendments
  hdf validate evidence.json --type evidence-package
  cat results.json | hdf validate -`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Sync local flags to global variables for runValidate
			schemaType = localSchemaType
			quiet = localQuiet

			files, err := expandGlobs(args)
			if err != nil {
				return err
			}
			if len(files) > 1 {
				return runValidateBulk(cmd, files)
			}
			return runValidate(cmd, args)
		},
	}

	cmd.Flags().StringVarP(&localSchemaType, "type", "t", "", "Schema type (auto-detected if omitted): results, baseline, comparison, system, plan, amendments, evidence-package")
	cmd.Flags().BoolVarP(&localQuiet, "quiet", "q", false, "Suppress output on success (exit code only)")

	return cmd
}

func runValidate(_ *cobra.Command, args []string) error {
	var filename string
	if len(args) == 0 || args[0] == "-" {
		filename = "-"
	} else {
		filename = args[0]
	}

	printDebug("Reading input")
	data, err := readInputFile(filename)
	if err != nil {
		return err
	}

	printDebug("Read %d bytes", len(data))

	// Auto-detect document type if --type not provided
	if schemaType == "" {
		schemaType = detectHDFDocumentType(data)
		printDebug("Auto-detected document type: %s", schemaType)
	}

	// Determine display name for output
	displayName := filename
	if filename == "-" {
		displayName = "<stdin>"
	}

	// Validate based on type
	var validationErr error
	switch schemaType {
	case "results":
		_, validationErr = parseHDFResults(data)
	case "baseline":
		_, validationErr = parseHDFBaseline(data)
	case "comparison", "system", "plan", "amendments", "evidence-package":
		result := validators.Validate(data, validators.SchemaType(schemaType))
		if !result.Valid {
			validationErr = fmt.Errorf("schema validation failed: %s", result.Error())
		}
	default:
		printError(fmt.Sprintf("Unknown schema type: %s", schemaType),
			"Use --type=results|baseline|comparison|system|plan|amendments|evidence-package")
		return fmt.Errorf("unknown schema type: %s", schemaType)
	}

	if validationErr != nil {
		if jsonOutput {
			result := map[string]interface{}{
				"valid": false,
				"file":  displayName,
				"type":  schemaType,
				"error": validationErr.Error(),
			}
			output, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(output))
		} else {
			printError(fmt.Sprintf("Validation failed for %s", displayName),
				fmt.Sprintf("Error: %v", validationErr),
				"Ensure the file conforms to the HDF schema")
		}
		return validationErr
	}

	// Success
	if jsonOutput {
		result := map[string]interface{}{
			"valid": true,
			"file":  displayName,
			"type":  schemaType,
		}
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	} else if !quiet {
		fmt.Printf("✓ %s is a valid HDF %s file\n", displayName, schemaType)
	}

	return nil
}

func runValidateBulk(cmd *cobra.Command, files []string) error {
	return runBulk(files, "validation", "validated", func(file string) error {
		return runValidate(cmd, []string{file})
	})
}
