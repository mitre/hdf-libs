package cmd

import (
	"encoding/json"
	"fmt"
	"os"

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
	var validationResult *validators.ValidationResult
	switch schemaType {
	case "results":
		_, err := parseHDFResults(data)
		if err != nil {
			validationResult = &validators.ValidationResult{
				Valid:  false,
				Errors: []validators.ValidationError{{Field: "(parse)", Description: err.Error()}},
			}
		}
	case "baseline":
		_, err := parseHDFBaseline(data)
		if err != nil {
			validationResult = &validators.ValidationResult{
				Valid:  false,
				Errors: []validators.ValidationError{{Field: "(parse)", Description: err.Error()}},
			}
		}
	case "comparison", "system", "plan", "amendments", "evidence-package":
		result := validators.Validate(data, validators.SchemaType(schemaType))
		if !result.Valid {
			validationResult = &result
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown schema type: %s\n", schemaType)
		fmt.Fprintf(os.Stderr, "  Use --type=results|baseline|comparison|system|plan|amendments|evidence-package\n")
		return &exitCodeError{code: 1, message: fmt.Sprintf("unknown schema type: %s", schemaType)}
	}

	if validationResult != nil && !validationResult.Valid {
		if jsonOutput {
			result := map[string]interface{}{
				"valid":  false,
				"file":   displayName,
				"type":   schemaType,
				"errors": validationResult.Errors,
			}
			output, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(output))
		} else {
			fmt.Fprintf(os.Stderr, "✗ %s — not a valid HDF %s document\n", displayName, schemaType)
			fmt.Fprintf(os.Stderr, "\n  Errors:\n")
			for _, e := range validationResult.Errors {
				if e.Field != "" && e.Field != "(parse)" {
					fmt.Fprintf(os.Stderr, "    %s: %s\n", e.Field, e.Description)
				} else {
					fmt.Fprintf(os.Stderr, "    %s\n", e.Description)
				}
			}
			fmt.Fprintf(os.Stderr, "\n  Hint: ensure the file conforms to the HDF %s schema\n", schemaType)
		}
		return &exitCodeError{code: 1, message: fmt.Sprintf("validation failed for %s", displayName)}
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
