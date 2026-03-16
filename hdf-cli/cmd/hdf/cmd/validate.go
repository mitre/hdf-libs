package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// Global flag variables for validate command (used by runValidate).
var (
	schemaType string // "results" or "baseline"
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
		Long: `Validate an HDF results or baseline file against the JSON schema.

Reads from stdin if file is '-' or omitted.

Examples:
  hdf validate results.json
  hdf validate baseline.json --type baseline
  cat results.json | hdf validate -
  curl -s https://example.com/scan.json | hdf validate`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Sync local flags to global variables for runValidate
			schemaType = localSchemaType
			quiet = localQuiet
			return runValidate(cmd, args)
		},
	}

	cmd.Flags().StringVarP(&localSchemaType, "type", "t", "results", "Schema type: 'results' or 'baseline'")
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
		printError(err.Error())
		return err
	}

	printDebug("Read %d bytes", len(data))

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
	default:
		printError(fmt.Sprintf("Unknown schema type: %s", schemaType),
			"Use --type=results or --type=baseline")
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
