package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

// agentOverrideReadout is the §3 detective line surfaced by the validate,
// validate threshold, and evidence verify readouts: the count of overrides an AI
// agent applied (appliedBy.type=="agent"), which auditors scrutinize separately
// from deterministic system/human overrides. Read directly from the applied
// results — the attribution survives the apply step and is never back-traced to
// the amendments document.
func agentOverrideReadout(n int) string {
	return fmt.Sprintf("Agent-attributed overrides: %d", n)
}

// countAgentOverrides parses HDF results bytes and returns the agent-attributed
// override count via the shared engine function (the same one the MCP
// hdf_compliance tool consumes). Parse failures yield 0 — callers surface the
// count only for documents already confirmed to be valid results.
func countAgentOverrides(data []byte) int {
	results, err := parseHDFResults(data)
	if err != nil {
		return 0
	}
	return hdfengine.AgentOverrideCount(results)
}

// Global flag variables for validate command (used by runValidate).
var (
	schemaType string // "results", "baseline", "comparison", "system", "plan", "amendments", "evidence-package", or "requirement-change-event"
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

Supported types: results, baseline, comparison, system, plan, amendments, evidence-package, requirement-change-event.

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

	cmd.Flags().StringVarP(&localSchemaType, "type", "t", "", "Schema type (auto-detected if omitted): results, baseline, comparison, system, plan, amendments, evidence-package, requirement-change-event")
	cmd.Flags().BoolVarP(&localQuiet, "quiet", "q", false, "Suppress output on success (exit code only)")

	cmd.AddCommand(newValidateThresholdCmd())

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

	// Determine display name for output
	displayName := filename
	if filename == "-" {
		displayName = "<stdin>"
	}

	// Auto-detect document type if --type not provided
	if schemaType == "" {
		schemaType = detectHDFDocumentType(data)
		printDebug("Auto-detected document type: %s", schemaType)
	}

	if schemaType == "" {
		fmt.Fprintf(os.Stderr, "✗ %s — input not recognized as any HDF document type\n", displayName)
		fmt.Fprintf(os.Stderr, "  Use --type to specify: results, baseline, comparison, system, plan, amendments, evidence-package, requirement-change-event\n")
		return &exitCodeError{code: 1, message: fmt.Sprintf("unrecognized document type for %s", displayName)}
	}

	// Validate against schema — use the validator directly for structured errors
	validType := validators.SchemaType(schemaType)
	if !isKnownSchemaType(validType) {
		fmt.Fprintf(os.Stderr, "Unknown schema type: %s\n", schemaType)
		fmt.Fprintf(os.Stderr, "  Use --type=results|baseline|comparison|system|plan|amendments|evidence-package|requirement-change-event\n")
		return &exitCodeError{code: 1, message: fmt.Sprintf("unknown schema type: %s", schemaType)}
	}

	// Normalize bare InSpec timestamps before validation, matching what
	// hdfparsers.ParseResults does. Without this, real InSpec output trips
	// the schema's `date-time` format check.
	result := validators.Validate(hdfparsers.NormalizeTimestamps(data), validType)
	var validationResult *validators.ValidationResult
	if !result.Valid {
		validationResult = &result
	}

	if validationResult != nil && !validationResult.Valid {
		// Build line map for file inputs (not stdin) to annotate errors
		var lineMap map[string]int
		if filename != "-" {
			lineMap = hdfutil.JSONPathLineMap(data)
		}

		if jsonOutput {
			outputValidationJSON(displayName, schemaType, validationResult, lineMap)
		} else {
			outputValidationHuman(displayName, schemaType, validationResult, lineMap)
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
		if schemaType == "results" {
			result["agentOverrides"] = countAgentOverrides(data)
		}
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	} else if !quiet {
		fmt.Printf("✓ %s is a valid HDF %s file\n", displayName, schemaType)
		if schemaType == "results" {
			fmt.Println(agentOverrideReadout(countAgentOverrides(data)))
		}
	}

	return nil
}

func runValidateBulk(cmd *cobra.Command, files []string) error {
	return runBulk(files, "validation", "validated", func(file string) error {
		return runValidate(cmd, []string{file})
	})
}

// isKnownSchemaType returns true if the schema type is one we can validate.
func isKnownSchemaType(st validators.SchemaType) bool {
	switch st {
	case validators.TypeResults, validators.TypeBaseline, validators.TypeComparison,
		validators.TypeSystem, validators.TypePlan, validators.TypeAmendments,
		validators.TypeEvidencePackage, validators.TypeRequirementChangeEvent:
		return true
	default:
		return false
	}
}

// outputValidationHuman prints validation errors in human-readable format,
// annotating with line numbers when a line map is available.
func outputValidationHuman(displayName, schemaType string, vr *validators.ValidationResult, lineMap map[string]int) {
	fmt.Fprintf(os.Stderr, "✗ %s — not a valid HDF %s document\n", displayName, schemaType)
	fmt.Fprintf(os.Stderr, "\n  Errors:\n")
	for _, e := range vr.Errors {
		line := 0
		if lineMap != nil {
			line = hdfutil.LookupLineNumber(lineMap, e.Field)
		}

		switch {
		case line > 0 && e.Field != "" && e.Field != hdfutil.FieldRoot:
			fmt.Fprintf(os.Stderr, "    line %d: %s: %s\n", line, e.Field, e.Description)
		case e.Field != "" && e.Field != hdfutil.FieldRoot:
			fmt.Fprintf(os.Stderr, "    %s: %s\n", e.Field, e.Description)
		default:
			fmt.Fprintf(os.Stderr, "    %s\n", e.Description)
		}
	}
}

// outputValidationJSON prints validation errors in JSON format,
// including line numbers when a line map is available.
func outputValidationJSON(displayName, schemaType string, vr *validators.ValidationResult, lineMap map[string]int) {
	type errorWithLine struct {
		Field       string `json:"field"`
		Description string `json:"description"`
		Line        int    `json:"line,omitempty"`
	}

	errors := make([]errorWithLine, 0, len(vr.Errors))
	for _, e := range vr.Errors {
		ewl := errorWithLine{Field: e.Field, Description: e.Description}
		if lineMap != nil {
			ewl.Line = hdfutil.LookupLineNumber(lineMap, e.Field)
		}
		errors = append(errors, ewl)
	}

	result := map[string]interface{}{
		"valid":  false,
		"file":   displayName,
		"type":   schemaType,
		"errors": errors,
	}
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}
