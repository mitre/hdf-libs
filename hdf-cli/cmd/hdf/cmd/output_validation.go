package cmd

import (
	"encoding/json"
	"fmt"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

// noValidateFlag is the persistent flag name used by convert and fetch
// commands to opt out of post-conversion / post-fetch schema validation.
const noValidateFlag = "no-validate"

// addNoValidateFlag attaches the --no-validate opt-out to a cobra command.
// Used by convert and every fetch subcommand so users can bypass the
// post-conversion validation gate in development scenarios.
func addNoValidateFlag(cmd *cobra.Command) {
	cmd.Flags().Bool(noValidateFlag, false, "Skip schema validation of converter output before writing")
}

// shouldSkipValidation reads the --no-validate flag from the command.
func shouldSkipValidation(cmd *cobra.Command) bool {
	skip, _ := cmd.Flags().GetBool(noValidateFlag)
	return skip
}

// validateHDFOutput runs the appropriate HDF schema validator over the
// produced output bytes. It auto-detects Results vs Baseline by examining
// the top-level JSON keys.
//
// Returns nil if the input does not look like an HDF JSON document
// (e.g., it's a CKL/CSV/OSCAL export that is not HDF-shaped). The caller
// is responsible for only invoking this when the output is expected to
// be HDF.
func validateHDFOutput(data []byte) error {
	docType, ok := detectHDFDocType(data)
	if !ok {
		return nil
	}
	switch docType {
	case "results":
		result := validators.ValidateResults(data)
		if !result.Valid {
			return fmt.Errorf("output failed HDF Results schema validation: %s", result.Error())
		}
	case "baseline":
		result := validators.ValidateBaseline(data)
		if !result.Valid {
			return fmt.Errorf("output failed HDF Baseline schema validation: %s", result.Error())
		}
	}
	return nil
}

// detectHDFDocType inspects the top-level JSON shape and returns
// "results" if the doc has a `baselines` array (Evaluated_Baseline list)
// or "baseline" if it has a top-level `requirements` array
// (Baseline_Requirement list). Returns ok=false when the input isn't JSON
// or doesn't match either shape, signalling "skip validation".
func detectHDFDocType(data []byte) (string, bool) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", false
	}
	if _, hasBaselines := probe["baselines"]; hasBaselines {
		return "results", true
	}
	if _, hasRequirements := probe["requirements"]; hasRequirements {
		return "baseline", true
	}
	return "", false
}

// writeValidatedHDFOutput validates HDF-shaped output before writing.
// On validation failure, returns an error and does NOT write — the caller
// must surface the error to the user. This is the runtime gate that
// complements the CI-side fixture round-trip gate (see ufz8).
//
// If the caller passed --no-validate, validation is skipped and the
// behaviour matches writeConvertOutput.
func writeValidatedHDFOutput(cmd *cobra.Command, data []byte, path string) error {
	if !shouldSkipValidation(cmd) {
		if err := validateHDFOutput(data); err != nil {
			return fmt.Errorf("%w (re-run with --%s to skip this check and write the invalid output anyway)",
				err, noValidateFlag)
		}
	}
	return writeConvertOutput(data, path)
}
