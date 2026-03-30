package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newValidateThresholdCmd() *cobra.Command {
	var templateFile string

	cmd := &cobra.Command{
		Use:   "threshold <results.json>",
		Short: "Validate HDF results against compliance thresholds",
		Long: `Validate that an HDF results file meets compliance thresholds
defined in a YAML threshold template.

Exit code 0 if all thresholds pass, exit code 1 on any violation.
Use with 'hdf generate threshold' to create threshold templates.

Designed for CI/CD compliance gates.`,
		Example: `  hdf validate threshold results.json -T threshold.yaml
  hdf validate threshold results.json -T threshold.yaml --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if templateFile == "" {
				return fmt.Errorf("--template (-T) is required")
			}

			// Read results
			data, err := readInputFile(args[0])
			if err != nil {
				return err
			}

			// Read threshold template
			templateData, err := os.ReadFile(templateFile) //nolint:gosec // user-provided path
			if err != nil {
				return fmt.Errorf("failed to read threshold template: %w", err)
			}

			var config ThresholdConfig
			if err := yaml.Unmarshal(templateData, &config); err != nil {
				return fmt.Errorf("failed to parse threshold YAML: %w", err)
			}

			// Count controls
			counts, err := countControlsByStatusSeverity(data)
			if err != nil {
				return err
			}

			compliance := calculateCompliance(counts)

			// Build control ID map for per-control validation
			controlMap, mapErr := mapControlIDs(data)
			if mapErr != nil {
				return mapErr
			}

			// Validate all thresholds
			violations := validateThresholds(&config, counts, compliance, controlMap)
			if len(violations) > 0 {
				for _, v := range violations {
					fmt.Fprintf(os.Stderr, "FAIL: %s\n", v)
				}
				fmt.Fprintf(os.Stderr, "\n%d threshold violation(s)\n", len(violations))
				return &exitCodeError{
					code:    1,
					message: fmt.Sprintf("threshold validation failed: %s", violations[0]),
				}
			}

			if !quiet {
				fmt.Fprintf(os.Stderr, "All thresholds passed (compliance: %.2f%%)\n", compliance)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&templateFile, "template", "T", "", "Threshold YAML template file (required)")

	return cmd
}

// validateThresholds checks all threshold bounds against observed counts.
// Returns a list of human-readable violation messages.
func validateThresholds(config *ThresholdConfig, counts *StatusCounts, compliance float64, controlMap []ControlIDMapping) []string {
	var violations []string

	// Build lookup: controlID → {status, severity}
	actualControls := make(map[string]ControlIDMapping)
	for _, m := range controlMap {
		actualControls[m.ID] = m
	}

	// Compliance
	if config.Compliance != nil {
		if config.Compliance.Min != nil && compliance < *config.Compliance.Min {
			violations = append(violations, fmt.Sprintf(
				"compliance %.2f%% is below minimum %.2f%%", compliance, *config.Compliance.Min))
		}
		if config.Compliance.Max != nil && compliance > *config.Compliance.Max {
			violations = append(violations, fmt.Sprintf(
				"compliance %.2f%% exceeds maximum %.2f%%", compliance, *config.Compliance.Max))
		}
	}

	// Per-status checks
	violations = append(violations, checkSeverityThreshold("passed", config.Passed, &counts.Passed, actualControls)...)
	violations = append(violations, checkSeverityThreshold("failed", config.Failed, &counts.Failed, actualControls)...)
	violations = append(violations, checkSeverityThreshold("skipped", config.Skipped, &counts.Skipped, actualControls)...)
	violations = append(violations, checkSeverityThreshold("error", config.Error, &counts.Error, actualControls)...)
	violations = append(violations, checkSeverityThreshold("no_impact", config.NoImpact, &counts.NoImpact, actualControls)...)

	return violations
}

// checkSeverityThreshold validates all severity bounds within a status category.
func checkSeverityThreshold(status string, threshold *ThresholdSeverity, actual *SeverityCounts, actualControls map[string]ControlIDMapping) []string {
	if threshold == nil {
		return nil
	}

	var violations []string
	check := func(label string, bound *ThresholdBound, actualCount int) {
		if bound == nil {
			return
		}
		path := fmt.Sprintf("%s.%s", status, label)
		if bound.Min != nil && actualCount < *bound.Min {
			violations = append(violations, fmt.Sprintf(
				"%s: %d is below minimum %d", path, actualCount, *bound.Min))
		}
		if bound.Max != nil && actualCount > *bound.Max {
			violations = append(violations, fmt.Sprintf(
				"%s: %d exceeds maximum %d", path, actualCount, *bound.Max))
		}
		// Check control IDs if specified
		for _, expectedID := range bound.Controls {
			actual, found := actualControls[expectedID]
			if !found {
				violations = append(violations, fmt.Sprintf(
					"%s: expected control %s not found in results", path, expectedID))
			} else if actual.Status != status || actual.Severity != label {
				violations = append(violations, fmt.Sprintf(
					"%s: control %s expected %s/%s but found %s/%s",
					path, expectedID, status, label, actual.Status, actual.Severity))
			}
		}
	}

	check("critical", threshold.Critical, actual.Critical)
	check("high", threshold.High, actual.High)
	check("medium", threshold.Medium, actual.Medium)
	check("low", threshold.Low, actual.Low)
	check("none", threshold.None, actual.None)
	check("total", threshold.Total, actual.Total)

	return violations
}
