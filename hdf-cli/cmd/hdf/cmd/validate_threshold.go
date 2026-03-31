package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newValidateThresholdCmd() *cobra.Command {
	var (
		templateFile   string
		templateInline string
	)

	cmd := &cobra.Command{
		Use:   "threshold <results.json>",
		Short: "Validate HDF results against compliance thresholds",
		Long: `Validate that an HDF results file meets compliance thresholds
defined in a YAML threshold template or an inline specification.

Exit code 0 if all thresholds pass, exit code 1 on any violation.
Use with 'hdf generate threshold' to create threshold templates.

Designed for CI/CD compliance gates.`,
		Example: `  # From YAML template
  hdf validate threshold results.json -T threshold.yaml

  # Inline (for CI one-liners)
  hdf validate threshold results.json -I "{compliance.min: 80}, {failed.total.max: 0}"
  hdf validate threshold results.json -I "{passed.high.min: 20}, {failed.critical.max: 0}"`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if templateFile == "" && templateInline == "" {
				return fmt.Errorf("either --template (-T) or --inline (-I) is required")
			}
			if templateFile != "" && templateInline != "" {
				return fmt.Errorf("--template (-T) and --inline (-I) are mutually exclusive")
			}

			// Read results
			data, err := readInputFile(args[0])
			if err != nil {
				return err
			}

			// Parse threshold config from file or inline
			var config ThresholdConfig
			if templateFile != "" {
				templateData, readErr := os.ReadFile(templateFile) //nolint:gosec // user-provided path
				if readErr != nil {
					return fmt.Errorf("failed to read threshold template: %w", readErr)
				}
				if unmarshalErr := yaml.Unmarshal(templateData, &config); unmarshalErr != nil {
					return fmt.Errorf("failed to parse threshold YAML: %w", unmarshalErr)
				}
			} else {
				parsed, parseErr := parseInlineThreshold(templateInline)
				if parseErr != nil {
					return parseErr
				}
				config = *parsed
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
				fmt.Fprintf(os.Stderr, "All thresholds passed\n")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&templateFile, "template", "T", "", "Threshold YAML template file")
	cmd.Flags().StringVarP(&templateInline, "inline", "I", "", `Inline threshold (e.g. "{compliance.min: 80}, {failed.total.max: 0}")`)

	return cmd
}

// parseInlineThreshold parses SAF CLI-compatible inline threshold format:
// "{compliance.min: 80}, {passed.total.min: 50}, {failed.critical.max: 0}"
//
// Each item is a dotted path and a numeric value. The path is split into
// segments and used to populate the ThresholdConfig struct.
func parseInlineThreshold(inline string) (*ThresholdConfig, error) {
	config := &ThresholdConfig{}

	// Split on commas, strip braces and whitespace
	parts := strings.Split(inline, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "{}")
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split on first colon
		colonIdx := strings.Index(part, ":")
		if colonIdx < 0 {
			return nil, fmt.Errorf("invalid inline threshold entry %q: expected 'key: value'", part)
		}
		key := strings.TrimSpace(part[:colonIdx])
		valStr := strings.TrimSpace(part[colonIdx+1:])

		segments := strings.Split(key, ".")
		if len(segments) < 2 {
			return nil, fmt.Errorf("invalid threshold path %q: need at least two segments (e.g. 'compliance.min')", key)
		}

		val, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid threshold value %q for key %q: %w", valStr, key, err)
		}

		if err := setThresholdValue(config, segments, val); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// setThresholdValue sets a single value in the ThresholdConfig based on a
// dotted path like ["compliance", "min"] or ["failed", "high", "max"].
func setThresholdValue(config *ThresholdConfig, segments []string, val float64) error {
	intVal := int(val)

	switch segments[0] {
	case "compliance":
		if config.Compliance == nil {
			config.Compliance = &ComplianceBound{}
		}
		switch segments[1] {
		case "min":
			config.Compliance.Min = &val
		case "max":
			config.Compliance.Max = &val
		default:
			return fmt.Errorf("unknown compliance field %q", segments[1])
		}
		return nil

	case thresholdPassed, thresholdFailed, thresholdSkipped, thresholdError, thresholdNoImpact:
		ts := getOrCreateStatusSeverity(config, segments[0])
		if len(segments) < 3 {
			return fmt.Errorf("threshold path %q needs three segments (e.g. 'passed.high.min')", strings.Join(segments, "."))
		}
		var bound *ThresholdBound
		if segments[1] == "total" {
			if ts.Total == nil {
				ts.Total = &ThresholdBound{}
			}
			bound = ts.Total
		} else {
			bound = getSeverityBound(ts, segments[1])
		}
		switch segments[2] {
		case "min":
			bound.Min = &intVal
		case "max":
			bound.Max = &intVal
		default:
			return fmt.Errorf("unknown bound type %q (expected 'min' or 'max')", segments[2])
		}
		return nil

	default:
		return fmt.Errorf("unknown threshold category %q", segments[0])
	}
}

// getOrCreateStatusSeverity returns the ThresholdSeverity for a status,
// creating it on the config if nil.
func getOrCreateStatusSeverity(config *ThresholdConfig, status string) *ThresholdSeverity {
	switch status {
	case thresholdPassed:
		if config.Passed == nil {
			config.Passed = &ThresholdSeverity{}
		}
		return config.Passed
	case thresholdFailed:
		if config.Failed == nil {
			config.Failed = &ThresholdSeverity{}
		}
		return config.Failed
	case thresholdSkipped:
		if config.Skipped == nil {
			config.Skipped = &ThresholdSeverity{}
		}
		return config.Skipped
	case thresholdError:
		if config.Error == nil {
			config.Error = &ThresholdSeverity{}
		}
		return config.Error
	case thresholdNoImpact:
		if config.NoImpact == nil {
			config.NoImpact = &ThresholdSeverity{}
		}
		return config.NoImpact
	default:
		return &ThresholdSeverity{}
	}
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
	violations = append(violations, checkSeverityThreshold(thresholdPassed, config.Passed, &counts.Passed, actualControls)...)
	violations = append(violations, checkSeverityThreshold(thresholdFailed, config.Failed, &counts.Failed, actualControls)...)
	violations = append(violations, checkSeverityThreshold(thresholdSkipped, config.Skipped, &counts.Skipped, actualControls)...)
	violations = append(violations, checkSeverityThreshold(thresholdError, config.Error, &counts.Error, actualControls)...)
	violations = append(violations, checkSeverityThreshold(thresholdNoImpact, config.NoImpact, &counts.NoImpact, actualControls)...)

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
