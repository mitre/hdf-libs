package cmd

import (
	"fmt"
	"os"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newGenerateThresholdCmd() *cobra.Command {
	var (
		outputPath      string
		exact           bool
		includeControls bool
	)

	cmd := &cobra.Command{
		Use:   "threshold <results.json>",
		Short: "Generate compliance threshold from HDF results",
		Long: `Generate a YAML threshold template from an HDF results file.

The threshold defines min/max bounds for control status counts by severity.
Use it with 'hdf validate threshold' to enforce compliance regression
detection in CI/CD pipelines.

By default, generates "at-least-as-good-as-current" thresholds:
  - passed counts get a minimum (more passes always acceptable)
  - failed counts get a maximum (fewer failures always acceptable)

Use --exact to generate thresholds where all counts must match exactly.
Use --include-controls to list specific control IDs under each status/severity,
so the validator checks that each control has the expected status.`,
		Example: `  # Generate threshold to stdout
  hdf generate threshold results.json

  # Generate threshold to file
  hdf generate threshold results.json -o threshold.yaml

  # Exact mode (all counts must match)
  hdf generate threshold results.json --exact -o threshold.yaml

  # Include control ID lists for per-control validation
  hdf generate threshold results.json --include-controls -o threshold.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			data, err := readInputFile(args[0])
			if err != nil {
				return err
			}

			counts, err := countControlsByStatusSeverity(data)
			if err != nil {
				return err
			}

			compliance := hdfengine.CalculateCompliance(counts)
			config := buildThresholdConfig(counts, compliance, exact)

			if includeControls {
				mappings, mapErr := mapControlIDs(data)
				if mapErr != nil {
					return mapErr
				}
				addControlIDsToConfig(config, mappings)
			}

			out, err := yaml.Marshal(config)
			if err != nil {
				return fmt.Errorf("failed to marshal threshold YAML: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, out, 0o600); err != nil {
					return fmt.Errorf("failed to write threshold file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Wrote threshold to %s\n", outputPath)
				return nil
			}

			fmt.Print(string(out))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolVar(&exact, "exact", false, "All counts must match exactly (sets both min and max)")
	cmd.Flags().BoolVarP(&includeControls, "include-controls", "c", false, "Include control ID lists for per-control validation")

	return cmd
}

// buildThresholdConfig creates a ThresholdConfig from observed counts.
func buildThresholdConfig(counts *StatusCounts, compliance float64, exact bool) *ThresholdConfig {
	config := &ThresholdConfig{}

	if exact {
		config.Compliance = &ComplianceBound{Min: &compliance, Max: &compliance}
	} else {
		config.Compliance = &ComplianceBound{Min: &compliance}
	}

	config.Passed = buildSeverityThreshold(&counts.Passed, exact, false)
	config.Failed = buildSeverityThreshold(&counts.Failed, exact, true)
	config.Skipped = buildSeverityThreshold(&counts.Skipped, exact, true)
	config.Error = buildSeverityThreshold(&counts.Error, exact, true)
	config.NoImpact = buildSeverityThreshold(&counts.NoImpact, exact, false)

	return config
}

// buildSeverityThreshold creates a ThresholdSeverity from counts.
// If useMax is true (for negative statuses like failed/error), non-exact mode
// generates max bounds. Otherwise generates min bounds.
func buildSeverityThreshold(sc *SeverityCounts, exact, useMax bool) *ThresholdSeverity {
	if sc.Total == 0 && !exact {
		return nil
	}

	ts := &ThresholdSeverity{}
	ts.Total = makeBound(sc.Total, exact, useMax)

	if sc.Critical > 0 || exact {
		ts.Critical = makeBound(sc.Critical, exact, useMax)
	}
	if sc.High > 0 || exact {
		ts.High = makeBound(sc.High, exact, useMax)
	}
	if sc.Medium > 0 || exact {
		ts.Medium = makeBound(sc.Medium, exact, useMax)
	}
	if sc.Low > 0 || exact {
		ts.Low = makeBound(sc.Low, exact, useMax)
	}
	if sc.None > 0 || exact {
		ts.None = makeBound(sc.None, exact, useMax)
	}

	return ts
}

// addControlIDsToConfig populates control ID lists in the threshold config
// based on observed control → status/severity mappings.
func addControlIDsToConfig(config *ThresholdConfig, mappings []ControlIDMapping) {
	for _, m := range mappings {
		var ts *ThresholdSeverity
		switch m.Status {
		case thresholdPassed:
			if config.Passed == nil {
				config.Passed = &ThresholdSeverity{}
			}
			ts = config.Passed
		case thresholdFailed:
			if config.Failed == nil {
				config.Failed = &ThresholdSeverity{}
			}
			ts = config.Failed
		case thresholdSkipped:
			if config.Skipped == nil {
				config.Skipped = &ThresholdSeverity{}
			}
			ts = config.Skipped
		case thresholdError:
			if config.Error == nil {
				config.Error = &ThresholdSeverity{}
			}
			ts = config.Error
		case thresholdNoImpact:
			if config.NoImpact == nil {
				config.NoImpact = &ThresholdSeverity{}
			}
			ts = config.NoImpact
		default:
			continue
		}

		bound := getSeverityBound(ts, m.Severity)
		bound.Controls = append(bound.Controls, m.ID)
	}
}

// getSeverityBound returns the ThresholdBound for a severity level,
// creating it if nil.
func getSeverityBound(ts *ThresholdSeverity, severity string) *ThresholdBound {
	switch severity {
	case "critical":
		if ts.Critical == nil {
			ts.Critical = &ThresholdBound{}
		}
		return ts.Critical
	case "high":
		if ts.High == nil {
			ts.High = &ThresholdBound{}
		}
		return ts.High
	case "medium":
		if ts.Medium == nil {
			ts.Medium = &ThresholdBound{}
		}
		return ts.Medium
	case "low":
		if ts.Low == nil {
			ts.Low = &ThresholdBound{}
		}
		return ts.Low
	default:
		if ts.None == nil {
			ts.None = &ThresholdBound{}
		}
		return ts.None
	}
}

// makeBound creates a ThresholdBound from a count value.
func makeBound(val int, exact, useMax bool) *ThresholdBound {
	v := val
	if exact {
		return &ThresholdBound{Min: &v, Max: &v}
	}
	if useMax {
		return &ThresholdBound{Max: &v}
	}
	return &ThresholdBound{Min: &v}
}
