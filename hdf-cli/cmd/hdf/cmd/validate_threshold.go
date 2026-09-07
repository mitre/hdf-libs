package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/threshold"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"

	"github.com/spf13/cobra"
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
		// A gate applies one policy to a directory of documents, so this takes
		// many files. MinimumNArgs rather than ArbitraryArgs: an unmatched shell
		// glob must be an error, never a vacuous pass.
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			// The template is the same for every file, so resolve it once.
			config, cfgErr := resolveThresholdConfig(templateFile, templateInline)
			if cfgErr != nil {
				return cfgErr
			}

			files, err := expandGlobs(args)
			if err != nil {
				return err
			}
			if len(files) > 1 {
				return runBulk(files, "threshold validation", "passed thresholds", func(file string) error {
					return runValidateThresholdFile(file, config)
				})
			}
			return runValidateThresholdFile(files[0], config)
		},
	}

	cmd.Flags().StringVarP(&templateFile, "template", "T", "", "Threshold YAML template file")
	cmd.Flags().StringVarP(&templateInline, "inline", "I", "", `Inline threshold (e.g. "{compliance.min: 80}, {failed.total.max: 0}")`)

	return cmd
}

// resolveThresholdConfig turns the -T/-I flag pair into a parsed, non-vacuous
// threshold config. Separated from the per-file work because the policy is the
// same for every document in a bulk run — parsing it once also means a broken
// template fails before any file is read.
func resolveThresholdConfig(templateFile, templateInline string) (*ThresholdConfig, error) {
	if templateFile == "" && templateInline == "" {
		return nil, fmt.Errorf("either --template (-T) or --inline (-I) is required")
	}
	if templateFile != "" && templateInline != "" {
		return nil, fmt.Errorf("--template (-T) and --inline (-I) are mutually exclusive")
	}

	var config ThresholdConfig
	if templateFile != "" {
		templateData, readErr := os.ReadFile(templateFile) //nolint:gosec // user-provided path
		if readErr != nil {
			return nil, fmt.Errorf("failed to read threshold template: %w", readErr)
		}
		parsed, decodeErr := threshold.Decode(templateData)
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to parse threshold YAML: %w", decodeErr)
		}
		config = *parsed
	} else {
		parsed, parseErr := parseInlineThreshold(templateInline)
		if parseErr != nil {
			return nil, parseErr
		}
		config = *parsed
	}

	// A template that asserts nothing passes every document, so reporting
	// success would be a green gate that checked nothing — the same false
	// green a misspelled key used to produce.
	if threshold.AssertionCount(&config) == 0 {
		return nil, threshold.ErrNoAssertions
	}
	return &config, nil
}

// runValidateThresholdFile applies an already-parsed threshold to one document.
func runValidateThresholdFile(file string, config *ThresholdConfig) error {
	data, err := readInputFile(file)
	if err != nil {
		return err
	}

	counts, err := countControlsByStatusSeverity(data)
	if err != nil {
		return err
	}

	compliance := hdfengine.CalculateCompliance(counts)

	if !quiet {
		fmt.Fprintln(os.Stderr, agentOverrideReadout(countAgentOverrides(data)))
	}

	controlMap, mapErr := mapControlIDs(data)
	if mapErr != nil {
		return mapErr
	}

	violations := hdfengine.ValidateThresholds(config, counts, compliance, controlMap)
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
}

// parseInlineThreshold parses SAF CLI-compatible inline threshold format:
// "{compliance.min: 80}, {passed.total.min: 50}, {failed.critical.max: 0}"
//
// This walks dotted segments rather than deferring to internal/threshold's
// decoder, and the two deliberately do not share one routine: they validate
// different grammars. -T decodes YAML, where the struct tags on
// hdfengine.ThresholdConfig are themselves the key vocabulary; -I has no
// document to decode. Sharing would mean reimplementing YAML parsing as segment
// walking, or having -I synthesize YAML. Both enforce the same guarantee — no
// key that isn't in the vocabulary — by different means.
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
			// getSeverityBound buckets anything it does not recognize into
			// "none", which is right when generate is placing a scan's own
			// severity but wrong here: this segment was typed by a user, so an
			// unrecognized name is a typo that would otherwise assert a bound
			// nobody asked for and pass silently.
			if !isKnownSeverityField(segments[1]) {
				return fmt.Errorf("unknown severity field %q (expected 'critical', 'high', 'medium', 'low', 'none', or 'total')", segments[1])
			}
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

// knownSeverityFields is the severity vocabulary a threshold path may name.
// getSeverityBound (generate_threshold.go) maps anything else to "none" on
// purpose, so the inline path checks membership here before calling it.
var knownSeverityFields = []string{"critical", "high", "medium", "low", "none"}

func isKnownSeverityField(name string) bool {
	for _, known := range knownSeverityFields {
		if name == known {
			return true
		}
	}
	return false
}
