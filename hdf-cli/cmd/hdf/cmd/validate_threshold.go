package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"

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
				// Decode strictly: an unrecognized key must be an error, never a
				// silently dropped one. A template whose keys are misspelled would
				// otherwise parse to an empty threshold set and pass vacuously —
				// a committed gate that asserts nothing while reporting success.
				decoder := yaml.NewDecoder(bytes.NewReader(templateData))
				decoder.KnownFields(true)
				if decodeErr := decoder.Decode(&config); decodeErr != nil && !errors.Is(decodeErr, io.EOF) {
					return fmt.Errorf("failed to parse threshold YAML: %s", templateKeyVocabulary.Replace(decodeErr.Error()))
				}
			} else {
				parsed, parseErr := parseInlineThreshold(templateInline)
				if parseErr != nil {
					return parseErr
				}
				config = *parsed
			}

			// A template that asserts nothing passes every document, so reporting
			// success would be a green gate that checked nothing — the same false
			// green a misspelled key used to produce.
			if thresholdAssertionCount(&config) == 0 {
				return fmt.Errorf("threshold asserts nothing: add at least one bound (e.g. a 'failed.total.max' entry)")
			}

			// Count controls
			counts, err := countControlsByStatusSeverity(data)
			if err != nil {
				return err
			}

			compliance := hdfengine.CalculateCompliance(counts)

			if !quiet {
				fmt.Fprintln(os.Stderr, agentOverrideReadout(countAgentOverrides(data)))
			}

			// Build control ID map for per-control validation
			controlMap, mapErr := mapControlIDs(data)
			if mapErr != nil {
				return mapErr
			}

			// Validate all thresholds
			violations := hdfengine.ValidateThresholds(&config, counts, compliance, controlMap)
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

// The -T and -I paths validate different grammars and so do not share one
// routine: -I walks dotted segments, while -T decodes YAML where the struct
// tags on hdfengine.ThresholdConfig are themselves the key vocabulary. Sharing
// would mean reimplementing YAML parsing as segment walking, or having -I
// synthesize YAML. Both enforce the same guarantee by different means.
//
// yaml's KnownFields error names the Go type that rejected the key; restate it
// in the template's own vocabulary so a failing gate reads in the same terms as
// the -I path's "unknown threshold category" errors rather than leaking a type.
var templateKeyVocabulary = strings.NewReplacer(
	"not found in type hdfengine.ThresholdConfig", "is not a known threshold category",
	"not found in type hdfengine.ThresholdSeverity", "is not a known severity field",
	"not found in type hdfengine.ThresholdBound", "is not a known bound",
	"not found in type hdfengine.ComplianceBound", "is not a known compliance field",
)

// thresholdAssertionCount reports how many bounds a template actually asserts,
// counting every level: a nested section present but empty (`failed: {}`)
// asserts as little as an empty file.
func thresholdAssertionCount(config *ThresholdConfig) int {
	count := 0
	if config.Compliance != nil {
		if config.Compliance.Min != nil {
			count++
		}
		if config.Compliance.Max != nil {
			count++
		}
	}
	for _, severity := range []*ThresholdSeverity{config.Passed, config.Failed, config.Skipped, config.Error, config.NoImpact} {
		if severity == nil {
			continue
		}
		for _, bound := range []*ThresholdBound{severity.Critical, severity.High, severity.Medium, severity.Low, severity.None, severity.Total} {
			if bound == nil {
				continue
			}
			if bound.Min != nil {
				count++
			}
			if bound.Max != nil {
				count++
			}
			count += len(bound.Controls)
		}
	}
	return count
}
