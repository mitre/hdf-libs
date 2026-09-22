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
		templateFiles   []string
		templateInlines []string
	)

	cmd := &cobra.Command{
		Use:   "threshold <results.json>",
		Short: "Validate HDF results against compliance thresholds",
		Long: `Validate that an HDF results file meets compliance thresholds
defined in a YAML threshold template or an inline specification.

-T and -I are repeatable and may be combined, and one -T file may hold several
YAML documents. Every spec is evaluated and the run fails if any of them fails;
a violation names the spec it came from.

Exit code 0 if all thresholds pass, exit code 1 on any violation.
Use with 'hdf generate threshold' to create threshold templates.

Designed for CI/CD compliance gates.`,
		Example: `  # From YAML template
  hdf validate threshold results.json -T threshold.yaml

  # Inline (for CI one-liners)
  hdf validate threshold results.json -I "{compliance.min: 80}, {failed.total.max: 0}"
  hdf validate threshold results.json -I "{passed.high.min: 20}, {failed.critical.max: 0}"

  # Several specs: an org-wide baseline plus a repo-specific overlay. Both must pass.
  hdf validate threshold results.json -T baseline.yaml -T repo.yaml`,
		// A gate applies one policy to a directory of documents, so this takes
		// many files. MinimumNArgs rather than ArbitraryArgs: an unmatched shell
		// glob must be an error, never a vacuous pass.
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			// The template is the same for every file, so resolve it once.
			specs, cfgErr := resolveThresholdSpecs(templateFiles, templateInlines)
			if cfgErr != nil {
				return cfgErr
			}

			files, err := expandGlobs(args)
			if err != nil {
				return err
			}
			if len(files) > 1 {
				return runBulk(files, "threshold validation", "passed thresholds", func(file string) error {
					return runValidateThresholdFile(file, specs)
				})
			}
			return runValidateThresholdFile(files[0], specs)
		},
	}

	// StringArray, not StringSlice: StringSlice splits its value on commas, and an
	// inline spec is itself comma-separated, so it would arrive shredded into
	// fragments. Repeating either flag adds a policy; every policy must pass.
	cmd.Flags().StringArrayVarP(&templateFiles, "template", "T", nil, "Threshold YAML template file (repeatable; every spec must pass)")
	cmd.Flags().StringArrayVarP(&templateInlines, "inline", "I", nil, `Inline threshold, repeatable (e.g. "{compliance.min: 80}, {failed.total.max: 0}")`)

	return cmd
}

// resolveThresholdSpecs turns the -T/-I flags into parsed, non-vacuous policies.
// Separated from the per-file work because the policy set is the same for every
// document in a bulk run — parsing once also means a broken spec fails before any
// file is read.
//
// Several policies are a CONJUNCTION: each is evaluated against the document and
// the violations are unioned. They are never merged, because two specs bounding
// the same key would need a precedence rule nobody asked for; evaluated
// separately, the stricter one simply fails on its own terms. -T and -I may be
// combined for the same reason — a committed baseline plus a one-off tightening
// are just two policies, and nothing about them conflicts.
func resolveThresholdSpecs(templateFiles, templateInlines []string) ([]threshold.Spec, error) {
	if len(templateFiles) == 0 && len(templateInlines) == 0 {
		return nil, fmt.Errorf("either --template (-T) or --inline (-I) is required")
	}

	var specs []threshold.Spec
	for _, file := range templateFiles {
		// allowEmpty: an empty template is still size-capped, but must reach the
		// "asserts nothing" content check rather than being rejected as empty here.
		templateData, readErr := readInputFileAllowEmpty(file)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read threshold template: %w", readErr)
		}
		parsed, decodeErr := threshold.DecodeAll(templateData, file)
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to parse threshold YAML: %w", decodeErr)
		}
		specs = append(specs, parsed...)
	}
	for _, inline := range templateInlines {
		parsed, parseErr := parseInlineThreshold(inline)
		if parseErr != nil {
			return nil, parseErr
		}
		specs = append(specs, threshold.Spec{Config: parsed, Label: inlineLabel(inline)})
	}

	// A spec that asserts nothing passes every document, so reporting success
	// would be a green gate that checked nothing — the same false green a
	// misspelled key used to produce. Among several it is worse, because it rides
	// along on its neighbours' bounds, so the offender is named.
	if len(specs) == 0 {
		return nil, threshold.ErrNoAssertions
	}
	for _, spec := range specs {
		if threshold.AssertionCount(spec.Config) > 0 {
			continue
		}
		if len(specs) == 1 {
			return nil, threshold.ErrNoAssertions
		}
		return nil, fmt.Errorf("%s: %w", spec.Label, threshold.ErrNoAssertions)
	}
	return specs, nil
}

// inlineLabel names an inline spec by echoing the spec back. A file's documents
// are named by path and index because their content is not on the command line;
// an inline spec's content IS what the author typed, so quoting it identifies the
// policy exactly and an index would add nothing. It is not truncated: shortening
// a policy's identity to keep a line tidy defeats the point of naming it.
func inlineLabel(inline string) string {
	return fmt.Sprintf("-I '%s'", inline)
}

// runValidateThresholdFile applies every parsed policy to one document.
func runValidateThresholdFile(file string, specs []threshold.Spec) error {
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

	var violations []string
	for _, spec := range specs {
		for _, violation := range hdfengine.ValidateThresholds(spec.Config, counts, compliance, controlMap) {
			// Attribute only when there is something to disambiguate, so the
			// single-policy output — nearly every run — is unchanged. The label
			// goes into the violation STRING rather than only the printed line,
			// so it survives into the error and therefore into the bulk summary,
			// which reports the first violation per file.
			if len(specs) > 1 {
				violation = fmt.Sprintf("[%s] %s", spec.Label, violation)
			}
			violations = append(violations, violation)
		}
	}
	if len(violations) > 0 {
		for _, violation := range violations {
			fmt.Fprintf(os.Stderr, "FAIL: %s\n", violation)
		}
		fmt.Fprintf(os.Stderr, "\n%d threshold violation(s)\n", len(violations))
		return &exitCodeError{
			code:    1,
			message: fmt.Sprintf("threshold validation failed: %s", violations[0]),
		}
	}

	if !quiet {
		if len(specs) > 1 {
			// Name them: a green gate that does not say which policies ran is the
			// same false green as one that asserted nothing.
			for _, spec := range specs {
				fmt.Fprintf(os.Stderr, "PASS: %s\n", spec.Label)
			}
			fmt.Fprintf(os.Stderr, "All thresholds passed (%d specs)\n", len(specs))
		} else {
			fmt.Fprintf(os.Stderr, "All thresholds passed\n")
		}
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
		if len(segments) > 2 {
			return errTooManySegments(segments, 2, "compliance.min")
		}
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
		if len(segments) > 3 {
			return errTooManySegments(segments, 3, "passed.high.min")
		}
		var bound *ThresholdBound
		if segments[1] == "total" {
			if ts.Total == nil {
				ts.Total = &ThresholdBound{}
			}
			bound = ts.Total
		} else {
			// getSeverityBound buckets anything it does not recognize into
			// "informational", which is right when generate is placing a scan's
			// own severity but wrong here: this segment was typed by a user, so
			// an unrecognized name is a typo that would otherwise assert a bound
			// nobody asked for and pass silently.
			if !isKnownSeverityField(segments[1]) {
				return fmt.Errorf("unknown severity field %q (expected 'critical', 'high', 'medium', 'low', 'informational', or 'total')", segments[1])
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

// errTooManySegments reports a path longer than its branch consumes. It is kept
// distinct from the "unknown segment" errors on purpose: a typo and a run of
// trailing junk need different guidance, and a caller told only that something
// was unrecognized will hunt for a misspelling that is not there.
func errTooManySegments(segments []string, want int, example string) error {
	return fmt.Errorf("threshold path %q has too many segments: %q takes %d (e.g. %q)",
		strings.Join(segments, "."), segments[0], want, example)
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

// knownSeverityFields is the severity vocabulary a threshold path may name: the
// schema's severity enum, plus "none" as the pre-3.7 spelling of informational.
// getSeverityBound (generate_threshold.go) maps anything else to informational
// on purpose, so the inline path checks membership here before calling it.
var knownSeverityFields = []string{"critical", "high", "medium", "low", "informational", "none"}

func isKnownSeverityField(name string) bool {
	for _, known := range knownSeverityFields {
		if name == known {
			return true
		}
	}
	return false
}
