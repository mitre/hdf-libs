package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/threshold"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"

	"github.com/spf13/cobra"
)

// noFindings suppresses the per-requirement list under each violation. It is a
// package var rather than a closure capture because the printer that reads it is
// a free function, matching how `quiet` is carried on the sibling command.
var noFindings bool

// sourceName labels a document read from stdin in the verdict line. Package
// scope mirrors noFindings: the renderer is reached through runBulk, which has
// no route for per-command options.
var sourceName string

func newValidateThresholdCmd() *cobra.Command {
	var (
		templateFiles   []string
		templateInlines []string
		localNoFindings bool
		localSourceName string
	)

	cmd := &cobra.Command{
		Use:   "threshold <results.json>",
		Short: "Validate HDF results against compliance thresholds",
		Long: `Validate that an HDF results file meets compliance thresholds
defined in a YAML threshold template or an inline specification.

-T and -I are repeatable and may be combined, and one -T file may hold several
YAML documents. Every spec is evaluated and the run fails if any of them fails;
a violation names the spec it came from. -F stops after the first failing FILE,
never at the first failing spec within one.

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
		RunE: func(cmd *cobra.Command, args []string) error {
			noFindings = localNoFindings
			// Refused rather than preferred or ignored. Preferring it would let a
			// mislabelled name misattribute a real file, which is the opposite of
			// what the flag exists for; ignoring it would leave half the command
			// dead with no warning. One name also cannot label several documents.
			if err := checkSourceNameArgs(localSourceName, args); err != nil {
				return err
			}
			sourceName = localSourceName
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
				// withFailureDetail: runValidateThresholdFile already renders a
				// self-contained verdict per file — the document named, each
				// breached bound, and the requirements under it — so bulk keeps
				// that instead of collapsing it to the first line of the error.
				// Without it the same command read two ways depending on how many
				// files were passed, and a CI loop over per-tool thresholds got
				// the shape that says least.
				return runBulk(files, "threshold validation", "passed thresholds", func(file string) error {
					return runValidateThresholdFile(cmd.Context(), file, specs)
				}, withFailureDetail())
			}
			return runValidateThresholdFile(cmd.Context(), files[0], specs)
		},
	}

	// StringArray, not StringSlice: StringSlice splits its value on commas, and an
	// inline spec is itself comma-separated, so it would arrive shredded into
	// fragments. Repeating either flag adds a policy; every policy must pass.
	cmd.Flags().StringArrayVarP(&templateFiles, "template", "T", nil, "Threshold YAML template file (repeatable; every spec must pass)")
	cmd.Flags().StringArrayVarP(&templateInlines, "inline", "I", nil, `Inline threshold, repeatable (e.g. "{compliance.min: 80}, {failed.total.max: 0}")`)
	// On by default: a contributor who hits a red check has no reason to know a
	// flag exists, so the findings have to be there without being asked for. The
	// flag is for the pipeline that greps this output and wants them gone — and
	// that author will think to read --help.
	cmd.Flags().BoolVar(&localNoFindings, "no-findings", false,
		"Suppress the list of requirements printed under each violation")
	// A document on stdin has no filename, so every verdict reads <stdin> and a
	// pipeline streaming several of them cannot tell which one failed. Named
	// --source-name rather than --label because a spec already carries a Label
	// and violations are prefixed with it; --label here would read as naming the
	// policy, in output that already names policies.
	cmd.Flags().StringVar(&localSourceName, "source-name", "",
		"Name to report for a document read from stdin; one line, no control characters (default \"<stdin>\")")

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
		parsed, parseErr := decodeInline(inline)
		if parseErr != nil {
			return nil, parseErr
		}
		for _, spec := range parsed {
			spec.Label = inlineLabel(inline)
			specs = append(specs, spec)
		}
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

// decodeInline turns one -I value into policies. Anything expressible in a
// threshold file is expressible inline, because a structured spec goes through
// the SAME decoder a file does rather than through a second grammar; the dotted
// SAF form remains for the shape it was designed for.
//
// The two are told apart by their keys, not by trying one and falling back:
// the dotted form's top-level keys carry a "." (failed.total.max), a structured
// spec's do not (failed, rules, compliance). Guessing by fallback would diagnose
// a structured typo with the dotted grammar's error and send the author looking
// for a mistake they did not make.
func decodeInline(inline string) ([]threshold.Spec, error) {
	if inlineIsDotted(inline) {
		parsed, err := parseInlineThreshold(inline)
		if err != nil {
			return nil, err
		}
		return []threshold.Spec{{Config: parsed}}, nil
	}
	specs, err := threshold.DecodeAll([]byte(inline), "-I")
	if err != nil {
		return nil, fmt.Errorf("failed to parse inline threshold: %w", err)
	}
	return specs, nil
}

// inlineIsDotted reports whether a -I value is the dotted SAF form. A value that
// is not a YAML mapping at all is dotted too: "{a.b: 1}, {c.d: 2}" is two flow
// mappings separated by a comma, which YAML does not accept as one document.
func inlineIsDotted(inline string) bool {
	var probe map[string]interface{}
	if err := yaml.Unmarshal([]byte(inline), &probe); err != nil {
		return true
	}
	for key := range probe {
		if strings.Contains(key, ".") {
			return true
		}
	}
	return len(probe) == 0
}

// inlineLabel names an inline spec by echoing the spec back. A file's documents
// are named by path and index because their content is not on the command line;
// an inline spec's content IS what the author typed, so quoting it identifies the
// policy exactly and an index would add nothing. It is not truncated: shortening
// a policy's identity to keep a line tidy defeats the point of naming it.
func inlineLabel(inline string) string {
	return fmt.Sprintf("-I '%s'", inline)
}

// legacySeverityNotes reports a spec naming a severity bucket by a name that is
// not one of the categories. The five categories are critical, high, medium, low
// and informational; "none" is an accepted alias that resolves onto
// informational, so the bound is honoured — but a reader looking for a "none"
// bucket in the output will not find one, and should be told what their key
// actually names.
//
// It reports the SPEC, not the document, so it does not depend on what the
// document happens to contain.
func legacySeverityNotes(specs []threshold.Spec) []string {
	sections := func(c *hdfengine.ThresholdConfig) []struct {
		name string
		ts   *hdfengine.ThresholdSeverity
	} {
		return []struct {
			name string
			ts   *hdfengine.ThresholdSeverity
		}{
			{hdfengine.ThresholdPassed, c.Passed},
			{hdfengine.ThresholdFailed, c.Failed},
			{hdfengine.ThresholdSkipped, c.Skipped},
			{hdfengine.ThresholdError, c.Error},
			{hdfengine.ThresholdNoImpact, c.NoImpact},
		}
	}

	seen := map[string]bool{}
	var notes []string
	for _, spec := range specs {
		if spec.Config == nil {
			continue
		}
		for _, section := range sections(spec.Config) {
			if section.ts == nil || section.ts.None == nil || seen[section.name] {
				continue
			}
			// A section setting BOTH names is refused, not resolved, so saying
			// "none is read as informational" would assert a resolution that does
			// not happen — and the refusal printed moments later says so. The
			// refusal explains itself; this note would only contradict it.
			if section.ts.Informational != nil {
				continue
			}
			seen[section.name] = true
			notes = append(notes, fmt.Sprintf(
				"warning: 'none' is not a severity category; %s.none is read as %s.informational",
				section.name, section.name))
		}
	}
	return notes
}

// describeFinding renders one offending requirement: the id a reader will grep
// for, its title when it has one, and the bucket that put it in breach.
func describeFinding(f hdfengine.Match) string {
	line := f.ID
	if f.Title != "" {
		line += "  " + f.Title
	}
	return fmt.Sprintf("%s  [%s/%s]", line, f.Status, f.Severity)
}

// runValidateThresholdFile applies every parsed policy to one document.
func runValidateThresholdFile(ctx context.Context, file string, specs []threshold.Spec) error {
	data, err := readInputFile(file)
	if err != nil {
		return err
	}

	// One parse, one resolver: the grid's counts and the rules' filtering cannot
	// disagree about what "failed" means on this document.
	input, err := thresholdInputFor(data)
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintln(os.Stderr, agentOverrideReadout(countAgentOverrides(data)))
		notes := legacySeverityNotes(specs)
		for _, note := range notes {
			fmt.Fprintln(os.Stderr, note)
		}
		// A bulk run captures the stderr above and prints only "<file>: ok", so
		// without this the note is silent in exactly the directory shape this
		// command documents as the gate's primary use. The note channel survives
		// the capture.
		if len(notes) > 0 {
			noteLegacySeverityKey(len(notes))
		}
	}

	var violations []hdfengine.Violation
	for _, spec := range specs {
		// Evaluate, not ValidateThresholds: the grid alone cannot apply a rule,
		// and returning its verdict over a rules-bearing policy would report a
		// passing gate over policy nobody applied.
		for _, violation := range hdfengine.EvaluateContext(ctx, spec.Config, input) {
			// Attribute only when there is something to disambiguate, so the
			// single-policy output — nearly every run — is unchanged. The label
			// goes into the violation MESSAGE rather than only the printed line,
			// so it survives into the error and therefore into the bulk summary,
			// which reports the first violation per file.
			if len(specs) > 1 {
				violation.Message = fmt.Sprintf("[%s] %s", spec.Label, violation.Message)
			}
			violations = append(violations, violation)
		}
	}
	// A cancelled run returns what it had evaluated; that must not read as a
	// clean verdict, so the cancellation is the result.
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(violations) > 0 {
		// Mirrors `hdf validate`'s verdict shape: a ✗ headline on stderr naming
		// the document and why, a blank line, then an indented block of the
		// specifics. The two commands answer the same kind of question about the
		// same kind of file, so they should not read differently.
		fmt.Fprintf(os.Stderr, "✗ %s — %d threshold %s\n", displayNameFor(file), len(violations), plural("violation", len(violations)))
		fmt.Fprintf(os.Stderr, "\n  Violations:\n")
		for _, violation := range violations {
			fmt.Fprintf(os.Stderr, "    %s\n", violation.Message)
			// Under the violation it explains, indented beneath it, so a reader
			// scanning the block sees which bound each finding belongs to. Every
			// one of them: a gate over thousands of findings is why --no-findings
			// exists, not a reason to truncate and leave the reader guessing.
			if !noFindings {
				for _, f := range violation.Findings {
					fmt.Fprintf(os.Stderr, "      %s\n", describeFinding(f))
				}
			}
		}
		return &exitCodeError{
			code:    1,
			message: fmt.Sprintf("threshold validation failed: %s", violations[0].Message),
		}
	}

	// ✓ goes to stdout and ✗ to stderr, as in `hdf validate` — which means the
	// mark must be suppressed under --json, or a caller piping stdout to jq gets
	// a line of prose before the document. `hdf validate` emits a JSON verdict
	// here; this command has never emitted one, so --json stdout stays empty
	// rather than growing a surface this card did not design.
	if !jsonOutput && !quiet {
		if len(specs) > 1 {
			// Name them: a green gate that does not say which policies ran is the
			// same false green as one that asserted nothing.
			fmt.Printf("✓ %s passed all %d thresholds\n", displayNameFor(file), len(specs))
			for _, spec := range specs {
				fmt.Printf("    %s\n", spec.Label)
			}
		} else {
			fmt.Printf("✓ %s passed all thresholds\n", displayNameFor(file))
		}
	}
	return nil
}

// validateSourceName refuses a name that cannot occupy one verdict line.
//
// A verdict is a single line, so a newline in this value forges a second line
// that reads as a verdict — and the flag exists for pipelines whose label comes
// from a filename or matrix value the author does not fully control, so the value
// is not reliably self-chosen. ANSI escapes would reach the terminal the same way.
//
// Refused rather than stripped. Stripping would make the verdict name something
// that is not the document, which is the attribution failure the flag exists to
// fix, and a control character in a filename is worth surfacing rather than
// quietly removing. This is NOT sanitizeOutput: that one deliberately preserves
// newline, tab and carriage return because it guards multi-line document prose.
// checkSourceNameArgs applies the argument rules a --source-name carries, for
// every command that takes the flag: one name cannot label several documents,
// so more than one argument is refused even when every one of them is `-` (a
// bulk run would otherwise print the name against the first document and the
// raw `-` against the rest), and a real file is refused because a name applied
// to it could misattribute it.
func checkSourceNameArgs(name string, args []string) error {
	if err := validateSourceName(name); err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	if len(args) > 1 {
		return fmt.Errorf("--source-name names a single document read from stdin, "+
			"but %d arguments were given", len(args))
	}
	for _, arg := range args {
		if arg != "-" {
			return fmt.Errorf("--source-name names a document read from stdin; "+
				"drop it, or pass - instead of %s", arg)
		}
	}
	return nil
}

func validateSourceName(name string) error {
	for i, r := range name {
		// unicode.IsControl covers C0, DEL and C1 — so U+0085 NEL, a real break
		// vector in a UTF-8 terminal, is caught alongside \n. Zl and Zp are
		// U+2028/U+2029, which ARE line separators by definition: leaving them in
		// would make the message below a false claim even though they do not split
		// a line for grep. Format characters (bidi overrides, ZWNJ, soft hyphen)
		// are deliberately NOT rejected here — U+202E can reverse a displayed
		// filename, which is name spoofing rather than verdict forgery, and a
		// blanket Cf rejection would refuse legitimate Persian and Indic filenames
		// that use ZWNJ. Tracked separately.
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return fmt.Errorf("--source-name must not contain control or line-separator "+
				"characters; found %q at byte %d", r, i)
		}
	}
	return nil
}

// displayNameFor names a document in a verdict line, spelling stdin `<stdin>`
// rather than printing a bare dash. Shared with `hdf validate` so the two
// commands cannot drift apart on how they name the file they are talking about.
func displayNameFor(file string) string {
	if file == "" || file == "-" {
		if sourceName != "" {
			return sourceName
		}
		return "<stdin>"
	}
	return file
}

// plural is the count-aware noun the verdict line needs. "violation(s)" reads as
// a template nobody finished.
func plural(noun string, n int) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
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
// schema's severity enum, plus "none", the name informational replaced in 3.7.0.
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
