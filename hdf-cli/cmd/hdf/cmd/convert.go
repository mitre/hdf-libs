package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"

	hdfpassthrough "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-passthrough/go"
	legacyhdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/legacyhdf-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/registry/all" // register all fingerprints via init()
	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/hdfversion"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/spf13/cobra"
)

// NewConvertCmd creates the convert command.
func NewConvertCmd() *cobra.Command {
	var (
		fromFormat string
		toFormat   string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "convert <file|dir> [file...] [flags]",
		Short: "Convert between HDF and other security formats",
		Long:  buildConvertLong(),
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return dispatchConvert(cmd, args, fromFormat, toFormat, outputPath)
		},
	}

	cmd.Flags().StringVar(&fromFormat, "from", "", "Source format (auto-detected if omitted)")
	cmd.Flags().StringVar(&toFormat, "to", "hdf", "Target format (default: hdf)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolP("force", "f", false, "Allow overwriting the input file with output")
	cmd.Flags().StringSlice("labels", nil, "Labels to apply to all targets, --to hdf only (key=value pairs, e.g., --labels system=Portal,environment=production)")
	cmd.Flags().String("component-id", "", "Set componentId (a UUID) on all components in the output, --to hdf only")
	cmd.Flags().Int("nist-rev", 0, "NIST 800-53 revision for emitted control tags (4 or 5; default 5)")
	cmd.Flags().String("report-type", "", "Detail level for --to html: executive, manager or administrator (default administrator)")
	cmd.Flags().Bool("nist-strict", false, "Fail if input references rules mapped only at a different NIST revision")
	addNoValidateFlag(cmd)

	// Converter-specific flags
	AddOSCALFlags(cmd)

	return cmd
}

// dispatchConvert routes the arguments to the single, bulk or combined path.
func dispatchConvert(cmd *cobra.Command, args []string, fromFormat, toFormat, outputPath string) error {
	if err := checkHDFOnlyFlags(cmd, toFormat); err != nil {
		return err
	}
	componentID, _ := cmd.Flags().GetString("component-id")
	if err := checkComponentIDFlag(componentID); err != nil {
		return err
	}
	files, err := expandGlobs(args)
	if err != nil {
		return err
	}
	// A target that can combine documents (the HTML report) turns several
	// inputs, or a directory of them, into ONE output when -o names a file.
	// With -o <dir>/ each input still gets its own output, as for any target.
	if multi, converter, ok := aggregatingConverter(toFormat); ok {
		expanded, hadDirectory, expandErr := expandResultDirectories(files)
		if expandErr != nil {
			return expandErr
		}
		files = expanded
		if (len(files) > 1 || hadDirectory) && !isDirectoryOutput(outputPath) {
			return runConvertAggregate(cmd, multi, converter, files, fromFormat, toFormat, outputPath)
		}
	}
	// A gate writes every scan into one directory with a single
	// command, and whether that matched one file or twelve is an
	// accident of how many scanners ran — so -o <dir> routes through
	// the same directory logic at either arity.
	if len(files) > 1 || isDirectoryOutput(outputPath) {
		return runConvertBulk(cmd, files, fromFormat, toFormat, outputPath)
	}
	return runConvert(cmd, files, fromFormat, toFormat, outputPath)
}

// checkHDFOnlyFlags refuses the flags that post-process an HDF document when the
// target is something else. They are applied to the converted bytes, so for a
// non-HDF target they can only be dropped (the combined path) or fail on bytes
// that are not JSON (the single path) — a mistake either way, and one the user
// should hear about before an input is read. Same rule as applyReportType, the
// other way round.
func checkHDFOnlyFlags(cmd *cobra.Command, toFormat string) error {
	format, _ := parseFormatVersion(toFormat)
	if strings.EqualFold(format, "hdf") {
		return nil
	}
	for _, name := range []string{"labels", "component-id"} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--%s applies to --to hdf only, not --to %s", name, format)
		}
	}
	return nil
}

// applyReportType hands --report-type to a converter that offers report types.
// It is always called for such a converter, flag or no flag, because the
// registry holds one instance: an earlier conversion's choice must not carry
// over. For any other target the flag is a mistake, not a no-op.
func applyReportType(cmd *cobra.Command, converter Converter, toFormat string) error {
	reportType, _ := cmd.Flags().GetString("report-type")
	setter, ok := converter.(ReportTypeSetter)
	if !ok {
		if reportType != "" {
			return fmt.Errorf("--report-type applies to --to html only, not --to %s", toFormat)
		}
		return nil
	}
	if err := setter.SetReportType(reportType); err != nil {
		return fmt.Errorf("invalid --report-type: %w", err)
	}
	return nil
}

// parseFormatVersion splits a format@version specifier on the last '@'.
// Returns (format, version). If there is no '@' or only a leading '@', version
// is empty. An empty version string after '@' is treated as no version.
func parseFormatVersion(s string) (format, version string) {
	idx := strings.LastIndex(s, "@")
	if idx <= 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// buildConvertLong generates the Long help text from the live converter registry.
func buildConvertLong() string {
	pairs := ListConverters()
	sort.Slice(pairs, func(i, j int) bool {
		si := pairs[i].Source + " to " + pairs[i].Dest
		sj := pairs[j].Source + " to " + pairs[j].Dest
		return si < sj
	})

	var sb strings.Builder
	sb.WriteString("Convert security assessment data between formats.\n\n")
	sb.WriteString("Auto-detects the input format when --from is omitted.\n")
	sb.WriteString("Default output format is HDF.\n\n")
	sb.WriteString("Supported conversions:\n")
	for _, pair := range pairs {
		fmt.Fprintf(&sb, "  %s → %s\n", pair.Source, pair.Dest)
	}
	sb.WriteString(`
Input can be a file path or "-" for stdin.
Output defaults to stdout if not specified.

With --to html, several inputs, or a directory of HDF results documents,
and -o <file> produce ONE combined report. -o <dir>/ writes one report per
input instead. A directory is searched recursively; files in it that are not
HDF results documents are passed over.

Use format@version to specify a format version:
  --from sarif@2.0    Convert SARIF 2.0 input
  --to hdf@3          Modern HDF (default)
  --to hdf@2          Legacy Heimdall HDF schema (InSpec exec-json shape; loads in Heimdall2)
  --from hdf@2        Convert from the legacy Heimdall HDF schema
  (hdf@1 is not a distinct schema — raw InSpec; use --from inspec)

Examples:
  hdf convert scan.nessus                              # Auto-detect, convert to HDF
  hdf convert scan.nessus -o results.json              # Write to file
  hdf convert --from nessus --to hdf scan.nessus       # Explicit formats
  hdf convert --from sarif@2.0 scan.sarif              # Explicit version
  hdf convert scan.json --nist-rev 5                   # Emit NIST 800-53 Rev 5 control tags
  hdf convert results.json --to html -o report.html    # Self-contained HTML report
  hdf convert results.json --to html --report-type manager -o report.html
  hdf convert scan1.json scan2.json --to html -o report.html   # One combined report
  hdf convert scans/ --to html -o report.html          # Every results document under scans/
  hdf convert scan1.nessus scan2.xml -o output-dir/    # Bulk convert to directory
  hdf convert *.sarif -o converted/                     # Bulk, continues past failures
  hdf convert *.sarif -o converted/ -F                 # Bulk, abort on first failure
  cat scan.json | hdf convert -                        # Read from stdin`)

	return sb.String()
}

// loadConvertInput reads one input and brings it to the form the converter for
// toFormat consumes: source format resolved (auto-detected when --from is not
// given), a legacy SAF supplement absorbed, and legacy HDF upgraded to the
// current schema for an export target. It returns the possibly rewritten data
// with the source format and version to resolve the converter by.
func loadConvertInput(cmd *cobra.Command, inputPath, fromFormat, fromVersion, toFormat string) ([]byte, string, string, error) {
	// Read input. Empty input is allowed through the read boundary so the convert
	// path can honor converters that treat "no bytes" as a valid zero-findings
	// signal (e.g. exit-code-first scanners that emit no report on a clean run).
	// The empty-input policy is enforced below, once the resolved converter is
	// known — every other read boundary still rejects empty via readInputFile.
	printDebug("Reading input from %s", inputPath)
	data, err := readInputFileAllowEmpty(inputPath)
	if err != nil {
		return nil, "", "", err
	}
	printDebug("Read %d bytes", len(data))

	// Empty input carries no bytes to fingerprint, so it is only meaningful with
	// an explicit --from whose converter opts into empty input. Without --from,
	// keep the standard "no input provided" error rather than a confusing
	// auto-detect failure.
	if len(data) == 0 && fromFormat == "" {
		return nil, "", "", fmt.Errorf("no input provided")
	}

	fromFormat, fromVersion, err = detectConvertSource(cmd, data, inputPath, fromFormat, fromVersion)
	if err != nil {
		return nil, "", "", err
	}
	data, fromFormat, fromVersion, err = absorbSAFSupplement(data, fromFormat, fromVersion)
	if err != nil {
		return nil, "", "", err
	}

	// Legacy HDF v1 (InSpec exec-json shape) carries no `baselines`, which every
	// HDF-export converter requires. The hdf→hdf path upgrades it implicitly;
	// mirror that for all other export targets so legacy input converts in one
	// step instead of failing on the missing field. (SAF-supplemented legacy input
	// was already upgraded above, so this is a no-op for it.)
	return normalizeLegacyHDFInput(data, fromFormat, fromVersion, toFormat)
}

// detectConvertSource resolves the source format, auto-detecting it when
// --from was not given; an explicit --from is returned unchanged.
func detectConvertSource(cmd *cobra.Command, data []byte, inputPath, fromFormat, fromVersion string) (format, version string, err error) {
	if fromFormat != "" {
		return fromFormat, fromVersion, nil
	}
	detected, detectedVersion, err := autoDetectFormat(data, inputPath)
	if err != nil {
		return "", "", err
	}
	if fromVersion == "" {
		fromVersion = detectedVersion
	}

	// Native HDF input fingerprints as the passthrough id, which matches no
	// converter (exports are registered under the "hdf" source). When the
	// user asked for a specific export target, normalize so hdf→<target>
	// resolves. When they didn't, there is nothing to convert to — guide
	// them to --to instead of attempting an hdf→hdf no-op or dumping the
	// converter registry.
	if detected == hdfpassthrough.FingerprintID {
		if !cmd.Flags().Changed("to") {
			return "", "", buildAlreadyHDFError()
		}
		detected = "hdf"
	}
	return detected, fromVersion, nil
}

// absorbSAFSupplement absorbs a legacy SAF-supplement shape (top-level
// target/passthrough, which SAF writes onto HDF documents) into v3-native
// carriers so attribution survives the
// convert path — the motivating #234 case — not only the parse path. These keys
// ride v2's additionalProperties, so they are present on the raw bytes even
// though the legacy struct has no field for them. For legacy (v2) input we
// capture them, upgrade to v3 (which would otherwise drop target), re-attach, and
// normalize on the v3 doc so the rewrite lands where it survives; the version
// transform below then carries the result (including a down-pin to hdf@2).
//
// This runs BEFORE normalizeLegacyHDFInput: for a non-hdf export target that
// helper upgrades legacy→v3 itself, dropping the top-level target before we could
// capture it. Doing the capture/upgrade/normalize here (which sets fromFormat=hdf
// for legacy input) leaves normalizeLegacyHDFInput a no-op on the now-v3 data.
// Gated to HDF/legacy input so a scanner format that happens to carry a top-level
// "target" key is untouched.
func absorbSAFSupplement(data []byte, fromFormat, fromVersion string) (out []byte, format, version string, err error) {
	isHDF := strings.EqualFold(fromFormat, "hdf") || strings.EqualFold(fromFormat, "legacyhdf")
	if !isHDF || !hasSAFSupplement(data) {
		return data, fromFormat, fromVersion, nil
	}
	if legacyhdf.IsLegacyHDF(data) {
		supp := captureSAFSupplement(data)
		upgraded, _, upErr := hdfversion.TransformHDF(data, hdfversion.LegacyVersion, hdfversion.ModernVersion)
		if upErr != nil {
			return nil, "", "", fmt.Errorf("failed to upgrade legacy HDF (v2) input for SAF-supplement absorption: %w", upErr)
		}
		if data, err = reattachSAFSupplement(upgraded, supp); err != nil {
			return nil, "", "", err
		}
		fromFormat = "hdf"
		fromVersion = ""
	}
	var safWarnings []string
	data, safWarnings = hdfparsers.NormalizeSAFSupplement(data)
	for _, w := range safWarnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", sanitizeOutput(w))
	}
	return data, fromFormat, fromVersion, nil
}

// runConvert executes the convert command.
func runConvert(cmd *cobra.Command, args []string, fromFormat, toFormat, outputPath string) error {
	inputPath := args[0]

	// Raise the converters' own input-size guard (they pass a literal 0 = the
	// 50 MiB default) to the resolved --max-size, so input the CLI pre-read admits
	// is not then rejected by the converter — the "use --max-size to increase"
	// advice now works end to end. Same resolver as the pre-read; scoped to this
	// convert invocation (the process exits after).
	hdfutil.SetDefaultMaxInputSize(maxInputSizeBytes())

	// Parse version specifiers from format flags (e.g. "sarif@2.0" → "sarif", "2.0")
	fromFormat, fromVersion := parseFormatVersion(fromFormat)
	toFormat, toVersion := parseFormatVersion(toFormat)

	// There is no distinct HDF v1 schema (v1 = raw InSpec, same shape as the v2
	// legacy Heimdall schema). Map hdf@1 → v2 with a warning; hdf@2/@3 pass
	// through silently. Guarded on the hdf format so a "1" version on another
	// format (e.g. sarif@1) is left untouched.
	fromVersion = normalizeHDFVersion(fromFormat, fromVersion)
	toVersion = normalizeHDFVersion(toFormat, toVersion)

	// Select the NIST revision converters emit control tags for, restoring the
	// defaults afterward so one invocation can't leak into the next.
	if reset, err := applyNistOptions(cmd); err != nil {
		return err
	} else if reset != nil {
		defer reset()
	}

	if err := checkConvertOverwrite(cmd, inputPath, outputPath); err != nil {
		return err
	}

	data, fromFormat, fromVersion, err := loadConvertInput(cmd, inputPath, fromFormat, fromVersion, toFormat)
	if err != nil {
		return err
	}

	// Sync the CLI --catalog flag into the lifted registry so the oscal-profile
	// converter can read it (the registry owns the catalog path now, not cmd).
	convreg.SetOSCALCatalogPath(oscalCatalogFlag)

	// Get converter
	converter, err := GetConverter(fromFormat, toFormat)
	if err != nil {
		return buildConverterNotFoundError(fromFormat, toFormat)
	}
	printDebug("Using converter: %s", converter.Name())

	if err := applyReportType(cmd, converter, toFormat); err != nil {
		return err
	}

	if err := checkEmptyInput(converter, data); err != nil {
		return err
	}

	// Run conversion with version handling
	output, err := runVersionedConvert(converter, data, fromVersion, toVersion, inputPath)
	if err != nil {
		return err
	}

	output, err = applyConvertFlags(cmd, output)
	if err != nil {
		return err
	}

	// Write output (with schema validation if target is HDF and --no-validate not set)
	if strings.EqualFold(toFormat, "hdf") {
		output, err = stampConvertOutput(output)
		if err != nil {
			return err
		}
		if w := outputSizeWarning(len(output)); w != "" {
			fmt.Fprintln(os.Stderr, "Warning: "+w)
		}
		return writeValidatedHDFOutput(cmd, output, outputPath)
	}
	return writeConvertOutput(output, outputPath)
}

// normalizeHDFVersion maps an hdf@ version onto the schema that exists for it,
// warning on stderr when it had to; any other format's version is left alone.
func normalizeHDFVersion(format, version string) string {
	if !strings.EqualFold(format, "hdf") {
		return version
	}
	normalized, warn := hdfversion.NormalizeVersion(version)
	if warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}
	return normalized
}

// checkConvertOverwrite refuses an output path that is the input file, unless --force.
func checkConvertOverwrite(cmd *cobra.Command, inputPath, outputPath string) error {
	if outputPath == "" || outputPath == "-" || inputPath == "-" {
		return nil
	}
	if force, _ := cmd.Flags().GetBool("force"); force {
		return nil
	}
	return checkOutputOverwritesInput(inputPath, outputPath)
}

// checkEmptyInput enforces the empty-input policy once the converter is known:
// empty input is only valid for converters that explicitly accept it
// (EmptyInputAccepting, e.g. exit-code-first scanners). Everything else keeps
// the standard error.
func checkEmptyInput(converter Converter, data []byte) error {
	if len(data) != 0 {
		return nil
	}
	if e, ok := converter.(EmptyInputAccepting); !ok || !e.AcceptsEmptyInput() {
		return fmt.Errorf("no input provided")
	}
	printDebug("Empty input accepted by %s converter as zero findings", converter.Name())
	return nil
}

// applyConvertFlags applies --labels and --component-id to converted output.
func applyConvertFlags(cmd *cobra.Command, output []byte) ([]byte, error) {
	labelPairs, _ := cmd.Flags().GetStringSlice("labels")
	if len(labelPairs) > 0 {
		labels, err := parseLabelsFlag(labelPairs)
		if err != nil {
			return nil, fmt.Errorf("invalid --labels flag: %w", err)
		}
		output, err = hdfdoc.ApplyLabels(output, labels)
		if err != nil {
			return nil, fmt.Errorf("failed to apply labels: %w", err)
		}
		printDebug("Applied %d labels to output", len(labels))
	}

	componentID, _ := cmd.Flags().GetString("component-id")
	if componentID != "" {
		stamped, err := hdfdoc.ApplyComponentID(output, componentID, false)
		switch {
		// A converter whose source names no target legitimately produces no
		// component, so the conversion stands and only the flag goes unapplied.
		case errors.Is(err, hdfdoc.ErrNoComponents):
			fmt.Fprintf(os.Stderr, "Warning: --component-id was not applied: %v\n", err)
		case err != nil:
			return nil, fmt.Errorf("failed to apply component-id: %w", err)
		default:
			output = stamped
			printDebug("Applied componentId %s to output", componentID)
		}
	}
	return output, nil
}

// outputSizeWarning returns a warning (or "") when converted HDF output is larger
// than the default input read limit, so the user knows downstream commands (hdf
// validate, label, amend) will need --max-size to read it at the default — the
// convert-emits-what-validate-rejects trap from issue #334. It reports downstream
// need regardless of this invocation's --max-size, since the next command starts
// from the default again.
func outputSizeWarning(outputLen int) string {
	if outputLen <= hdfutil.DefaultMaxInputSize {
		return ""
	}
	const mib = 1024 * 1024
	needMB := (outputLen + mib - 1) / mib
	return fmt.Sprintf(
		"output is %d bytes, larger than the %d MB default read limit; downstream commands will need --max-size %d to read it.",
		outputLen, hdfutil.DefaultMaxInputSize/mib, needMB)
}

// applyNistOptions reads the --nist-rev and --nist-strict flags and sets the
// matching process-global NIST options the mapping/converter packages consult.
// It returns a reset func to restore the defaults (nil when neither flag was
// set), or an error for an unsupported revision.
func applyNistOptions(cmd *cobra.Command) (reset func(), err error) {
	rev, _ := cmd.Flags().GetInt("nist-rev")
	strict, _ := cmd.Flags().GetBool("nist-strict")
	if rev == 0 && !strict {
		return nil, nil
	}
	if rev != 0 {
		if err := nist.SetRevision(rev); err != nil {
			return nil, err
		}
		printDebug("Emitting NIST 800-53 Rev %d control tags", rev)
	}
	if strict {
		nist.SetStrict(true)
		printDebug("Strict NIST revision alignment enabled")
	}
	return func() {
		nist.ResetRevision()
		nist.SetStrict(false)
	}, nil
}

// hasSAFSupplement reports whether the bytes carry a top-level SAF-supplement key
// (target or passthrough) — the non-schema attribution SAF writes onto HDF
// documents. A cheap presence check; NormalizeSAFSupplement owns the rewrite.
func hasSAFSupplement(data []byte) bool {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return false
	}
	_, hasTarget := doc["target"]
	_, hasPassthrough := doc["passthrough"]
	return hasTarget || hasPassthrough
}

// captureSAFSupplement extracts the top-level target/passthrough keys so they can
// be re-attached after a legacy→v3 upgrade drops them (the legacy struct has no
// field for target, so a plain unmarshal/marshal loses it).
func captureSAFSupplement(data []byte) map[string]json.RawMessage {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	out := map[string]json.RawMessage{}
	for _, k := range []string{"target", "passthrough"} {
		if v, ok := doc[k]; ok {
			out[k] = v
		}
	}
	return out
}

// reattachSAFSupplement puts captured SAF-supplement keys back onto an upgraded v3
// document so NormalizeSAFSupplement can absorb them into components[]/extensions.
func reattachSAFSupplement(data []byte, supp map[string]json.RawMessage) ([]byte, error) {
	if len(supp) == 0 {
		return data, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to re-attach SAF supplement: %w", err)
	}
	for k, v := range supp {
		doc[k] = v
	}
	return json.Marshal(doc)
}

// normalizeLegacyHDFInput upgrades legacy HDF (v2, the InSpec exec-json
// profiles/platform shape, which has no `baselines`) to modern HDF (v3) before a
// non-hdf export converter consumes it. Conversions to hdf are left untouched —
// the hdf→hdf converter handles version transforms itself. Returns the
// (possibly upgraded) data along with the source format/version to use
// downstream; on upgrade the source becomes plain modern hdf.
func normalizeLegacyHDFInput(data []byte, fromFormat, fromVersion, toFormat string) ([]byte, string, string, error) {
	if strings.EqualFold(toFormat, "hdf") {
		return data, fromFormat, fromVersion, nil
	}
	// Only HDF-source conversions are candidates: explicit --from hdf (with or
	// without an @version) or the auto-detected legacyhdf fingerprint. Whether
	// the bytes are actually v1 is decided by content below, not by the version.
	if !strings.EqualFold(fromFormat, "hdf") && !strings.EqualFold(fromFormat, "legacyhdf") {
		return data, fromFormat, fromVersion, nil
	}
	// Skip when there is no hdf→target export converter to feed — let the normal
	// "no converter found" error report against the original source format.
	if _, err := GetConverter("hdf", toFormat); err != nil {
		return data, fromFormat, fromVersion, nil //nolint:nilerr // absence of a converter is not an error here; fall through to the standard not-found path
	}
	// Detect the legacy shape by content so `--from hdf`, `--from hdf@2`, and
	// auto-detected legacyhdf input are all handled; modern HDF is left untouched.
	if !legacyhdf.IsLegacyHDF(data) {
		return data, fromFormat, fromVersion, nil
	}
	upgraded, _, err := hdfversion.TransformHDF(data, hdfversion.LegacyVersion, hdfversion.ModernVersion)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to upgrade legacy HDF (v2) input for %s conversion: %w", toFormat, err)
	}
	printDebug("Upgraded legacy HDF (v2) input to modern HDF for %s conversion", toFormat)
	return upgraded, "hdf", "", nil
}

// runVersionedConvert passes version specifiers to the converter and runs
// the conversion with optional post-processing for output version downgrades.
func runVersionedConvert(converter Converter, data []byte, fromVersion, toVersion, inputPath string) ([]byte, error) {
	// Pass input version to versioned converters
	if fromVersion != "" {
		if vc, ok := converter.(VersionedConverter); ok {
			vc.SetInputVersion(fromVersion)
		}
	}

	// Pass output version to converters that support it (e.g. hdf→hdf)
	if toVersion != "" {
		if ovs, ok := converter.(OutputVersionSetter); ok {
			ovs.SetOutputVersion(toVersion)
		}
	}

	// Convert
	output, err := converter.Convert(data)
	if err != nil {
		return nil, fmt.Errorf("conversion failed: %w", err)
	}
	printDebug("Conversion produced %d bytes", len(output))

	// Count fidelity: a converter that declares how many requirements its input
	// must yield is held to it on the document it produced, before a version
	// downgrade or anything else reshapes it.
	if err := checkConversionFidelity(converter, data, output, inputPath); err != nil {
		return nil, err
	}

	// Post-process: downgrade HDF version if --to hdf@N was specified
	// (only for non-HDF→HDF converters; the hdf→hdf converter handles it internally)
	if toVersion != "" && toVersion != hdfversion.ModernVersion {
		if !convreg.HandlesOutputVersionInternally(converter) {
			printDebug("Post-processing output to HDF version %s", toVersion)
			output, err = convreg.PostProcessToVersion(output, toVersion)
			if err != nil {
				return nil, err
			}
		}
	}

	return output, nil
}

// autoDetectFormat runs fingerprint detection on the input and returns the
// detected format name and version. Prints the detection result to stderr.
func autoDetectFormat(data []byte, inputPath string) (format, version string, err error) {
	result := registry.DetectConverter(data)
	if result == nil {
		return "", "", fmt.Errorf("could not auto-detect input format for %s (confidence too low or ambiguous)\n"+
			"Specify the format explicitly with --from <format>\n"+
			"Run 'hdf convert --help' to see supported formats", inputPath)
	}
	format = registry.SourceNameFromFingerprintID(result.Fingerprint.ID)
	version = result.Version
	printDebug("Auto-detected format: %s (confidence: %.0f%%)", format, result.Confidence*100)
	if result.Version != "" {
		fmt.Fprintf(os.Stderr, "Detected: %s %s (confidence: %.0f%%)\n", result.Fingerprint.Label, result.Version, result.Confidence*100)
	} else {
		fmt.Fprintf(os.Stderr, "Detected: %s (confidence: %.0f%%)\n", result.Fingerprint.Label, result.Confidence*100)
	}
	return format, version, nil
}

// buildAlreadyHDFError reports that the input is already HDF and lists the
// export targets the "hdf" source can convert to. Used when native-HDF input
// is auto-detected and no --to was given, so the user gets actionable guidance
// instead of an hdf→hdf no-op or a registry dump.
func buildAlreadyHDFError() error {
	var targets []string
	for _, pair := range ListConverters() {
		if strings.EqualFold(pair.Source, "hdf") && !strings.EqualFold(pair.Dest, "hdf") {
			targets = append(targets, pair.Dest)
		}
	}
	sort.Strings(targets)

	if len(targets) == 0 {
		return fmt.Errorf("input is already HDF; specify --to <format> to export it")
	}
	return fmt.Errorf("input is already HDF; specify --to <format> to export it (e.g. %s)",
		strings.Join(targets, ", "))
}

// buildConverterNotFoundError creates a helpful error message when a converter is not found.
func buildConverterNotFoundError(source, dest string) error {
	allPairs := ListConverters()

	var sourceDestinations []string
	for _, pair := range allPairs {
		if strings.EqualFold(pair.Source, source) {
			sourceDestinations = append(sourceDestinations, pair.Dest)
		}
	}

	var destSources []string
	for _, pair := range allPairs {
		if strings.EqualFold(pair.Dest, dest) {
			destSources = append(destSources, pair.Source)
		}
	}

	var msg strings.Builder
	fmt.Fprintf(&msg, "no converter found for: %s → %s", source, dest)

	switch {
	case len(sourceDestinations) > 0:
		fmt.Fprintf(&msg, "\n\nThe '%s' format can convert to: %s", source, strings.Join(sourceDestinations, ", "))
	case len(destSources) > 0:
		fmt.Fprintf(&msg, "\n\nUnrecognized source format: '%s'", source)
		fmt.Fprintf(&msg, "\nFormats that can convert to '%s': %s", dest, strings.Join(destSources, ", "))
	default:
		fmt.Fprintf(&msg, "\n\nUnrecognized format(s): '%s', '%s'", source, dest)
	}

	msg.WriteString("\n\nRun 'hdf convert --help' to see all available conversions")

	return fmt.Errorf("%s", msg.String())
}

// checkOutputOverwritesInput returns an error if the resolved output path
// is the same file as the input path.
func checkOutputOverwritesInput(inputPath, outputPath string) error {
	inputAbs, err := filepath.Abs(inputPath)
	if err != nil {
		return nil //nolint:nilerr // If we can't resolve, allow the operation
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return nil //nolint:nilerr // If we can't resolve, allow the operation
	}
	if inputAbs == outputAbs {
		return fmt.Errorf("output path %q would overwrite input file; use a different output path or --force to override", outputPath)
	}
	return nil
}

// writeConvertOutput writes conversion output to a file or stdout.
func writeConvertOutput(data []byte, path string) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

// runConvertBulk converts multiple files, writing output to a directory.
// Each output file is named <stem>.hdf.json (or .hdf.<ext> for non-HDF targets).
func runConvertBulk(cmd *cobra.Command, files []string, fromFormat, toFormat, outputDir string) error {
	// -o is required for bulk convert (stdout doesn't work for multiple files).
	if outputDir == "" {
		return fmt.Errorf("bulk convert requires -o <output-directory> for multiple files")
	}

	// Name every output before creating the directory, so a set that cannot be
	// written without losing a report is refused having written nothing.
	paths, err := bulkOutputPaths(outputDir, files, toFormat)
	if err != nil {
		return err
	}
	outputs := make(map[string]string, len(files))
	for i, file := range files {
		outputs[file] = paths[i]
	}

	// Ensure output directory exists.
	if err := os.MkdirAll(outputDir, 0o750); err != nil { // #nosec G301 -- CLI creates user-requested directory
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return runBulk(files, "conversion", "converted", func(file string) error {
		return runConvert(cmd, []string{file}, fromFormat, toFormat, outputs[file])
	})
}

// bulkOutputPaths names an output file for every input. Inputs that share a file
// name — routine for a directory of per-host scans — would all be named after
// that one base name, so each of them is named by its path below the directory
// they share instead, with the separators mapped to a character a file name can
// hold. Two different inputs that still name one output are refused: one of them
// silently overwriting the other reports both files converted while keeping only
// the last. The same input named twice is left alone — an argument list may do
// that on purpose, and the second conversion writes the same bytes.
func bulkOutputPaths(outputDir string, files []string, toFormat string) ([]string, error) {
	grouped := map[string][]int{}
	for i, file := range files {
		base := filepath.Base(file)
		grouped[base] = append(grouped[base], i)
	}

	paths := make([]string, len(files))
	for _, group := range grouped {
		if len(group) == 1 {
			paths[group[0]] = bulkOutputPath(outputDir, files[group[0]], toFormat)
			continue
		}
		shared := commonParentDir(files, group)
		for _, i := range group {
			paths[i] = bulkOutputPath(outputDir, qualifiedInputName(files[i], shared), toFormat)
		}
	}

	named := make(map[string]string, len(paths))
	for i, path := range paths {
		first, repeat := named[path]
		switch {
		case !repeat:
			named[path] = files[i]
		case !sameInputFile(first, files[i]):
			return nil, fmt.Errorf("%s and %s would both be written to %s; convert them separately or to different directories",
				first, files[i], path)
		}
	}
	return paths, nil
}

// sameInputFile reports whether two arguments name one file, which an argument
// list may do on purpose — a literal repeated, or one a glob also matched.
func sameInputFile(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return absA == absB
}

// commonParentDir returns the deepest directory every named input lies under, or
// "" when they share none (a mix of absolute and relative paths, or two volumes).
func commonParentDir(files []string, group []int) string {
	parts := strings.Split(filepath.ToSlash(filepath.Dir(files[group[0]])), "/")
	for _, i := range group[1:] {
		other := strings.Split(filepath.ToSlash(filepath.Dir(files[i])), "/")
		shared := 0
		for shared < len(parts) && shared < len(other) && parts[shared] == other[shared] {
			shared++
		}
		parts = parts[:shared]
	}
	return strings.Join(parts, "/")
}

// qualifiedInputName renders an input path as a single file-name component: its
// path below root, with the separators (and a Windows volume colon) mapped to
// characters a file name can carry.
func qualifiedInputName(file, root string) string {
	name := filepath.ToSlash(filepath.Clean(file))
	if root != "" {
		if rel, err := filepath.Rel(root, file); err == nil {
			name = filepath.ToSlash(rel)
		}
	}
	name = strings.ReplaceAll(name, ":", "-")
	return strings.Trim(strings.ReplaceAll(name, "/", "--"), "-")
}
