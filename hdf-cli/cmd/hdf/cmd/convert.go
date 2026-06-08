package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	hdfpassthrough "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-passthrough/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/registry/all" // register all fingerprints via init()
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
		Use:   "convert <file> [file...] [flags]",
		Short: "Convert between HDF and other security formats",
		Long:  buildConvertLong(),
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := expandGlobs(args)
			if err != nil {
				return err
			}
			if len(files) > 1 {
				return runConvertBulk(cmd, files, fromFormat, toFormat, outputPath)
			}
			return runConvert(cmd, args, fromFormat, toFormat, outputPath)
		},
	}

	cmd.Flags().StringVar(&fromFormat, "from", "", "Source format (auto-detected if omitted)")
	cmd.Flags().StringVar(&toFormat, "to", "hdf", "Target format (default: hdf)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolP("force", "f", false, "Allow overwriting the input file with output")
	cmd.Flags().StringSlice("labels", nil, "Labels to apply to all targets (key=value pairs, e.g., --labels system=Portal,environment=production)")
	cmd.Flags().String("component-id", "", "Set componentId on all components in the output")
	addNoValidateFlag(cmd)

	// Converter-specific flags
	AddOSCALFlags(cmd)

	return cmd
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

Use format@version to specify a format version:
  --from sarif@2.0    Convert SARIF 2.0 input
  --from hdf@1        Convert from legacy InSpec exec-json
  --to hdf@1          Downgrade output to legacy InSpec format

Examples:
  hdf convert scan.nessus                              # Auto-detect, convert to HDF
  hdf convert scan.nessus -o results.json              # Write to file
  hdf convert --from nessus --to hdf scan.nessus       # Explicit formats
  hdf convert --from sarif@2.0 scan.sarif              # Explicit version
  hdf convert scan1.nessus scan2.xml -o output-dir/    # Bulk convert to directory
  hdf convert *.sarif -o converted/                     # Bulk, continues past failures
  hdf convert *.sarif -o converted/ -F                 # Bulk, abort on first failure
  cat scan.json | hdf convert -                        # Read from stdin`)

	return sb.String()
}

// runConvert executes the convert command.
func runConvert(cmd *cobra.Command, args []string, fromFormat, toFormat, outputPath string) error {
	inputPath := args[0]

	// Parse version specifiers from format flags (e.g. "sarif@2.0" → "sarif", "2.0")
	fromFormat, fromVersion := parseFormatVersion(fromFormat)
	toFormat, toVersion := parseFormatVersion(toFormat)

	// Check if output would overwrite input
	if outputPath != "" && outputPath != "-" && inputPath != "-" {
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			if err := checkOutputOverwritesInput(inputPath, outputPath); err != nil {
				return err
			}
		}
	}

	// Read input
	printDebug("Reading input from %s", inputPath)
	data, err := readInputFile(inputPath)
	if err != nil {
		return err
	}
	printDebug("Read %d bytes", len(data))

	// Auto-detect source format if --from not provided
	if fromFormat == "" {
		detected, detectedVersion, err := autoDetectFormat(data, inputPath)
		if err != nil {
			return err
		}
		fromFormat = detected
		if fromVersion == "" {
			fromVersion = detectedVersion
		}

		// Native HDF input fingerprints as the passthrough id, which matches no
		// converter (exports are registered under the "hdf" source). When the
		// user asked for a specific export target, normalize so hdf→<target>
		// resolves. When they didn't, there is nothing to convert to — guide
		// them to --to instead of attempting an hdf→hdf no-op or dumping the
		// converter registry.
		if fromFormat == hdfpassthrough.FingerprintID {
			if !cmd.Flags().Changed("to") {
				return buildAlreadyHDFError()
			}
			fromFormat = "hdf"
		}
	}

	// Get converter
	converter, err := GetConverter(fromFormat, toFormat)
	if err != nil {
		return buildConverterNotFoundError(fromFormat, toFormat)
	}
	printDebug("Using converter: %s", converter.Name())

	// Run conversion with version handling
	output, err := runVersionedConvert(converter, data, fromVersion, toVersion)
	if err != nil {
		return err
	}

	// Apply labels if --labels flag was provided
	labelPairs, _ := cmd.Flags().GetStringSlice("labels")
	if len(labelPairs) > 0 {
		labels, err := parseLabelsFlag(labelPairs)
		if err != nil {
			return fmt.Errorf("invalid --labels flag: %w", err)
		}
		output, err = applyLabels(output, labels)
		if err != nil {
			return fmt.Errorf("failed to apply labels: %w", err)
		}
		printDebug("Applied %d labels to output", len(labels))
	}

	// Apply --component-id if provided
	componentID, _ := cmd.Flags().GetString("component-id")
	if componentID != "" {
		output, err = applyComponentIDs(output, componentID, false)
		if err != nil {
			return fmt.Errorf("failed to apply component-id: %w", err)
		}
		printDebug("Applied componentId %s to output", componentID)
	}

	// Write output (with schema validation if target is HDF and --no-validate not set)
	if strings.EqualFold(toFormat, "hdf") {
		return writeValidatedHDFOutput(cmd, output, outputPath)
	}
	return writeConvertOutput(output, outputPath)
}

// runVersionedConvert passes version specifiers to the converter and runs
// the conversion with optional post-processing for output version downgrades.
func runVersionedConvert(converter Converter, data []byte, fromVersion, toVersion string) ([]byte, error) {
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

	// Post-process: downgrade HDF version if --to hdf@N was specified
	// (only for non-HDF→HDF converters; the hdf→hdf converter handles it internally)
	if toVersion != "" && toVersion != "2" {
		if _, isHDFVer := converter.(*hdfVersionConverter); !isHDFVer {
			printDebug("Post-processing output to HDF version %s", toVersion)
			output, err = PostProcessToVersion(output, toVersion)
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
	format = result.Fingerprint.ID
	// Strip the "-to-hdf" suffix to get the source format name
	if idx := strings.Index(format, "-to-"); idx > 0 {
		format = format[:idx]
	}
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

	// Ensure output directory exists.
	if err := os.MkdirAll(outputDir, 0o750); err != nil { // #nosec G301 -- CLI creates user-requested directory
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return runBulk(files, "conversion", "converted", func(file string) error {
		outPath := bulkOutputPath(outputDir, file, toFormat)
		return runConvert(cmd, []string{file}, fromFormat, toFormat, outPath)
	})
}
