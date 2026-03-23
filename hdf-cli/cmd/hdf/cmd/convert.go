package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mitre/hdf-converters/registry"
	_ "github.com/mitre/hdf-converters/registry/all" // register all fingerprints via init()
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
		Use:   "convert <file> [flags]",
		Short: "Convert between HDF and other security formats",
		Long:  buildConvertLong(),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConvert(cmd, args, fromFormat, toFormat, outputPath)
		},
	}

	cmd.Flags().StringVar(&fromFormat, "from", "", "Source format (auto-detected if omitted)")
	cmd.Flags().StringVar(&toFormat, "to", "hdf", "Target format (default: hdf)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolP("force", "f", false, "Allow overwriting the input file with output")
	cmd.Flags().StringSlice("labels", nil, "Labels to apply to all targets (key=value pairs, e.g., --labels system=Portal,environment=production)")

	// Converter-specific flags
	AddOSCALFlags(cmd)

	return cmd
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

Examples:
  hdf convert scan.nessus                         # Auto-detect, convert to HDF
  hdf convert scan.nessus -o results.json         # Auto-detect, write to file
  hdf convert --to csv results.json               # Auto-detect, convert to CSV
  hdf convert --from nessus --to hdf scan.nessus  # Explicit formats
  hdf convert --from hdf --to csv results.json -o output.csv
  cat scan.json | hdf convert -                   # Read from stdin`)

	return sb.String()
}

// runConvert executes the convert command.
func runConvert(cmd *cobra.Command, args []string, fromFormat, toFormat, outputPath string) error {
	inputPath := args[0]

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
		result := registry.DetectConverter(data)
		if result == nil {
			return fmt.Errorf("could not auto-detect input format (confidence too low or ambiguous)\n" +
				"Specify the format explicitly with --from <format>\n" +
				"Run 'hdf convert --help' to see supported formats")
		}
		fromFormat = result.Fingerprint.ID
		// Strip the "-to-hdf" suffix to get the source format name
		if idx := strings.Index(fromFormat, "-to-"); idx > 0 {
			fromFormat = fromFormat[:idx]
		}
		printDebug("Auto-detected format: %s (confidence: %.0f%%)", fromFormat, result.Confidence*100)
		fmt.Fprintf(os.Stderr, "Detected: %s (confidence: %.0f%%)\n", result.Fingerprint.Label, result.Confidence*100)
	}

	// Get converter
	converter, err := GetConverter(fromFormat, toFormat)
	if err != nil {
		return buildConverterNotFoundError(fromFormat, toFormat)
	}
	printDebug("Using converter: %s", converter.Name())

	// Convert
	output, err := converter.Convert(data)
	if err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}
	printDebug("Conversion produced %d bytes", len(output))

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

	// Write output
	return writeConvertOutput(output, outputPath)
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
