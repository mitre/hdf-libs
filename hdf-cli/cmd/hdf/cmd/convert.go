package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// NewConvertCmd creates the convert command.
func NewConvertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert <src-format> to <dest-format> <input> [output]",
		Short: "Convert between HDF and other security formats",
		Long:  buildConvertLong(),
		Args:  validateConvertArgs,
		RunE:  runConvert,
	}

	cmd.Flags().BoolP("force", "f", false, "Allow overwriting the input file with output")

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
	sb.WriteString("Convert security assessment data between formats.\n\nSupported conversions:\n")
	for _, pair := range pairs {
		fmt.Fprintf(&sb, "  %s to %s\n", pair.Source, pair.Dest)
	}
	sb.WriteString(`
Input can be a file path or "-" for stdin.
Output defaults to stdout if not specified.

Examples:
  hdf convert nessus to hdf scan.nessus results.json        # Convert to file
  hdf convert hdf to csv results.json output.csv            # Export HDF to CSV
  hdf convert legacyhdf to hdf - output.json                # Read from stdin
  cat scan.json | hdf convert legacyhdf to hdf -            # Pipe through stdin`)

	return sb.String()
}

// validateConvertArgs validates the convert command arguments.
func validateConvertArgs(_ *cobra.Command, args []string) error {
	if len(args) < 4 || len(args) > 5 {
		return fmt.Errorf("requires: <src-format> to <dest-format> <input> [output]\n" +
			"Run 'hdf convert --help' for usage")
	}

	if strings.ToLower(args[1]) != "to" {
		return fmt.Errorf("expected 'to' keyword between formats, got %q\n"+
			"Usage: hdf convert <src-format> to <dest-format> <input> [output]", args[1])
	}

	// Validate converter exists for this format pair
	source, dest := args[0], args[2]
	if _, err := GetConverter(source, dest); err != nil {
		return buildConverterNotFoundError(source, dest)
	}

	return nil
}

// buildConverterNotFoundError creates a helpful error message when a converter is not found.
func buildConverterNotFoundError(source, dest string) error {
	// Get all available converters
	allPairs := ListConverters()

	// Find what formats the source can convert to
	var sourceDestinations []string
	for _, pair := range allPairs {
		if strings.EqualFold(pair.Source, source) {
			sourceDestinations = append(sourceDestinations, pair.Dest)
		}
	}

	// Find what formats can convert to the destination
	var destSources []string
	for _, pair := range allPairs {
		if strings.EqualFold(pair.Dest, dest) {
			destSources = append(destSources, pair.Source)
		}
	}

	// Build helpful error message
	var msg strings.Builder
	fmt.Fprintf(&msg, "no converter found for: %s to %s", source, dest)

	switch {
	case len(sourceDestinations) > 0:
		fmt.Fprintf(&msg, "\n\nThe '%s' format can convert to: %s", source, strings.Join(sourceDestinations, ", "))
	case len(destSources) > 0:
		// Source format not recognized, but dest is
		fmt.Fprintf(&msg, "\n\nUnrecognized source format: '%s'", source)
		fmt.Fprintf(&msg, "\nFormats that can convert to '%s': %s", dest, strings.Join(destSources, ", "))
	default:
		// Neither format recognized or no converters available
		fmt.Fprintf(&msg, "\n\nUnrecognized format(s): '%s', '%s'", source, dest)
	}

	msg.WriteString("\n\nRun 'hdf convert --help' to see all available conversions")

	return fmt.Errorf("%s", msg.String())
}

// runConvert executes the convert command.
func runConvert(cmd *cobra.Command, args []string) error {
	srcFormat := args[0]
	destFormat := args[2]
	inputPath := args[3]

	var outputPath string
	if len(args) == 5 {
		outputPath = args[4]
	}

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

	// Get converter
	converter, err := GetConverter(srcFormat, destFormat)
	if err != nil {
		return err
	}
	printDebug("Using converter: %s", converter.Name())

	// Convert
	output, err := converter.Convert(data)
	if err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}
	printDebug("Conversion produced %d bytes", len(output))

	// Write output
	return writeConvertOutput(output, outputPath)
}

// checkOutputOverwritesInput returns an error if the resolved output path
// is the same file as the input path. This prevents accidental data loss.
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
