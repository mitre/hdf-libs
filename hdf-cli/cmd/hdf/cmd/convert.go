package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// NewConvertCmd creates the convert command.
func NewConvertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert <src-format> to <dest-format> <input> [output]",
		Short: "Convert between HDF and other security formats",
		Long: `Convert security assessment data between formats.

Supported conversions:
  legacyhdf to hdf    Convert legacy HDF v1.0 (InSpec JSON) to HDF v2.0
  nessus to hdf       Convert Nessus XML scan results to HDF v2.0
  hdf to csv          Export HDF JSON to CSV spreadsheet format
  hdf to xml          Export HDF JSON to XML format

Input can be a file path or "-" for stdin.
Output defaults to stdout if not specified.

Examples:
  hdf convert legacyhdf to hdf scan.json                    # Convert, output to stdout
  hdf convert nessus to hdf scan.nessus results.json        # Convert Nessus to file
  hdf convert hdf to csv results.json output.csv            # Export HDF to CSV
  hdf convert legacyhdf to hdf - output.json                # Read from stdin
  cat scan.json | hdf convert legacyhdf to hdf -            # Pipe through stdin`,
		Args: validateConvertArgs,
		RunE: runConvert,
	}

	return cmd
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
	msg.WriteString(fmt.Sprintf("no converter found for: %s to %s", source, dest))

	switch {
	case len(sourceDestinations) > 0:
		msg.WriteString(fmt.Sprintf("\n\nThe '%s' format can convert to: %s", source, strings.Join(sourceDestinations, ", ")))
	case len(destSources) > 0:
		// Source format not recognized, but dest is
		msg.WriteString(fmt.Sprintf("\n\nUnrecognized source format: '%s'", source))
		msg.WriteString(fmt.Sprintf("\nFormats that can convert to '%s': %s", dest, strings.Join(destSources, ", ")))
	default:
		// Neither format recognized or no converters available
		msg.WriteString(fmt.Sprintf("\n\nUnrecognized format(s): '%s', '%s'", source, dest))
	}

	msg.WriteString("\n\nRun 'hdf convert --help' to see all available conversions")

	return fmt.Errorf("%s", msg.String())
}

// runConvert executes the convert command.
func runConvert(_ *cobra.Command, args []string) error {
	srcFormat := args[0]
	destFormat := args[2]
	inputPath := args[3]

	var outputPath string
	if len(args) == 5 {
		outputPath = args[4]
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
	if err := writeConvertOutput(output, outputPath); err != nil {
		return err
	}

	return nil
}

// writeConvertOutput writes conversion output to a file or stdout.
func writeConvertOutput(data []byte, path string) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}

	return os.WriteFile(path, data, 0600)
}
