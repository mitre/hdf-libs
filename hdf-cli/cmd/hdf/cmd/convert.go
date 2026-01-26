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

Input can be a file path or "-" for stdin.
Output defaults to stdout if not specified.

Examples:
  hdf convert legacyhdf to hdf scan.json                    # Convert, output to stdout
  hdf convert legacyhdf to hdf scan.json results.json       # Convert to file
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
		return fmt.Errorf("unsupported conversion: %s to %s\n"+
			"Run 'hdf convert --help' to see available conversions", source, dest)
	}

	return nil
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
		printError(err.Error())
		return err
	}
	printDebug("Read %d bytes", len(data))

	// Get converter
	converter, err := GetConverter(srcFormat, destFormat)
	if err != nil {
		printError(err.Error())
		return err
	}
	printDebug("Using converter: %s", converter.Name())

	// Convert
	output, err := converter.Convert(data)
	if err != nil {
		printError(fmt.Sprintf("Conversion failed: %v", err))
		return err
	}
	printDebug("Conversion produced %d bytes", len(output))

	// Write output
	if err := writeConvertOutput(output, outputPath); err != nil {
		printError(err.Error())
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
