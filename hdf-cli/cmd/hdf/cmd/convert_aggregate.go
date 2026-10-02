package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/spf13/cobra"
)

// aggregatingConverter returns the hdf→toFormat converter when it can combine
// several documents into one output.
func aggregatingConverter(toFormat string) (MultiInputConverter, Converter, bool) {
	format, _ := parseFormatVersion(toFormat)
	converter, err := GetConverter("hdf", format)
	if err != nil {
		return nil, nil, false
	}
	multi, ok := converter.(MultiInputConverter)
	return multi, converter, ok
}

// isResultsDocument reports whether data is a current HDF results document.
func isResultsDocument(data []byte) bool {
	return detectHDFDocumentType(data) == "results"
}

// isHDFResults reports whether data is an HDF results document, current or
// legacy; the convert path upgrades the legacy shape.
func isHDFResults(data []byte) bool {
	return isResultsDocument(data) || looksLikeLegacyHDFv2(data)
}

// expandResultDirectories replaces each directory argument with the HDF results
// documents under it, in path order. A run directory routinely holds other
// artifacts beside the results (amendments, OSCAL exports, logs), so those are
// passed over rather than refused, and counted on stderr so the caller can see
// it happened. An explicitly named file is never filtered.
func expandResultDirectories(args []string) (files []string, hadDirectory bool, err error) {
	skipped := 0
	for _, arg := range args {
		if info, statErr := os.Stat(arg); statErr != nil || !info.IsDir() {
			files = append(files, arg)
			continue
		}
		hadDirectory = true
		found, passedOver, walkErr := resultsUnder(arg)
		if walkErr != nil {
			return nil, false, fmt.Errorf("failed to read directory %s: %w", arg, walkErr)
		}
		if len(found) == 0 {
			return nil, false, fmt.Errorf("no HDF results documents found in %s", arg)
		}
		files = append(files, found...)
		skipped += passedOver
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "Skipped %d file(s) that are not HDF results documents\n", skipped)
	}
	return files, hadDirectory, nil
}

// resultsUnder walks dir for HDF results documents and counts the .json files
// it passed over: the ones that are something else, and the ones it could not read.
func resultsUnder(dir string) (files []string, skipped int, err error) {
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		data, readErr := readInputFileAllowEmpty(path)
		switch {
		case readErr != nil:
			fmt.Fprintf(os.Stderr, "Warning: skipped %s: %v\n", sanitizeOutput(path), readErr)
			skipped++
		case !isHDFResults(data):
			skipped++
		default:
			files = append(files, path)
		}
		return nil
	})
	return files, skipped, err
}

// sourceNames gives each input the name the report shows: its file name, or the
// path as given when two inputs share a file name.
func sourceNames(files []string) []string {
	count := map[string]int{}
	for _, f := range files {
		count[filepath.Base(f)]++
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = filepath.Base(f)
		if count[names[i]] > 1 {
			names[i] = filepath.ToSlash(filepath.Clean(f))
		}
	}
	return names
}

// runConvertAggregate renders several HDF results documents as one output.
func runConvertAggregate(cmd *cobra.Command, multi MultiInputConverter, converter Converter, files []string, fromFormat, toFormat, outputPath string) error {
	hdfutil.SetDefaultMaxInputSize(maxInputSizeBytes())
	fromFormat, fromVersion := parseFormatVersion(fromFormat)
	toFormat, _ = parseFormatVersion(toFormat)

	if err := applyReportType(cmd, converter, toFormat); err != nil {
		return err
	}
	writesFile := outputPath != "" && outputPath != "-"
	if force, _ := cmd.Flags().GetBool("force"); writesFile && !force {
		if err := checkOutputOverwritesAnyInput(files, outputPath); err != nil {
			return err
		}
	}
	inputs, err := loadResultInputs(cmd, files, fromFormat, fromVersion, toFormat)
	if err != nil {
		return err
	}

	output, err := multi.ConvertMany(inputs)
	if err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}
	if err := writeConvertOutput(output, outputPath); err != nil {
		return err
	}
	if writesFile {
		fmt.Fprintf(os.Stderr, "Combined %d documents into %s\n", len(inputs), sanitizeOutput(outputPath))
	}
	return nil
}

func checkOutputOverwritesAnyInput(files []string, outputPath string) error {
	for _, file := range files {
		if err := checkOutputOverwritesInput(file, outputPath); err != nil {
			return err
		}
	}
	return nil
}

// loadResultInputs reads every file through the convert input path and holds
// each to being an HDF results document, named as the report will show it.
func loadResultInputs(cmd *cobra.Command, files []string, fromFormat, fromVersion, toFormat string) ([]NamedInput, error) {
	names := sourceNames(files)
	inputs := make([]NamedInput, len(files))
	for i, file := range files {
		data, format, _, err := loadConvertInput(cmd, file, fromFormat, fromVersion, toFormat)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if !strings.EqualFold(format, "hdf") || !isResultsDocument(data) {
			return nil, fmt.Errorf("%s: not an HDF results document; a combined %s report takes HDF results only", file, toFormat)
		}
		inputs[i] = NamedInput{Name: names[i], Data: data}
	}
	return inputs, nil
}
