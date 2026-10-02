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

// isHDFResults reports whether data is an HDF results document, current or
// legacy; the convert path upgrades the legacy shape.
func isHDFResults(data []byte) bool {
	return detectHDFDocumentType(data) == "results" || looksLikeLegacyHDFv2(data)
}

// expandResultDirectories replaces each directory argument with the HDF results
// documents under it, in path order. A run directory routinely holds other
// artifacts beside the results (amendments, OSCAL exports, logs), so those are
// passed over rather than refused; skipped counts them so the caller can say so.
// An explicitly named file is never filtered.
func expandResultDirectories(args []string) (files []string, hadDirectory bool, skipped int, err error) {
	for _, arg := range args {
		info, statErr := os.Stat(arg)
		if statErr != nil || !info.IsDir() {
			files = append(files, arg)
			continue
		}
		hadDirectory = true
		found := 0
		walkErr := filepath.WalkDir(arg, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".json") {
				return nil
			}
			data, readErr := readInputFileAllowEmpty(path)
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: skipped %s: %v\n", sanitizeOutput(path), readErr)
				skipped++
				return nil
			}
			if !isHDFResults(data) {
				skipped++
				return nil
			}
			files = append(files, path)
			found++
			return nil
		})
		if walkErr != nil {
			return nil, false, 0, fmt.Errorf("failed to read directory %s: %w", arg, walkErr)
		}
		if found == 0 {
			return nil, false, 0, fmt.Errorf("no HDF results documents found in %s", arg)
		}
	}
	return files, hadDirectory, skipped, nil
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

	if force, _ := cmd.Flags().GetBool("force"); !force && outputPath != "" && outputPath != "-" {
		for _, file := range files {
			if err := checkOutputOverwritesInput(file, outputPath); err != nil {
				return err
			}
		}
	}

	names := sourceNames(files)
	inputs := make([]NamedInput, len(files))
	for i, file := range files {
		data, format, _, err := loadConvertInput(cmd, file, fromFormat, fromVersion, toFormat)
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if !strings.EqualFold(format, "hdf") || detectHDFDocumentType(data) != "results" {
			return fmt.Errorf("%s: not an HDF results document; a combined %s report takes HDF results only", file, toFormat)
		}
		inputs[i] = NamedInput{Name: names[i], Data: data}
	}

	output, err := multi.ConvertMany(inputs)
	if err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}
	if err := writeConvertOutput(output, outputPath); err != nil {
		return err
	}
	if outputPath != "" && outputPath != "-" {
		fmt.Fprintf(os.Stderr, "Combined %d documents into %s\n", len(inputs), sanitizeOutput(outputPath))
	}
	return nil
}
