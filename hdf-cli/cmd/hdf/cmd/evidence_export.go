package cmd

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/atomicfile"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	"github.com/spf13/cobra"
)

func newEvidenceExportCmd() *cobra.Command {
	var (
		format    string
		outputDir string
	)

	cmd := &cobra.Command{
		Use:   "export <package-file>",
		Short: "Export evidence package documents to another format",
		Long: `Export documents referenced in an evidence package to another format.

Currently supports OSCAL format: converts HDF results to OSCAL SAR
and HDF amendments to OSCAL POA&M using the registered converters.

Each document is written under the output directory as <name>.oscal-sar.json
or <name>.oscal-poam.json, where <name> is its file name without the extension.
Two documents that would share an output name are refused before anything is
written. The command fails (exit 1) when the package lists results or
amendments and none of them could be exported, and exits 3 when only some
could.

Examples:
  hdf evidence export package.json --format oscal -o output/
  hdf evidence export package.json --format oscal`,
		Args: evidencePackageArg,
		RunE: func(c *cobra.Command, args []string) error {
			// A stdin package resolves against -o, so the default "." must not stand in for it.
			if args[0] == stdinPackage && !c.Flags().Changed("output") {
				return stdinNeedsOutput("package", "<dir>")
			}
			return runEvidenceExport(args[0], format, outputDir)
		},
	}

	cmd.Flags().StringVar(&format, "format", "oscal", "Export format (currently: oscal)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", ".", "Output directory")

	return cmd
}

// exportTarget is one convertible contents[] entry, resolved but not yet read.
type exportTarget struct {
	uri        string // as the package records it
	path       string
	source     string
	dest       string
	outputName string
}

// exportOutputName names an export for its source document, so two documents never
// share an output: rhel9-results.json becomes rhel9-results.oscal-sar.json.
func exportOutputName(ref evidenceref.Decoded, dest string) string {
	base := path.Base(string(ref))
	return strings.TrimSuffix(base, path.Ext(base)) + "." + dest + ".json"
}

// exportConverterFor maps a content type to the converter pair export uses, or false
// for a type export does not convert.
func exportConverterFor(docType string) (source, dest string, ok bool) {
	switch docType {
	case "hdf-results":
		return "hdf", "oscal-sar", true
	case "hdf-amendments":
		return "hdf-amendments", "oscal-poam", true
	default:
		return "", "", false
	}
}

// collectExportTargets resolves every convertible entry and refuses two that would
// export to one file. It returns how many convertible entries the package lists, so a
// reference skipped here still counts as a document that failed to export.
func collectExportTargets(doc map[string]interface{}, refs evidenceref.References, pkgDir string) ([]exportTarget, int, error) {
	contents, _ := doc["contents"].([]interface{})
	var targets []exportTarget
	convertible := 0
	// Keyed case-folded: on a case-insensitive volume Results.* and results.* are one file.
	claimed := map[string]string{}
	for i, cRaw := range contents {
		entry, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}
		docType, _ := entry["type"].(string)
		source, dest, ok := exportConverterFor(docType)
		if !ok {
			continue
		}
		convertible++
		rec, found := refs.At("contents", i)
		if !found {
			fmt.Fprintf(os.Stderr, "Warning: skipping contents[%d]: it records no uri\n", i)
			continue
		}
		uri := rec.Stored
		if rec.Err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", uri, rec.Err)
			continue
		}
		ref, inTree := packageSubtreeRef(pkgDir, rec.Decoded)
		if !inTree {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: it does not resolve inside the package's directory\n", uri)
			continue
		}
		refPath, pathErr := evidenceref.Path(pkgDir, ref)
		if pathErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", uri, pathErr)
			continue
		}
		name := exportOutputName(ref, dest)
		if prior, taken := claimed[strings.ToLower(name)]; taken {
			return nil, 0, fmt.Errorf("%s and %s would both export to %s; nothing was written. "+
				"Rename one of the documents so each exports to its own file", prior, uri, name)
		}
		claimed[strings.ToLower(name)] = uri
		targets = append(targets, exportTarget{uri: uri, path: refPath, source: source, dest: dest, outputName: name})
	}
	return targets, convertible, nil
}

// exportOne converts one target and writes it, reporting why when it cannot. A write
// failure is returned, because the output directory itself is then in question.
func exportOne(t exportTarget, outputDir string) (bool, error) {
	refData, readErr := readFromFile(t.path, true)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", t.uri, readErr)
		return false, nil
	}
	converter, convErr := GetConverter(t.source, t.dest)
	if convErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: no converter for %s to %s: %v\n", t.source, t.dest, convErr)
		return false, nil
	}
	output, convErr := converter.Convert(refData)
	if convErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: conversion failed for %s: %v\n", t.uri, convErr)
		return false, nil
	}
	outPath := filepath.Join(outputDir, t.outputName)
	if writeErr := atomicfile.WriteFile(outPath, output, 0o600); writeErr != nil {
		return false, fmt.Errorf("failed to write %s: %w", outPath, writeErr)
	}
	fmt.Fprintf(os.Stderr, "Exported %s → %s\n", t.uri, outPath)
	return true, nil
}

func runEvidenceExport(pkgPath, format, outputDir string) error {
	if format != "oscal" {
		return fmt.Errorf("unsupported export format %q (supported: oscal)", format)
	}

	data, err := readInputFile(pkgPath) // size-gated read boundary (honors --max-size)
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}

	doc, err := loadAndValidateHDFDoc(data, "evidence-package")
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}

	refs, err := evidenceref.Collect(data)
	if err != nil {
		return err
	}
	// A stdin package has no directory; the output directory is where its exports live.
	pkgDir := filepath.Dir(pkgPath)
	if pkgPath == stdinPackage {
		pkgDir = outputDir
	}
	targets, convertible, err := collectExportTargets(doc, refs, pkgDir)
	if err != nil {
		return err
	}
	if convertible == 0 {
		fmt.Fprintln(os.Stderr, "No documents exported: the package has no hdf-results or hdf-amendments")
		return nil
	}

	if err := os.MkdirAll(outputDir, 0o750); err != nil { // #nosec G301 -- CLI creates user-specified directory
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	exported := 0
	for _, t := range targets {
		ok, writeErr := exportOne(t, outputDir)
		if writeErr != nil {
			return writeErr
		}
		if ok {
			exported++
		}
	}

	switch failed := convertible - exported; {
	case exported == 0:
		return fmt.Errorf("none of the %d hdf-results/hdf-amendments documents in the package could be exported; "+
			"the warnings above say why", convertible)
	case failed > 0:
		fmt.Fprintf(os.Stderr, "%d of %d documents exported to %s (%d failed; see the warnings above)\n",
			exported, convertible, outputDir, failed)
		// A mixed run is the CLI's documented exit 3, so a pipeline cannot read a
		// missing document as success. The summary above is the report.
		return &exitCodeError{code: exitPartial, message: "some documents could not be exported"}
	default:
		fmt.Fprintf(os.Stderr, "%d documents exported to %s\n", exported, outputDir)
	}
	return nil
}
