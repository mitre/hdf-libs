package cmd

import (
	"fmt"
	"os"
	"path/filepath"

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

Examples:
  hdf evidence export package.json --format oscal -o output/
  hdf evidence export package.json --format oscal`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceExport(args[0], format, outputDir)
		},
	}

	cmd.Flags().StringVar(&format, "format", "oscal", "Export format (currently: oscal)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", ".", "Output directory")

	return cmd
}

func runEvidenceExport(pkgPath, format, outputDir string) error {
	if format != "oscal" {
		return fmt.Errorf("unsupported export format %q (supported: oscal)", format)
	}

	data, err := os.ReadFile(pkgPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}

	doc, err := loadAndValidateHDFDoc(data, "evidencePackage")
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}

	if err := os.MkdirAll(outputDir, 0o750); err != nil { // #nosec G301 -- CLI creates user-specified directory
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	pkgDir := filepath.Dir(pkgPath)
	contents, _ := doc["contents"].([]interface{})
	exported := 0

	for _, cRaw := range contents {
		entry, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}

		docType, _ := entry["type"].(string)
		uri, _ := entry["uri"].(string)

		var converterSource, converterDest, outputName string
		switch docType {
		case "hdf-results":
			converterSource = "hdf"
			converterDest = "oscal-sar"
			outputName = "oscal-sar.json"
		case "hdf-amendments":
			converterSource = "hdf-amendments"
			converterDest = "oscal-poam"
			outputName = "oscal-poam.json"
		default:
			continue // Skip non-convertible types
		}

		// Read the referenced document (validate path stays within package directory)
		refPath, pathErr := safePath(pkgDir, uri)
		if pathErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", uri, pathErr)
			continue
		}
		refData, readErr := os.ReadFile(refPath) //nolint:gosec // validated by safePath
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", uri, readErr)
			continue
		}

		// Get converter and convert
		converter, convErr := GetConverter(converterSource, converterDest)
		if convErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: no converter for %s to %s: %v\n", converterSource, converterDest, convErr)
			continue
		}

		output, convErr := converter.Convert(refData)
		if convErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: conversion failed for %s: %v\n", uri, convErr)
			continue
		}

		outPath := filepath.Join(outputDir, outputName)
		if writeErr := os.WriteFile(outPath, output, 0o600); writeErr != nil { // #nosec G703
			return fmt.Errorf("failed to write %s: %w", outPath, writeErr)
		}

		fmt.Fprintf(os.Stderr, "Exported %s → %s\n", uri, outPath)
		exported++
	}

	if exported == 0 {
		fmt.Fprintln(os.Stderr, "No documents exported (package has no hdf-results or hdf-amendments)")
	} else {
		fmt.Fprintf(os.Stderr, "%d documents exported to %s\n", exported, outputDir)
	}

	return nil
}
