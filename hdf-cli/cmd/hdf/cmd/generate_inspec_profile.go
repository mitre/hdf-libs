package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	generators "github.com/mitre/hdf-generators/go"
	schema "github.com/mitre/hdf-schema"
	validators "github.com/mitre/hdf-validators/go"
	"github.com/spf13/cobra"
)

func newGenerateInSpecProfileCmd() *cobra.Command {
	var (
		singleFile    bool
		maintainer    string
		copyright     string
		license       string
		version       string
		inspecVersion string
	)

	cmd := &cobra.Command{
		Use:   "inspec-profile <baseline.json> <output-dir>",
		Short: "Generate InSpec profile from HDF Baseline",
		Long: `Generate an InSpec profile directory from an HDF Baseline JSON file.

Creates:
  - inspec.yml with profile metadata
  - controls/ directory with Ruby control files

By default, each requirement becomes its own .rb file.
Use --single-file to put all controls in controls/controls.rb.`,
		Example: `  hdf generate inspec-profile baseline.json my-profile/
  hdf generate inspec-profile baseline.json my-profile/ --single-file
  hdf generate inspec-profile baseline.json my-profile/ --maintainer "MITRE SAF"`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			inputPath := args[0]
			outputDir := args[1]

			// Read and validate input
			data, err := readInputFile(inputPath)
			if err != nil {
				return err
			}

			validationResult := validators.ValidateBaseline(data)
			if !validationResult.Valid {
				return fmt.Errorf("schema validation failed: %s", validationResult.Error())
			}

			// Parse into generator's HDFBaseline type
			var baseline schema.HDFBaseline
			if err := json.Unmarshal(data, &baseline); err != nil {
				return fmt.Errorf("failed to parse baseline JSON: %w", err)
			}

			// Build generator options
			opts := &generators.GeneratorOptions{
				SingleFile: singleFile,
			}
			if inspecVersion != "" {
				opts.InSpecVersion = inspecVersion
			}
			if maintainer != "" || copyright != "" || license != "" || version != "" {
				opts.Metadata = &generators.ProfileMetadata{
					Maintainer: maintainer,
					Copyright:  copyright,
					License:    license,
					Version:    version,
				}
			}

			// Generate profile
			profile := generators.GenerateInSpecProfile(baseline, opts)

			// Write output
			return writeInSpecProfile(profile, outputDir)
		},
	}

	cmd.Flags().BoolVar(&singleFile, "single-file", false, "Put all controls in a single controls/controls.rb")
	cmd.Flags().StringVar(&maintainer, "maintainer", "", "Override maintainer in inspec.yml")
	cmd.Flags().StringVar(&copyright, "copyright", "", "Override copyright in inspec.yml")
	cmd.Flags().StringVar(&license, "license", "", "Override license in inspec.yml")
	cmd.Flags().StringVar(&version, "version", "", "Override version in inspec.yml")
	cmd.Flags().StringVar(&inspecVersion, "inspec-version", "", "InSpec version constraint (default: ~>6.0)")

	return cmd
}

// writeInSpecProfile writes an InSpecProfile to the output directory.
func writeInSpecProfile(profile generators.InSpecProfile, outputDir string) error {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0o750); err != nil { //nolint:gosec // profile dirs need group read for InSpec
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write inspec.yml
	ymlPath := filepath.Join(outputDir, "inspec.yml")
	if err := os.WriteFile(ymlPath, []byte(profile.InSpecYml), 0o600); err != nil {
		return fmt.Errorf("failed to write inspec.yml: %w", err)
	}
	printDebug("Wrote %s", ymlPath)

	// Write control files (sorted for deterministic output)
	filenames := make([]string, 0, len(profile.Controls))
	for name := range profile.Controls {
		filenames = append(filenames, name)
	}
	sort.Strings(filenames)

	for _, name := range filenames {
		controlPath := filepath.Join(outputDir, name)
		controlDir := filepath.Dir(controlPath)
		if err := os.MkdirAll(controlDir, 0o750); err != nil { //nolint:gosec // profile dirs need group read
			return fmt.Errorf("failed to create directory %s: %w", controlDir, err)
		}
		if err := os.WriteFile(controlPath, []byte(profile.Controls[name]), 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
		printDebug("Wrote %s", controlPath)
	}

	fmt.Fprintf(os.Stderr, "Generated InSpec profile in %s (%d controls)\n", outputDir, len(profile.Controls))
	return nil
}
