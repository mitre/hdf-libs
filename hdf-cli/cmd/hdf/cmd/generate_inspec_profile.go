package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	xccdf "github.com/mitre/hdf-converters/converters/xccdf-results-to-hdf/go"
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
		profileVer    string
		inspecVersion string
		sourceType    string
	)

	cmd := &cobra.Command{
		Use:   "inspec-profile <input> <output-dir>",
		Short: "Generate InSpec profile from HDF Baseline or XCCDF Benchmark",
		Long: `Generate an InSpec profile directory from an HDF Baseline JSON file
or an XCCDF Benchmark XML file.

Creates:
  - inspec.yml with profile metadata
  - controls/ directory with Ruby control files

By default, each requirement becomes its own .rb file.
Use --single-file to put all controls in controls/controls.rb.

Input format is auto-detected from file content: XML files are treated
as XCCDF benchmarks, JSON files as HDF Baselines. Use --source-type
to override auto-detection.`,
		Example: `  # From an HDF Baseline JSON file
  hdf generate inspec-profile baseline.json my-profile/

  # From a DISA STIG XCCDF benchmark (auto-detected from XML content)
  hdf generate inspec-profile U_RHEL_9_STIG_V2R4_Manual-xccdf.xml rhel9-stig/

  # Explicit source type
  hdf generate inspec-profile benchmark.xml my-profile/ -s xccdf

  # All controls in a single file
  hdf generate inspec-profile baseline.json my-profile/ --single-file

  # Override profile metadata
  hdf generate inspec-profile baseline.json my-profile/ --maintainer "MITRE SAF" --license Apache-2.0`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			inputPath := args[0]
			outputDir := args[1]

			data, err := readInputFile(inputPath)
			if err != nil {
				return err
			}

			// Determine source type
			srcType := sourceType
			if srcType == "" {
				srcType, err = detectGenerateSourceType(data)
				if err != nil {
					return err
				}
			}

			// Parse baseline from the appropriate source
			var baseline schema.HDFBaseline
			switch srcType {
			case "xccdf":
				baselinePtr, xccdfErr := xccdf.ConvertXccdfBenchmarkToHDF(data, version)
				if xccdfErr != nil {
					return fmt.Errorf("XCCDF conversion failed: %w", xccdfErr)
				}
				baseline = *baselinePtr
			case "baseline":
				validationResult := validators.ValidateBaseline(data)
				if !validationResult.Valid {
					return fmt.Errorf("schema validation failed: %s", validationResult.Error())
				}
				if unmarshalErr := json.Unmarshal(data, &baseline); unmarshalErr != nil {
					return fmt.Errorf("failed to parse baseline JSON: %w", unmarshalErr)
				}
			default:
				return fmt.Errorf("unsupported --source-type %q; use \"baseline\" or \"xccdf\"", srcType)
			}

			// Build generator options
			opts := &generators.GeneratorOptions{
				SingleFile: singleFile,
			}
			if inspecVersion != "" {
				opts.InSpecVersion = inspecVersion
			}
			if maintainer != "" || copyright != "" || license != "" || profileVer != "" {
				opts.Metadata = &generators.ProfileMetadata{
					Maintainer: maintainer,
					Copyright:  copyright,
					License:    license,
					Version:    profileVer,
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
	cmd.Flags().StringVar(&profileVer, "version", "", "Override version in inspec.yml")
	cmd.Flags().StringVar(&inspecVersion, "inspec-version", "", "InSpec version constraint (default: >=6.0)")
	cmd.Flags().StringVarP(&sourceType, "source-type", "s", "", "Input format: \"baseline\" (JSON) or \"xccdf\" (XML). Auto-detected if omitted.")

	return cmd
}

// detectGenerateSourceType auto-detects the input format by peeking at the
// first non-whitespace byte. '<' indicates XML (XCCDF), '{' indicates JSON
// (HDF Baseline).
func detectGenerateSourceType(data []byte) (string, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return "", fmt.Errorf("empty input: cannot auto-detect format")
	}
	switch trimmed[0] {
	case '<':
		return "xccdf", nil
	case '{':
		return "baseline", nil
	default:
		return "", fmt.Errorf("cannot auto-detect input format: expected JSON ('{') or XML ('<'), got %q", string(trimmed[:1]))
	}
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
		controlPath, pathErr := safePath(outputDir, name)
		if pathErr != nil {
			return fmt.Errorf("unsafe control path %q: %w", name, pathErr)
		}
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
