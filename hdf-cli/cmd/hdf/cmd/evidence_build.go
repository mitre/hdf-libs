package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

func newEvidenceBuildCmd() *cobra.Command {
	var (
		systemPath     string
		resultsPaths   []string
		amendmentsPath string
		comparisonPath string
		outputPath     string
	)

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Bundle HDF documents into an evidence package",
		Long: `Build an HDF evidence package from component documents.

Computes SHA-256 checksums for each document and populates a
completeness check (baselines assessed, components covered,
compliance percentage).

The --results flag is repeatable and supports file globs.

Examples:
  hdf evidence build --system portal.json --results scan.json
  hdf evidence build --system portal.json --results rhel9.json --results postgres.json
  hdf evidence build --system portal.json --results "/tmp/scans/*.json"
  hdf evidence build --system portal.json /tmp/scans/*.json
  hdf evidence build --system portal.json --results scan.json --amendments waivers.json -o package.json`,
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			// Combine --results flags and positional args as results files
			allResults := make([]string, 0, len(resultsPaths)+len(args))
			allResults = append(allResults, resultsPaths...)
			allResults = append(allResults, args...)
			expanded, err := expandGlobs(allResults)
			if err != nil {
				return fmt.Errorf("failed to expand results paths: %w", err)
			}
			if len(expanded) == 0 {
				return fmt.Errorf("no results files provided; use --results or pass files as arguments")
			}
			return runEvidenceBuild(systemPath, expanded, amendmentsPath, comparisonPath, outputPath)
		},
	}

	cmd.Flags().StringVar(&systemPath, "system", "", "System document (required)")
	cmd.Flags().StringArrayVar(&resultsPaths, "results", nil, "Results document(s) (repeatable, supports globs)")
	cmd.Flags().StringVar(&amendmentsPath, "amendments", "", "Amendments document (optional)")
	cmd.Flags().StringVar(&comparisonPath, "comparison", "", "Comparison document (optional)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")

	_ = cmd.MarkFlagRequired("system")

	return cmd
}

func runEvidenceBuild(systemPath string, resultsPaths []string, amendmentsPath, comparisonPath, outputPath string) error {
	contents := make([]map[string]interface{}, 0, len(resultsPaths)+3)

	// Add system
	entry, err := buildContentEntry("hdf-system", systemPath)
	if err != nil {
		return err
	}
	contents = append(contents, entry)

	// Add results
	for _, rp := range resultsPaths {
		entry, err = buildContentEntry("hdf-results", rp)
		if err != nil {
			return err
		}
		contents = append(contents, entry)
	}

	// Optional: amendments
	if amendmentsPath != "" {
		entry, err = buildContentEntry("hdf-amendments", amendmentsPath)
		if err != nil {
			return err
		}
		contents = append(contents, entry)
	}

	// Optional: comparison
	if comparisonPath != "" {
		entry, err = buildContentEntry("hdf-comparison", comparisonPath)
		if err != nil {
			return err
		}
		contents = append(contents, entry)
	}

	// Extract system name for package name
	sysData, err := os.ReadFile(systemPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return fmt.Errorf("failed to re-read system file: %w", err)
	}
	var sysDoc map[string]interface{}
	_ = json.Unmarshal(sysData, &sysDoc)
	sysName, _ := sysDoc["name"].(string)
	if sysName == "" {
		sysName = "unnamed-system"
	}

	// Compute completeness check from all results
	completeness := computeCompleteness(sysDoc, resultsPaths)

	pkg := map[string]interface{}{
		"name":              sysName + "-evidence-package",
		"systemRef":         filepath.Base(systemPath),
		"preparedAt":        time.Now().UTC().Format(time.RFC3339),
		"contents":          contents,
		"completenessCheck": completeness,
	}

	output, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize evidence package: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := os.WriteFile(outputPath, output, 0o600); err != nil { // #nosec G703 -- CLI writes user path
		return fmt.Errorf("failed to write evidence package: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Evidence package written to %s (%d documents)\n", outputPath, len(contents))
	return nil
}

func buildContentEntry(docType, filePath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filePath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file %s: %w", docType, filePath, err)
	}

	hash := sha256.Sum256(data)
	return map[string]interface{}{
		"type": docType,
		"uri":  filepath.Base(filePath),
		"checksum": map[string]interface{}{
			"algorithm": "sha256",
			"value":     hex.EncodeToString(hash[:]),
		},
	}, nil
}

func computeCompleteness(sysDoc map[string]interface{}, resultsPaths []string) map[string]interface{} { //nolint:gocognit // nested JSON traversal
	cc := map[string]interface{}{
		"allBaselinesAssessed": false,
		"allComponentsCovered": false,
		"compliancePercent":    0.0,
	}

	baselineNames := make(map[string]bool)
	totalReqs := 0
	passedReqs := 0

	for _, resultsPath := range resultsPaths {
		resultsData, err := os.ReadFile(resultsPath) //nolint:gosec // CLI reads user-provided path
		if err != nil {
			continue
		}
		var resultsDoc map[string]interface{}
		if json.Unmarshal(resultsData, &resultsDoc) != nil {
			continue
		}

		baselines, _ := resultsDoc["baselines"].([]interface{})
		for _, bRaw := range baselines {
			b, ok := bRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := b["name"].(string); ok {
				baselineNames[name] = true
			}
			reqs, _ := b["requirements"].([]interface{})
			for _, rRaw := range reqs {
				r, ok := rRaw.(map[string]interface{})
				if !ok {
					continue
				}
				totalReqs++
				results, _ := r["results"].([]interface{})
				if len(results) > 0 {
					first, _ := results[0].(map[string]interface{})
					if status, ok := first["status"].(string); ok && status == StatusPassed {
						passedReqs++
					}
				}
			}
		}
	}

	if totalReqs > 0 {
		cc["compliancePercent"] = float64(passedReqs) / float64(totalReqs) * 100.0
	}

	// Check if all system component baselines are assessed
	components, _ := sysDoc["components"].([]interface{})
	allCovered := len(components) > 0
	allAssessed := len(baselineNames) > 0
	for _, cRaw := range components {
		c, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}
		refs, _ := c["baselineRefs"].([]interface{})
		for _, refRaw := range refs {
			ref, ok := refRaw.(string)
			if !ok {
				continue
			}
			if !baselineNames[ref] {
				allAssessed = false
				allCovered = false
			}
		}
	}

	cc["allBaselinesAssessed"] = allAssessed
	cc["allComponentsCovered"] = allCovered

	return cc
}
