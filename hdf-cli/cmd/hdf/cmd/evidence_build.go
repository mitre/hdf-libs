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
		resultsPath    string
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

Examples:
  hdf evidence build --system portal.json --results scan.json
  hdf evidence build --system portal.json --results scan.json --amendments waivers.json -o package.json`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runEvidenceBuild(systemPath, resultsPath, amendmentsPath, comparisonPath, outputPath)
		},
	}

	cmd.Flags().StringVar(&systemPath, "system", "", "System document (required)")
	cmd.Flags().StringVar(&resultsPath, "results", "", "Results document (required)")
	cmd.Flags().StringVar(&amendmentsPath, "amendments", "", "Amendments document (optional)")
	cmd.Flags().StringVar(&comparisonPath, "comparison", "", "Comparison document (optional)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: stdout)")

	_ = cmd.MarkFlagRequired("system")
	_ = cmd.MarkFlagRequired("results")

	return cmd
}

func runEvidenceBuild(systemPath, resultsPath, amendmentsPath, comparisonPath, outputPath string) error {
	contents := make([]map[string]interface{}, 0, 4)

	// Add system
	entry, err := buildContentEntry("hdf-system", systemPath)
	if err != nil {
		return err
	}
	contents = append(contents, entry)

	// Add results
	entry, err = buildContentEntry("hdf-results", resultsPath)
	if err != nil {
		return err
	}
	contents = append(contents, entry)

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

	// Compute completeness check from results
	completeness := computeCompleteness(sysDoc, resultsPath)

	pkg := map[string]interface{}{
		"name":              sysName + "-evidence-package",
		"systemRef":         systemPath,
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

func computeCompleteness(sysDoc map[string]interface{}, resultsPath string) map[string]interface{} {
	cc := map[string]interface{}{
		"allBaselinesAssessed": false,
		"allComponentsCovered": false,
		"compliancePercent":    0.0,
	}

	// Read results to compute compliance
	resultsData, err := os.ReadFile(resultsPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return cc
	}
	var resultsDoc map[string]interface{}
	if err := json.Unmarshal(resultsData, &resultsDoc); err != nil {
		return cc
	}

	// Count pass/total across all baselines
	baselines, _ := resultsDoc["baselines"].([]interface{})
	baselineNames := make(map[string]bool)
	totalReqs := 0
	passedReqs := 0
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

	if totalReqs > 0 {
		cc["compliancePercent"] = float64(passedReqs) / float64(totalReqs) * 100.0
	}

	// Check if all system component baselines are assessed
	components, _ := sysDoc["components"].([]interface{})
	allCovered := len(components) > 0
	allAssessed := true
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
