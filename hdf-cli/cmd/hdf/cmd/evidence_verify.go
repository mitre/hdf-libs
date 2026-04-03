package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newEvidenceVerifyCmd() *cobra.Command {
	var checksumsOnly bool

	cmd := &cobra.Command{
		Use:   "verify <package-file>",
		Short: "Verify an evidence package against its assessment plan",
		Long: `Verify an HDF evidence package. By default, checks completeness:
every baseline in the referenced plan must have a corresponding results
document in the evidence package.

Use --checksums-only to skip completeness checking and only verify
SHA-256 checksums of referenced files.

If the evidence package has no planRef, falls back to checksum
verification with a warning.

Examples:
  hdf evidence verify package.json
  hdf evidence verify package.json --checksums-only
  hdf evidence verify package.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceVerify(args[0], checksumsOnly)
		},
	}

	cmd.Flags().BoolVar(&checksumsOnly, "checksums-only", false, "Only verify file checksums, skip completeness checking")

	return cmd
}

// Verification status constants.
const (
	verifyMatch    = "match"
	verifyMismatch = "mismatch"
	verifySkipped  = "skipped"
	verifyError    = "error"
)

// evidenceVerifyResult holds per-document verification status.
type evidenceVerifyResult struct {
	URI      string `json:"uri"`
	Type     string `json:"type"`
	Status   string `json:"status"` // "match", "mismatch", "skipped", "error"
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Error    string `json:"error,omitempty"`
}

type verifyCounts struct {
	match    int
	mismatch int
	skipped  int
	errors   int
}

func runEvidenceVerify(pkgPath string, checksumsOnly bool) error {
	data, err := os.ReadFile(pkgPath) //nolint:gosec // CLI reads user-provided path
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse evidence package: %w", err)
	}

	pkgDir := filepath.Dir(pkgPath)
	contents, _ := doc["contents"].([]interface{})

	// Always verify checksums
	results, counts := verifyContents(contents, pkgDir)
	renderVerifyOutput(doc, results, counts)

	if counts.mismatch > 0 || counts.errors > 0 {
		return fmt.Errorf("%d checksum mismatches, %d errors", counts.mismatch, counts.errors)
	}

	// Completeness checking (default behavior unless --checksums-only)
	if checksumsOnly {
		return nil
	}

	planRef, hasPlanRef := doc["planRef"].(string)
	if !hasPlanRef || planRef == "" {
		fmt.Fprintf(os.Stderr, "Note: no planRef in evidence package — skipping completeness check\n")
		return nil
	}

	return verifyCompleteness(pkgDir, planRef, contents)
}

// verifyCompleteness checks that every baseline in the plan has a
// corresponding results document in the evidence package.
func verifyCompleteness(pkgDir, planRef string, contents []interface{}) error { //nolint:gocyclo // complexity from path validation error handling
	// Load the plan (validate path stays within package directory)
	planPath, err := safePath(pkgDir, planRef)
	if err != nil {
		return fmt.Errorf("invalid plan reference: %w", err)
	}
	planData, err := os.ReadFile(planPath) //nolint:gosec // validated by safePath
	if err != nil {
		return fmt.Errorf("failed to read plan %s: %w", planRef, err)
	}

	var plan map[string]interface{}
	if err := json.Unmarshal(planData, &plan); err != nil {
		return fmt.Errorf("failed to parse plan %s: %w", planRef, err)
	}

	// Extract planned baselines
	assessments, _ := plan["assessments"].([]interface{})
	plannedBaselines := make(map[string]bool)
	for _, aRaw := range assessments {
		a, ok := aRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if ref, ok := a["baselineRef"].(string); ok {
			plannedBaselines[ref] = false // false = not yet covered
		}
	}

	// Load each results document in the package and extract baseline names
	for _, cRaw := range contents {
		entry, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}
		docType, _ := entry["type"].(string)
		if docType != "hdf-results" {
			continue
		}
		uri, _ := entry["uri"].(string)
		if uri == "" {
			continue
		}

		resultsPath, pathErr := safePath(pkgDir, uri)
		if pathErr != nil {
			return fmt.Errorf("invalid results URI %q: %w", uri, pathErr)
		}
		resultsData, readErr := os.ReadFile(resultsPath) //nolint:gosec // validated by safePath
		if readErr != nil {
			continue // checksum verification already reported this
		}

		var results map[string]interface{}
		if json.Unmarshal(resultsData, &results) != nil {
			continue
		}

		baselines, _ := results["baselines"].([]interface{})
		for _, bRaw := range baselines {
			b, ok := bRaw.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := b["name"].(string)
			if _, planned := plannedBaselines[name]; planned {
				plannedBaselines[name] = true
			}
		}
	}

	// Report missing baselines
	var missing []string
	for baseline, covered := range plannedBaselines {
		if !covered {
			missing = append(missing, baseline)
		}
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "\nCompleteness check FAILED:\n")
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  Missing results for baseline: %s\n", m)
		}
		return &exitCodeError{
			code:    1,
			message: fmt.Sprintf("evidence package incomplete: missing results for %s", missing[0]),
		}
	}

	fmt.Fprintf(os.Stderr, "Completeness check passed: all %d planned baselines have results\n", len(plannedBaselines))
	return nil
}

func verifyContents(contents []interface{}, pkgDir string) ([]evidenceVerifyResult, verifyCounts) {
	results := make([]evidenceVerifyResult, 0, len(contents))
	var counts verifyCounts

	for _, cRaw := range contents {
		entry, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}

		uri, _ := entry["uri"].(string)
		docType, _ := entry["type"].(string)
		r := verifyContentEntry(entry, uri, docType, pkgDir)
		results = append(results, r)

		switch r.Status {
		case verifyMatch:
			counts.match++
		case verifyMismatch:
			counts.mismatch++
		case verifySkipped:
			counts.skipped++
		case verifyError:
			counts.errors++
		}
	}

	return results, counts
}

func verifyContentEntry(entry map[string]interface{}, uri, docType, pkgDir string) evidenceVerifyResult {
	checksumObj, hasChecksum := entry["checksum"].(map[string]interface{})
	if !hasChecksum {
		return evidenceVerifyResult{URI: uri, Type: docType, Status: verifySkipped}
	}

	expectedHash, _ := checksumObj["value"].(string)
	if expectedHash == "" {
		return evidenceVerifyResult{URI: uri, Type: docType, Status: verifySkipped}
	}

	filePath, pathErr := safePath(pkgDir, uri)
	if pathErr != nil {
		return evidenceVerifyResult{URI: uri, Type: docType, Status: verifyError, Error: pathErr.Error()}
	}
	fileData, err := os.ReadFile(filePath) //nolint:gosec // validated by safePath
	if err != nil {
		return evidenceVerifyResult{URI: uri, Type: docType, Status: verifyError, Error: err.Error()}
	}

	actualHash := sha256.Sum256(fileData)
	actualHex := hex.EncodeToString(actualHash[:])

	if actualHex == expectedHash {
		return evidenceVerifyResult{URI: uri, Type: docType, Status: verifyMatch}
	}
	return evidenceVerifyResult{URI: uri, Type: docType, Status: verifyMismatch, Expected: expectedHash, Actual: actualHex}
}

func renderVerifyOutput(doc map[string]interface{}, results []evidenceVerifyResult, counts verifyCounts) {
	if jsonOutput {
		out := map[string]interface{}{
			"results":    results,
			"matched":    counts.match,
			"mismatched": counts.mismatch,
			"skipped":    counts.skipped,
			"errors":     counts.errors,
		}
		output, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(output))
		return
	}

	name, _ := doc["name"].(string)
	if name != "" {
		fmt.Printf("Verifying evidence package: %s\n\n", sanitizeOutput(name))
	}
	for _, r := range results {
		switch r.Status {
		case verifyMatch:
			fmt.Printf("  \u2713 %s (sha256 match)\n", sanitizeOutput(r.URI))
		case verifyMismatch:
			fmt.Printf("  \u2717 %s (sha256 MISMATCH)\n", sanitizeOutput(r.URI))
		case verifySkipped:
			fmt.Printf("  - %s (no checksum)\n", sanitizeOutput(r.URI))
		case verifyError:
			fmt.Printf("  ! %s (error: %s)\n", sanitizeOutput(r.URI), r.Error)
		}
	}
	total := counts.match + counts.mismatch
	fmt.Printf("\nVerified: %d/%d checksums valid", counts.match, total)
	if counts.mismatch > 0 {
		fmt.Printf(", %d failed", counts.mismatch)
	}
	if counts.skipped > 0 {
		fmt.Printf(", %d skipped", counts.skipped)
	}
	fmt.Println()
}
