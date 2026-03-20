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
	return &cobra.Command{
		Use:   "verify <package-file>",
		Short: "Verify checksums of documents in an evidence package",
		Long: `Verify integrity of an HDF evidence package by checking SHA-256 checksums
of all referenced documents.

For each content reference with a checksum, reads the referenced file and
verifies the checksum matches. Reports results and exits with code 1 if
any checksum mismatches are found.

Examples:
  hdf evidence verify package.json
  hdf evidence verify package.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceVerify(args[0])
		},
	}
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

func runEvidenceVerify(pkgPath string) error {
	data, err := os.ReadFile(pkgPath) // #nosec G304 -- CLI reads user-provided path
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse evidence package: %w", err)
	}

	pkgDir := filepath.Dir(pkgPath)
	contents, _ := doc["contents"].([]interface{})

	results, counts := verifyContents(contents, pkgDir)

	renderVerifyOutput(doc, results, counts)

	if counts.mismatch > 0 || counts.errors > 0 {
		return fmt.Errorf("%d checksum mismatches, %d errors", counts.mismatch, counts.errors)
	}
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

	filePath := filepath.Join(pkgDir, uri)
	fileData, err := os.ReadFile(filePath) // #nosec G304 -- resolves relative to package
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
