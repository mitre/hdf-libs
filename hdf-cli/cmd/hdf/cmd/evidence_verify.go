package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
	data, err := readInputFile(pkgPath) // size-gated read boundary (honors --max-size)
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}

	doc, err := loadAndValidateHDFDoc(data, "evidence-package")
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}

	pkgDir := filepath.Dir(pkgPath)
	planRef, contents, err := hdfengine.ParseEvidencePackage(data)
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}

	// Validate every content reference's SHAPE before any IO. This cannot ride
	// along with checksum verification: an entry carrying no checksum is skipped
	// there, so a malformed reference on such an entry would never be looked at.
	if err := validateContentRefs(pkgDir, planRef, contents); err != nil {
		return err
	}

	// Always verify checksums. Path confinement stays here (the adapter); the
	// engine performs no IO and classifies match/mismatch/skipped/error.
	fetch := confinedFetch(pkgDir)
	results, counts := toVerifyResults(hdfengine.VerifyChecksums(contents, fetch))
	renderVerifyOutput(doc, results, counts, hdfengine.AgentOverridesInPackage(contents, fetch))

	if counts.mismatch > 0 || counts.errors > 0 {
		return fmt.Errorf("%d checksum mismatches, %d errors", counts.mismatch, counts.errors)
	}

	// Completeness checking (default behavior unless --checksums-only)
	if checksumsOnly {
		return nil
	}

	if planRef == "" {
		fmt.Fprintf(os.Stderr, "Note: no planRef in evidence package — skipping completeness check\n")
		return nil
	}

	return verifyCompleteness(pkgDir, planRef, contents)
}

// validateContentRefs enforces what a contents[] reference is: a path relative to
// the evidence package's own directory, confined to that subtree. Absolute and
// remote references are refused rather than reinterpreted — SafePath would
// silently re-root "/etc/passwd" under the package directory, and turn a URL into
// a path with a "https:" component, reporting on a file the reference never named.
//
// Scope is contents[] and planRef ONLY. externalEvidence URIs are absolute or
// remote by design, and a bundled document's own externalReferences are bare URIs;
// both are correct, neither is resolved here, and neither is inspected.
func validateContentRefs(pkgDir, planRef string, contents []hdfengine.EvidenceContent) error {
	refs := make([]string, 0, len(contents)+1)
	if planRef != "" {
		refs = append(refs, planRef)
	}
	for _, c := range contents {
		if c.URI != "" {
			refs = append(refs, c.URI)
		}
	}
	for _, uri := range refs {
		if err := checkContentRefShape(uri); err != nil {
			return err
		}
		if _, err := hdfutil.SafePath(pkgDir, uri); err != nil {
			return fmt.Errorf("content reference %q: %w", uri, err)
		}
	}
	return nil
}

// checkContentRefShape refuses the two reference shapes the schema's description
// once invited but nothing ever resolved.
func checkContentRefShape(uri string) error {
	if i := strings.Index(uri, "://"); i > 0 {
		return fmt.Errorf("content reference %q is remote; contents[] lists documents carried with the "+
			"package and its references are relative to it — record a remote artifact under "+
			"externalEvidence instead, where it is kept by URI and hash", uri)
	}
	if strings.HasPrefix(uri, "/") || filepath.IsAbs(uri) {
		return fmt.Errorf("content reference %q is absolute; references are relative to the evidence "+
			"package's own directory", uri)
	}
	return nil
}

// confinedFetch returns a FetchFunc that resolves a content URI relative to the
// package directory, confined by SafePath and read through the same size-gated
// boundary as the package itself — a referenced file is untrusted input too.
// SafePath and read failures both surface as errors, which VerifyChecksums
// classifies as an error status.
func confinedFetch(pkgDir string) hdfengine.FetchFunc {
	return func(uri string) ([]byte, error) {
		path, err := hdfutil.SafePath(pkgDir, uri)
		if err != nil {
			return nil, err
		}
		return readFromFile(path, true)
	}
}

// verifyCompleteness checks that every baseline in the plan has a corresponding
// results document in the package. The planned/covered extraction and the diff
// are the engine's; path confinement and schema-validation warnings stay here.
func verifyCompleteness(pkgDir, planRef string, contents []hdfengine.EvidenceContent) error {
	planPath, err := hdfutil.SafePath(pkgDir, planRef)
	if err != nil {
		return fmt.Errorf("invalid plan reference: %w", err)
	}
	planData, err := readFromFile(planPath, true)
	if err != nil {
		return fmt.Errorf("failed to read plan %s: %w", planRef, err)
	}
	planned, err := hdfengine.PlannedBaselineRefs(planData)
	if err != nil {
		return fmt.Errorf("failed to parse plan %s: %w", planRef, err)
	}

	var covered []string
	for _, c := range contents {
		if c.Type != "hdf-results" || c.URI == "" {
			continue
		}
		resultsPath, pathErr := hdfutil.SafePath(pkgDir, c.URI)
		if pathErr != nil {
			return fmt.Errorf("invalid results URI %q: %w", c.URI, pathErr)
		}
		resultsData, readErr := readFromFile(resultsPath, true)
		if readErr != nil {
			continue // checksum verification already reported this
		}
		if _, validateErr := loadAndValidateHDFDoc(resultsData, "results"); validateErr != nil {
			// Checksum verification only confirms the bytes match the recorded
			// hash; it does not validate schema. Surfacing this keeps a
			// schema-invalid results doc from masquerading as a missing baseline.
			fmt.Fprintf(os.Stderr, "Warning: results doc %q failed schema validation; skipping for completeness check: %v\n", c.URI, validateErr)
			continue
		}
		names, nameErr := hdfengine.CoveredBaselineNames(resultsData)
		if nameErr != nil {
			continue
		}
		covered = append(covered, names...)
	}

	comp := hdfengine.Completeness(planned, covered)
	if !comp.Complete {
		fmt.Fprintf(os.Stderr, "\nCompleteness check FAILED:\n")
		for _, m := range comp.Missing {
			fmt.Fprintf(os.Stderr, "  Missing results for baseline: %s\n", m)
		}
		return &exitCodeError{
			code:    1,
			message: fmt.Sprintf("evidence package incomplete: missing results for %s", comp.Missing[0]),
		}
	}

	fmt.Fprintf(os.Stderr, "Completeness check passed: all %d planned baselines have results\n", len(comp.Planned))
	return nil
}

// toVerifyResults maps engine checksum results to the CLI's render/count shape.
func toVerifyResults(checksums []hdfengine.ChecksumResult) ([]evidenceVerifyResult, verifyCounts) {
	results := make([]evidenceVerifyResult, 0, len(checksums))
	var counts verifyCounts
	for _, c := range checksums {
		results = append(results, evidenceVerifyResult{
			URI:      c.URI,
			Type:     c.Type,
			Status:   string(c.Status),
			Expected: c.Expected,
			Actual:   c.Actual,
			Error:    c.Error,
		})
		switch c.Status {
		case hdfengine.ChecksumMatch:
			counts.match++
		case hdfengine.ChecksumMismatch:
			counts.mismatch++
		case hdfengine.ChecksumSkipped:
			counts.skipped++
		case hdfengine.ChecksumError:
			counts.errors++
		}
	}
	return results, counts
}

func renderVerifyOutput(doc map[string]interface{}, results []evidenceVerifyResult, counts verifyCounts, agentOverrides int) {
	if jsonOutput {
		out := map[string]interface{}{
			"results":        results,
			"matched":        counts.match,
			"mismatched":     counts.mismatch,
			"skipped":        counts.skipped,
			"errors":         counts.errors,
			"agentOverrides": agentOverrides,
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
	fmt.Println(agentOverrideReadout(agentOverrides))
}
