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
	var opts evidenceBuildOpts

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
			allResults := make([]string, 0, len(opts.resultsPaths)+len(args))
			allResults = append(allResults, opts.resultsPaths...)
			allResults = append(allResults, args...)
			expanded, err := expandGlobs(dropEmpty(allResults))
			if err != nil {
				return fmt.Errorf("failed to expand results paths: %w", err)
			}
			if len(expanded) == 0 {
				return fmt.Errorf("no results files provided; use --results or pass files as arguments")
			}
			opts.resultsPaths = expanded
			for _, g := range []*[]string{&opts.baselinePaths, &opts.bomPaths, &opts.amendmentsPaths, &opts.comparisonPaths} {
				ex, gerr := expandGlobs(dropEmpty(*g))
				if gerr != nil {
					return fmt.Errorf("failed to expand paths: %w", gerr)
				}
				*g = ex
			}
			return runEvidenceBuild(opts)
		},
	}

	cmd.Flags().StringVar(&opts.systemPath, "system", "", "System document (required)")
	cmd.Flags().StringArrayVar(&opts.resultsPaths, "results", nil, "Results document(s) (repeatable, supports globs)")
	cmd.Flags().StringVar(&opts.planPath, "plan", "", "Assessment plan document; also sets the package's planRef (optional)")
	cmd.Flags().StringArrayVar(&opts.baselinePaths, "baseline", nil, "Baseline document(s) (repeatable, supports globs)")
	cmd.Flags().StringArrayVar(&opts.bomPaths, "bom", nil, "BOM document(s) — SBOM, AI model/dataset manifest (repeatable, supports globs)")
	cmd.Flags().StringArrayVar(&opts.amendmentsPaths, "amendments", nil, "Amendments document(s) (repeatable, supports globs)")
	cmd.Flags().StringArrayVar(&opts.comparisonPaths, "comparison", nil, "Comparison document(s) (repeatable, supports globs)")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "Output file (default: stdout)")

	_ = cmd.MarkFlagRequired("system")

	return cmd
}

// dropEmpty removes empty path elements. An unset shell variable (--amendments
// "$AMEND") was a no-op before these flags became repeatable, and must stay one:
// readInputFile("") reads stdin, which would otherwise be swallowed and listed
// as a content entry with uri ".".
func dropEmpty(paths []string) []string {
	kept := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return kept
}

// evidenceBuildOpts carries the documents a package is built from. The schema
// permits seven Content_Type values; every one of them is reachable here, so a
// package never has to be finished by a second command.
type evidenceBuildOpts struct {
	systemPath      string
	resultsPaths    []string
	planPath        string
	baselinePaths   []string
	bomPaths        []string
	amendmentsPaths []string
	comparisonPaths []string
	outputPath      string
}

// requireDetectedType rejects a document whose fingerprint is not what the flag
// promised. Mistyping a content entry is worse than refusing it: `evidence
// verify` reads these types to judge completeness, so a plan filed as a
// baseline yields a confident wrong verdict. Build is deliberately not a full
// validation gate for its inputs (see computeCompleteness), so this checks the
// fingerprint only.
func requireDetectedType(data []byte, path, want, flag string) error {
	got := detectHDFDocumentType(data)
	if got == want {
		return nil
	}
	if got == "" {
		return fmt.Errorf("--%s file %s is not a recognized HDF document", flag, path)
	}
	return fmt.Errorf("--%s file %s is an HDF %s document, expected %s", flag, path, got, want)
}

// appendTyped fingerprint-checks each path, then lists it under contentType. The
// file is read ONCE and its bytes reused for both the check and the checksum:
// reading twice consumed stdin in the guard and left the second read empty.
func appendTyped(contents []map[string]interface{}, paths []string, schemaType, contentType, flag string) ([]map[string]interface{}, error) {
	for _, p := range paths {
		data, err := readInputFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read --%s file %s: %w", flag, p, err)
		}
		if err := requireDetectedType(data, p, schemaType, flag); err != nil {
			return nil, err
		}
		contents = append(contents, contentEntryFromBytes(contentType, p, data))
	}
	return contents, nil
}

func runEvidenceBuild(opts evidenceBuildOpts) error {
	contents := make([]map[string]interface{}, 0, len(opts.resultsPaths)+6)

	// Add system
	entry, err := buildContentEntry("hdf-system", opts.systemPath)
	if err != nil {
		return err
	}
	contents = append(contents, entry)

	// Add results
	for _, rp := range opts.resultsPaths {
		entry, err = buildContentEntry("hdf-results", rp)
		if err != nil {
			return err
		}
		contents = append(contents, entry)
	}

	// Optional: plan. Its presence also sets the package's planRef, which is
	// what `evidence verify` reads to check completeness against the plan.
	if opts.planPath != "" {
		if contents, err = appendTyped(contents, []string{opts.planPath}, "plan", "hdf-plan", "plan"); err != nil {
			return err
		}
	}

	// Optional: baselines
	if contents, err = appendTyped(contents, opts.baselinePaths, "baseline", "hdf-baseline", "baseline"); err != nil {
		return err
	}

	// Optional: BOMs. Deliberately NOT fingerprint-checked. A BOM is not one of
	// the eight HDF document types, and hdfengine.Detect classifies any root
	// `components` key as an HDF system — which is exactly CycloneDX's primary
	// field, so a guard here rejects real SBOMs. The schema carries a BOM's kind
	// in the referenced document's own bomType, not in the Content_Type.
	for _, bp := range opts.bomPaths {
		if entry, err = buildContentEntry("bom", bp); err != nil {
			return err
		}
		contents = append(contents, entry)
	}

	// Optional: amendments and comparisons. These are NOT fingerprint-checked,
	// because they never were: making them repeatable must not also tighten what
	// they accept. That asymmetry against --plan/--baseline is tracked on its own card.
	for _, ap := range opts.amendmentsPaths {
		if entry, err = buildContentEntry("hdf-amendments", ap); err != nil {
			return err
		}
		contents = append(contents, entry)
	}
	for _, cp := range opts.comparisonPaths {
		if entry, err = buildContentEntry("hdf-comparison", cp); err != nil {
			return err
		}
		contents = append(contents, entry)
	}

	// Extract system name for package name
	sysData, err := readInputFile(opts.systemPath)
	if err != nil {
		return fmt.Errorf("failed to re-read system file: %w", err)
	}
	sysDoc, err := loadAndValidateHDFDoc(sysData, "system")
	if err != nil {
		return fmt.Errorf("system file %s: %w", opts.systemPath, err)
	}
	sysName, _ := sysDoc["name"].(string)
	if sysName == "" {
		sysName = "unnamed-system"
	}

	// Compute completeness check from all results
	completeness := computeCompleteness(sysDoc, opts.resultsPaths)

	pkg := map[string]interface{}{
		"name":              sysName + "-evidence-package",
		"systemRef":         filepath.Base(opts.systemPath),
		"preparedAt":        time.Now().UTC().Format(time.RFC3339),
		"contents":          contents,
		"completenessCheck": completeness,
	}
	if opts.planPath != "" {
		pkg["planRef"] = filepath.Base(opts.planPath)
	}

	output, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize evidence package: %w", err)
	}

	if err := validateHDFDocument(output); err != nil {
		return fmt.Errorf("evidence package failed validation before write: %w", err)
	}

	if opts.outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := os.WriteFile(opts.outputPath, output, 0o600); err != nil { // #nosec G703 -- CLI writes user path
		return fmt.Errorf("failed to write evidence package: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Evidence package written to %s (%d documents)\n", opts.outputPath, len(contents))
	return nil
}

func buildContentEntry(docType, filePath string) (map[string]interface{}, error) {
	data, err := readInputFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file %s: %w", docType, filePath, err)
	}
	return contentEntryFromBytes(docType, filePath, data), nil
}

// contentEntryFromBytes is buildContentEntry's body for a caller that has
// already read the file. Shared, not forked: both paths produce the same entry.
func contentEntryFromBytes(docType, filePath string, data []byte) map[string]interface{} {
	hash := sha256.Sum256(data)
	return map[string]interface{}{
		"type": docType,
		"uri":  filepath.Base(filePath),
		"checksum": map[string]interface{}{
			"algorithm": "sha256",
			"value":     hex.EncodeToString(hash[:]),
		},
	}
}

// computeCompleteness is a best-effort courtesy metric. It deliberately
// walks results as raw JSON (rather than going through parseHDFResults)
// so a partial / not-yet-schema-valid results file still produces a
// useful number for an evidence package summary. The evidence-build
// command is not the validation gate for its inputs — `hdf validate`
// is. Audit hdf-libs-qio1 confirmed this is intentional, not
// wheel-reinvention.
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
		resultsData, err := readInputFile(resultsPath)
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
