package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
			if len(expanded) == 0 && opts.fromDir == "" {
				return fmt.Errorf("no results files provided; use --results, --from-dir, or pass files as arguments")
			}
			opts.resultsPaths = expanded
			for _, g := range []*[]string{&opts.baselinePaths, &opts.bomPaths, &opts.amendmentsPaths, &opts.comparisonPaths} {
				ex, gerr := expandGlobs(dropEmpty(*g))
				if gerr != nil {
					return fmt.Errorf("failed to expand paths: %w", gerr)
				}
				*g = ex
			}
			if opts.fromDir != "" {
				if err := mergeScannedDir(&opts); err != nil {
					return err
				}
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
	cmd.Flags().StringVar(&opts.fromDir, "from-dir", "",
		"Scan a directory and route every document by its content; recurses, and reports what it cannot place")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "Output file (default: stdout)")

	// --system is required unless --from-dir will supply it.
	cmd.PreRunE = func(c *cobra.Command, _ []string) error {
		if opts.systemPath == "" && opts.fromDir == "" {
			return fmt.Errorf("--system is required (or use --from-dir to discover it)")
		}
		return nil
	}

	return cmd
}

// mergeScannedDir folds a directory scan into the explicit flags. Explicit wins:
// a path named on the command line is skipped by the scan, so it is listed once.
func mergeScannedDir(opts *evidenceBuildOpts) error {
	skip := map[string]struct{}{}
	for _, group := range [][]string{{opts.systemPath, opts.planPath}, opts.resultsPaths,
		opts.baselinePaths, opts.bomPaths, opts.amendmentsPaths, opts.comparisonPaths} {
		for _, p := range group {
			if p == "" {
				continue
			}
			if abs, err := resolvedAbs(p); err == nil {
				skip[abs] = struct{}{}
			}
		}
	}

	found, err := scanEvidenceDir(opts.fromDir, skip)
	if err != nil {
		return err
	}

	// The package must have exactly one system document. Naming every candidate is
	// what lets the operator see which one to move out of the tree.
	switch {
	case opts.systemPath != "":
		// explicitly given; any scanned system documents are additional candidates
		if len(found.systems) > 0 {
			return fmt.Errorf("--system was given as %s, but --from-dir also found %s; "+
				"an evidence package has exactly one system document",
				opts.systemPath, strings.Join(found.systems, ", "))
		}
	case len(found.systems) == 0:
		return fmt.Errorf("--from-dir %s contains no HDF system document; "+
			"an evidence package needs exactly one", opts.fromDir)
	case len(found.systems) > 1:
		return fmt.Errorf("--from-dir %s contains %d HDF system documents (%s); "+
			"an evidence package has exactly one — move the others out of the tree",
			opts.fromDir, len(found.systems), strings.Join(found.systems, ", "))
	default:
		opts.systemPath = found.systems[0]
	}

	opts.resultsPaths = append(opts.resultsPaths, found.results...)
	opts.baselinePaths = append(opts.baselinePaths, found.baselines...)
	opts.bomPaths = append(opts.bomPaths, found.boms...)
	opts.amendmentsPaths = append(opts.amendmentsPaths, found.amendments...)
	opts.comparisonPaths = append(opts.comparisonPaths, found.comparisons...)
	// Which plan is the bar (planRef) is singular and can be ambiguous; which
	// documents the package carries is not. Every scanned plan is listed either
	// way, so following the ">1 plans" error's own advice cannot make one vanish.
	switch {
	case opts.planPath != "":
		opts.extraPlanPaths = append(opts.extraPlanPaths, found.plans...)
	case len(found.plans) == 1:
		opts.planPath = found.plans[0]
	case len(found.plans) > 1:
		return fmt.Errorf("--from-dir %s contains %d HDF plan documents (%s); "+
			"name the one the package was assessed against with --plan "+
			"(the others will still be listed in the package)",
			opts.fromDir, len(found.plans), strings.Join(found.plans, ", "))
	}
	if opts.planPath != "" && len(opts.extraPlanPaths) > 0 {
		rel := func(p string) string { return displayUnderBase(opts.fromDir, p) }
		others := make([]string, 0, len(opts.extraPlanPaths))
		for _, p := range opts.extraPlanPaths {
			others = append(others, rel(p))
		}
		fmt.Fprintf(os.Stderr, "planRef is %s; also listed, but not the assessment bar: %s\n",
			rel(opts.planPath), strings.Join(others, ", "))
	}

	reportScan(found, opts.fromDir, opts.outputPath)
	return nil
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

// resolvedAbs returns a path's symlink-resolved absolute form, falling back to
// the lexical absolute form for a path not yet on disk.
//
// Resolving matters: `hdf evidence verify` confines references through
// hdfutil.SafePath, which resolves symlinks, so a reference written by comparing
// paths lexically disagrees with the reader. On macOS /tmp is a symlink to
// /private/tmp, so a pipeline mixing $TMPDIR-derived and realpath-derived paths
// would be told a document is outside a directory it is plainly inside — with the
// prescribed remedy already satisfied and no way forward.
func resolvedAbs(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Both inputs exist by the time this runs: a document has just been read, and
	// the output directory is checked before any reference is computed. So a
	// resolution failure here is a real one (a permission wall, a symlink loop)
	// and is surfaced rather than degraded to the lexical form — degrading would
	// silently reintroduce the /tmp-versus-/private/tmp mismatch this exists to
	// prevent, with no error to show for it.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %w", path, err)
	}
	return resolved, nil
}

// packageRelativeRef renders a document's path as a reference relative to the
// package's own directory. The package sits at the root of the base directory —
// the artifacts folder a CI orchestrator hands from job to job — so that
// directory IS the base, and a document outside it is not a content reference at
// all: it belongs in externalEvidence, carried by URI and hash.
//
// The result always uses forward slashes. A reference is data read by whoever
// opens the package, not a path on the machine that wrote it, so a package built
// on Windows must still say "scans/x.json".
func packageRelativeRef(baseDir, docPath string) (string, error) {
	absBase, err := resolvedAbs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve package directory %s: %w", baseDir, err)
	}
	absDoc, err := resolvedAbs(docPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %w", docPath, err)
	}
	rel, err := filepath.Rel(absBase, absDoc)
	if err != nil {
		return "", fmt.Errorf("failed to relate %s to the package directory %s: %w", docPath, absBase, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s is outside the evidence package's directory (%s); "+
			"move it under that directory, or record it with `hdf evidence add-evidence`", docPath, absBase)
	}
	return filepath.ToSlash(rel), nil
}

// documentRef is the one definition of what a content reference is. With a
// package directory it is the package-relative path; writing to stdout there is
// none, so the basename stands and the caller is told the layout will not
// survive a subdirectory.
func documentRef(baseDir, path string) (string, error) {
	if baseDir == "" {
		return filepath.Base(path), nil
	}
	return packageRelativeRef(baseDir, path)
}

// mustRef is documentRef for a path already proven in-tree by addEntry.
// A failure cannot happen at that point; the basename is a harmless fallback
// rather than a panic in a CLI.
func mustRef(baseDir, path string) string {
	ref, err := documentRef(baseDir, path)
	if err != nil {
		return filepath.Base(path)
	}
	return ref
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
	fromDir         string
	// extraPlanPaths are plans a scan found that are NOT the planRef. They are
	// still listed in contents[]: planRef names which plan the package was
	// assessed against, while contents[] is the manifest of documents carried —
	// conflating the two silently dropped every plan but one.
	extraPlanPaths []string
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
func appendTyped(contents []map[string]interface{}, baseDir string, paths []string, schemaType, contentType, flag string) ([]map[string]interface{}, error) {
	for _, p := range paths {
		data, err := readInputFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read --%s file %s: %w", flag, p, err)
		}
		if err := requireDetectedType(data, p, schemaType, flag); err != nil {
			return nil, err
		}
		ref, refErr := documentRef(baseDir, p)
		if refErr != nil {
			return nil, refErr
		}
		contents = append(contents, contentEntryFromBytes(contentType, ref, data))
	}
	return contents, nil
}

func runEvidenceBuild(opts evidenceBuildOpts) error {
	contents := make([]map[string]interface{}, 0, len(opts.resultsPaths)+6)

	// Every reference is relative to the package's own directory. Writing to
	// stdout leaves no package location at all, so no relative reference can be
	// computed: that case keeps the historical basename and warns, rather than
	// inventing a base directory the reader will not share.
	baseDir := ""
	if opts.outputPath != "" {
		baseDir = filepath.Dir(opts.outputPath)
		if info, statErr := os.Stat(baseDir); statErr != nil || !info.IsDir() {
			return fmt.Errorf("output directory %s does not exist; create it before writing the package there", baseDir)
		}
	} else {
		// Said once, and only what is true: there is no package directory, so
		// every reference is a bare filename whatever the layout.
		fmt.Fprintf(os.Stderr,
			"Warning: writing to stdout, so references are recorded as bare filenames — "+
				"there is no package directory to resolve them against. "+
				"Use -o <file> for references that resolve.\n")
	}

	// addEntry computes the document's reference from the package's location and
	// lists it. One path for every content type, so no type can drift.
	addEntry := func(docType, path string) error {
		ref, refErr := documentRef(baseDir, path)
		if refErr != nil {
			return refErr
		}
		e, entryErr := buildContentEntry(docType, path, ref)
		if entryErr != nil {
			return entryErr
		}
		contents = append(contents, e)
		return nil
	}

	// Add system
	if err := addEntry("hdf-system", opts.systemPath); err != nil {
		return err
	}

	// Add results
	for _, rp := range opts.resultsPaths {
		if err := addEntry("hdf-results", rp); err != nil {
			return err
		}
	}
	var err error

	// Optional: plan. Its presence also sets the package's planRef, which is
	// what `evidence verify` reads to check completeness against the plan.
	planPaths := make([]string, 0, 1+len(opts.extraPlanPaths))
	if opts.planPath != "" {
		planPaths = append(planPaths, opts.planPath)
	}
	planPaths = append(planPaths, opts.extraPlanPaths...)
	if len(planPaths) > 0 {
		if contents, err = appendTyped(contents, baseDir, planPaths, "plan", "hdf-plan", "plan"); err != nil {
			return err
		}
	}

	// Optional: baselines
	if contents, err = appendTyped(contents, baseDir, opts.baselinePaths, "baseline", "hdf-baseline", "baseline"); err != nil {
		return err
	}

	// Optional: BOMs. Deliberately NOT fingerprint-checked. A BOM is not one of
	// the eight HDF document types, and hdfengine.Detect classifies any root
	// `components` key as an HDF system — which is exactly CycloneDX's primary
	// field, so a guard here rejects real SBOMs. The schema carries a BOM's kind
	// in the referenced document's own bomType, not in the Content_Type.
	for _, bp := range opts.bomPaths {
		if aerr := addEntry("bom", bp); aerr != nil {
			return aerr
		}
	}

	// Optional: amendments and comparisons, fingerprint-checked like --plan and
	// --baseline. verify reads contents[].type to judge completeness, so filing a
	// document under the wrong type yields a confident wrong verdict, not an error.
	if contents, err = appendTyped(contents, baseDir, opts.amendmentsPaths, "amendments", "hdf-amendments", "amendments"); err != nil {
		return err
	}
	if contents, err = appendTyped(contents, baseDir, opts.comparisonPaths, "comparison", "hdf-comparison", "comparison"); err != nil {
		return err
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
		"systemRef":         mustRef(baseDir, opts.systemPath),
		"preparedAt":        time.Now().UTC().Format(time.RFC3339),
		"contents":          contents,
		"completenessCheck": completeness,
	}
	if opts.planPath != "" {
		pkg["planRef"] = mustRef(baseDir, opts.planPath)
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

// buildContentEntry reads filePath and lists it under ref. The reference is
// computed by the caller from the package's location (packageRelativeRef), not
// derived here: the same document has different references depending on where
// the package is written.
func buildContentEntry(docType, filePath, ref string) (map[string]interface{}, error) {
	data, err := readInputFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file %s: %w", docType, filePath, err)
	}
	return contentEntryFromBytes(docType, ref, data), nil
}

// contentEntryFromBytes is buildContentEntry's body for a caller that has
// already read the file. Shared, not forked: both paths produce the same entry.
func contentEntryFromBytes(docType, ref string, data []byte) map[string]interface{} {
	hash := sha256.Sum256(data)
	return map[string]interface{}{
		"type": docType,
		"uri":  ref,
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
