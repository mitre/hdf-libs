package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/atomicfile"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	"github.com/spf13/cobra"
)

func newEvidenceBuildCmd() *cobra.Command {
	var opts evidenceBuildOpts

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Bundle HDF documents into an evidence package",
		Long: `Build an HDF evidence package from component documents.

Computes a checksum for each document and populates a
completeness check (baselines assessed, components covered,
compliance percentage).

The --results flag is repeatable and supports file globs.

--system is optional. A package that records no systemRef asserts no system: it stands
for the documents it lists and nothing more, which is what an assessment of a library or
any other lone component actually claims. Its completeness check then claims neither full
baseline coverage nor component coverage, because both are claims about system components
and there is no system document to check against.

Each document is recorded as a reference relative to the package's own directory, which is
where -o writes it. Without -o the package goes to stdout, there is no package directory,
and every reference is a bare filename — so two documents sharing a filename cannot both
be recorded and are refused rather than collapsed into one reference. Pass -o <file> to
keep the directories that tell them apart.

Examples:
  hdf evidence build --system portal.json --results scan.json
  hdf evidence build --system portal.json --results rhel9.json --results postgres.json
  hdf evidence build --system portal.json --results "/tmp/scans/*.json"
  hdf evidence build --system portal.json /tmp/scans/*.json
  hdf evidence build --system portal.json --results scan.json --amendments waivers.json -o package.json
  hdf evidence build --results scan.json -o package.json`,
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

	cmd.Flags().StringVar(&opts.systemPath, "system", "",
		"System document this package covers (optional; omit for a package that asserts no system)")
	cmd.Flags().StringArrayVar(&opts.resultsPaths, "results", nil, "Results document(s) (repeatable, supports globs)")
	cmd.Flags().StringVar(&opts.planPath, "plan", "", "Assessment plan document; also sets the package's planRef (optional)")
	cmd.Flags().StringArrayVar(&opts.baselinePaths, "baseline", nil, "Baseline document(s) (repeatable, supports globs)")
	cmd.Flags().StringArrayVar(&opts.bomPaths, "bom", nil, "BOM document(s) — SBOM, AI model/dataset manifest (repeatable, supports globs)")
	cmd.Flags().StringArrayVar(&opts.amendmentsPaths, "amendments", nil, "Amendments document(s) (repeatable, supports globs)")
	cmd.Flags().StringArrayVar(&opts.comparisonPaths, "comparison", nil, "Comparison document(s) (repeatable, supports globs)")
	cmd.Flags().StringVar(&opts.fromDir, "from-dir", "",
		"Scan a directory and route every document by its content; recurses, and reports what it cannot place")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "Output file (default: stdout)")

	return cmd
}

// mergeScannedDir folds a directory scan into the explicit flags. Explicit wins:
// a path named on the command line is skipped by the scan, so it is listed once.
func mergeScannedDir(opts *evidenceBuildOpts) error {
	skip := &explicitSkips{}
	for _, group := range [][]string{{opts.systemPath, opts.planPath}, opts.resultsPaths,
		opts.baselinePaths, opts.bomPaths, opts.amendmentsPaths, opts.comparisonPaths} {
		for _, p := range group {
			if p == "" {
				continue
			}
			skip.add(p)
		}
	}

	found, err := scanEvidenceDir(opts.fromDir, skip)
	if err != nil {
		return err
	}

	// A package has at most one system document, and none is a valid answer: a scanned
	// CI artifacts directory for a software package has no system document in it. Naming
	// every candidate is what lets the operator see which one to move out of the tree.
	switch {
	case opts.systemPath != "":
		// explicitly given; any scanned system documents are additional candidates
		if len(found.systems) > 0 {
			return fmt.Errorf("--system was given as %s, but --from-dir also found %s; "+
				"an evidence package has exactly one system document",
				opts.systemPath, strings.Join(found.systems, ", "))
		}
	case len(found.systems) > 1:
		return fmt.Errorf("--from-dir %s contains %d HDF system documents (%s); "+
			"an evidence package has exactly one — move the others out of the tree",
			opts.fromDir, len(found.systems), strings.Join(found.systems, ", "))
	case len(found.systems) == 1:
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
// Resolving matters: `hdf evidence info --verify` confines references through
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
	// A resolution failure here is a real one — a permission wall, a symlink loop, a
	// dangling link — and is surfaced rather than degraded to the lexical form:
	// degrading would silently reintroduce the /tmp-versus-/private/tmp mismatch this
	// exists to prevent, with no error to show for it. Most callers reach this after the
	// document has been read and the output directory checked, so the inputs exist; the
	// reference-claim check does not, and relies on exactly this error instead.
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
		// Only the role is added: resolvedAbs states the operation and the path, so
		// restating either reads as "failed to resolve X: failed to resolve X". Its
		// filepath.Abs branch names neither, but nothing has been found to fail it.
		return "", fmt.Errorf("package directory: %w", err)
	}
	absDoc, err := resolvedAbs(docPath)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absBase, absDoc)
	if err != nil {
		return "", fmt.Errorf("failed to relate %s to the package directory %s: %w", docPath, absBase, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s is outside the evidence package's directory (%s); "+
			"move it under that directory, or record it with `hdf evidence add-evidence`", docPath, absBase)
	}
	// ENCODED, because the value returned here is RECORDED in contents[].uri, which the
	// schema declares a uri-reference. Returning the raw path wrote a reference the
	// schema calls malformed as soon as a filename contained a space or a percent — and
	// it is also what made such a file look inexpressible when it is merely unescaped.
	return evidenceref.Encode(filepath.ToSlash(rel)), nil
}

// documentRef is the one definition of what a content reference is. With a
// package directory it is the package-relative path; writing to stdout there is
// none, so the basename stands and the caller is told the layout will not
// survive a subdirectory.
func documentRef(baseDir, path string) (string, error) {
	if baseDir == "" {
		return evidenceref.Encode(filepath.Base(path)), nil
	}
	return packageRelativeRef(baseDir, path)
}

// refClaims records which source path first claimed each content reference. A reference
// must name ONE document: two documents recorded under a single reference produce a
// package carrying both their checksums against it, so verify resolves the reference once
// and reports at least one mismatch — accusing the operator's own evidence of tampering.
// Writing to stdout is where this bites, because without a package directory every
// reference is a bare filename and a daily scan always called audit.json collides with
// itself across date directories.
type refClaims map[string]refClaim

// refClaim is the document holding a reference: the path as the operator typed it, for
// messages, and the resolved path, for deciding whether a later claim is the same document.
type refClaim struct{ path, resolved string }

// claim records ref for path, or refuses if another document already holds it. Three
// cases, because conflating them produced false advice: the same path twice is a repeat,
// one document reached by two spellings is still one document, and two DIFFERENT documents
// under one reference is unrepresentable in the package.
func (c refClaims) claim(ref, path string) error {
	// Compared on the RESOLVED path, because documentRef resolves too. Keying on the string
	// as typed reported one document reached through a symlink — a `latest ->` beside dated
	// scan directories — as two different documents, told the operator its package could
	// not verify when both checksums were identical and it verified, and prescribed -o
	// where -o was already in effect.
	resolved, err := resolvedAbs(path)
	if err != nil {
		// Returned unwrapped: resolvedAbs already names the path and the cause, and
		// wrapping it again reads as "failed to resolve X: failed to resolve X: ...".
		return err
	}
	first, taken := c[ref]
	switch {
	case taken && first.resolved == resolved && first.path == path:
		return fmt.Errorf("%s is given twice; it is the same document, so list it once", path)
	case taken && first.resolved == resolved:
		return fmt.Errorf("%s and %s are the same document; list it once", first.path, path)
	case taken:
		return fmt.Errorf("%s and %s would both be recorded as %q, and a reference must name "+
			"one document — a package recording two checksums against it cannot verify. "+
			"Give them distinct filenames, or pass -o <file> so references keep the "+
			"directories that tell them apart", first.path, path, ref)
	}
	c[ref] = refClaim{path: path, resolved: resolved}
	return nil
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
// promised. Mistyping a content entry is worse than refusing it:
// `evidence info --verify` reads these types to judge completeness, so a plan filed as a
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
func appendTyped(contents []map[string]interface{}, claims refClaims, baseDir string, paths []string, schemaType, contentType, flag string) ([]map[string]interface{}, error) {
	for _, p := range paths {
		data, raw, err := readInputFileAndRaw(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read --%s file %s: %w", flag, p, err)
		}
		// Detection parses; the entry below hashes. A BOM must not reach the first and
		// must not be missing from the second.
		if err := requireDetectedType(data, p, schemaType, flag); err != nil {
			return nil, err
		}
		ref, refErr := documentRef(baseDir, p)
		if refErr != nil {
			return nil, refErr
		}
		if err := claims.claim(ref, p); err != nil {
			return nil, err
		}
		contents = append(contents, contentEntryFromBytes(contentType, ref, raw))
	}
	return contents, nil
}

func runEvidenceBuild(opts evidenceBuildOpts) error {
	contents := make([]map[string]interface{}, 0, len(opts.resultsPaths)+6)
	// One claims map for the whole package: a collision between a results document and a
	// baseline is as unrepresentable as one between two results documents.
	claims := refClaims{}

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
		// Said once, and only what is true: there is no package directory, so every
		// reference is a bare filename whatever the layout — and a bare filename does not
		// identify a document uniquely, which is the part that costs evidence rather than
		// just portability.
		fmt.Fprintf(os.Stderr,
			"Warning: writing to stdout, so references are recorded as bare filenames — "+
				"there is no package directory to resolve them against, and a bare filename "+
				"does not identify a document uniquely: two documents sharing a filename are "+
				"refused rather than recorded under one reference. "+
				"Use -o <file> for references that resolve and keep their directories.\n")
	}

	// addEntry computes the document's reference from the package's location and
	// lists it. One path for every content type, so no type can drift.
	addEntry := func(docType, path string) error {
		ref, refErr := documentRef(baseDir, path)
		if refErr != nil {
			return refErr
		}
		if err := claims.claim(ref, path); err != nil {
			return err
		}
		e, entryErr := buildContentEntry(docType, path, ref)
		if entryErr != nil {
			return entryErr
		}
		contents = append(contents, e)
		return nil
	}

	// Add system, when the package records one. Nothing stands in for an absent one:
	// an entry with an empty uri would claim a reference to nothing.
	if opts.systemPath != "" {
		if err := addEntry("hdf-system", opts.systemPath); err != nil {
			return err
		}
	}

	// Add results
	for _, rp := range opts.resultsPaths {
		if err := addEntry("hdf-results", rp); err != nil {
			return err
		}
	}
	var err error

	// Optional: plan. Its presence also sets the package's planRef, which is
	// what `evidence info --verify` reads to check completeness against the plan.
	planPaths := make([]string, 0, 1+len(opts.extraPlanPaths))
	if opts.planPath != "" {
		planPaths = append(planPaths, opts.planPath)
	}
	planPaths = append(planPaths, opts.extraPlanPaths...)
	if len(planPaths) > 0 {
		if contents, err = appendTyped(contents, claims, baseDir, planPaths, "plan", "hdf-plan", "plan"); err != nil {
			return err
		}
	}

	// Optional: baselines
	if contents, err = appendTyped(contents, claims, baseDir, opts.baselinePaths, "baseline", "hdf-baseline", "baseline"); err != nil {
		return err
	}

	// Optional: BOMs. Deliberately NOT fingerprint-checked. A BOM is not one of
	// the eight HDF document types, and hdfengine.Detect falls to `components`
	// after five more specific keys — so a CycloneDX document, whose primary field
	// that is, gets filed as an HDF system and a guard here would reject real
	// SBOMs. The schema carries a BOM's kind in the referenced document's own
	// bomType, not in the Content_Type.
	for _, bp := range opts.bomPaths {
		if aerr := addEntry("bom", bp); aerr != nil {
			return aerr
		}
	}

	// Optional: amendments and comparisons, fingerprint-checked like --plan and
	// --baseline. verify reads contents[].type to judge completeness, so filing a
	// document under the wrong type yields a confident wrong verdict, not an error.
	if contents, err = appendTyped(contents, claims, baseDir, opts.amendmentsPaths, "amendments", "hdf-amendments", "amendments"); err != nil {
		return err
	}
	if contents, err = appendTyped(contents, claims, baseDir, opts.comparisonPaths, "comparison", "hdf-comparison", "comparison"); err != nil {
		return err
	}

	// Reachable only through --from-dir: the flag path requires a results document, so
	// a package with nothing in it can only come from a scan that found nothing.
	// contents[] has minItems 1, so this would otherwise surface as "failed validation
	// before write", blaming the package for an empty directory.
	if len(contents) == 0 {
		return fmt.Errorf("--from-dir %s contains no HDF documents; there is nothing to record",
			opts.fromDir)
	}

	// Extract system name for package name. A package recording no system has no name to
	// take: "unnamed-system" would assert a system exists and is merely nameless.
	var sysDoc map[string]interface{}
	pkgName := systemlessPackageName
	if opts.systemPath != "" {
		sysData, readErr := readInputFile(opts.systemPath)
		if readErr != nil {
			return fmt.Errorf("failed to re-read system file: %w", readErr)
		}
		var loadErr error
		sysDoc, loadErr = loadAndValidateHDFDoc(sysData, "system")
		if loadErr != nil {
			return fmt.Errorf("system file %s: %w", opts.systemPath, loadErr)
		}
		sysName, _ := sysDoc["name"].(string)
		if sysName == "" {
			sysName = "unnamed-system"
		}
		pkgName = sysName + "-evidence-package"
	}

	// Compute completeness check from all results
	completeness := completenessForPackage(sysDoc, opts.systemPath != "", opts.resultsPaths)

	pkg := map[string]interface{}{
		"name":              pkgName,
		"preparedAt":        time.Now().UTC().Format(time.RFC3339),
		"contents":          contents,
		"completenessCheck": completeness,
	}
	if opts.systemPath != "" {
		pkg["systemRef"] = mustRef(baseDir, opts.systemPath)
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

	if opts.systemPath == "" {
		fmt.Fprintf(os.Stderr,
			"Note: no --system was given, so this package records no systemRef and asserts no "+
				"system — it stands for the documents it lists and nothing more. Its completeness "+
				"check claims neither full baseline coverage nor component coverage, because there "+
				"is no system document to check against, and the package is named %q. "+
				"`hdf evidence set --system-ref` records a system later, and `--name` names the "+
				"package.\n", systemlessPackageName)
	}

	if opts.outputPath == "" {
		fmt.Println(string(output))
		return nil
	}

	if err := atomicfile.WriteFile(opts.outputPath, output, 0o600); err != nil {
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
	_, raw, err := readInputFileAndRaw(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file %s: %w", docType, filePath, err)
	}
	// The bytes on disk, which is what verification re-reads and what bundle archives.
	return contentEntryFromBytes(docType, ref, raw), nil
}

// contentEntryFromBytes is buildContentEntry's body for a caller that has
// already read the file. Shared, not forked: both paths produce the same entry.
func contentEntryFromBytes(docType, ref string, data []byte) map[string]interface{} {
	// Through the engine so the algorithm build RECORDS is the one it computed with, and
	// so build cannot drift from what verification can check. The error is unreachable
	// for evidenceComputedAlgorithm, which this build computes by construction; if that
	// constant ever names something it cannot, an empty value is better than a digest
	// under the wrong name.
	value, algorithm, err := computeEvidenceDigest(data)
	entry := map[string]interface{}{"type": docType, "uri": ref}
	if err == nil {
		entry["checksum"] = map[string]interface{}{"algorithm": algorithm, "value": value}
	}
	return entry
}

// systemlessPackageName is the name of a package that records no system. It describes
// what the document is and asserts nothing further; `hdf evidence set --name` replaces it.
const systemlessPackageName = "evidence-package"

// completenessForPackage is computeCompleteness plus the one rule that must not differ
// between `build` and `update`: with no system document, nothing was available to check
// the results against, so the claim is not made. computeCompleteness reads
// allBaselinesAssessed off the results alone, which would mint it from nothing.
func completenessForPackage(sysDoc map[string]interface{}, haveSystem bool, resultsPaths []string) map[string]interface{} {
	cc := computeCompleteness(sysDoc, resultsPaths)
	if !haveSystem {
		cc["allBaselinesAssessed"] = false
	}
	return cc
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
