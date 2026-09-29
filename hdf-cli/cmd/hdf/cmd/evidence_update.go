package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/spf13/cobra"
)

type evidenceUpdateOpts struct {
	resultsPaths []string
	outputPath   string
	overwrite    bool
	dryRun       bool
}

func newEvidenceUpdateCmd() *cobra.Command {
	var opts evidenceUpdateOpts

	cmd := &cobra.Command{
		Use:   "update <package> --results <doc>... (-o <out> | --overwrite | --dry-run)",
		Short: "Record newer results in an existing evidence package, keeping its identity and history",
		Long: `Read an evidence package back, record this run's results, recompute the completeness
check, and keep everything the package already carried: packageId, name, description,
planRef, and every external evidence and reference already attached.

The package ACCUMULATES. A results document is replaced only when it sits at the same
contents[] reference — the same slot, a file refreshed in place. A document at any
other path is ADDED, even when it covers a baseline the package already covers,
because a baseline is a set of requirements that can apply to many components, so one
baseline appearing twice is normal rather than a collision. No results entry is ever
removed: the package is meant to hold the scan history, which is what makes a trend over
time tellable. A --results document whose reference is already held by an entry of a
DIFFERENT type is refused rather than retyped.

References are compared after normalisation on BOTH sides — the path given and the one
already recorded — so ./scans/x.json and scans/../scans/x.json name the same entry whichever
side they appear on. An absolute path GIVEN on the command line resolves to its
package-relative form too; an absolute path already RECORDED in the package does not, because
such a reference is out of contract and 'hdf evidence verify' refuses it outright.

Two scans covering one baseline are told apart by their own content — a results
document's timestamp and the components it targeted. Both are optional in HDF, so when
they are absent this says so rather than implying the entries are distinguishable.

An evidence package is an attestation, so this never silently rewrites one: name the
package to write with -o, or pass --overwrite to replace the input deliberately.

Examples:
  hdf evidence update boe.json --results scans/q4.json -o boe-q4.json
  hdf evidence update boe.json --results "scans/*.json" --overwrite
  hdf evidence update boe.json --results scans/q4.json --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceUpdate(args[0], opts)
		},
	}

	cmd.Flags().StringArrayVar(&opts.resultsPaths, "results", nil,
		"Results document(s) to record (repeatable, supports globs)")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "Package to write")
	cmd.Flags().BoolVar(&opts.overwrite, "overwrite", false,
		"Replace the input package deliberately, instead of writing a new one with -o")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false,
		"Report what would change and write nothing")

	return cmd
}

// updateTarget resolves where the updated package is written. An evidence package is an
// attestation, so neither flag means refuse rather than overwrite by default — the
// opposite of add-evidence and add-reference, which only ever append.
func updateTarget(pkgPath string, opts evidenceUpdateOpts) (string, error) {
	// Contradictory flags are misuse whether or not anything is written.
	if opts.outputPath != "" && opts.overwrite {
		return "", fmt.Errorf("-o and --overwrite both name where to write; pass one")
	}
	switch {
	case opts.outputPath != "":
		return opts.outputPath, nil
	case opts.overwrite:
		return pkgPath, nil
	case opts.dryRun:
		// A dry run writes nothing, so it need not name a destination. Requiring one made
		// this command's own documented --dry-run example fail.
		return "", nil
	default:
		return "", fmt.Errorf("an evidence package is an attestation and this would rewrite one: "+
			"name the package to write with -o, or pass --overwrite to replace %s deliberately", pkgPath)
	}
}

func runEvidenceUpdate(pkgPath string, opts evidenceUpdateOpts) error {
	resultsPaths, err := expandGlobs(opts.resultsPaths)
	if err != nil {
		return err
	}
	if len(resultsPaths) == 0 {
		return fmt.Errorf("--results is required: name the results document(s) to record")
	}
	// Resolved before any work, so a missing destination is not discovered after every
	// read and hash.
	// Resolved even for a dry run: a contradiction between -o and --overwrite is misuse
	// whether or not anything is written, and a dry run that accepts flags the real run
	// rejects is not a preview of it.
	target, err := updateTarget(pkgPath, opts)
	if err != nil {
		return err
	}

	pkgData, err := readInputFile(pkgPath)
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}
	doc, err := loadAndValidateHDFDoc(pkgData, "evidence-package")
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}
	pkgDir := filepath.Dir(pkgPath)

	contents, _ := doc["contents"].([]interface{})
	coveredBefore := baselinesByRef(pkgDir, contents)

	// ref -> source path, built once as the refs are derived. Recomputing them later to
	// build a lookup map would be a second derivation of the same value, which is exactly
	// what let a checksum check silently miss in card .4.
	sourceOf := map[string]string{}
	seen := map[string]struct{}{}
	var replaced, added []string
	for _, path := range resultsPaths {
		ref, refErr := packageRelativeRef(pkgDir, path)
		if refErr != nil {
			return refErr
		}
		// Named twice in one invocation. Reported as that, not as a replacement: the
		// second pass would otherwise find the first pass's own append and call it
		// "refreshed in place", which is false — the ref was not in the package when the
		// command started.
		if _, dup := seen[ref]; dup {
			fmt.Fprintf(os.Stderr, "  %s named more than once; recorded once\n", ref)
			continue
		}
		seen[ref] = struct{}{}

		data, readErr := readInputFile(path)
		if readErr != nil {
			return fmt.Errorf("failed to read --results file %s: %w", path, readErr)
		}
		// Fingerprinted, not taken on the flag's word. The type was hardcoded from the
		// flag name, so --results on a system document filed it as results — weaker than
		// the filename guess this repo already forbids, and `evidence verify` reads these
		// types to judge completeness, so a mistyped entry yields a confident wrong verdict.
		if err := requireDetectedType(data, path, "results", "results"); err != nil {
			return err
		}

		sourceOf[ref] = path
		i, conflictType := indexOfResultsRef(contents, ref)
		if conflictType != "" {
			return fmt.Errorf("%s is already recorded in this package with type %s; "+
				"update replaces a results entry in place and will not retype an existing one — "+
				"remove that entry first if it really is results now", ref, conflictType)
		}
		entry := contentEntryFromBytes("hdf-results", ref, data)
		if i >= 0 {
			contents[i] = entry
			replaced = append(replaced, ref)
			continue
		}
		contents = append(contents, entry)
		added = append(added, ref)
		// Recorded as we go, so a second same-baseline scan added in the SAME invocation is
		// reported too. A snapshot taken before the loop said nothing about them, which is
		// exactly the documented pipeline shape: --results "scans/*.json".
		if names, nameErr := hdfengine.CoveredBaselineNames(data); nameErr == nil {
			coveredBefore[ref] = names
		}
	}
	doc["contents"] = contents

	// Recomputed from the POST-update content, never carried forward: a package that
	// claims coverage it no longer has is worse than one that fails validation. Reuses
	// build's computeCompleteness rather than a second implementation of it.
	sysDoc, haveSystem, sysErr := systemDocForPackage(pkgDir, doc)
	if sysErr != nil {
		return sysErr
	}
	allResults, resErr := resultsPathsInPackage(pkgDir, contents)
	if resErr != nil {
		return resErr
	}
	completeness := computeCompleteness(sysDoc, allResults)
	if !haveSystem {
		// Nothing was available to check against, so "all baselines assessed" would be a
		// claim minted from no system document at all.
		completeness["allBaselinesAssessed"] = false
		fmt.Fprintf(os.Stderr, "  no system document resolved; completeness cannot claim full baseline coverage\n")
	}
	doc["completenessCheck"] = completeness
	doc["preparedAt"] = time.Now().UTC().Format(time.RFC3339)

	reportUpdate(replaced, added, coveredBefore, sourceOf)

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize evidence package: %w", err)
	}
	// Validated before the dry-run exit, so a dry run cannot report a change the real
	// run would refuse.
	if err := validateHDFDocument(output); err != nil {
		return fmt.Errorf("evidence package failed validation before write: %w", err)
	}
	if opts.dryRun {
		fmt.Fprintf(os.Stderr, "Dry run: nothing written.\n")
		return nil
	}
	if err := os.WriteFile(target, output, 0o600); err != nil {
		return fmt.Errorf("failed to write evidence package: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Updated %s\n", target)
	return nil
}

// normalizedRef puts a reference in the form packageRelativeRef produces, so a stored uri
// and an incoming one are compared on equal terms. Normalising only the incoming side left
// a stored "./scans/x.json" invisible to both the replacement match and the type-conflict
// guard: the same file could be declared twice under different types, and a genuine refresh
// added a second entry while the first kept a stale checksum, so the package failed its own
// `evidence verify`.
func normalizedRef(uri string) string {
	if uri == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(uri))
}

// indexOfResultsRef finds the hdf-results entry at a reference, or -1. It additionally
// reports the type of an entry holding that reference under ANOTHER type, so the caller
// can refuse rather than overwrite it: matching on uri alone let --results on a system
// document destroy the package's only hdf-system entry and re-type it, which schema
// validation accepts in silence.
//
// The reference is the only replacement key. Keying on baseline name would delete one
// component's evidence when another component assessed against the same baseline is
// recorded.
func indexOfResultsRef(contents []interface{}, ref string) (int, string) {
	for i, e := range contents {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		uri, _ := entry["uri"].(string)
		if normalizedRef(uri) != normalizedRef(ref) {
			continue
		}
		docType, _ := entry["type"].(string)
		if docType == "hdf-results" {
			return i, ""
		}
		return -1, docType
	}
	return -1, ""
}

// baselinesByRef maps each results reference to the baselines it covers, for reporting
// which incoming document lands beside an existing one.
func baselinesByRef(pkgDir string, contents []interface{}) map[string][]string {
	covered := map[string][]string{}
	for _, e := range contents {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if docType, _ := entry["type"].(string); docType != "hdf-results" {
			continue
		}
		uri, _ := entry["uri"].(string)
		if uri == "" {
			continue
		}
		path, err := hdfutil.SafePath(pkgDir, uri)
		if err != nil {
			continue
		}
		data, err := readFromFile(path, true)
		if err != nil {
			continue
		}
		names, err := hdfengine.CoveredBaselineNames(data)
		if err != nil {
			continue
		}
		covered[uri] = names
	}
	return covered
}

// resultsPathsInPackage resolves every results reference to a readable path, for
// recomputing completeness over the post-update content.
func resultsPathsInPackage(pkgDir string, contents []interface{}) ([]string, error) {
	paths := make([]string, 0, len(contents))
	for _, e := range contents {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		// Load-bearing, not defence in depth: computeCompleteness counts any document
		// carrying a top-level baselines array, so a bom entry pointing at such JSON would
		// mint the green verdict this command otherwise refuses to mint. It also keeps a
		// non-results entry's uri from being resolved at all, so an escaping one is left to
		// `evidence verify` rather than failing an update that has nothing to do with it.
		if docType, _ := entry["type"].(string); docType != "hdf-results" {
			continue
		}
		uri, _ := entry["uri"].(string)
		if uri == "" {
			continue
		}
		path, err := hdfutil.SafePath(pkgDir, uri)
		if err != nil {
			return nil, fmt.Errorf("results reference %q cannot be resolved: %w", uri, err)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// systemDocForPackage reads the system document the package references, so completeness
// can be recomputed against it. It reports whether a document was actually resolved,
// because computeCompleteness does NOT treat an empty system document as "nothing to
// check against": it sets allBaselinesAssessed from the results alone, so an unresolvable
// systemRef would mint a green verdict from nothing. systemRef is optional in the schema,
// and a remote one is never fetched, so both cases are reachable on valid input.
func systemDocForPackage(pkgDir string, doc map[string]interface{}) (map[string]interface{}, bool, error) {
	ref, _ := doc["systemRef"].(string)
	if ref == "" || isRemoteURI(ref) {
		return map[string]interface{}{}, false, nil
	}
	path, err := hdfutil.SafePath(pkgDir, ref)
	if err != nil {
		return nil, false, fmt.Errorf("systemRef %q cannot be resolved: %w", ref, err)
	}
	data, err := readFromFile(path, true)
	if err != nil {
		return nil, false, fmt.Errorf("systemRef %q is referenced but could not be read: %w", ref, err)
	}
	var sysDoc map[string]interface{}
	if err := json.Unmarshal(data, &sysDoc); err != nil {
		return nil, false, fmt.Errorf("systemRef %q is not readable JSON: %w", ref, err)
	}
	return sysDoc, true, nil
}

// reportUpdate says what changed, and for an added document covering a baseline the
// package already covered, what distinguishes the two. A results document's timestamp
// and components are both OPTIONAL in HDF, so their absence is stated rather than
// papered over — two indistinguishable scans are still both retained.
func reportUpdate(replaced, added []string, coveredBefore map[string][]string, sourceOf map[string]string) {
	for _, ref := range replaced {
		fmt.Fprintf(os.Stderr, "  replaced %s (same reference, refreshed in place)\n", ref)
	}
	for _, ref := range added {
		fmt.Fprintf(os.Stderr, "  added %s\n", ref)
		overlap := overlappingBaselines(ref, sourceOf[ref], coveredBefore)
		if len(overlap) == 0 {
			continue
		}
		fmt.Fprintf(os.Stderr, "    also covered by an existing entry: %s\n", strings.Join(overlap, ", "))
		fmt.Fprintf(os.Stderr, "    both are kept — %s\n", distinguishingFacts(sourceOf[ref]))
	}
}

// overlappingBaselines names the baselines an incoming document shares with OTHER entries —
// those the package already held, plus any added earlier in this same invocation.
func overlappingBaselines(selfRef, path string, coveredBefore map[string][]string) []string {
	if path == "" {
		return nil
	}
	data, err := readFromFile(path, true)
	if err != nil {
		return nil
	}
	incoming, err := hdfengine.CoveredBaselineNames(data)
	if err != nil {
		return nil
	}
	existing := map[string]struct{}{}
	for ref, names := range coveredBefore {
		// An entry does not overlap itself. Added entries are recorded in this map so two
		// documents in one invocation are compared, which put each entry's own baselines in
		// the union and made every new scan report overlapping "an existing entry".
		if ref == selfRef {
			continue
		}
		for _, n := range names {
			existing[n] = struct{}{}
		}
	}
	var shared []string
	for _, n := range incoming {
		if _, ok := existing[n]; ok {
			shared = append(shared, n)
		}
	}
	sort.Strings(shared)
	return shared
}

// distinguishingFacts reports the timestamp and targeted components a reader can use to
// tell two scans of one baseline apart, naming whichever is absent.
func distinguishingFacts(path string) string {
	data, err := readFromFile(path, true)
	if err != nil {
		return "this document could not be read to say what distinguishes them"
	}
	// Read through the generated type, as hdf-engine's merge does, so these two fields
	// cannot drift from the schema the way a local anonymous struct would.
	var res hdf.HDFResults
	if json.Unmarshal(data, &res) != nil {
		return "this document could not be read to say what distinguishes them"
	}
	var facts []string
	if res.Timestamp != nil {
		facts = append(facts, "assessed "+res.Timestamp.UTC().Format(time.RFC3339))
	} else {
		facts = append(facts, "no timestamp recorded")
	}
	names := make([]string, 0, len(res.Components))
	for _, c := range res.Components {
		if c.Name != "" {
			names = append(names, c.Name)
		}
	}
	if len(names) > 0 {
		facts = append(facts, "targets "+strings.Join(names, ", "))
	} else {
		facts = append(facts, "no target components recorded")
	}
	return strings.Join(facts, "; ")
}
