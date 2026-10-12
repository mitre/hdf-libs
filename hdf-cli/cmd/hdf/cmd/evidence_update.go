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
	"golang.org/x/text/unicode/norm"
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
such a reference is out of contract and 'hdf evidence info --verify' refuses it outright.

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
	// Pairs of (stored spelling, the spelling given on the command line) that are one name
	// written differently — case, Unicode normalization, or both — and name one file here.
	var spelledDifferently [][2]string
	// Pairs of (count, reference) where more than one recorded entry named one file.
	var multiRef [][2]string
	for _, path := range resultsPaths {
		ref, refErr := packageRelativeRef(pkgDir, path)
		if refErr != nil {
			return refErr
		}
		// Named twice in one invocation. Reported as that, not as a replacement: the
		// second pass would otherwise find the first pass's own append and call it
		// "refreshed in place", which is false — the ref was not in the package when the
		// command started.
		//
		// Keyed on the file, not on the reference string: two spellings of one name evaded
		// a string key, so the same entry was reported twice and an entry THIS run appended
		// was reported as refreshed in place — exactly the falsehood described above.
		dupKey := ref
		for prior := range seen {
			if sameNameDifferentSpelling(normalizedRef(prior), normalizedRef(ref)) &&
				samePath(refPath(pkgDir, prior), refPath(pkgDir, ref)) {
				dupKey = prior
				break
			}
		}
		if _, dup := seen[dupKey]; dup {
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
		// the filename guess this repo already forbids, and `evidence info --verify` reads
		// these types to judge completeness, so a mistyped entry yields a confident wrong verdict.
		if err := requireDetectedType(data, path, "results", "results"); err != nil {
			return err
		}

		sourceOf[ref] = path
		matched, conflictType, conflictRef, storedSpellings := indexesOfResultsRef(pkgDir, contents, ref)
		if conflictType != "" {
			// Names the STORED spelling, which is the entry the operator has to find and
			// remove. Naming the incoming spelling told them to remove a reference that does
			// not appear in their package, because a conflict can be reached by a spelling
			// that merely names the same file.
			return fmt.Errorf("%s is already recorded in this package with type %s; "+
				"update replaces a results entry in place and will not retype an existing one — "+
				"remove that entry first if it really is results now", conflictRef, conflictType)
		}
		for _, stored := range storedSpellings {
			spelledDifferently = append(spelledDifferently, [2]string{stored, ref})
		}
		if len(matched) > 0 {
			// Each matched entry keeps ITS OWN recorded spelling and gains the fresh
			// checksum: a recorded reference is part of an attestation and is not rewritten
			// silently, so the stored form survives and the difference is reported instead.
			for _, i := range matched {
				existing, _ := contents[i].(map[string]interface{})
				uri, _ := existing["uri"].(string)
				contents[i] = contentEntryFromBytes("hdf-results", uri, data)
				replaced = append(replaced, uri)
			}
			if len(matched) > 1 {
				multiRef = append(multiRef, [2]string{fmt.Sprint(len(matched)), ref})
			}
			continue
		}
		contents = append(contents, contentEntryFromBytes("hdf-results", ref, data))
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
	sysDoc, haveSystem, unresolvedRef, sysErr := systemDocForPackage(pkgDir, doc)
	if sysErr != nil {
		return sysErr
	}
	allResults, resErr := resultsPathsInPackage(pkgDir, contents)
	if resErr != nil {
		return resErr
	}
	// Through build's completenessForPackage, so the "no system document means no
	// coverage claim" rule has one definition: a package built without a system and a
	// package whose systemRef stopped resolving must describe themselves the same way.
	completeness := completenessForPackage(sysDoc, haveSystem, allResults)
	if !haveSystem {
		if unresolvedRef != "" {
			// Named, because a systemRef the package RECORDS and this run rejected is a
			// different situation from one it never recorded, and the two used to be
			// indistinguishable on stderr.
			fmt.Fprintf(os.Stderr, "  systemRef %s does not resolve inside the package's directory; "+
				"completeness cannot claim full baseline coverage\n", sanitizeOutput(unresolvedRef))
		} else {
			fmt.Fprintf(os.Stderr, "  no system document resolved; completeness cannot claim full baseline coverage\n")
		}
	}
	doc["completenessCheck"] = completeness
	doc["preparedAt"] = time.Now().UTC().Format(time.RFC3339)

	reportUpdate(replaced, added, spelledDifferently, multiRef, coveredBefore, sourceOf)

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
// verification.
func normalizedRef(uri string) string {
	if uri == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(uri))
}

// indexesOfResultsRef finds EVERY hdf-results entry naming a reference's file. It additionally
// reports the type, and the stored spelling, of an entry holding that reference under ANOTHER
// type, so the caller can refuse rather than overwrite it: matching on uri alone let --results
// on a system document destroy the package's only hdf-system entry and re-type it, which
// schema validation accepts in silence.
//
// The reference is the only replacement key. Keying on baseline name would delete one
// component's evidence when another component assessed against the same baseline is
// recorded.
func indexesOfResultsRef(pkgDir string, contents []interface{}, ref string) ([]int, string, string, []string) {
	wantNorm := normalizedRef(ref)
	wantPath := refPath(pkgDir, ref)
	var matched []int
	var storedSpellings []string
	for i, e := range contents {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		uri, _ := entry["uri"].(string)
		norm := normalizedRef(uri)
		exact := norm == wantNorm
		// Narrowed to ONE NAME SPELLED DIFFERENTLY — a case difference, a Unicode
		// normalization difference, or both. samePath compares inodes, so on its own it also
		// matches a hardlink and an absolute-versus-relative spelling of one file; those are
		// two NAMES for one file and merging them is a separate decision, deliberately not
		// taken here. samePath is still what decides, so on a case-sensitive filesystem the
		// two spellings are different files and nothing matches.
		sameName := !exact && sameNameDifferentSpelling(norm, wantNorm) &&
			samePath(wantPath, refPath(pkgDir, uri))
		if !exact && !sameName {
			continue
		}
		if docType, _ := entry["type"].(string); docType != "hdf-results" {
			return nil, docType, uri, nil
		}
		// EVERY entry naming the file, not just the first: a package the previous release
		// wrote can hold two, and refreshing one left the other with a stale checksum, so
		// update exited 0 reporting "refreshed in place" while verify exited 1.
		matched = append(matched, i)
		if sameName {
			storedSpellings = append(storedSpellings, uri)
		}
	}
	return matched, "", "", storedSpellings
}

// sameNameDifferentSpelling reports whether two references are the SAME NAME written
// differently — a case difference, a Unicode normalization difference, or both.
//
// Normalization is folded as well as case because NFC and NFD are one name in two
// encodings, and on macOS that split is routine: readdir and extracted archives yield NFD
// while shell completion yields NFC, and `build` records whichever it was handed. A
// case-fold alone left those unmatched — strings.EqualFold("café" NFC, "café" NFD) is
// false — which appended a duplicate and so reopened the stale-checksum failure this card
// exists to close, for a filesystem that os.SameFile says holds one file.
//
// Deliberately NOT a general identity test: a hardlink and an absolute-versus-relative
// spelling are two NAMES for one file, and merging those is a separate decision. samePath
// still decides, so on a case-sensitive filesystem two spellings are different files and
// nothing matches.
func sameNameDifferentSpelling(a, b string) bool {
	return strings.EqualFold(norm.NFC.String(a), norm.NFC.String(b))
}

// refPath is where a recorded reference points, for IDENTITY COMPARISON ONLY — never for
// reading, which goes through the confined resolution in add-evidence. A relative
// reference is package-relative, matching what bundle and verify resolve; anything else
// stands as recorded so samePath's lexical fallback can still compare it.
func refPath(pkgDir, uri string) string {
	if uri == "" || isRemoteURI(uri) || filepath.IsAbs(uri) {
		return uri
	}
	return filepath.Join(pkgDir, filepath.FromSlash(uri))
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
		// Classified first: SafePath JOINS, so a root-anchored reference re-roots onto a
		// same-basename file inside the package and this scan would credit coverage to a
		// document the package never named.
		ref, inTree := packageSubtreeRef(pkgDir, uri)
		if !inTree {
			continue
		}
		path, err := hdfutil.SafePath(pkgDir, ref)
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
		// `evidence info --verify` rather than failing an update that has nothing to do with it.
		if docType, _ := entry["type"].(string); docType != "hdf-results" {
			continue
		}
		uri, _ := entry["uri"].(string)
		if uri == "" {
			continue
		}
		ref, inTree := packageSubtreeRef(pkgDir, uri)
		if !inTree {
			return nil, fmt.Errorf("results reference %q cannot be resolved: it is outside the package's "+
				"directory", uri)
		}
		path, err := hdfutil.SafePath(pkgDir, ref)
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
//
// A MIS-resolved systemRef is worse than an unresolvable one and was the live defect:
// SafePath JOINS, so a root-anchored "/system.json" re-rooted to <pkgDir>/system.json
// and the reference RESOLVED — to a document it did not name — and completeness was
// asserted from it, so the verdict looked earned. Classified through the same predicate
// verify and bundle use, a reference that does not resolve inside the package is reported
// as unresolved rather than substituted.
// unresolvedSystemRef names a systemRef the package records but this run could not
// resolve, empty when there was nothing to resolve. It exists so the caller can print
// the reference: returning only "no system document" made a REJECTED systemRef
// indistinguishable from one the package never recorded, and a rejected one used to
// abort the run by name. A remote systemRef is still reported as no system document,
// since it is recorded but was never a candidate to resolve.
func systemDocForPackage(pkgDir string, doc map[string]interface{}) (map[string]interface{}, bool, string, error) {
	ref, _ := doc["systemRef"].(string)
	if ref == "" || isRemoteURI(ref) {
		return map[string]interface{}{}, false, "", nil
	}
	resolved, inTree := packageSubtreeRef(pkgDir, ref)
	if !inTree {
		return map[string]interface{}{}, false, ref, nil
	}
	path, err := hdfutil.SafePath(pkgDir, resolved)
	if err != nil {
		return nil, false, "", fmt.Errorf("systemRef %q cannot be resolved: %w", ref, err)
	}
	data, err := readFromFile(path, true)
	if err != nil {
		return nil, false, "", fmt.Errorf("systemRef %q is referenced but could not be read: %w", ref, err)
	}
	var sysDoc map[string]interface{}
	if err := json.Unmarshal(data, &sysDoc); err != nil {
		return nil, false, "", fmt.Errorf("systemRef %q is not readable JSON: %w", ref, err)
	}
	return sysDoc, true, "", nil
}

// reportUpdate says what changed, and for an added document covering a baseline the
// package already covered, what distinguishes the two. A results document's timestamp
// and components are both OPTIONAL in HDF, so their absence is stated rather than
// papered over — two indistinguishable scans are still both retained.
func reportUpdate(replaced, added []string, spelledDifferently, multiRef [][2]string, coveredBefore map[string][]string, sourceOf map[string]string) {
	// Reported BEFORE the per-reference lines, so the explanation precedes the line it
	// explains: the entry was refreshed under the spelling the package already records.
	// Which of the two spellings names the file on a filesystem that distinguishes them is
	// not known here, so neither is described as the one on disk — the operator may have
	// mistyped the command line, in which case the recorded reference is the correct one.
	for _, pair := range spelledDifferently {
		fmt.Fprintf(os.Stderr, "  note: the recorded spelling %s and the spelling you gave %s are "+
			"one name written differently (case or Unicode normalization); they name one file on "+
			"this filesystem, so the entry was refreshed in place and the reference was left as "+
			"recorded\n", sanitizeOutput(pair[0]), sanitizeOutput(pair[1]))
	}
	for _, pair := range multiRef {
		fmt.Fprintf(os.Stderr, "  note: %s recorded references name one file (%s); all were refreshed\n",
			pair[0], sanitizeOutput(pair[1]))
	}
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
