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
	var checksumsOnly, requireReachable, requireChecksumsMatch bool

	cmd := &cobra.Command{
		Use:   "verify <package-file>",
		Short: "Verify an evidence package against its assessment plan",
		Long: `Verify an HDF evidence package. By default, checks completeness:
every baseline in the referenced plan must have a corresponding results
document in the evidence package.

Use --checksums-only to skip completeness checking and only verify the
checksums of referenced files, each under the algorithm its entry records.

A package may reference artifacts it does not contain — an absolute local
path, a parent traversal, or a URI on another system. Carrying copies is
expected but not required, so a reference this machine cannot reach is
reported and skipped, not treated as a malformed package. A planned baseline
whose only results document is unreachable counts as NOT covered, so
completeness never credits a document that was not read. --require-reachable turns that into a
failure: an assessor accepting a package as the evidence of record may need
it self-contained, but demanding that by default would reject the external
references the format supports deliberately.

Checksums are verified in BOTH arrays the package records them in — contents[]
and externalEvidence[] — because a package is as intact as its weakest recorded
claim, and 'hdf evidence bundle' already refused a package over an
externalEvidence mismatch that this command passed.

A mismatch fails the command. --require-checksums-match=false reports one
without failing, for a pipeline that must proceed past known drift; the
mismatch is still named and counted, so nothing goes quiet. That flag defaults
to TRUE, unlike --require-reachable, because a mismatch already failed before
the flag existed and a false default would have loosened that rather than
added a valve. It governs an entry that WAS verified and disagreed, which is a
different question from one that records no checksum to verify at all — that
entry is reported as skipped and does not fail.

If the evidence package has no planRef, falls back to checksum
verification with a warning.

Examples:
  hdf evidence verify package.json
  hdf evidence verify package.json --checksums-only
  hdf evidence verify package.json --require-reachable
  hdf evidence verify package.json --require-checksums-match=false
  hdf evidence verify package.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEvidenceVerify(args[0], checksumsOnly, requireReachable, requireChecksumsMatch)
		},
	}

	cmd.Flags().BoolVar(&checksumsOnly, "checksums-only", false, "Only verify file checksums, skip completeness checking")
	cmd.Flags().BoolVar(&requireReachable, "require-reachable", false,
		"Fail if the package records a reference this machine cannot resolve")
	// The true here is the real default — and it is the OPPOSITE of the other
	// --require-* flags, deliberately. A contents[] mismatch already failed before
	// this flag existed, so defaulting it false would not add a valve: it would
	// quietly stop a tampered document from failing. Three pre-existing tests depend
	// on that, which is what makes the inversion measurable rather than a matter of
	// taste.
	cmd.Flags().BoolVar(&requireChecksumsMatch, "require-checksums-match", true,
		"Fail if a checksum this run could compute disagrees with the file; "+
			"pass =false to report a mismatch without failing")

	return cmd
}

// Verification status constants.
const (
	verifyMatch    = "match"
	verifyMismatch = "mismatch"
	verifySkipped  = "skipped"
	verifyError    = "error"
	// verifyUnsupported mirrors the engine's own status: a recorded algorithm this
	// build cannot compute. Reported and counted, never fatal by default — the bytes
	// may be intact, and a digest we cannot compute is the same kind of claim as a
	// reference we cannot reach.
	verifyUnsupported = "unsupported"
	// verifyUnreachable is a CLI-level status, deliberately not an engine one: the
	// engine classifies what it could hash, and whether a reference resolves on THIS
	// machine is the adapter's question. Keeping it here also avoids adding a value
	// to a vocabulary whose consumers ignore statuses they do not know.
	verifyUnreachable = "unreachable"
)

// evidenceVerifyResult holds per-document verification status.
type evidenceVerifyResult struct {
	URI  string `json:"uri"`
	Type string `json:"type"`
	// Field is the array the entry came from: "contents" or "externalEvidence". The
	// two record different things — a Content_Type against a native Native_Format —
	// so Type stays empty for an external entry rather than carrying "raw-log" in a
	// field whose vocabulary is the seven document types. A reader needs to know
	// which array a line is about: a mismatch in contents[] is a document the
	// package carries, one in externalEvidence[] an artifact held elsewhere.
	Field  string `json:"field"`
	Format string `json:"format,omitempty"`
	// Algorithm is what the entry was verified with, not a fixed sha256: the
	// package chooses, and the human output names it, so the line cannot claim an
	// algorithm that was not used.
	Algorithm string `json:"algorithm,omitempty"`
	Status    string `json:"status"` // "match", "mismatch", "skipped", "error"
	Expected  string `json:"expected,omitempty"`
	Actual    string `json:"actual,omitempty"`
	Error     string `json:"error,omitempty"`
}

type verifyCounts struct {
	match       int
	mismatch    int
	skipped     int
	errors      int
	unreachable int
	unsupported int
}

func runEvidenceVerify(pkgPath string, checksumsOnly, requireReachable, requireChecksumsMatch bool) error {
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

	// Classify EVERY reference the package records, deriving them from the one place
	// that knows all five fields rather than re-enumerating them here — the
	// hand-enumeration this replaces covered planRef and contents[] only, so an
	// absolute systemRef was never examined at all. This cannot ride along with
	// checksum verification: an entry carrying no checksum is skipped there, so a
	// reference on such an entry would never be looked at.
	external, err := hdfengine.ParseExternalEvidence(data)
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}
	recorded, err := recordedRefs(data, contents)
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}
	refStatus := classifyReferences(pkgDir, recorded)
	resolvedBy := make(map[string]string, len(refStatus))
	unreachableBy := make(map[string]string, len(refStatus))
	for _, st := range refStatus {
		if st.Reachable {
			resolvedBy[st.Recorded] = st.resolved
		} else {
			unreachableBy[st.Recorded] = st.Reason
		}
	}

	fetch := confinedFetch(pkgDir, resolvedBy)

	// BOTH arrays, through one path. Verifying contents[] alone let a wrong checksum
	// in externalEvidence[] pass at exit 0 while `bundle` refused the same package —
	// the command whose job is verification missing what the packaging command caught.
	results, counts, reachable := verifyRecordedArray(contents, refFieldContents, unreachableBy, fetch)
	extResults, extCounts, _ := verifyRecordedArray(external, refFieldExternal, unreachableBy, fetch)
	results = append(results, extResults...)
	counts.add(extCounts)

	renderVerifyOutput(doc, results, counts, hdfengine.AgentOverridesInPackage(reachable, fetch), refStatus)

	// A fetch error always fails: the package named an artifact this run could not
	// read at all. A MISMATCH is the operator's to govern — it fails by default,
	// which is what contents[] already did, and --require-checksums-match=false is
	// the valve. Tolerated mismatches are still named above and counted in the
	// summary, because a fail-open switch that also goes quiet is how a pipeline
	// passes for months without anyone learning.
	switch {
	case counts.errors > 0 && counts.mismatch > 0 && requireChecksumsMatch:
		return fmt.Errorf("%d checksum mismatches, %d errors", counts.mismatch, counts.errors)
	case counts.errors > 0:
		return fmt.Errorf("%d reference(s) could not be read", counts.errors)
	case counts.mismatch > 0 && requireChecksumsMatch:
		return fmt.Errorf("%d checksum mismatch(es)", counts.mismatch)
	case counts.mismatch > 0:
		fmt.Fprintf(os.Stderr, "Note: %d checksum mismatch(es) tolerated because "+
			"--require-checksums-match=false; the package is NOT intact\n", counts.mismatch)
	}
	if requireReachable && (len(unreachableBy) > 0 || counts.unsupported > 0) {
		// Only what actually happened is named. Reporting "0 references could not be
		// resolved" alongside a real checksum problem reads as noise and invites the
		// operator to look for a reference fault that is not there.
		var why []string
		if n := len(unreachableBy); n > 0 {
			why = append(why, fmt.Sprintf("%d recorded reference(s) could not be resolved", n))
		}
		// RETAINED THOUGH CURRENTLY UNREACHABLE HERE: this build computes every algorithm
		// Hash_Algorithm admits, and validation refuses an off-schema one before any
		// checksum is read, so counts.unsupported cannot rise through this command today.
		// Kept deliberately — if a value is ever added to the enum before the tooling
		// implements it, deleting this would make --require-reachable silently stop
		// failing, which is the fail-open class this command exists to prevent.
		if counts.unsupported > 0 {
			why = append(why, fmt.Sprintf("%d checksum(s) name an algorithm this build cannot compute",
				counts.unsupported))
		}
		return fmt.Errorf("%s; --require-reachable was given", strings.Join(why, " and "))
	}

	// Completeness checking (default behavior unless --checksums-only)
	if checksumsOnly {
		return nil
	}

	if planRef == "" {
		fmt.Fprintf(os.Stderr, "Note: no planRef in evidence package — skipping completeness check\n")
		return nil
	}
	if reason, bad := unreachableBy[planRef]; bad {
		fmt.Fprintf(os.Stderr, "Note: the plan is %s, so completeness was not checked — "+
			"it needs the plan document to read the baselines it requires\n", reason)
		return nil
	}

	return verifyCompleteness(pkgDir, resolvedBy[planRef], contents, resolvedBy)
}

// referenceStatus is one reference the package records, and whether this machine
// can resolve it. Reason is empty exactly when Reachable is true.
type referenceStatus struct {
	Field    string `json:"field"`
	Recorded string `json:"recorded"`
	Reason   string `json:"reason,omitempty"`
	// resolved is the package-relative path to read, unexported because it is this
	// machine's answer and means nothing to a reader of the JSON.
	resolved  string
	Reachable bool `json:"reachable"`
}

// classifyReferences resolves every reference the package records against the
// package's own directory, REPORTING what it cannot reach rather than refusing the
// package. An evidence package may legitimately point at an artifact it does not
// contain — an absolute local path, or a URI on another system; carrying copies is
// expected but never required, so an unresolvable reference is a fact about this
// machine, not a defect in the document.
//
// Resolution goes through packageSubtreeRef, the same predicate `evidence bundle`
// uses to decide what can travel, so the two commands cannot drift apart about what
// a reference means. That predicate is also what keeps the old shape check honest:
// it never hands an absolute or escaping path to SafePath, which would silently
// re-root "/etc/passwd" under the package directory and report on a file the
// reference never named.
//
// externalReferences[] is skipped — those are bare URIs of inert context (advisories,
// CTI) inside referenced documents, never resolved here.
func classifyReferences(pkgDir string, refs []recordedRef) []referenceStatus {
	out := make([]referenceStatus, 0, len(refs))
	for _, r := range refs {
		if r.uri == "" || r.kind == refContext {
			continue
		}
		st := referenceStatus{Field: r.field, Recorded: r.uri}
		switch resolved, ok := packageSubtreeRef(pkgDir, r.uri); {
		case isRemoteURI(r.uri):
			st.Reason = "remote"
		case ok:
			st.resolved, st.Reachable = resolved, true
		default:
			st.Reason = "outside the package's directory"
		}
		out = append(out, st)
	}
	return out
}

// checkContentRefShape refuses the two shapes that cannot name an entry inside an
// archive. It is NOT a judgement on whether a reference is legal — a package may
// record an absolute or remote reference, and both commands accept one. Its single
// caller sanitizes the archive entry name AFTER resolution, which is why the
// messages talk about entry paths rather than about references.
// label names the kind of reference being checked, so a caller applying this rule to
// something other than contents[] does not report it as a content reference. Taking the
// label extends the shared check rather than forking a near-duplicate of it.
func checkContentRefShape(uri, label string) error {
	if i := strings.Index(uri, "://"); i > 0 {
		return fmt.Errorf("%s %q cannot name an archive entry: a remote URI is not a path "+
			"inside the archive, and a recorded remote artifact travels by URI and hash, "+
			"not as a carried file", label, uri)
	}
	if strings.HasPrefix(uri, "/") || filepath.IsAbs(uri) {
		return fmt.Errorf("%s %q cannot name an archive entry: an entry path is relative to "+
			"the archive root", label, uri)
	}
	return nil
}

// confinedFetch returns a FetchFunc that resolves a content URI relative to the
// package directory, confined by SafePath and read through the same size-gated
// boundary as the package itself — a referenced file is untrusted input too.
// SafePath and read failures both surface as errors, which VerifyChecksums
// classifies as an error status.
func confinedFetch(pkgDir string, resolvedBy map[string]string) hdfengine.FetchFunc {
	return func(uri string) ([]byte, error) {
		// The classifier already reduced a recorded reference to a package-relative
		// path; SafePath is handed that, never the raw reference, so an absolute one
		// cannot be silently re-rooted under the package directory.
		target := uri
		if resolved, ok := resolvedBy[uri]; ok {
			target = resolved
		}
		path, err := hdfutil.SafePath(pkgDir, target)
		if err != nil {
			return nil, err
		}
		return readFromFile(path, true)
	}
}

// verifyCompleteness checks that every baseline in the plan has a corresponding
// results document in the package. The planned/covered extraction and the diff
// are the engine's; path confinement and schema-validation warnings stay here.
func verifyCompleteness(pkgDir, planRef string, contents []hdfengine.EvidenceContent,
	resolvedBy map[string]string,
) error {
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
		// The classified resolution, never the raw reference. Handing SafePath the raw
		// URI re-rooted a root-anchored "/results.json" back under the package and
		// credited a baseline from a file the reference never named — while the same run
		// reported that reference as not reachable. An unresolved reference is skipped
		// here because it was already reported; failing on it would also make verify
		// refuse a package bundle accepts, which is the divergence this card closes.
		resultsRef, resolved := resolvedBy[c.URI]
		if !resolved {
			continue
		}
		resultsPath, pathErr := hdfutil.SafePath(pkgDir, resultsRef)
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

// The two arrays a package records checksums in. Named constants rather than
// literals so a reader of a result can match the field to the schema.
const (
	refFieldContents = "contents"
	refFieldExternal = "externalEvidence"
)

// add folds another array's counts in, so the verdict is over the whole package.
func (c *verifyCounts) add(o verifyCounts) {
	c.match += o.match
	c.mismatch += o.mismatch
	c.skipped += o.skipped
	c.errors += o.errors
	c.unreachable += o.unreachable
	c.unsupported += o.unsupported
}

// verifyRecordedArray runs one array of recorded entries through the shared path:
// skip what the classifier could not resolve, hash the rest through the one fetcher,
// and rebuild the per-entry list in the document's own order so a reader can match it
// against the array regardless of what resolved. Both arrays go through here, so
// neither can be verified under a rule the other does not apply — which is exactly
// the divergence that let externalEvidence go unchecked. Returns the reachable
// entries too, for the aggregators that walk results documents.
func verifyRecordedArray(entries []hdfengine.EvidenceContent, field string,
	unreachableBy map[string]string, fetch hdfengine.FetchFunc,
) ([]evidenceVerifyResult, verifyCounts, []hdfengine.EvidenceContent) {
	reachable := make([]hdfengine.EvidenceContent, 0, len(entries))
	for _, c := range entries {
		if _, bad := unreachableBy[c.URI]; !bad {
			reachable = append(reachable, c)
		}
	}
	verified, counts := toVerifyResults(hdfengine.VerifyChecksums(reachable, fetch), field)

	results := make([]evidenceVerifyResult, 0, len(entries))
	next := 0
	for _, c := range entries {
		if reason, bad := unreachableBy[c.URI]; bad {
			results = append(results, evidenceVerifyResult{
				URI: c.URI, Type: c.Type, Format: c.Format, Field: field,
				Status: verifyUnreachable, Error: reason,
			})
			counts.unreachable++
			continue
		}
		results = append(results, verified[next])
		next++
	}
	return results, counts, reachable
}

// toVerifyResults maps engine checksum results to the CLI's render/count shape.
func toVerifyResults(checksums []hdfengine.ChecksumResult, field string) ([]evidenceVerifyResult, verifyCounts) {
	results := make([]evidenceVerifyResult, 0, len(checksums))
	var counts verifyCounts
	for _, c := range checksums {
		results = append(results, evidenceVerifyResult{
			URI:       c.URI,
			Type:      c.Type,
			Field:     field,
			Format:    c.Format,
			Algorithm: c.Algorithm,
			Status:    string(c.Status),
			Expected:  c.Expected,
			Actual:    c.Actual,
			Error:     c.Error,
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
		case hdfengine.ChecksumUnsupported:
			counts.unsupported++
		}
	}
	return results, counts
}

func renderVerifyOutput(doc map[string]interface{}, results []evidenceVerifyResult, counts verifyCounts,
	agentOverrides int, refStatus []referenceStatus,
) {
	unreachable := make([]referenceStatus, 0, len(refStatus))
	for _, st := range refStatus {
		if !st.Reachable {
			unreachable = append(unreachable, st)
		}
	}

	if jsonOutput {
		out := map[string]interface{}{
			"results":    results,
			"matched":    counts.match,
			"mismatched": counts.mismatch,
			"skipped":    counts.skipped,
			"errors":     counts.errors,
			// Every reference this machine could not resolve, across all the fields the
			// package records — a pipeline gates on this without needing
			// --require-reachable. contents[] entries also appear in results with the
			// unreachable status, because the two answer different questions: what
			// happened to each content entry, and what this consumer cannot reach.
			"unreachableReferences": unreachable,
			"unreachable":           counts.unreachable,
			"unsupported":           counts.unsupported,
			"agentOverrides":        agentOverrides,
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
			fmt.Printf("  \u2713 %s (%s match)\n", sanitizeOutput(r.URI), sanitizeOutput(r.Algorithm))
		case verifyMismatch:
			fmt.Printf("  \u2717 %s (%s MISMATCH)\n", sanitizeOutput(r.URI), sanitizeOutput(r.Algorithm))
		case verifySkipped:
			fmt.Printf("  - %s (no checksum)\n", sanitizeOutput(r.URI))
		case verifyError:
			fmt.Printf("  ! %s (error: %s)\n", sanitizeOutput(r.URI), r.Error)
		case verifyUnreachable:
			fmt.Printf("  ? %s (not reachable here: %s)\n", sanitizeOutput(r.URI), sanitizeOutput(r.Error))
		case verifyUnsupported:
			fmt.Printf("  ? %s (not verified here: %s)\n", sanitizeOutput(r.URI), sanitizeOutput(r.Error))
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
	if counts.unreachable > 0 {
		fmt.Printf(", %d not reachable here", counts.unreachable)
	}
	// Same retention as the --require-reachable branch above: unreachable through this
	// command today, kept so a future unimplemented enum value is still reported.
	if counts.unsupported > 0 {
		fmt.Printf(", %d not verifiable here", counts.unsupported)
	}
	fmt.Println()
	fmt.Println(agentOverrideReadout(agentOverrides))

	// Reported, never fatal by default: an evidence package may point at artifacts it
	// does not contain. The lines name the recording field so the reader knows which
	// part of the package to look at, mirroring what `evidence bundle` prints when it
	// cannot carry something.
	if len(unreachable) > 0 {
		fmt.Println()
		for _, st := range unreachable {
			fmt.Printf("  not reachable here: %s (%s) — recorded in %s\n",
				sanitizeOutput(st.Recorded), sanitizeOutput(st.Reason), sanitizeOutput(st.Field))
		}
		fmt.Println("These are recorded references the package does not carry; pass --require-reachable to treat that as a failure.")
	}
}
