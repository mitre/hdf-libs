package cmd

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/spf13/cobra"
)

// archiveWriter is the seam a tar.gz implementation can satisfy later without
// touching the traversal, checksum or reporting logic around it. zip is the format
// this card ships because it is what most GRC tools ingest and it opens everywhere.
type archiveWriter interface {
	Add(path string, data []byte) error
	Close() error
}

// zipWriter writes a reproducible zip: entries are added in sorted order by the
// caller, and every header carries one fixed timestamp, so the same inputs produce
// byte-identical output. A wall-clock mtime would make two bundles of identical
// evidence differ, which defeats comparing or attesting an archive across runs.
type zipWriter struct{ zw *zip.Writer }

// bundleEpoch is the fixed modification time stamped on every entry.
var bundleEpoch = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

func newZipWriter(f *os.File) *zipWriter { return &zipWriter{zw: zip.NewWriter(f)} }

func (z *zipWriter) Add(path string, data []byte) error {
	h := &zip.FileHeader{Name: path, Method: zip.Deflate, Modified: bundleEpoch}
	w, err := z.zw.CreateHeader(h)
	if err != nil {
		return fmt.Errorf("add %s to archive: %w", path, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write %s to archive: %w", path, err)
	}
	return nil
}

func (z *zipWriter) Close() error { return z.zw.Close() }

// bundleEntry is one file destined for the archive, at its reference path.
type bundleEntry struct {
	path string // the archive entry name: the reference resolved relative to the package
	data []byte
}

func newEvidenceBundleCmd() *cobra.Command {
	var outputPath string
	var overwrite bool

	cmd := &cobra.Command{
		Use:   "bundle <package-file>",
		Short: "Bundle an evidence package and every document it references into one archive",
		Long: `Write an evidence package and all of its referenced documents into a single portable
    archive, for handing to a GRC tool or an assessor.

The archive root IS the package's own directory: an entry's path is its reference
    resolved relative to the package, so extracting anywhere reproduces the layout it
    was built from, and a package whose references are recorded relatively verifies
    identically on the extracted copy with no path rewriting.
A reference recorded as an ABSOLUTE path inside the package is the exception: its
    document travels under a relative name while the package still names the producing
    machine's path, so the extracted copy cannot resolve it.
Every reference that travels is covered, both documents and in-tree external evidence.
That is reported here and never repaired by rewriting the package:
'hdf evidence set' (systemRef, planRef) and 'hdf evidence add-evidence'
    (externalEvidence) record such a reference relatively at authoring time.

Bundle and 'hdf evidence info --verify' resolve references identically, and neither
    refuses a package for the shape of one: a reference to something the package does
    not contain — an absolute path elsewhere, a parent traversal, or a URI on another
    system — is reported by both.
Verification additionally checks completeness, which bundle does not, so it can still
    fail a package bundle accepts — for instance when a planned baseline's only results
    document is one of those unreachable references.
Both honour the checksum algorithm the package records.
Nothing outside the package directory is read: such a reference is never resolved into a
    path, and a symlink that leaves the package is refused at the read boundary.

What travels: the package, the documents named by systemRef and planRef, every document
    in contents[], and externalEvidence[] artifacts that live inside the package's
    directory. externalReferences[] is inert context and never travels, though -o may
    not overwrite what it names.
Anything that cannot travel is reported on stderr, naming the field that records it —
    with one deliberate exception, a remote externalReferences href, since inert context
    was never a candidate.
A reference whose document would TRAVEL — systemRef, planRef, a contents[] entry, a
    local externalEvidence artifact — that resolves inside the package with no file there
    is an ERROR rather than a report: the package says the artifact is here, it is not,
    and there is nothing to put in the archive under the name it promises. An
    externalReferences href is inert context either way and is only ever reported.
Everything stays recorded in the package, which travels in the archive and is the
    durable list.

Every recorded checksum is verified before anything is written: this build computes
    every algorithm Hash_Algorithm admits.
Three kinds cannot be verified: one recording no checksum at all, one recording an empty
    value, and one on a reference that cannot travel, whose bytes are not here to check.
The first two DO travel, and are reported separately because the remedy differs — one
    needs a checksum added, the other has one to fill in.
The third does not travel at all and is reported as not carried.
Every one is reported on stderr NAMING the reference it concerns, with a count after
    each kind.
'hdf evidence info --verify' names every entry too, in contents[] and in
    externalEvidence[] alike, and says what hashing the ones it could reach produced.
The two counts reconcile: both are over the entries the schema gives a checksum, so a
    root reference field — systemRef and planRef have none to record — moves neither.
A mismatch or a missing document fails the command and writes no archive — a partial
    bundle is worse than none, because it looks complete.

-o refuses a path naming the package or anything it references, so bundling cannot
    destroy the evidence it is packaging.
It also refuses a path that already exists, so a previous archive is never replaced
    silently; pass --overwrite to replace it deliberately.
--overwrite does not lift the refusals above it: a path naming an input is refused with
    or without the flag.
Under --overwrite a failed run leaves whatever was already at that path untouched rather
    than deleting it, and says so on stderr naming the path.

Examples:
  hdf evidence bundle boe.json -o boe.zip
  hdf evidence bundle boe.json -o /tmp/portal-q3-evidence.zip`,
		Args: evidencePackageArg,
		RunE: func(_ *cobra.Command, args []string) error {
			if outputPath == "" {
				return fmt.Errorf("-o is required: name the archive to write")
			}
			return runEvidenceBundle(args[0], outputPath, overwrite, newArchiveWriter)
		},
	}
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Archive to write (required)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false,
		"Replace an existing archive at -o (without this, an existing path is refused)")
	return cmd
}

// externalRef is one externalEvidence entry: where the artifact is, and the
// integrity record the package keeps for it. add-evidence records a checksum for
// every local artifact, so discarding it here is how tampered bytes reached the
// archive unverified.
type externalRef struct {
	uri       string
	checksum  string
	algorithm string
	recorded  bool
}

// refKind says how a recorded reference resolves: a document reference is read
// relative to the package, an external one may be absolute and may lie outside it.
type refKind int

const (
	refDocument refKind = iota
	refExternal
	// refContext is inert context — CTI/STIX, advisories — recorded in
	// externalReferences[]. It is never evidence and never travels, but it is still a
	// location the package records, so -o must not destroy it. Whether it SHOULD
	// travel is a contract question for the maintainer; that it must not be
	// obliterated is not.
	refContext
)

// recordedRef is one reference an evidence package makes.
type recordedRef struct {
	uri              string
	label            string
	field            string // the document field that records it, named in every report
	kind             refKind
	checksum         string
	algorithm        string
	checksumRecorded bool
	// Whether the schema gives this reference's field a checksum property at all.
	// systemRef and planRef are bare uri-reference strings, so "records no checksum"
	// is not a gap in them — there is nowhere to record one. Counting them put
	// something in that number an operator could not act on, and made the count
	// diverge from the verification surface's for every package naming a system.
	// Set at the same construction sites that set the three fields above, so the two
	// cannot drift apart.
	canRecordChecksum bool
	// decoded is what the reference MEANS: the uri with its percent-escapes resolved. A
	// recorded reference is a uri-reference, so every consumer that resolves, joins or
	// compares one must use this and not uri — while uri is what gets REPORTED, because
	// that is the string an operator has to find in their package.
	//
	// Decoded once per reference ON THIS PATH, where the enumeration is built, so the
	// consumers that read a recordedRef never decode again. Other entry points decode
	// their own raw input — an operator's --uri, a root reference field read straight off
	// the document — which is a different reference, not a second decode of this one.
	// Decoding a reference twice destroys it: "100%25done" means "100%done", and decoding
	// that again is an error.
	decoded evidenceref.Decoded
	// decodeErr is set when the uri is not a valid uri-reference — a bare % that
	// introduces no escape. Carried rather than returned so one bad reference does not
	// abort the enumeration, and each consumer decides what an unresolvable reference
	// means to it.
	//
	// DEFENSIVE, not a path the CLI reaches: a package carrying such a value is refused
	// by schema validation first, with "Does not match format 'uri-reference'" naming the
	// field. Measured, because an earlier version of this comment claimed the
	// report-not-refuse contract applied here and it does not. This exists for a caller
	// that resolves references without validating first.
	decodeErr error
}

// reportUnverifiable names each reference of one unverifiable kind, then states the
// count. The names are what an operator acts on; the count stays because a long list
// needs a total, and because it is the number the verification surface reconciles with.
//
// Bounded through hdfutil.LimitSlice — the same mechanism LimitSliceWithWarning uses,
// rather than a second one. Not that wrapper itself: its message says "Input truncated",
// which is true of a converter reading a document and false of a report describing one.
func reportUnverifiable(uris []string, recorded bool, summary string) {
	if len(uris) == 0 {
		return
	}
	state := checksumStateFrom(recorded, "")
	shown, truncated := hdfutil.LimitSlice(uris, maxNamedUnverifiable)
	for _, uri := range shown {
		fmt.Fprintf(os.Stderr, "  - %s (%s)\n", sanitizeOutput(uri), state)
	}
	if truncated {
		fmt.Fprintf(os.Stderr, "    ... and %d more, not listed\n", len(uris)-len(shown))
	}
	fmt.Fprintf(os.Stderr, "  %d reference(s) %s and could not be verified\n", len(uris), summary)
}

// Enough that a real package lists every entry, few enough that a pathological one does
// not bury the rest of the report.
const maxNamedUnverifiable = 50

// recordedRefs returns EVERY reference the document makes, with the per-entry checksum
// data bundle and verify report. The enumeration itself comes from evidenceref.Collect,
// because hand-enumeration at each call site made the same data-loss bug recur four times, once
// per reference field nobody remembered to add. The schema declares six: systemRef,
// planRef, contents[].uri, externalEvidence[].uri, externalReferences[].href and
// extensions.rawSourceArtifacts[].href — the last two being inert context that never
// travels, though both are still enumerated here because the -o guard needs them.
// TestEvidenceBundle_CoversEverySchemaReferenceField walks the schema and fails if that
// set changes, so the schema is the authority rather than this comment.
func recordedRefs(pkgData []byte, contents []hdfengine.EvidenceContent) ([]recordedRef, error) {
	collected, err := evidenceref.Collect(pkgData)
	if err != nil {
		return nil, err
	}
	external := externalEvidenceRefs(pkgData)

	// Label and kind are this command's presentation concerns, so they live here
	// rather than in the seam. Keyed by field, not by position in the list.
	meta := map[string]struct {
		label string
		kind  refKind
	}{
		"systemRef":                     {"system reference", refDocument},
		"planRef":                       {"plan reference", refDocument},
		"contents":                      {"content reference", refDocument},
		"externalEvidence":              {"external evidence", refExternal},
		"externalReferences":            {"external reference", refContext},
		"extensions.rawSourceArtifacts": {"raw source artifact", refContext},
	}

	refs := make([]recordedRef, 0, len(collected))
	for _, c := range collected {
		m, known := meta[c.Field]
		if !known {
			return nil, fmt.Errorf("reference field %q has no label here: the seam enumerates a field this command does not report", c.Field)
		}
		r := recordedRef{
			uri: c.Stored, label: m.label, field: c.Field, kind: m.kind,
			decoded: c.Decoded, decodeErr: c.Err,
		}
		// Per-entry checksum data is re-attached by (field, index). The spelling is
		// compared rather than trusted, because pairing a checksum with the wrong
		// reference is silent and the index is the only thing joining them.
		//
		// Both refusals below are defensive and unreachable today: hdf-engine parses
		// the same bytes with the same walk and no filtering or reordering, so the
		// two enumerations cannot diverge. They exist because that is a property of
		// today's parser, not of this function's contract. Untested for the same
		// reason — a test would have to break the parser to reach them.
		switch c.Field {
		case "contents":
			if c.Index < 0 || c.Index >= len(contents) || contents[c.Index].URI != c.Stored {
				return nil, fmt.Errorf("contents[%d] does not line up with the package's own parse (%q): refusing to attach a checksum to the wrong reference", c.Index, c.Stored)
			}
			e := contents[c.Index]
			r.checksum, r.algorithm, r.checksumRecorded = e.Checksum, e.ChecksumAlgorithm, e.ChecksumRecorded
			r.canRecordChecksum = true
		case "externalEvidence":
			if c.Index < 0 || c.Index >= len(external) || external[c.Index].uri != c.Stored {
				return nil, fmt.Errorf("externalEvidence[%d] does not line up with the package's own parse (%q): refusing to attach a checksum to the wrong reference", c.Index, c.Stored)
			}
			e := external[c.Index]
			r.checksum, r.algorithm, r.checksumRecorded = e.checksum, e.algorithm, e.recorded
			r.canRecordChecksum = true
		case "externalReferences", "extensions.rawSourceArtifacts":
			// Both declare a checksum in the schema, so the flag is true even
			// though nothing reads it: whether a reference is fetched is decided
			// by kind, not by this flag, and the two stay separate so each comes
			// from one source.
			r.canRecordChecksum = true
		}
		refs = append(refs, r)
	}
	return refs, nil
}

// externalEvidenceRefs adapts the engine's parse to the shape bundle's reference
// enumeration uses. It is an ADAPTER, not a parse: hdf-libs-52n0c.36 added
// hdfengine.ParseExternalEvidence for verify, and keeping a second near-identical
// decode of the same array here is the drift this epic keeps paying for — the two
// would eventually disagree about a shape neither author had in mind.
//
// An empty uri is schema-valid (uri is required but has no minLength) and survives
// the parse rather than being dropped, so the caller can report it. Dropping it was
// the same silent-skip defect already fixed for contents[], left in place one array
// over; the engine preserves every entry, which is what keeps that fix in force here.
func externalEvidenceRefs(pkg []byte) []externalRef {
	entries, err := hdfengine.ParseExternalEvidence(pkg)
	if err != nil {
		return nil
	}
	out := make([]externalRef, 0, len(entries))
	for _, e := range entries {
		out = append(out, externalRef{
			uri: e.URI, checksum: e.Checksum, algorithm: e.ChecksumAlgorithm, recorded: e.ChecksumRecorded,
		})
	}
	return out
}

// escapesPackageRef reports whether a reference names something outside the package,
// as recorded or as a resolved archive-entry path. All three containment sites share it.
//
// BOTH slashes root a path on Windows and filepath.IsAbs is false for either, so IsAbs
// alone judged such a reference in-tree and SafePath then re-rooted it onto a different
// document. The backslash form arrives without a literal backslash: "%5Cx.json" is a
// legal uri-reference, and decoding runs before containment because it can create one.
func escapesPackageRef(uri string) bool {
	return strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, `\`) || filepath.IsAbs(uri)
}

// isRemoteURI reports whether a URI names something the archive cannot carry.
func isRemoteURI(uri string) bool { return strings.Contains(uri, "://") }

// packageSubtreeRef renders a local URI as its path relative to the package's own
// directory, reporting whether it lives inside that subtree at all. An
// externalEvidence URI may legitimately be absolute — add-evidence records
// whatever the operator typed — so an absolute path inside the tree must still
// resolve to the reference path the archive uses.
func packageSubtreeRef(pkgDir string, uri evidenceref.Decoded) (evidenceref.Decoded, bool) {
	// A RELATIVE uri is package-relative by contract — the same rule contents[]
	// obeys — so it needs no filesystem comparison at all. Measuring it with
	// filepath.Abs was wrong twice over: Abs resolves against the process CWD, not
	// the package, so an in-tree artifact was judged against an unrelated
	// directory; and pairing an unresolved candidate with a symlink-resolved base
	// made every symlinked base (on macOS, all of /tmp and every t.TempDir())
	// report a path plainly inside it as outside. A missing in-tree file must reach
	// collect and be reported as unreadable, not blamed on containment.
	raw := string(uri)
	if !escapesPackageRef(raw) {
		ref := filepath.ToSlash(filepath.Clean(raw))
		if ref == ".." || strings.HasPrefix(ref, "../") {
			return "", false
		}
		return evidenceref.Decoded(ref), true
	}
	under := func(base, p string) (evidenceref.Decoded, bool) {
		rel, relErr := filepath.Rel(base, p)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", false
		}
		return evidenceref.Decoded(filepath.ToSlash(rel)), true
	}
	// An absolute uri is compared against the package directory, with both sides
	// resolved the SAME way in each attempt. The lexical attempt comes first
	// because resolvedAbs cannot resolve a path that is not on disk.
	if base, baseErr := filepath.Abs(pkgDir); baseErr == nil {
		if rel, ok := under(base, filepath.Clean(raw)); ok {
			return rel, true
		}
	}
	if base, baseErr := resolvedAbs(pkgDir); baseErr == nil {
		if abs, absErr := resolvedAbs(raw); absErr == nil {
			if rel, ok := under(base, abs); ok {
				return rel, true
			}
		}
	}
	return "", false
}

// makeWriter is threaded from the caller so a test can drive this command through
// the seam itself, rather than only constructing an alternative writer beside it.
func runEvidenceBundle(pkgPath, outputPath string, overwrite bool, makeWriter func(*os.File) archiveWriter) (err error) {
	pkgData, err := readInputFile(pkgPath)
	if err != nil {
		return fmt.Errorf("failed to read evidence package: %w", err)
	}
	if _, err := loadAndValidateHDFDoc(pkgData, "evidence-package"); err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}

	pkgDir := filepath.Dir(pkgPath)
	_, contents, err := hdfengine.ParseEvidencePackage(pkgData)
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}

	// The archive must not be written over an input. Checked before any REFERENCED
	// DOCUMENT is read (the package itself must be read first — refs derive from it), and
	// over recordedRefs — every reference the document makes, not the
	// subset that travels and not a hand-written list of fields. Scoping this to what
	// travels, then to two of its then-five reference fields, let the command destroy an
	// irreplaceable artifact three separate times; deriving it is what stops a fourth.
	refs, err := recordedRefs(pkgData, contents)
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}
	if err := refuseOutputOverAnInput(outputPath, pkgDir, pkgPath, refs, overwrite); err != nil {
		return err
	}
	// Past the pre-flight refusals, so whatever is still at outputPath is a file the operator
	// asked to replace rather than an input we refuse outright. It need NOT be an archive — it
	// may be any pre-existing file they pointed at — so this says only what is known: nothing
	// replaced it. Without it, "no archive written" alone reads as "the path is empty", and an
	// operator can ship a stale deliverable on that reading.
	if overwrite {
		if info, statErr := os.Stat(outputPath); statErr == nil && !info.IsDir() {
			defer func() {
				if err != nil {
					fmt.Fprintf(os.Stderr,
						"Note: %s was not replaced; the file already at that path is unchanged.\n",
						outputPath)
				}
			}()
		}
	}

	// Collect and verify EVERYTHING before opening the output. Nothing is written
	// until every document is present and every recorded checksum matches.
	entries := []bundleEntry{{path: filepath.ToSlash(filepath.Base(pkgPath)), data: pkgData}}
	collected := map[string][]byte{entries[0].path: pkgData}

	// subject is what the PACKAGE records and is what every message quotes; uri is
	// what is read and what names the archive entry. They differ for an
	// externalEvidence entry recorded as an absolute path, where quoting the derived
	// relative ref would name a string that appears nowhere in the package.
	type target struct {
		uri                                 evidenceref.Decoded
		subject, label, checksum, algorithm string
		checksumRecorded, canRecordChecksum bool
	}
	// Counted inside collect so BOTH contents[] and externalEvidence[] are covered by
	// one path. Incrementing it in the contents loop alone is what left a tampered
	// artifact travelling unverified behind an externalEvidence entry whose recorded
	// checksum value was empty.
	// Collections, not counters: a count tells an operator how many references to fix
	// and not which, and these two kinds are the ones they can actually act on. The
	// kind that cannot travel was already named.
	var emptyChecksum, noChecksum []string
	// Recorded checksums this build cannot compute, reported by subject and reason.
	var unverifiable []string
	collect := func(t target) error {
		uri, label, checksum := t.uri, t.label, t.checksum
		subject := t.subject
		if subject == "" {
			subject = string(uri)
		}
		// The entry NAME is sanitized here, separately from the read. SafePath gates
		// what may be read but says nothing about what name is written, so a crafted
		// package could otherwise put an absolute path or a ".." segment into the
		// archive — a zip-slip primitive for any consumer that does not normalize
		// f.Name, in the very artifact handed to a third party. checkContentRefShape
		// is verify's rule, reused rather than restated.
		// The shared check names the reference kind itself, so wrapping it with the label
		// again stuttered ("content reference %q cannot be bundled: content reference %q
		// is absolute").
		// Checked on the ENTRY NAME, not the recorded subject: an externalEvidence uri
		// may legitimately be absolute, and packageSubtreeRef has already resolved it to
		// a relative ref by here. For a contents[] reference the two are the same string.
		if err := checkContentRefShape(string(uri), label); err != nil {
			return fmt.Errorf("cannot bundle: %w", err)
		}
		ref := filepath.ToSlash(filepath.Clean(string(uri)))
		if ref == ".." || strings.HasPrefix(ref, "../") || escapesPackageRef(ref) {
			return fmt.Errorf("%s %q cannot be bundled: it would write an archive entry outside the root", label, subject)
		}
		data, already := collected[ref]
		if !already {
			path, pathErr := evidenceref.Path(pkgDir, uri)
			if pathErr != nil {
				return fmt.Errorf("%s %q cannot be bundled: %w", label, subject, pathErr)
			}
			var readErr error
			if data, readErr = readFromFile(path, true); readErr != nil {
				return fmt.Errorf("%s %q is referenced but could not be read: %w", label, subject, readErr)
			}
			collected[ref] = data
			entries = append(entries, bundleEntry{path: ref, data: data})
		}
		// The bytes about to travel must be the bytes the package describes, checked
		// HERE against the very data that enters the archive. It used to be a second
		// loop matching entry paths against the raw URI, but the path had been
		// cleaned — so a non-canonical reference ("./x", "a/../x", "a//x") matched no
		// entry, fell through a loop with no else branch, and its checksum was never
		// verified while the archive was still written and declared complete.
		// Computing the reference in two places is what made that possible.
		// Deliberately OUTSIDE the `already` branch above: a second reference to the
		// same file carries its own recorded checksum and must be checked too.
		if strings.TrimSpace(checksum) == "" {
			// A recorded-but-blank value is unverifiable, not a mismatch. Hashing against
			// it would report "the package records <blank> but the file hashes to …",
			// presenting an unverifiable record as a changed file.
			//
			// Counted either way. checksumRecorded used to gate this, so an entry
			// recording NO checksum object fell through silently and its document
			// travelled under the extent claim with nothing vouching for it, while
			// verification reported the same entry as skipped — the two commands
			// disagreed about whether the operator should be told. The two shapes stay
			// separate because the remedy differs: one has a checksum to fill in, the
			// other needs one added.
			switch {
			case !t.canRecordChecksum:
				// Travels, and is not counted: a reference field has nowhere to record a
				// checksum, so its absence is not a gap. The document is normally also a
				// contents[] entry carrying its own, which is where it is counted.
			case t.checksumRecorded:
				emptyChecksum = append(emptyChecksum, subject)
			default:
				noChecksum = append(noChecksum, subject)
			}
			return nil
		}
		got, hashErr := hdfengine.ChecksumHex(t.algorithm, data)
		if hashErr != nil {
			// Not a refusal. The bytes may be intact, so the document is carried and the
			// checksum reported as unverified, exactly as a recorded-but-blank value
			// already is. This build computes every algorithm Hash_Algorithm admits, so a
			// schema-valid package no longer reaches here at all; it remains for an
			// off-schema document, which validation refuses before this point in the CLI
			// but which a library caller can still hand to the engine.
			unverifiable = append(unverifiable, fmt.Sprintf("%s (%s)", subject, hashErr))
			return nil
		}
		if got != checksum {
			return fmt.Errorf("checksum mismatch for %s: the package records %s but the file hashes to %s; "+
				"no archive written", subject, checksum, got)
		}
		return nil
	}

	// planRef and systemRef are carried because `evidence info --verify` reads the plan for
	// its completeness check: an archive omitting it would verify in the original tree
	// and fail on the extracted copy.
	var noURI, noExtURI, documentsDropped int
	var notCarried []string
	carried := map[refKind]int{}
	for _, r := range refs {
		if r.uri == "" {
			// A recorded field left empty names nothing, and is reported rather than
			// skipped because the extent line claims every document in contents[].
			// systemRef and planRef are optional, so an absent one is normal.
			switch {
			case r.field == "contents":
				noURI++
				documentsDropped++
			case r.kind == refExternal:
				noExtURI++
			}
			continue
		}
		// Every report names the field that records the reference. It used to be
		// hardcoded to externalEvidence, so a remote planRef was reported as "still
		// recorded in the package's externalEvidence" — where it is not.
		aside := func(why string) {
			// Recorded here, not just counted for the empty-uri case: a document is
			// equally absent whether it named nothing, was remote, or lay outside the
			// package, and the extent sentence must be qualified for all three. Hooking
			// the qualifier to one drop reason left the claim false for the other two.
			if r.kind == refDocument {
				documentsDropped++
			}
			notCarried = append(notCarried,
				fmt.Sprintf("%s (%s) — recorded in %s", r.uri, why, r.field))
		}
		if r.kind == refContext {
			// Inert context never travels: it is not evidence, and the extent sentence
			// does not claim it. Said once, for a local href that might look like a
			// candidate; a remote advisory URL needs no remark.
			if !isRemoteURI(r.uri) {
				aside("context, not evidence")
			}
			continue
		}
		if isRemoteURI(r.uri) {
			aside("remote")
			continue
		}
		// EVERY reference is a LOCATION and may legitimately be absolute — `evidence set
		// --plan-ref /abs/path` and `add-evidence --uri /abs/path` both record one.
		// Resolved, so an absolute path landing inside the package is carried and one
		// outside it is reported rather than refused. contents[] used to be special-cased
		// through the strict shape check and refusing it made bundle reject packages
		// `evidence info --verify` accepts. The schema now describes the package-relative form as
		// the one the tooling resolves, and says in the same breath that another shape is
		// schema-valid and reported — so that description is not a licence to refuse one.
		if r.decodeErr != nil {
			aside("not a valid uri-reference")
			continue
		}
		ref, inTree := packageSubtreeRef(pkgDir, r.decoded)
		if !inTree {
			aside("outside the package's directory")
			continue
		}
		if err := collect(target{
			uri: ref, subject: r.uri, label: r.label,
			checksum: r.checksum, algorithm: r.algorithm, checksumRecorded: r.checksumRecorded,
			canRecordChecksum: r.canRecordChecksum,
		}); err != nil {
			return err
		}
		carried[r.kind]++
	}
	sort.Strings(notCarried)

	// Sorted order plus a fixed timestamp make the archive reproducible.
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	if err := writeArchiveAtomically(outputPath, entries, makeWriter); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Archive written to %s (%d file(s))\n", outputPath, len(entries))
	if noURI > 0 {
		fmt.Fprintf(os.Stderr, "  %d content reference(s) record no uri and name nothing to carry\n", noURI)
	}
	if noExtURI > 0 {
		fmt.Fprintf(os.Stderr, "  %d external evidence reference(s) record no uri and name nothing to carry\n", noExtURI)
	}
	reportUnverifiable(noChecksum, false, "record no checksum")
	reportUnverifiable(emptyChecksum, true, "record an empty checksum value")
	for _, u := range unverifiable {
		fmt.Fprintf(os.Stderr, "  checksum could not be verified for %s\n", sanitizeOutput(u))
	}
	// ANY reference that travels — a document, or in-tree external evidence — recorded as
	// an absolute path inside the package travels as a RELATIVE archive entry, so the
	// archived package names a path the extracted copy will not have: the bytes travelled
	// and the reference did not. Reported, never rewritten: the package can carry a
	// whole-document integrity and signature, and editing its bytes here would invalidate
	// them. `hdf evidence set` (systemRef, planRef) and `hdf evidence add-evidence`
	// (externalEvidence) normalize this shape at authoring time; a package already in it,
	// or one from another producer, is reported.
	for _, r := range refs {
		// refContext is excluded because externalReferences[] never travels; everything
		// that DOES travel — documents and in-tree external evidence — is covered.
		if r.uri == "" || r.kind == refContext || isRemoteURI(r.uri) || !filepath.IsAbs(r.uri) {
			continue
		}
		if resolved, ok := packageSubtreeRef(pkgDir, r.decoded); ok {
			fmt.Fprintf(os.Stderr,
				"  %s records %s; it is carried as %s, so the extracted package will not resolve it as recorded\n",
				r.field, sanitizeOutput(r.uri), resolved)
		}
	}

	// The satisfiable half of "report what is NOT in here": bundle cannot know what
	// `build` skipped — that lives only in build's stderr — but it can state the
	// archive's exact extent. Built from what was actually carried, because a fixed
	// sentence became false the moment root references started travelling: it said
	// "nothing else" while a systemRef document sat in the archive.
	parts := []string{"the package"}
	if carried[refDocument] > 0 {
		scope := "every document it references"
		if documentsDropped > 0 {
			// One qualifier for every reason a referenced document did not travel — it
			// named nothing, it is remote, or it lies outside the package. The notice
			// lines below say which and why; this clause only has to stop claiming them.
			scope = "every document it references that could travel"
		}
		parts = append(parts, scope)
	}
	if carried[refExternal] > 0 {
		parts = append(parts, "in-tree external evidence")
	}
	fmt.Fprintf(os.Stderr, "Contains exactly %s — nothing else.\n", strings.Join(parts, ", "))
	// Reported to the operator, not written into the archive. The package's own
	// externalEvidence[] is already the durable record of every external reference —
	// URI, format and checksum — and it travels in the archive, so a manifest file
	// would be a second, unvalidated copy that can drift from the schema-validated
	// one. Which references travelled is derivable: an entry exists at that path, or
	// it does not. Each line names the field that records the reference, because a
	// hardcoded "recorded in externalEvidence" was false for a planRef.
	for _, r := range notCarried {
		fmt.Fprintf(os.Stderr, "  not carried: %s\n", r)
	}

	return nil
}

// refuseOutputOverAnInput refuses an -o that names the package or anything it
// references, and then an -o that already exists unless overwrite is set. Every message
// quotes the uri as RECORDED, never a ref derived from it. The order is load-bearing: see
// the comment on the existence check.
func refuseOutputOverAnInput(outputPath, pkgDir, pkgPath string, refs []recordedRef, overwrite bool) error {
	if info, err := os.Stat(outputPath); err == nil && info.IsDir() {
		return fmt.Errorf("-o %s is a directory; name the archive file to write", outputPath)
	}
	// Checked here rather than left to os.CreateTemp, which fails after every read and
	// hash with an "open <dir>/.hdf-bundle-NNN" naming a temp path the operator never
	// typed.
	if parent := filepath.Dir(outputPath); parent != "" {
		if _, err := os.Stat(parent); err != nil {
			return fmt.Errorf("-o %s: the directory %s does not exist", outputPath, parent)
		}
	}
	if samePath(outputPath, pkgPath) {
		return fmt.Errorf("refusing to write the archive over the evidence package itself (%s); "+
			"name a different -o", pkgPath)
	}
	for _, r := range refs {
		if r.uri == "" || isRemoteURI(r.uri) {
			continue
		}
		// The DECODED reference, because that is the file on disk. Built from the raw one,
		// this compared against a path nothing occupies whenever a reference carried a
		// percent-escape — so bundling over "my scans/q4.json" was permitted for a
		// package recording "my%20scans/q4.json", and the archive replaced the evidence.
		// The recorded spelling is still what the refusal NAMES, since that is what the
		// operator has to find.
		candidate := string(r.decoded)
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(pkgDir, candidate)
		}
		if samePath(outputPath, candidate) {
			return fmt.Errorf("refusing to write the archive over %q, the %s this package records; name a different -o", r.uri, r.label)
		}
	}
	// LAST, so --overwrite is never offered for a path the checks above refuse outright:
	// suggesting it for an input would invite the operator to destroy the evidence, and no
	// flag makes that acceptable. A prior archive, by contrast, is the operator's own
	// deliverable and is replaced on request — still before any document is read, so a run
	// that will not proceed costs nothing and reports nothing else first.
	if info, err := os.Stat(outputPath); err == nil && !info.IsDir() && !overwrite {
		return fmt.Errorf("-o %s already exists; pass --overwrite to replace it", outputPath)
	}
	return nil
}

// samePath reports whether two paths name the same file. os.SameFile is asked first
// because it compares device and inode, so it sees through a symlink, a hardlink, and
// a case-insensitive filesystem's two spellings of one file — none of which a string
// comparison catches, and the case-only spelling destroyed a recorded document on the
// maintainer's own platform. The lexical comparison is the fallback for when the
// output does not exist yet, which is the common case and is sound: a path that does
// not exist cannot be an input about to be lost.
//
// It errs toward reporting a match. A symlink or hardlink named as -o would survive a
// rename, so refusing those is stricter than strictly necessary; "name a different -o"
// is a cheap remedy, and the alternative is reasoning about link semantics in the one
// command whose job is not destroying evidence.
func samePath(a, b string) bool {
	if infoA, err := os.Stat(a); err == nil {
		if infoB, statErr := os.Stat(b); statErr == nil {
			return os.SameFile(infoA, infoB)
		}
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	return errA == nil && errB == nil && absA == absB
}

// newArchiveWriter is the default seam binding: zip. A tar.gz implementation
// replaces this one function and nothing else.
func newArchiveWriter(f *os.File) archiveWriter { return newZipWriter(f) }

// writeArchiveAtomically writes to a temporary file beside the target and renames it
// into place, so a failure part-way cannot leave a partial archive that looks
// complete. It takes the writer constructor so the seam is exercised by the command,
// not merely implemented beside it.
func writeArchiveAtomically(outputPath string, entries []bundleEntry, makeWriter func(*os.File) archiveWriter) error {
	dir := filepath.Dir(outputPath)
	tmp, err := os.CreateTemp(dir, ".hdf-bundle-*")
	if err != nil {
		return fmt.Errorf("failed to create the archive: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName) // no-op once renamed
	}()

	w := makeWriter(tmp)
	for _, e := range entries {
		if err := w.Add(e.path, e.data); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finalize the archive: %w", err)
	}
	// Before the rename, not after: a crash can otherwise make the rename durable while the
	// bytes are not, leaving a present-but-truncated archive — the exact failure the
	// write-then-rename exists to prevent.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to flush the archive to disk: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close the archive: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("failed to set archive permissions: %w", err)
	}
	if err := os.Rename(tmpName, outputPath); err != nil {
		return fmt.Errorf("failed to write %s: %w", outputPath, err)
	}
	return nil
}
