package cmd

import (
	"archive/zip"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

	cmd := &cobra.Command{
		Use:   "bundle <package-file>",
		Short: "Bundle an evidence package and every document it references into one archive",
		Long: `Write an evidence package and all of its referenced documents into a single portable
archive, for handing to a GRC tool or an assessor.

The archive root IS the package's own directory: an entry's path is its reference resolved
relative to the package, so extracting anywhere reproduces the layout it was built from, and a
package 'hdf evidence verify' accepts verifies identically on the extracted copy with no path
rewriting.

Bundle is deliberately more permissive than verify today, and a package can bundle that verify
refuses: bundle carries an absolute systemRef or planRef, and honours a recorded sha384 or
sha512 checksum, while verify requires every reference to be relative and hashes sha256 only.
Reconciling the two is tracked separately.

What travels: the package, the documents named by systemRef and planRef, every document
in contents[], and externalEvidence[] artifacts that live inside the package's
directory. externalReferences[] is inert context and never travels, though -o may not
overwrite what it names. Anything that cannot travel is reported on stderr, naming the
field that records it — with one deliberate exception, a remote externalReferences href,
since inert context was never a candidate. Everything stays recorded in the package,
which travels in the archive and is the durable list.

Every recorded checksum on a reference that travels is verified before anything is written. A
reference recording a checksum with an empty value cannot be verified: it travels and the run
says so. A reference recording no checksum at all also travels, but silently — 'hdf evidence
verify' is what reports those. A reference that cannot travel is not verified either, because
its bytes are not here to check. A mismatch or a missing document fails the command and writes
no archive — a partial bundle is worse than none, because it looks complete.

-o refuses a path naming the package or anything it references, so bundling cannot
destroy the evidence it is packaging.

Examples:
  hdf evidence bundle boe.json -o boe.zip
  hdf evidence bundle boe.json -o /tmp/portal-q3-evidence.zip`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if outputPath == "" {
				return fmt.Errorf("-o is required: name the archive to write")
			}
			return runEvidenceBundle(args[0], outputPath, newArchiveWriter)
		},
	}
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Archive to write (required)")
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
}

// recordedRefs returns EVERY reference the document makes. Every consumer of "what does
// this package point at" derives from here rather than enumerating fields at its own
// call site, because hand-enumeration made the same data-loss bug recur four times, once
// per reference field nobody remembered to add. The schema declares five: systemRef,
// planRef, contents[].uri, externalEvidence[].uri and externalReferences[].href.
// TestEvidenceBundle_CoversEverySchemaReferenceField walks the schema and fails if that
// set changes, so the schema is the authority rather than this comment.
func recordedRefs(pkgData []byte, contents []hdfengine.EvidenceContent) ([]recordedRef, error) {
	var doc struct {
		SystemRef string `json:"systemRef"`
		PlanRef   string `json:"planRef"`
	}
	if err := json.Unmarshal(pkgData, &doc); err != nil {
		return nil, fmt.Errorf("read the package's references: %w", err)
	}
	sums := contentChecksums(pkgData)
	if len(sums) != len(contents) {
		return nil, fmt.Errorf("could not read the checksum of every content reference (%d of %d); "+
			"refusing rather than hashing with an assumed algorithm", len(sums), len(contents))
	}
	refs := make([]recordedRef, 0, len(contents)+4)
	refs = append(refs,
		recordedRef{uri: doc.SystemRef, label: "system reference", field: "systemRef", kind: refDocument},
		recordedRef{uri: doc.PlanRef, label: "plan reference", field: "planRef", kind: refDocument})
	for i, c := range contents {
		refs = append(refs, recordedRef{
			uri: c.URI, label: "content reference", field: "contents", kind: refDocument,
			checksum: sums[i].value, algorithm: sums[i].algorithm, checksumRecorded: sums[i].recorded,
		})
	}
	for _, e := range externalEvidenceRefs(pkgData) {
		refs = append(refs, recordedRef{
			uri: e.uri, label: "external evidence", field: "externalEvidence", kind: refExternal,
			checksum: e.checksum, algorithm: e.algorithm, checksumRecorded: e.recorded,
		})
	}
	for _, c := range externalContextRefs(pkgData) {
		refs = append(refs, recordedRef{
			uri: c, label: "external reference", field: "externalReferences", kind: refContext,
		})
	}
	return refs, nil
}

// externalContextRefs reads externalReferences[].href — the fifth reference field, and
// the one a hand-written list of four missed.
func externalContextRefs(pkg []byte) []string {
	var doc struct {
		ExternalReferences []struct {
			Href string `json:"href"`
		} `json:"externalReferences"`
	}
	if json.Unmarshal(pkg, &doc) != nil {
		return nil
	}
	out := make([]string, 0, len(doc.ExternalReferences))
	for _, r := range doc.ExternalReferences {
		out = append(out, r.Href)
	}
	return out
}

// contentChecksum is what the document records for one contents[] entry.
// hdfengine.ParseEvidencePackage flattens checksum to its value alone, so neither
// the algorithm nor the difference between "no checksum" and "a checksum whose
// value is empty" survives its parse — and both matter here. Extending the shared
// engine type is the real fix and is a follow-up card, being a cross-module change
// with a TypeScript peer to keep in step.
type contentChecksum struct {
	algorithm string
	value     string
	recorded  bool
}

// contentChecksums is index-aligned with ParseEvidencePackage's slice, which
// appends one entry per contents[] element with no filtering. The caller REFUSES a
// length mismatch rather than tolerating it: silently falling back to sha256 would
// reintroduce exactly the "your file changed" lie this card already fixed once.
func contentChecksums(pkg []byte) []contentChecksum {
	var doc struct {
		Contents []struct {
			Checksum *struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"checksum"`
		} `json:"contents"`
	}
	if json.Unmarshal(pkg, &doc) != nil {
		return nil
	}
	out := make([]contentChecksum, len(doc.Contents))
	for i, c := range doc.Contents {
		if c.Checksum != nil {
			out[i] = contentChecksum{c.Checksum.Algorithm, c.Checksum.Value, true}
		}
	}
	return out
}

func externalEvidenceRefs(pkg []byte) []externalRef {
	var doc struct {
		ExternalEvidence []struct {
			URI      string `json:"uri"`
			Checksum *struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"checksum"`
		} `json:"externalEvidence"`
	}
	if json.Unmarshal(pkg, &doc) != nil {
		return nil
	}
	out := make([]externalRef, 0, len(doc.ExternalEvidence))
	for _, e := range doc.ExternalEvidence {
		// An empty uri is schema-valid (uri is required but has no minLength) and is
		// returned rather than dropped, so the caller can report it. Dropping it here
		// was the same silent-skip defect already fixed for contents[], left in place
		// one array over.
		ref := externalRef{uri: e.URI}
		if e.Checksum != nil {
			ref.checksum, ref.algorithm, ref.recorded = e.Checksum.Value, e.Checksum.Algorithm, true
		}
		out = append(out, ref)
	}
	return out
}

// hashHex computes the recorded algorithm's digest. sha256 goes through the shared
// hdfutil helper rather than a second inline implementation. An algorithm this
// cannot compute is refused, never reported as a mismatch: saying "the file hashes
// to <sha256>" about a recorded sha512 names the wrong thing and tells the operator
// their file changed when it did not.
func hashHex(algorithm string, data []byte) (string, error) {
	switch algorithm {
	case "", "sha256":
		return hdfutil.SHA256Hex(data), nil
	case "sha384":
		sum := sha512.Sum384(data)
		return hex.EncodeToString(sum[:]), nil
	case "sha512":
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("cannot verify a %s checksum: this command computes sha256, sha384 and sha512", algorithm)
	}
}

// isRemoteURI reports whether a URI names something the archive cannot carry.
func isRemoteURI(uri string) bool { return strings.Contains(uri, "://") }

// packageSubtreeRef renders a local URI as its path relative to the package's own
// directory, reporting whether it lives inside that subtree at all. An
// externalEvidence URI may legitimately be absolute — add-evidence records
// whatever the operator typed — so an absolute path inside the tree must still
// resolve to the reference path the archive uses.
func packageSubtreeRef(pkgDir, uri string) (string, bool) {
	// A RELATIVE uri is package-relative by contract — the same rule contents[]
	// obeys — so it needs no filesystem comparison at all. Measuring it with
	// filepath.Abs was wrong twice over: Abs resolves against the process CWD, not
	// the package, so an in-tree artifact was judged against an unrelated
	// directory; and pairing an unresolved candidate with a symlink-resolved base
	// made every symlinked base (on macOS, all of /tmp and every t.TempDir())
	// report a path plainly inside it as outside. A missing in-tree file must reach
	// collect and be reported as unreadable, not blamed on containment.
	if !filepath.IsAbs(uri) {
		ref := filepath.ToSlash(filepath.Clean(uri))
		if ref == ".." || strings.HasPrefix(ref, "../") {
			return "", false
		}
		return ref, true
	}
	under := func(base, p string) (string, bool) {
		rel, relErr := filepath.Rel(base, p)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", false
		}
		return filepath.ToSlash(rel), true
	}
	// An absolute uri is compared against the package directory, with both sides
	// resolved the SAME way in each attempt. The lexical attempt comes first
	// because resolvedAbs cannot resolve a path that is not on disk.
	if base, baseErr := filepath.Abs(pkgDir); baseErr == nil {
		if rel, ok := under(base, filepath.Clean(uri)); ok {
			return rel, true
		}
	}
	if base, baseErr := resolvedAbs(pkgDir); baseErr == nil {
		if abs, absErr := resolvedAbs(uri); absErr == nil {
			if rel, ok := under(base, abs); ok {
				return rel, true
			}
		}
	}
	return "", false
}

// makeWriter is threaded from the caller so a test can drive this command through
// the seam itself, rather than only constructing an alternative writer beside it.
func runEvidenceBundle(pkgPath, outputPath string, makeWriter func(*os.File) archiveWriter) error {
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
	// travels, then to two of its five reference fields, let the command destroy an
	// irreplaceable artifact three separate times; deriving it is what stops a fourth.
	refs, err := recordedRefs(pkgData, contents)
	if err != nil {
		return fmt.Errorf("evidence package %s: %w", pkgPath, err)
	}
	if err := refuseOutputOverAnInput(outputPath, pkgDir, pkgPath, refs); err != nil {
		return err
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
		uri, subject, label, checksum, algorithm string
		checksumRecorded                         bool
	}
	// Counted inside collect so BOTH contents[] and externalEvidence[] are covered by
	// one path. Incrementing it in the contents loop alone is what left a tampered
	// artifact travelling unverified behind an externalEvidence entry whose recorded
	// checksum value was empty.
	var emptyChecksum int
	collect := func(t target) error {
		uri, label, checksum := t.uri, t.label, t.checksum
		subject := t.subject
		if subject == "" {
			subject = uri
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
		if err := checkContentRefShape(uri, label); err != nil {
			return fmt.Errorf("cannot bundle: %w", err)
		}
		ref := filepath.ToSlash(filepath.Clean(uri))
		if ref == ".." || strings.HasPrefix(ref, "../") || strings.HasPrefix(ref, "/") {
			return fmt.Errorf("%s %q cannot be bundled: it would write an archive entry outside the root", label, subject)
		}
		data, already := collected[ref]
		if !already {
			path, pathErr := hdfutil.SafePath(pkgDir, uri)
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
			if t.checksumRecorded {
				emptyChecksum++
			}
			return nil
		}
		got, hashErr := hashHex(t.algorithm, data)
		if hashErr != nil {
			return fmt.Errorf("%s %q cannot be bundled: %w", label, subject, hashErr)
		}
		if got != checksum {
			return fmt.Errorf("checksum mismatch for %s: the package records %s but the file hashes to %s; "+
				"no archive written", subject, checksum, got)
		}
		return nil
	}

	// planRef and systemRef are carried because `evidence verify` reads the plan for
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
		// A contents[] reference is package-relative and confined BY CONTRACT, so it
		// keeps the strict shape check: an absolute or escaping one is a contract
		// violation and must be refused, not quietly dropped from the manifest.
		if r.field == "contents" {
			if err := collect(target{
				uri: r.uri, label: r.label,
				checksum: r.checksum, algorithm: r.algorithm, checksumRecorded: r.checksumRecorded,
			}); err != nil {
				return err
			}
			carried[r.kind]++
			continue
		}
		// A root or external reference is a LOCATION and may legitimately be absolute —
		// `evidence set --plan-ref /abs/path` and `add-evidence --uri /abs/path` both
		// record one. Resolved, so an absolute path landing inside the package is
		// carried; routing these through the contents[] shape check instead aborted the
		// bundle and described a plan reference as a "content reference".
		ref, inTree := packageSubtreeRef(pkgDir, r.uri)
		if !inTree {
			aside("outside the package's directory")
			continue
		}
		if err := collect(target{
			uri: ref, subject: r.uri, label: r.label,
			checksum: r.checksum, algorithm: r.algorithm, checksumRecorded: r.checksumRecorded,
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
	if emptyChecksum > 0 {
		fmt.Fprintf(os.Stderr, "  %d reference(s) record an empty checksum value and could not be verified\n", emptyChecksum)
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
// references. Every message quotes the uri as RECORDED, never a ref derived from it.
func refuseOutputOverAnInput(outputPath, pkgDir, pkgPath string, refs []recordedRef) error {
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
		candidate := r.uri
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(pkgDir, candidate)
		}
		if samePath(outputPath, candidate) {
			return fmt.Errorf("refusing to write the archive over %q, the %s this package records; name a different -o", r.uri, r.label)
		}
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
