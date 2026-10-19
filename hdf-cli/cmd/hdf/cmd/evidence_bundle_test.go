package cmd

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bundleTree builds a package from real fixtures in a base directory whose
// documents sit in a subdirectory, so the archive layout is actually exercised.
func bundleTree(t *testing.T) (dir, pkgPath string) {
	t.Helper()
	dir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
	copyFixture := func(name, dest string) {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, dest), src, 0o600))
	}
	copyFixture("system.json", "system.json")
	copyFixture("rhel9-results.json", filepath.Join("scans", "rhel9-results.json"))
	copyFixture("postgres-results.json", filepath.Join("scans", "postgres-results.json"))
	copyFixture("plan.json", "plan.json")

	pkgPath = filepath.Join(dir, "pkg.json")
	_, _, err := executeCommand("evidence", "build",
		"--system", filepath.Join(dir, "system.json"),
		"--results", filepath.Join(dir, "scans", "rhel9-results.json"),
		"--results", filepath.Join(dir, "scans", "postgres-results.json"),
		"--plan", filepath.Join(dir, "plan.json"),
		"-o", pkgPath)
	require.NoError(t, err)
	return dir, pkgPath
}

func zipEntries(t *testing.T, archive string) map[string][]byte {
	t.Helper()
	r, err := zip.OpenReader(archive)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	out := map[string][]byte{}
	for _, f := range r.File {
		rc, openErr := f.Open()
		require.NoError(t, openErr)
		// io.ReadFull, not a single Read: the flate reader may return fewer bytes
		// than requested, which would silently zero-pad the tail of every entry this
		// helper hands to an assertion.
		buf := make([]byte, f.UncompressedSize64)
		if len(buf) > 0 {
			_, readErr := io.ReadFull(rc, buf)
			require.NoError(t, readErr)
		}
		_ = rc.Close()
		out[f.Name] = buf
	}
	return out
}

// The card's named first test.
func TestEvidenceBundle_ContainsEveryReferencedDocument(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	archive := filepath.Join(dir, "boe.zip")

	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)

	entries := zipEntries(t, archive)
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	assert.Equal(t, []string{
		"pkg.json",
		"plan.json",
		"scans/postgres-results.json",
		"scans/rhel9-results.json",
		"system.json",
	}, names, "the package plus every document it references, at their reference paths")
}

// The layout decision: the archive root IS the base directory, so an entry's path
// is the reference resolved relative to the package, and an extracted copy verifies with no
// rewriting.
func TestEvidenceBundle_ExtractedArchiveVerifiesUnchanged(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	archive := filepath.Join(dir, "boe.zip")
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)

	// Extract into a fresh directory, nowhere near the original.
	dest := t.TempDir()
	for name, data := range zipEntries(t, archive) {
		target := filepath.Join(dest, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
		require.NoError(t, os.WriteFile(target, data, 0o600))
	}

	_, _, verifyErr := executeCommand("evidence", "info", "--verify", filepath.Join(dest, "pkg.json"))
	require.NoError(t, verifyErr,
		"an extracted archive must verify without any path rewriting")
}

// A checksum mismatch means the archive would carry bytes the package does not
// describe. Fail, name the document, and write nothing.
func TestEvidenceBundle_RefusesAChecksumMismatch(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	// Alter a referenced document after the package recorded its hash.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9-results.json"),
		[]byte(`{"baselines":[]}`), 0o600))
	archive := filepath.Join(dir, "boe.zip")

	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rhel9-results.json", "the error must name the document")
	assert.NoFileExists(t, archive, "no partial archive may be written")
}

// A referenced document that is gone fails the same way.
func TestEvidenceBundle_RefusesAMissingDocument(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	require.NoError(t, os.Remove(filepath.Join(dir, "scans", "postgres-results.json")))
	archive := filepath.Join(dir, "boe.zip")

	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "postgres-results.json")
	assert.NoFileExists(t, archive)
}

// A prior archive at -o is the operator's existing deliverable, so it is not replaced
// without being asked. The refusal lands before any document is read or hashed, which
// is what the byte-identity assertion below pins.
func TestEvidenceBundle_RefusesAnExistingArchiveUnlessOverwrite(t *testing.T) {
	const prior = "not really a zip, but the operator's file"

	t.Run("refuses and leaves the prior archive untouched", func(t *testing.T) {
		dir, pkgPath := bundleTree(t)
		archive := filepath.Join(dir, "boe.zip")
		require.NoError(t, os.WriteFile(archive, []byte(prior), 0o600))

		_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
		require.Error(t, err)
		assert.Contains(t, err.Error(), archive, "the error must name the path it refused")
		assert.Contains(t, err.Error(), "--overwrite", "and must name the flag that proceeds")
		got, readErr := os.ReadFile(archive)
		require.NoError(t, readErr)
		assert.Equal(t, prior, string(got), "the prior archive must be byte-identical")
	})

	t.Run("--overwrite replaces it", func(t *testing.T) {
		dir, pkgPath := bundleTree(t)
		archive := filepath.Join(dir, "boe.zip")
		require.NoError(t, os.WriteFile(archive, []byte(prior), 0o600))

		_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive, "--overwrite")
		require.NoError(t, err)
		assert.Contains(t, zipEntries(t, archive), "pkg.json", "a real archive replaced the file")
	})
}

// Ordering, stated as a test: with both faults present the existence refusal wins,
// because it is reached before the first document is read. Without this, a refusal
// added anywhere after the read loop would still satisfy the test above.
func TestEvidenceBundle_RefusesAnExistingArchiveBeforeReadingDocuments(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9-results.json"),
		[]byte(`{"baselines":[]}`), 0o600))
	archive := filepath.Join(dir, "boe.zip")
	require.NoError(t, os.WriteFile(archive, []byte("prior"), 0o600))

	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--overwrite")
	assert.NotContains(t, err.Error(), "rhel9-results.json",
		"the checksum mismatch must not be reported: the run stopped before reading it")
}

// --overwrite must never become a way to destroy an input. The existence refusal is
// ordered after the input-overlap refusals for exactly this reason: an earlier
// placement answered "-o system.json already exists; pass --overwrite to replace it",
// inviting the operator to overwrite a document the package records.
func TestEvidenceBundle_OverwriteNeverDestroysAnInput(t *testing.T) {
	for _, target := range []string{"system.json", "plan.json"} {
		t.Run(target, func(t *testing.T) {
			dir, pkgPath := bundleTree(t)
			victim := filepath.Join(dir, target)
			before, err := os.ReadFile(victim)
			require.NoError(t, err)

			_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", victim, "--overwrite")
			require.Error(t, err, "--overwrite may not override the input boundary")
			assert.Contains(t, err.Error(), "refusing to write the archive over",
				"the specific refusal must win, not the generic existence one")
			assert.NotContains(t, err.Error(), "--overwrite",
				"and it must not suggest a flag that would destroy evidence")
			// The WHOLE report, not just the error: a note describing this recorded document
			// as a leftover archive would re-create the defect the ordering fix removed. The
			// second assertion is the load-bearing one — it fails if the note is registered
			// before the pre-flight refusals. The first is a tripwire: that phrase exists
			// nowhere now, so it guards against the old wording coming back, not against a
			// live defect.
			assert.NotContains(t, stderr, "previous run",
				"a recorded document must never be described as a prior archive")
			assert.NotContains(t, stderr, "was not replaced",
				"and the not-replaced note belongs only past the pre-flight refusals")
			after, err := os.ReadFile(victim)
			require.NoError(t, err)
			assert.Equal(t, before, after, "the recorded document must be untouched")
		})
	}
}

// Past the pre-flight refusals the file at -o need not be an archive at all — it may be
// any pre-existing file the operator pointed at. The note may therefore say only what is
// known: it was not replaced and is unchanged. Calling it "the archive from a previous
// run" would assert something the code never established.
func TestEvidenceBundle_NoteDoesNotCallAnUnrelatedFileAnArchive(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	target := filepath.Join(dir, "notes.txt")
	require.NoError(t, os.WriteFile(target, []byte("operator's notes, never an archive"), 0o600))
	// Fail AFTER the pre-flight refusals, so the note is reached.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9-results.json"),
		[]byte(`{"baselines":[]}`), 0o600))

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", target, "--overwrite")
	require.Error(t, err)
	assert.Contains(t, stderr, target, "the note must name the path")
	assert.NotContains(t, stderr, "archive from a previous run",
		"the file there was never an archive; the note may not claim it was")
	body, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, "operator's notes, never an archive", string(body), "and it is untouched")
}

// "no archive written" is true but not the whole truth when --overwrite was asked for and
// the run then failed: the PREVIOUS run's archive is still sitting at that path. An
// operator who reads only "no archive written" can ship a stale deliverable believing the
// path is empty, so the report must name what is actually there.
func TestEvidenceBundle_SaysThePriorArchiveSurvivedAFailedOverwrite(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	archive := filepath.Join(dir, "boe.zip")

	// A good archive from an earlier run.
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	before, err := os.ReadFile(archive)
	require.NoError(t, err)

	// Now a referenced document changes, so the re-run fails after the output check.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9-results.json"),
		[]byte(`{"baselines":[]}`), 0o600))

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive, "--overwrite")
	require.Error(t, err)
	after, readErr := os.ReadFile(archive)
	require.NoError(t, readErr)
	require.Equal(t, before, after, "precondition: the prior archive is still on disk")

	assert.Contains(t, stderr, archive,
		"the report must name the path whose file survived")
	assert.Contains(t, stderr, "was not replaced",
		"and must say it was not replaced, so the path is not read as empty")
}

// Local external evidence travels; a remote URI cannot, so it is reported — and it
// stays recorded in the package's own externalEvidence[], which travels in the
// archive. No separate manifest file is written: that would duplicate the
// schema-validated record in an unvalidated format that can drift from it.
func TestEvidenceBundle_CarriesLocalExternalEvidenceAndReportsRemote(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	corpus := filepath.Join(dir, "scans", "audit.ndjson")
	require.NoError(t, os.WriteFile(corpus, []byte(`{"@timestamp":"2026-01-01T00:00:00Z"}`+"\n"), 0o600))
	_, _, addErr := executeCommand("evidence", "add-evidence", pkgPath,
		"--uri", corpus, "--format", "ecs")
	require.NoError(t, addErr)
	_, _, addErr2 := executeCommand("evidence", "add-evidence", pkgPath,
		"--uri", "https://lake.example/ocsf/q1.ndjson", "--format", "ocsf")
	require.NoError(t, addErr2)

	archive := filepath.Join(dir, "boe.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)

	entries := zipEntries(t, archive)
	_, localCarried := entries["scans/audit.ndjson"]
	assert.True(t, localCarried, "a local external artifact must travel in the archive")

	_, hasManifest := entries["external-evidence-manifest.txt"]
	assert.False(t, hasManifest,
		"no manifest file: the package's externalEvidence[] is already the record, and it travels here")
	assert.Contains(t, stderr, "https://lake.example/ocsf/q1.ndjson",
		"the operator must be told it could not travel")
	// The REASON is asserted. Only "outside the package's directory" was pinned, so a
	// remote URL could be reported as out-of-tree and nothing would notice.
	assert.Contains(t, stderr, "(remote)", "a remote uri must be reported as remote")
	assert.NotContains(t, stderr, "outside the package's directory",
		"and not as something it is not")

	// The extent sentence's external clause is asserted PRESENT here, because the only
	// other assertion on it is a NotContains in a package that has no external evidence.
	// Pinned one way only, nothing could tell "the clause is derived from what travelled"
	// apart from "the clause never appears": suppressing the carried-count for external
	// evidence left an archived file outside the "nothing else" claim, suite green.
	assert.Contains(t, stderr,
		"Contains exactly the package, every document it references, in-tree external evidence — nothing else.",
		"the clause must appear when in-tree external evidence actually travelled")
	// And the claim must hold: every archive entry is one the sentence accounts for.
	claimed := map[string]bool{"pkg.json": true, "system.json": true, "plan.json": true,
		"scans/rhel9-results.json": true, "scans/postgres-results.json": true,
		"scans/audit.ndjson": true}
	for name := range entries {
		assert.True(t, claimed[name],
			"%s is in the archive but the extent sentence does not account for it", name)
	}

	// The durable record is the package itself, carried in the archive.
	var carried map[string]interface{}
	require.NoError(t, json.Unmarshal(entries["pkg.json"], &carried))
	ext := carried["externalEvidence"].([]interface{})
	uris := []string{}
	for _, e := range ext {
		uris = append(uris, e.(map[string]interface{})["uri"].(string))
	}
	assert.Contains(t, uris, "https://lake.example/ocsf/q1.ndjson",
		"the remote reference is still in the package that travels in the archive")
}

// Two bundles of the same inputs must be byte-identical, or an archive cannot be
// compared or attested across runs.
func TestEvidenceBundle_IsReproducible(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	a := filepath.Join(dir, "a.zip")
	b := filepath.Join(dir, "b.zip")
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", a)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", b)
	require.NoError(t, err)

	first, err := os.ReadFile(a)
	require.NoError(t, err)
	second, err := os.ReadFile(b)
	require.NoError(t, err)
	assert.Equal(t, first, second, "two bundles of one package are byte-identical")

	// Byte-identity alone is a WEAK assertion and cannot pin either mechanism:
	// both archives are produced in one process, so a wall-clock stamp evaluated
	// once per process is identical in both, and entry order is already
	// deterministic without the sort (it follows contents[], read from a file).
	// Assert the two mechanisms directly from the headers instead.
	r, err := zip.OpenReader(a)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
		// Compared against the LITERAL date, never against bundleEpoch itself:
		// asserting f.Modified.Equal(bundleEpoch) passes for any value of that
		// variable, time.Now() included, so it would pin nothing.
		assert.True(t, f.Modified.Equal(time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)),
			"entry %s must carry the fixed epoch, not a wall-clock time: got %s", f.Name, f.Modified)
	}
	assert.True(t, sort.StringsAreSorted(names),
		"entries must be in canonical sorted order, not merely in a deterministic one: %v", names)
}

func TestEvidenceBundle_SaysWhatItDoesNotContain(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	// A file in the tree that the package does not reference.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "stray.ndjson"),
		[]byte("{}\n"), 0o600))
	archive := filepath.Join(dir, "boe.zip")

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.Contains(t, stderr, "5 file(s)",
		"the operator must be told what the archive holds")
	// The extent statement is the half of this AC that bundle can honestly make: it
	// cannot know what `build` skipped (that lives only in build's stderr), but it
	// can state exactly what the archive holds. Asserted because deleting the line
	// previously left the entire package green.
	// No external evidence in this package, so the sentence must not claim any: it is
	// built from what was actually carried.
	assert.Contains(t, stderr,
		"Contains exactly the package, every document it references — nothing else.",
		"and told what it does NOT hold, which a count alone does not say")
	assert.NotContains(t, stderr, "in-tree external evidence",
		"the claim must not list a category this package has none of")
	// The sentence must be TRUE, not merely present. It previously claimed "nothing
	// else" while a systemRef document sat in the archive, and the assertion could not
	// tell: it checked that the claim was printed, never that it held.
	claimed := map[string]bool{"pkg.json": true}
	for _, name := range []string{"system.json", "plan.json",
		"scans/rhel9-results.json", "scans/postgres-results.json"} {
		claimed[name] = true
	}
	for name := range zipEntries(t, archive) {
		assert.True(t, claimed[name], "%s is in the archive but the extent sentence does not claim it", name)
	}
	entries := zipEntries(t, archive)
	_, strayCarried := entries["scans/stray.ndjson"]
	assert.False(t, strayCarried, "only referenced documents travel")
}

// No entry may carry an absolute path or a traversal component, or extracting the
// archive could write outside the destination.
func TestEvidenceBundle_EntryPathsAreRelativeAndContained(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	archive := filepath.Join(dir, "boe.zip")
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)

	for name := range zipEntries(t, archive) {
		assert.False(t, filepath.IsAbs(name), "entry %q is absolute", name)
		assert.NotContains(t, name, "..", "entry %q traverses", name)
		assert.NotContains(t, name, `\`, "entry %q uses a backslash separator", name)
	}
}

// fakeArchiveWriter is a test double for the archiveWriter seam. Its existence is
// the AC: a tar.gz implementation must be able to satisfy the interface without the
// traversal, checksum or reporting logic around it changing. If the seam were
// abandoned for direct zip calls, this would not compile.
type fakeArchiveWriter struct {
	added  []string
	closed bool
}

func (f *fakeArchiveWriter) Add(path string, _ []byte) error {
	f.added = append(f.added, path)
	return nil
}

func (f *fakeArchiveWriter) Close() error {
	f.closed = true
	return nil
}

func TestEvidenceBundle_WriterSeamAcceptsAnotherImplementation(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	fake := &fakeArchiveWriter{}

	// The command is driven THROUGH the seam. Constructing the fake and calling
	// Add on it directly would only prove the interface compiles; it would pass
	// with the command still making zip calls of its own.
	require.NoError(t, runEvidenceBundle(pkgPath, filepath.Join(dir, "seam.zip"), false,
		func(*os.File) archiveWriter { return fake }))

	assert.Equal(t, []string{
		"pkg.json", "plan.json",
		"scans/postgres-results.json", "scans/rhel9-results.json",
		"system.json",
	}, fake.added, "a non-zip writer receives every entry, at its package-relative path")
	assert.True(t, fake.closed, "and is closed through the same contract")
}

// A package is an input like any other: bundle must not trust its refs. An entry
// name that is absolute or climbs out of the root is a zip-slip primitive for any
// consumer that does not normalize it — in the artifact handed to a third party.
// hdfutil.SafePath gates what may be READ and says nothing about what is WRITTEN,
// so the happy path (built by evidence build, which emits clean refs) cannot show
// this. The package here is hand-written for that reason.
func TestEvidenceBundle_RefusesHostileContentRefs(t *testing.T) {
	dir, _ := bundleTree(t)
	sum := func(rel string) string {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		require.NoError(t, err)
		return fmt.Sprintf("%x", sha256.Sum256(data))
	}
	write := func(name, uri, checksum string) string {
		pkg := map[string]any{
			"name": "hostile",
			"contents": []map[string]any{{
				"type": "hdf-results", "uri": uri,
				"checksum": map[string]string{"algorithm": "sha256", "value": checksum},
			}},
		}
		data, err := json.Marshal(pkg)
		require.NoError(t, err)
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}

	t.Run("an absolute uri never becomes an archive entry", func(t *testing.T) {
		// Root-anchored, NOT a full absolute path: filepath.Join(pkgDir, "/scans/x")
		// resolves back INSIDE the package, so SafePath would accept the read and the
		// only thing standing between it and an absolute archive entry is how the
		// reference is resolved. A full absolute path would leave the base and fail on
		// a missing file instead, which would pass this test without exercising it.
		//
		// The package is no longer REFUSED for recording this — a reference to
		// something the package does not contain is legitimate — but the entry must
		// still never appear, under any spelling. That is the security property; the
		// refusal was only ever the mechanism.
		abs := "/scans/rhel9-results.json"
		pkgPath := write("abs.json", abs, sum(filepath.Join("scans", "rhel9-results.json")))
		out := filepath.Join(dir, "abs.zip")
		_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", out)
		require.NoError(t, err, "an out-of-package reference is reported, not refused")
		assert.Contains(t, stderr, abs, "the not-carried report must name the reference")
		assert.Contains(t, stderr, "outside the package's directory")
		for name := range zipEntries(t, out) {
			assert.False(t, strings.HasPrefix(name, "/"), "no absolute archive entry: %q", name)
			assert.NotContains(t, name, "..", "no traversal segment in an archive entry: %q", name)
			assert.NotEqual(t, "scans/rhel9-results.json", name,
				"the document was not carried, so it must not appear under a cleaned name either")
		}
	})

	t.Run("a traversal segment is normalized away, not written", func(t *testing.T) {
		pkgPath := write("dots.json", "scans/../scans/rhel9-results.json",
			sum(filepath.Join("scans", "rhel9-results.json")))
		out := filepath.Join(dir, "dots.zip")
		_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", out)
		require.NoError(t, err, "the ref resolves inside the package, so it is carried")
		names := make([]string, 0, 2)
		for name := range zipEntries(t, out) {
			names = append(names, name)
		}
		sort.Strings(names)
		assert.Equal(t, []string{"dots.json", "scans/rhel9-results.json"}, names,
			"the entry is written at its cleaned path — no '..' segment reaches the archive")
	})
}

// A checksum must be verified against the bytes that actually travel, for EVERY
// reference shape — not only the canonical one. The entry path is cleaned, so
// matching entries against a raw URI in a second loop silently skipped this check
// for "./x", "a/../x" and "a//x": the archive was written, and declared complete,
// with bytes the package's own checksum contradicted.
func TestEvidenceBundle_VerifiesChecksumsForNonCanonicalRefs(t *testing.T) {
	for _, uri := range []string{
		"scans/rhel9-results.json",          // canonical — the only shape once covered
		"./scans/rhel9-results.json",        // leading dot
		"scans/../scans/rhel9-results.json", // a traversal that resolves back
		"scans//rhel9-results.json",         // a doubled separator
	} {
		t.Run(uri, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
			src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9-results.json"), src, 0o600))

			pkg, err := json.Marshal(map[string]any{
				"name": "t",
				"contents": []map[string]any{{
					"type": "hdf-results", "uri": uri,
					// Deliberately wrong: the command must refuse, whatever the shape.
					"checksum": map[string]string{"algorithm": "sha256", "value": strings.Repeat("0", 64)},
				}},
			})
			require.NoError(t, err)
			pkgPath := filepath.Join(dir, "pkg.json")
			require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

			out := filepath.Join(dir, "out.zip")
			_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", out)
			require.Error(t, err, "a wrong checksum must fail regardless of the reference's spelling")
			assert.Contains(t, err.Error(), "checksum mismatch")
			assert.NoFileExists(t, out, "and no archive may be written")
		})
	}
}

// External evidence naming a file plainly inside the package but MISSING must be
// reported as unreadable. It was reported as "outside the package's directory" —
// false, and it hid the real problem — whenever the base path contained a symlink,
// which on macOS is every /tmp path and every t.TempDir().
func TestEvidenceBundle_MissingInTreeExternalEvidenceIsHonest(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	_, _, err := executeCommand("evidence", "add-evidence", pkgPath,
		"--uri", "scans/gone.ndjson", "--format", "ecs", "-o", pkgPath)
	require.NoError(t, err)

	out := filepath.Join(dir, "missing.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", out)
	require.Error(t, err, "a referenced artifact that is absent must fail, not be quietly omitted")
	assert.Contains(t, err.Error(), "could not be read",
		"and the reason must be the real one")
	// The LABEL is asserted, not just the reason. No test pinned any collect-path label,
	// so hardcoding it back to "content reference" — the defect an AC records as fixed —
	// left every failure message mislabelling a plan, system or external reference.
	assert.Contains(t, err.Error(), `external evidence "scans/gone.ndjson"`,
		"the message must name the reference KIND, not default to content reference")
	assert.NotContains(t, err.Error()+stderr, "outside the package's directory",
		"never blame containment for a file that is simply missing")
	assert.NoFileExists(t, out)
}

// Two ways to name a file outside the package are treated differently ON PURPOSE.
// An absolute path SAYS the evidence lives elsewhere: honest, so it is reported and
// the bundle proceeds. A symlink at an in-tree path CLAIMS the evidence is inside
// the package when it is not — a misrepresentation of where the evidence lives, and
// the containment signal SafePath exists to raise — so it fails the bundle loudly
// rather than being quietly listed as "not carried".
func TestEvidenceBundle_DistinguishesAnHonestOutsidePathFromAnEscapingSymlink(t *testing.T) {
	outside := t.TempDir()
	realFile := filepath.Join(outside, "real.ndjson")
	require.NoError(t, os.WriteFile(realFile, []byte("{}\n"), 0o600))

	t.Run("an absolute path outside is reported, and the bundle is still written", func(t *testing.T) {
		dir, pkgPath := bundleTree(t)
		_, _, err := executeCommand("evidence", "add-evidence", pkgPath,
			"--uri", realFile, "--format", "ecs", "-o", pkgPath)
		require.NoError(t, err)

		archive := filepath.Join(dir, "abs.zip")
		_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
		require.NoError(t, err)
		assert.Contains(t, stderr, "outside the package's directory")
		assert.FileExists(t, archive, "an honest outside reference does not stop the bundle")
	})

	t.Run("a symlink escaping the package fails the bundle", func(t *testing.T) {
		dir, pkgPath := bundleTree(t)
		link := filepath.Join(dir, "scans", "link.ndjson")
		require.NoError(t, os.Symlink(realFile, link))
		_, _, err := executeCommand("evidence", "add-evidence", pkgPath,
			"--uri", "scans/link.ndjson", "--format", "ecs", "-o", pkgPath)
		require.NoError(t, err)

		archive := filepath.Join(dir, "link.zip")
		_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", archive)
		require.Error(t, err, "a package claiming in-tree evidence that escapes must not bundle silently")
		assert.Contains(t, err.Error(), "resolves outside base directory via symlink",
			"and the reason must name the escape, not a generic read failure")
		assert.NoFileExists(t, archive)
	})
}

// add-evidence records a sha256 for every local artifact, so an externalEvidence
// checksum is a real integrity record and must be verified against the bytes that
// travel. It was discarded at read time, so a tampered in-tree artifact entered the
// archive with exit 0 under the claim "nothing else" — and `evidence info --verify` does
// not check external evidence either, so bundle is the only place those bytes are
// ever captured.
func TestEvidenceBundle_VerifiesExternalEvidenceChecksums(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	artifact := filepath.Join(dir, "scans", "audit.ndjson")
	require.NoError(t, os.WriteFile(artifact, []byte(`{"event":"ok"}`+"\n"), 0o600))
	// An ABSOLUTE path is passed so add-evidence finds the artifact and records a real
	// checksum; a package-relative uri is still resolved against the process CWD rather
	// than the package directory, which records no checksum and made an earlier version
	// of this test vacuous — it "passed" a tampered artifact with nothing to verify.
	// add-evidence now RECORDS that uri relatively, so the absolute form is restored
	// below; the checksum asserted first is what keeps the vacuity closed.
	_, _, err := executeCommand("evidence", "add-evidence", pkgPath,
		"--uri", artifact, "--format", "ecs", "-o", pkgPath)
	require.NoError(t, err)

	// Assert the precondition, so this test cannot silently stop testing anything.
	pkgData, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	var doc struct {
		ExternalEvidence []struct {
			Checksum struct{ Algorithm, Value string } `json:"checksum"`
		} `json:"externalEvidence"`
	}
	require.NoError(t, json.Unmarshal(pkgData, &doc))
	require.Len(t, doc.ExternalEvidence, 1)
	require.NotEmpty(t, doc.ExternalEvidence[0].Checksum.Value,
		"add-evidence must have recorded a checksum, or this test verifies nothing")
	// Record the uri absolutely so "what the package records" and "the derived ref" differ
	// again; the checksum above stays, so nothing about this test goes vacuous.
	recordAbsoluteExternalURI(t, pkgPath, artifact)

	// Bundles cleanly while the artifact matches what the package recorded.
	clean := filepath.Join(dir, "clean.zip")
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", clean)
	require.NoError(t, err)
	assert.Contains(t, zipEntries(t, clean), "scans/audit.ndjson")

	// Tamper with it. The recorded checksum now contradicts the bytes on disk.
	require.NoError(t, os.WriteFile(artifact, []byte("TAMPERED\n"), 0o600))
	out := filepath.Join(dir, "tampered.zip")
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", out)
	require.Error(t, err, "tampered external evidence must not travel")
	assert.Contains(t, err.Error(), "checksum mismatch")
	// Anchored on the FULL recorded uri immediately after "for", because the recorded
	// absolute path CONTAINS the derived relative ref as a substring — so asserting
	// only on "scans/audit.ndjson" passes whether the message quotes what the package
	// records or a ref derived from it, and pins neither.
	assert.Contains(t, err.Error(), "checksum mismatch for "+artifact,
		"the message must quote the uri the PACKAGE records, not a ref derived from it")
	assert.NoFileExists(t, out)
}

// Two contents[] entries may name the same file with their own recorded checksums.
// Verification therefore cannot live behind the dedup-on-first-sight branch: the
// second entry's checksum would never be checked.
func TestEvidenceBundle_VerifiesEveryReferenceToADuplicatedFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9-results.json"), src, 0o600))
	right := fmt.Sprintf("%x", sha256.Sum256(src))

	pkg, err := json.Marshal(map[string]any{
		"name": "dup",
		"contents": []map[string]any{
			// First reference is correct, so the file is collected and cached.
			{"type": "hdf-results", "uri": "scans/rhel9-results.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": right}},
			// Second names the same file — via a different spelling — and is WRONG.
			{"type": "hdf-results", "uri": "./scans/rhel9-results.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": strings.Repeat("a", 64)}},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	out := filepath.Join(dir, "dup.zip")
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", out)
	require.Error(t, err, "the second reference's checksum must be verified too")
	assert.Contains(t, err.Error(), "checksum mismatch")
	assert.NoFileExists(t, out)
}

// The schema's Hash_Algorithm enum is sha256|sha384|sha512|blake3, but the code
// hashed sha256 unconditionally — so a package recording a CORRECT sha512 was told
// "checksum mismatch … the file hashes to <a sha256>", which names the wrong thing
// and tells the operator their evidence changed when it did not.
func TestEvidenceBundle_HonoursTheRecordedChecksumAlgorithm(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	sum384, sum512 := sha512.Sum384(src), sha512.Sum512(src)
	// Through the engine, which is pinned to the BLAKE3 reference vectors by
	// hdf-engine's own tests, rather than hardcoded here where it would rot.
	blake3Of, err := hdfengine.ChecksumHex("blake3", src)
	require.NoError(t, err)

	for _, tc := range []struct {
		algorithm, value, wantErr string
	}{
		{"sha384", hex.EncodeToString(sum384[:]), ""},
		{"sha512", hex.EncodeToString(sum512[:]), ""},
		{"sha512", strings.Repeat("b", 128), "checksum mismatch"},
		// blake3 is now computed, so it belongs in this table on the same terms as the
		// others: a correct digest verifies and a wrong one aborts the bundle. Carrying a
		// blake3 document with its checksum merely REPORTED was the gap this closes.
		{"blake3", blake3Of, ""},
		{"blake3", strings.Repeat("b", 64), "checksum mismatch"},
	} {
		t.Run(tc.algorithm+"/"+tc.wantErr, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "r.json"), src, 0o600))
			pkg, marshalErr := json.Marshal(map[string]any{
				"name": "alg",
				"contents": []map[string]any{{
					"type": "hdf-results", "uri": "scans/r.json",
					"checksum": map[string]string{"algorithm": tc.algorithm, "value": tc.value},
				}},
			})
			require.NoError(t, marshalErr)
			pkgPath := filepath.Join(dir, "pkg.json")
			require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

			out := filepath.Join(dir, "alg.zip")
			_, _, bundleErr := executeCommand("evidence", "bundle", pkgPath, "-o", out)
			if tc.wantErr == "" {
				require.NoError(t, bundleErr, "a correct %s checksum must verify", tc.algorithm)
				assert.FileExists(t, out)
				return
			}
			require.Error(t, bundleErr)
			assert.Contains(t, bundleErr.Error(), tc.wantErr)
			assert.NoFileExists(t, out)
		})
	}
}

// contents[].uri has no minLength, so a schema-valid package can carry an entry
// that names nothing. Skipping it silently made the extent line ("every document in
// its contents[]") false for such a package, so the skip is reported.
func TestEvidenceBundle_ReportsAContentEntryWithNoURI(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.json"), src, 0o600))

	pkg, err := json.Marshal(map[string]any{
		"name": "empty-uri",
		"contents": []map[string]any{
			{"type": "hdf-results", "uri": "r.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": fmt.Sprintf("%x", sha256.Sum256(src))}},
			{"type": "hdf-results", "uri": ""},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	archive := filepath.Join(dir, "e.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.NotContains(t, stderr, "external evidence reference(s) record no uri",
		"a contents[] empty uri must not also be reported against externalEvidence")
	assert.Contains(t, stderr, "1 content reference(s) record no uri",
		"the extent claim is only honest if the skipped entry is named")
	assert.Contains(t, stderr, "every document it references that could travel",
		"and the claim itself must be qualified, not left literally false")
	assert.NotContains(t, stderr, "the package, every document it references,",
		"the unqualified claim must not appear when an entry named nothing")
	assert.FileExists(t, archive)
}

// Checksum.value has no minLength, so a schema-valid package can record a checksum
// with nothing in it. There is nothing to verify against, and `evidence info --verify`
// already tells the operator such an entry was skipped — so bundle must say so too,
// rather than printing an absolute extent claim over an unverified document.
func TestEvidenceBundle_ReportsAnEmptyChecksumValue(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.json"), src, 0o600))

	pkg, err := json.Marshal(map[string]any{
		"name": "empty-sum",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "r.json",
			"checksum": map[string]string{"algorithm": "sha256", "value": ""},
		}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	archive := filepath.Join(dir, "e.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.Contains(t, stderr, "1 reference(s) record an empty checksum value",
		"an unverifiable document must not travel under a silent extent claim")
	assert.FileExists(t, archive, "the archive is still written; the point is that the gap is stated")
}

// An externalEvidence entry may also record an empty uri and stay schema-valid.
// Dropping it at read time was the same silent-skip defect already fixed for
// contents[], left in place one array over.
func TestEvidenceBundle_ReportsExternalEvidenceWithNoURI(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	pkgData, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(pkgData, &doc))
	doc["externalEvidence"] = []map[string]any{{"uri": "", "format": "ecs"}}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	archive := filepath.Join(dir, "x.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.NotContains(t, stderr, "content reference(s) record no uri",
		"an externalEvidence empty uri must not also be reported against contents[]")
	assert.Contains(t, stderr, "1 external evidence reference(s) record no uri",
		"an entry that names nothing must be reported, not dropped")
}

// Writing the archive over an input destroys the operator's evidence. It used to
// report success while doing it, in the command whose help argues that a bundle
// which looks complete but is not is worse than none.
func TestEvidenceBundle_RefusesToOverwriteAnInput(t *testing.T) {
	t.Run("the package itself", func(t *testing.T) {
		_, pkgPath := bundleTree(t)
		before, err := os.ReadFile(pkgPath)
		require.NoError(t, err)

		_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", pkgPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "over the evidence package itself")
		after, err := os.ReadFile(pkgPath)
		require.NoError(t, err)
		assert.Equal(t, before, after, "the package must be byte-for-byte untouched")
	})

	t.Run("a document the package references", func(t *testing.T) {
		dir, pkgPath := bundleTree(t)
		doc := filepath.Join(dir, "scans", "rhel9-results.json")
		before, err := os.ReadFile(doc)
		require.NoError(t, err)

		_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", doc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "content reference")
		// The message must quote the uri AS RECORDED — here a package-relative path —
		// and not the absolute path the guard joined to compare with. Asserting only
		// the label, or only a substring both spellings share, cannot tell the two
		// apart: that is why reverting this fix once left the whole suite green.
		assert.Contains(t, err.Error(), `"scans/rhel9-results.json"`,
			"the refusal must quote the recorded relative uri")
		assert.NotContains(t, err.Error(), dir,
			"and must not quote the absolute path derived from it")
		after, err := os.ReadFile(doc)
		require.NoError(t, err)
		assert.Equal(t, before, after, "the referenced document must be byte-for-byte untouched")
	})
}

// The overwrite guard must cover every reference the package RECORDS, not the subset
// that ends up travelling. An out-of-tree externalEvidence artifact does not travel —
// it is reported as "not carried" — but it is still a document the package references,
// and scoping the guard to the entries slice let the command destroy exactly the kind
// of artifact that cannot be regenerated, while printing "still recorded in the
// package's externalEvidence" about the file it had just overwritten.
func TestEvidenceBundle_RefusesToOverwriteExternalEvidence(t *testing.T) {
	for _, tc := range []struct{ name, where string }{
		{"in the package's own subtree", "inside"},
		{"outside it, so it never travels", "outside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, pkgPath := bundleTree(t)
			artifact := filepath.Join(dir, "scans", "corpus.ndjson")
			if tc.where == "outside" {
				artifact = filepath.Join(t.TempDir(), "corpus.ndjson")
			}
			const irreplaceable = `{"event":"cannot be regenerated"}` + "\n"
			require.NoError(t, os.WriteFile(artifact, []byte(irreplaceable), 0o600))
			_, _, err := executeCommand("evidence", "add-evidence", pkgPath,
				"--uri", artifact, "--format", "ecs", "-o", pkgPath)
			require.NoError(t, err)
			// As above: keep the recorded uri absolute so the refusal's quoting is pinned.
			recordAbsoluteExternalURI(t, pkgPath, artifact)

			_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", artifact)
			require.Error(t, err, "the archive must not be written over recorded evidence")
			assert.Contains(t, err.Error(), artifact,
				"and the refusal must quote the uri the package records")
			assert.Contains(t, err.Error(), "the external evidence this package records",
				"and name which kind of reference it is protecting")
			after, readErr := os.ReadFile(artifact)
			require.NoError(t, readErr)
			assert.Equal(t, irreplaceable, string(after), "the artifact must be untouched")
		})
	}
}

// An externalEvidence checksum recorded with an empty value must be reported too, not
// only a contents[] one. Counting it in the contents loop alone left a TAMPERED
// artifact travelling unverified at exit 0 — round 3's lead defect, reachable again
// through a schema-valid package shape.
func TestEvidenceBundle_ReportsAnEmptyExternalChecksumValue(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	artifact := filepath.Join(dir, "scans", "audit.ndjson")
	require.NoError(t, os.WriteFile(artifact, []byte(`{"event":"ok"}`+"\n"), 0o600))
	_, _, err := executeCommand("evidence", "add-evidence", pkgPath,
		"--uri", artifact, "--format", "ecs", "-o", pkgPath)
	require.NoError(t, err)

	// Blank the recorded value, keeping the package schema-valid.
	pkgData, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(pkgData, &doc))
	ext := doc["externalEvidence"].([]any)
	require.Len(t, ext, 1)
	ext[0].(map[string]any)["checksum"].(map[string]any)["value"] = ""
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	// Tamper with it, so an unreported skip would mean tampered bytes travelling.
	require.NoError(t, os.WriteFile(artifact, []byte("TAMPERED\n"), 0o600))
	archive := filepath.Join(dir, "x.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.Contains(t, stderr, "1 reference(s) record an empty checksum value",
		"an externalEvidence entry with a blank recorded value must be reported, like a contents[] one")
}

// A whitespace-only recorded value is unverifiable, not a mismatch. Hashing against it
// reported "the package records <blank> but the file hashes to …", presenting an
// unverifiable record as a changed file — the same wording defect fixed for algorithms.
func TestEvidenceBundle_TreatsABlankChecksumAsUnverifiableNotChanged(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.json"), src, 0o600))
	pkg, err := json.Marshal(map[string]any{
		"name": "blank",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "r.json",
			"checksum": map[string]string{"algorithm": "sha256", "value": "   "},
		}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	archive := filepath.Join(dir, "b.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err, "a blank record is not evidence that the file changed")
	assert.NotContains(t, stderr, "checksum mismatch")
	assert.Contains(t, stderr, "1 reference(s) record an empty checksum value")
}

// -o naming a directory produced "rename … file exists", which is neither true nor
// actionable.
func TestEvidenceBundle_RefusesADirectoryAsOutput(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "scans"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is a directory; name the archive file to write")
	assert.NotContains(t, err.Error(), "file exists")
}

// The same data-loss bug recurred FOUR times, once per reference field a hand-written
// list forgot — and the third fix moved the enumeration into one place while leaving it
// an enumeration, so a fifth field (externalReferences[].href) was still missed. This
// test makes the SCHEMA the authority for real: it walks the evidence-package schema
// through its $refs, including into primitives/, and collects every leaf declaring a
// location format — uri-reference, uri, iri, iri-reference or uri-template, since the
// schema already uses "uri" on leaves elsewhere. A $ref it cannot follow fails the test by
// name rather than being skipped, because a silently incomplete walk is how the fifth
// field stayed hidden. Adding any new reference field, in any shape, breaks it.
func TestEvidenceBundle_CoversEverySchemaReferenceField(t *testing.T) {
	schemaDir := filepath.Join("..", "..", "..", "..", "hdf-schema", "src", "schemas")
	load := func(rel string) map[string]any {
		raw, err := os.ReadFile(filepath.Join(schemaDir, rel))
		require.NoError(t, err, "the schema is the authority for what a package can reference")
		var doc map[string]any
		require.NoError(t, json.Unmarshal(raw, &doc))
		return doc
	}
	root := load("hdf-evidence-package.schema.json")

	// $refs come in two forms here: local "#/$defs/X" and
	// "…/primitives/<file>/vN#/$defs/X". Both must be followed, or the walk misses
	// every type declared in primitives — which is where External_Reference lives.
	primitiveRef := regexp.MustCompile(`primitives/([a-z-]+)/v[\d.]+#/\$defs/(\w+)`)
	localRef := regexp.MustCompile(`^#/\$defs/(\w+)$`)
	resolve := func(ref string, cur map[string]any) (map[string]any, map[string]any) {
		if m := localRef.FindStringSubmatch(ref); m != nil {
			defs, _ := cur["$defs"].(map[string]any)
			if node, ok := defs[m[1]].(map[string]any); ok {
				return node, cur
			}
			return nil, cur
		}
		if m := primitiveRef.FindStringSubmatch(ref); m != nil {
			doc := load(filepath.Join("primitives", m[1]+".schema.json"))
			defs, _ := doc["$defs"].(map[string]any)
			if node, ok := defs[m[2]].(map[string]any); ok {
				return node, doc
			}
		}
		return nil, cur
	}

	found := map[string]bool{}
	visited := map[string]bool{}
	var walk func(node, cur map[string]any, path string, depth int)
	walk = func(node, cur map[string]any, path string, depth int) {
		if node == nil || depth > 12 {
			return
		}
		if ref, ok := node["$ref"].(string); ok {
			key := ref + "@" + path
			if visited[key] {
				return
			}
			visited[key] = true
			target, newCur := resolve(ref, cur)
			// A $ref this walk cannot follow makes it silently incomplete, which is
			// exactly how a reference field stayed hidden for three rounds. Fail loudly
			// instead: a new $ref spelling is a signal to extend the resolver.
			require.NotNil(t, target,
				"cannot resolve $ref %q at %s — extend resolve() so the walk stays complete", ref, path)
			walk(target, newCur, path, depth+1)
			return
		}
		// Every location format, not just uri-reference: the schema already uses
		// `format: uri` on eleven leaves elsewhere in primitives/, so collecting one
		// spelling would miss a reference field added with another.
		switch format, _ := node["format"].(string); format {
		case "uri-reference", "uri", "iri", "iri-reference", "uri-template":
			found[path] = true
		}
		if props, ok := node["properties"].(map[string]any); ok {
			for name, sub := range props {
				if subNode, ok := sub.(map[string]any); ok {
					walk(subNode, cur, path+"."+name, depth+1)
				}
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(items, cur, path+"[]", depth+1)
		}
		for _, comb := range []string{"oneOf", "anyOf", "allOf"} {
			if list, ok := node[comb].([]any); ok {
				for _, sub := range list {
					if subNode, ok := sub.(map[string]any); ok {
						walk(subNode, cur, path, depth+1)
					}
				}
			}
		}
	}
	walk(root, root, "", 0)
	require.NotEmpty(t, visited, "the walk must actually follow $refs, or it proves nothing")

	paths := make([]string, 0, len(found))
	for p := range found {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	assert.Equal(t, []string{
		".contents[].uri",
		".extensions.rawSourceArtifacts[].href",
		".externalEvidence[].uri",
		".externalReferences[].href",
		".planRef",
		".systemRef",
	}, paths,
		"the schema's reference fields changed. Add the new one to evidenceref.Collect (which recordedRefs, "+
			"the -o guard and the collection loop all derive from) and to this list, then add it "+
			"to the package built below so its coverage is actually proven")

	// Every one of those fields, populated, must come back from recordedRefs.
	pkg := map[string]any{
		"name":      "coverage",
		"systemRef": "sys.json",
		"planRef":   "meta/plan.json",
		"contents":  []map[string]any{{"type": "hdf-results", "uri": "scans/r.json"}},
		"externalEvidence": []map[string]any{
			{"uri": "scans/audit.ndjson", "format": "ecs"},
		},
		"externalReferences": []map[string]any{
			{"sourceName": "runbook", "href": "scans/runbook.json"},
		},
		// The sixth field. A Raw_Source_Artifact carries the converter's input bytes
		// inline, so its href is a reader-meaningful location rather than a file the
		// archive carries — refContext, like externalReferences[]. Populated here so the
		// coverage this test asserts is proven rather than only listed above.
		"extensions": map[string]any{
			"rawSourceArtifacts": []map[string]any{
				{"sourceName": "nessus", "href": "scans/original.nessus", "rel": "raw-source"},
			},
		},
	}
	pkgData, err := json.Marshal(pkg)
	require.NoError(t, err)
	_, contents, err := hdfengine.ParseEvidencePackage(pkgData)
	require.NoError(t, err)

	refs, err := recordedRefs(pkgData, contents)
	require.NoError(t, err)
	got := map[string]string{}
	for _, r := range refs {
		if r.uri != "" {
			got[r.uri] = r.label
		}
	}
	assert.Equal(t, map[string]string{
		"sys.json":              "system reference",
		"meta/plan.json":        "plan reference",
		"scans/r.json":          "content reference",
		"scans/audit.ndjson":    "external evidence",
		"scans/runbook.json":    "external reference",
		"scans/original.nessus": "raw source artifact",
	}, got, "every reference field the schema declares must reach recordedRefs")
}

// An archive must be self-sufficient: `evidence info --verify` reads planRef for its
// completeness check, so a package whose planRef is NOT duplicated in contents[] used
// to verify in the original tree and fail on the extracted copy. The plan was silently
// absent, with no "not carried" line, under the claim "nothing else".
func TestEvidenceBundle_CarriesPlanAndSystemRefsNotListedInContents(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "meta"), 0o750))
	copyIn := func(fixture, dest string) {
		src, readErr := os.ReadFile(filepath.Join(evidenceFixtureDir, fixture))
		require.NoError(t, readErr)
		require.NoError(t, os.WriteFile(filepath.Join(dir, dest), src, 0o600))
	}
	copyIn("rhel9-results.json", "r.json")
	copyIn("postgres-results.json", "p.json")
	copyIn("plan.json", filepath.Join("meta", "plan.json"))
	copyIn("system.json", "sys.json")

	// Both results are listed because the plan names two baselines, and verify's
	// completeness check would otherwise fail for a reason unrelated to bundling.
	sumOf := func(name string) string {
		data, readErr := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, readErr)
		return fmt.Sprintf("%x", sha256.Sum256(data))
	}
	pkg, err := json.Marshal(map[string]any{
		"name":      "root-refs",
		"planRef":   "meta/plan.json",
		"systemRef": "sys.json",
		"contents": []map[string]any{
			{"type": "hdf-results", "uri": "r.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": sumOf("r.json")}},
			{"type": "hdf-results", "uri": "p.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": sumOf("p.json")}},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	archive := filepath.Join(dir, "a.zip")
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)

	entries := zipEntries(t, archive)
	assert.Contains(t, entries, "meta/plan.json", "the planRef document must travel")
	assert.Contains(t, entries, "sys.json", "and so must the systemRef document")

	// The real proof: verify the EXTRACTED copy, which is what an assessor receives.
	extracted := t.TempDir()
	for name, data := range entries {
		dest := filepath.Join(extracted, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(dest), 0o750))
		require.NoError(t, os.WriteFile(dest, data, 0o600))
	}
	_, _, err = executeCommand("evidence", "info", "--verify", filepath.Join(extracted, "pkg.json"))
	require.NoError(t, err, "the extracted archive must verify with no path rewriting")
}

// A case-only difference names the SAME file on a case-insensitive filesystem (APFS,
// NTFS), so comparing Abs strings accepted an -o that destroyed a recorded document.
// os.SameFile compares device and inode and sees through it. Skipped where the
// filesystem is case-sensitive, because there the two names are genuinely two files.
func TestEvidenceBundle_RefusesACaseOnlySpellingOfARecordedDocument(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(dir, "CaseProbe")
	require.NoError(t, os.WriteFile(probe, []byte("x"), 0o600))
	if _, err := os.Stat(filepath.Join(dir, "caseprobe")); err != nil {
		t.Skip("filesystem is case-sensitive; a case-only spelling is a different file here")
	}

	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Results.json"), src, 0o600))
	pkg, err := json.Marshal(map[string]any{
		"name": "case",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "Results.json",
			"checksum": map[string]string{"algorithm": "sha256", "value": fmt.Sprintf("%x", sha256.Sum256(src))},
		}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "results.json"))
	require.Error(t, err, "a case-only spelling names the same file here and must be refused")
	after, err := os.ReadFile(filepath.Join(dir, "Results.json"))
	require.NoError(t, err)
	assert.Equal(t, src, after, "the recorded document must be untouched")
}

// -o naming the planRef or systemRef target destroyed it at exit 0. They are two of the
// schema's five reference fields, and the guard covered only contents[] and
// externalEvidence[] at the time.
func TestEvidenceBundle_RefusesToOverwriteARootReference(t *testing.T) {
	for _, field := range []string{"planRef", "systemRef"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "r.json"), src, 0o600))
			const irreplaceable = `{"IRREPLACEABLE":"plan"}` + "\n"
			target := filepath.Join(dir, "target.json")
			require.NoError(t, os.WriteFile(target, []byte(irreplaceable), 0o600))

			pkg, err := json.Marshal(map[string]any{
				"name": "root-ref", field: "target.json",
				"contents": []map[string]any{{
					"type": "hdf-results", "uri": "r.json",
					"checksum": map[string]string{"algorithm": "sha256", "value": fmt.Sprintf("%x", sha256.Sum256(src))},
				}},
			})
			require.NoError(t, err)
			pkgPath := filepath.Join(dir, "pkg.json")
			require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

			_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", target)
			require.Error(t, err, "%s names a document this package records", field)
			assert.Contains(t, err.Error(), `"target.json"`, "and the refusal quotes the recorded uri")
			// The label too: a literal "content reference" here passed every test, so a
			// planRef or systemRef target was refused under the wrong noun.
			assert.Contains(t, err.Error(), "the "+strings.TrimSuffix(field, "Ref")+" reference this package records",
				"the refusal must name which kind of reference it is protecting")
			after, err := os.ReadFile(target)
			require.NoError(t, err)
			assert.Equal(t, irreplaceable, string(after), "the document must be untouched")
		})
	}
}

// externalReferences[].href is the FIFTH reference field — inert context (CTI/STIX,
// advisories), never evidence and never carried, but still a location the package
// records. A hand-written list of four missed it, so -o destroyed the artifact it named
// at exit 0. Whether such a reference should travel is a contract question; that it must
// not be obliterated is not.
func TestEvidenceBundle_GuardsAnExternalReferenceWithoutCarryingIt(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	const irreplaceable = `{"runbook":"cannot be regenerated"}` + "\n"
	runbook := filepath.Join(dir, "scans", "runbook.json")
	require.NoError(t, os.WriteFile(runbook, []byte(irreplaceable), 0o600))

	pkgData, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(pkgData, &doc))
	doc["externalReferences"] = []map[string]any{
		{"sourceName": "runbook", "href": "scans/runbook.json"},
	}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	t.Run("it is not carried, and the report names the field recording it", func(t *testing.T) {
		archive := filepath.Join(dir, "ctx.zip")
		_, stderr, bundleErr := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
		require.NoError(t, bundleErr)
		assert.NotContains(t, zipEntries(t, archive), "scans/runbook.json",
			"inert context is not evidence and does not travel")
		assert.Contains(t, stderr, "recorded in externalReferences",
			"and the report must name the field that records it, not assume externalEvidence")
		assert.Contains(t, stderr, "(context, not evidence)",
			"inert context must be reported as context, not as remote or out-of-tree")
		assert.NotContains(t, stderr, "(remote)",
			"this href is local — reporting it as remote would be a different claim")
	})

	t.Run("but -o may not destroy it", func(t *testing.T) {
		_, _, bundleErr := executeCommand("evidence", "bundle", pkgPath, "-o", runbook)
		require.Error(t, bundleErr, "an externalReferences href is a recorded location")
		assert.Contains(t, bundleErr.Error(), `"scans/runbook.json"`)
		assert.Contains(t, bundleErr.Error(), "the external reference this package records",
			"and name which kind of reference it is protecting")
		after, readErr := os.ReadFile(runbook)
		require.NoError(t, readErr)
		assert.Equal(t, irreplaceable, string(after))
	})
}

// A non-carryable reference must be attributed to the field that actually records it.
// The suffix was hardcoded to externalEvidence, so a remote planRef was reported as
// "still recorded in the package's externalEvidence" — where it is not, leaving an
// operator grepping that array to find nothing.
func TestEvidenceBundle_AttributesANonCarryableReferenceToItsOwnField(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.json"), src, 0o600))
	pkg, err := json.Marshal(map[string]any{
		"name":    "remote-plan",
		"planRef": "https://plans.example/q3.json",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "r.json",
			"checksum": map[string]string{"algorithm": "sha256", "value": fmt.Sprintf("%x", sha256.Sum256(src))},
		}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "a.zip"))
	require.NoError(t, err)
	assert.Contains(t, stderr, "recorded in planRef",
		"a remote planRef is recorded in planRef")
	assert.NotContains(t, stderr, "recorded in externalEvidence",
		"and must not be attributed to an array that does not contain it")
}

// A planRef or systemRef recorded as an ABSOLUTE path is legitimate — `evidence set
// --plan-ref /abs/path` produces one — and if it resolves inside the package it must be
// carried, consistently with an absolute externalEvidence uri. Routing root references
// through the contents[] shape check instead aborted the bundle AND described a plan
// reference as a "content reference" in the same sentence.
func TestEvidenceBundle_CarriesAnAbsoluteRootReferenceThatResolvesInTree(t *testing.T) {
	dir := t.TempDir()
	copyIn := func(fixture, dest string) {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, fixture))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, dest), src, 0o600))
	}
	copyIn("rhel9-results.json", "r.json")
	copyIn("postgres-results.json", "p.json")
	copyIn("plan.json", "plan.json")
	sumOf := func(name string) string {
		data, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		return fmt.Sprintf("%x", sha256.Sum256(data))
	}

	// The plan is deliberately NOT in contents[]: an earlier version of this test used
	// bundleTree, whose contents[] already lists plan.json, so "plan.json is in the
	// archive" was satisfied by the contents[] branch whatever the root reference did.
	// The assertion could not separate the two behaviours it named, and a mutant that
	// never resolved an absolute root reference left the whole suite green.
	pkg, err := json.Marshal(map[string]any{
		"name":    "abs-root",
		"planRef": filepath.Join(dir, "plan.json"), // absolute, in-tree, contents[]-free
		"contents": []map[string]any{
			{"type": "hdf-results", "uri": "r.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": sumOf("r.json")}},
			{"type": "hdf-results", "uri": "p.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": sumOf("p.json")}},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	archive := filepath.Join(dir, "abs.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err, "an absolute root reference resolving in-tree must be carried, not abort")

	entries := zipEntries(t, archive)
	assert.Contains(t, entries, "plan.json",
		"the only reference to the plan is an absolute planRef, so this fails unless it resolved")
	assert.NotContains(t, stderr, "not carried",
		"and it must not be reported as unable to travel")
}

// -o whose parent directory is absent used to fail after every read and hash, naming a
// temp path the operator never typed ("open nope/.hdf-bundle-3129740691").
func TestEvidenceBundle_RefusesAMissingOutputDirectoryByName(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "nope", "a.zip"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	assert.NotContains(t, err.Error(), ".hdf-bundle-",
		"the error must not name an internal temp file")
}

// The extent sentence must be qualified whenever a referenced DOCUMENT did not travel —
// for ANY reason, not only an empty uri. Hooking the qualifier to the empty-uri counter
// alone left "every document it references" printed while a remote or out-of-tree
// document was absent, which is the same false-claim defect the card already ruled on for
// the empty-uri case: a separate notice does not make a false sentence true.
func TestEvidenceBundle_QualifiesTheExtentForEveryReasonADocumentIsAbsent(t *testing.T) {
	for _, tc := range []struct{ name, planRef string }{
		{"a remote planRef", "https://plans.example/q3.json"},
		{"a planRef outside the package", filepath.Join("..", "outside-plan.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(parent, "outside-plan.json"), []byte("{}\n"), 0o600))
			dir := filepath.Join(parent, "pkg")
			require.NoError(t, os.MkdirAll(dir, 0o750))
			src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "r.json"), src, 0o600))

			pkg, err := json.Marshal(map[string]any{
				"name": "drop", "planRef": tc.planRef,
				"contents": []map[string]any{{
					"type": "hdf-results", "uri": "r.json",
					"checksum": map[string]string{"algorithm": "sha256", "value": fmt.Sprintf("%x", sha256.Sum256(src))},
				}},
			})
			require.NoError(t, err)
			pkgPath := filepath.Join(dir, "pkg.json")
			require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

			archive := filepath.Join(dir, "a.zip")
			_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
			require.NoError(t, err)

			// The plan is genuinely absent from the archive...
			assert.NotContains(t, zipEntries(t, archive), "plan.json")
			// ...so the sentence must not claim every referenced document.
			assert.NotContains(t, stderr, "every document it references —",
				"the unqualified claim is false while a referenced document is absent")
			assert.NotContains(t, stderr, "every document it references,",
				"the unqualified claim is false while a referenced document is absent")
			assert.Contains(t, stderr, "that could travel",
				"the claim must be qualified for this drop reason too")
		})
	}
}

// The -o guard runs before any REFERENCED DOCUMENT is read, so a failure reading one cannot
// mask it. The package itself is necessarily read first, since the references derive from it.
// That placement had no assertion: moving the guard back after collection left the whole
// suite green. Pinned by a package with BOTH faults, asserting the -o error wins.
func TestEvidenceBundle_RefusesTheOutputBeforeReadingAnything(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	// Fault one: a referenced document is missing, which fails during collection.
	require.NoError(t, os.Remove(filepath.Join(dir, "scans", "postgres-results.json")))

	// Fault two: -o names another referenced document. The boundary check must win.
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "system.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to write the archive over",
		"the output check must fire before the read that would otherwise fail first")
	assert.NotContains(t, err.Error(), "could not be read",
		"a collection failure must not mask the -o refusal")
}

// samePath asks os.SameFile first and falls back to a lexical compare, and the AC names that
// ordering. The fallback is the only branch available when the output does not exist on disk —
// which is the case for a reference the package records but whose file is absent. Deleting the
// fallback left the suite green: the existing boundary test uses a reference that DOES exist,
// so os.SameFile covers it and the lexical branch is never reached.
func TestEvidenceBundle_RefusesAnOutputNamingAnAbsentRecordedReference(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	ghost := filepath.Join(dir, "scans", "ghost.json")
	pkgData, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(pkgData, &doc))
	contents := doc["contents"].([]any)
	doc["contents"] = append(contents, map[string]any{"type": "hdf-results", "uri": "scans/ghost.json"})
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))
	require.NoFileExists(t, ghost, "the reference is recorded but the file is absent")

	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", ghost)
	require.Error(t, err)
	// The -o refusal must win, decided lexically since neither path can be stat'd.
	assert.Contains(t, err.Error(), "refusing to write the archive over",
		"a recorded reference must be protected even when its file is absent")
	assert.NotContains(t, err.Error(), "could not be read",
		"the read failure must not mask the -o refusal")
}

// packageSubtreeRef makes TWO containment attempts: lexical, then symlink-resolved. Only the
// lexical one was pinned. The resolved attempt is what handles a uri and a package directory
// spelled through different symlinks for the same place — on macOS, /tmp versus /private/tmp,
// the spelling this function's own history records biting this card twice. With it dead, the
// artifact is silently dropped and blamed on containment: the same false-message defect
// TestEvidenceBundle_MissingInTreeExternalEvidenceIsHonest pins for the lexical branch.
func TestEvidenceBundle_ResolvesContainmentThroughASymlinkedSpelling(t *testing.T) {
	actual := t.TempDir()
	linked := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(actual, linked))

	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(actual, "r.json"), src, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(actual, "art.ndjson"), []byte(`{"e":1}`+"\n"), 0o600))

	// The package sits under the REAL path; the artifact is recorded through the SYMLINK.
	// Only the symlink-resolved attempt can see that these name one directory.
	pkg, err := json.Marshal(map[string]any{
		"name": "symlinked",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "r.json",
			"checksum": map[string]string{"algorithm": "sha256", "value": fmt.Sprintf("%x", sha256.Sum256(src))},
		}},
		"externalEvidence": []map[string]any{
			{"uri": filepath.Join(linked, "art.ndjson"), "format": "ecs"},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(actual, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	archive := filepath.Join(actual, "s.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.Contains(t, zipEntries(t, archive), "art.ndjson",
		"the artifact is inside the package directory under a different spelling and must travel")
	assert.NotContains(t, stderr, "outside the package's directory",
		"never blame containment for a spelling difference")
	assert.Contains(t, stderr, "in-tree external evidence",
		"and the extent sentence must claim it")
}

// -o is required, and the check belongs at the boundary. Without it the failure surfaced from
// os.CreateTemp after every read and hash, naming an internal temp path the operator never
// typed — exactly what RefusesAMissingOutputDirectoryByName asserts against for its sibling.
func TestEvidenceBundle_RequiresAnOutputPath(t *testing.T) {
	_, pkgPath := bundleTree(t)
	_, _, err := executeCommand("evidence", "bundle", pkgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-o is required")
	assert.NotContains(t, err.Error(), ".hdf-bundle-",
		"the error must not name an internal temp file")
	assert.NotContains(t, err.Error(), "rename",
		"nor surface as a filesystem failure after the work is done")
}

// The counterpart of the verify case: bundle schema-validates too, so an algorithm it
// cannot compute cannot reach the checksum layer. A checksum that is RECORDED BUT BLANK
// remains the reachable "carried and reported as unverified" case, covered by
// TestEvidenceBundle_ReportsAnEmptyChecksumValue and
// TestEvidenceBundle_TreatsABlankChecksumAsUnverifiableNotChanged.
func TestEvidenceBundle_RefusesAnOffSchemaChecksumAlgorithm(t *testing.T) {
	dir, _ := bundleTree(t)
	pkg := map[string]any{
		"name": "off-schema-algorithm",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "scans/rhel9-results.json",
			"checksum": map[string]string{
				"algorithm": "md5",
				"value":     "d41d8cd98f00b204e9800998ecf8427e",
			},
		}},
	}
	data, err := json.Marshal(pkg)
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "offschema.json")
	require.NoError(t, os.WriteFile(pkgPath, data, 0o600))
	out := filepath.Join(dir, "offschema.zip")

	_, _, bundleErr := executeCommand("evidence", "bundle", pkgPath, "-o", out)
	require.Error(t, bundleErr, "an off-schema algorithm is refused at validation")
	assert.Contains(t, bundleErr.Error(), "contents.0.checksum.algorithm",
		"the refusal points at the offending field; the validator names the admitted set, not the value")
	assert.NoFileExists(t, out, "and no archive is written")
}

// absolutePlanRefTree builds a package whose planRef is an absolute in-subtree path,
// written directly because `evidence set` now normalizes exactly this shape. Packages in
// this state still arrive from hand-editing and from other producers, so bundle must cope.
func absolutePlanRefTree(t *testing.T) (dir, pkgPath string) {
	t.Helper()
	dir, pkgPath = bundleTree(t)
	doc := readEvidenceDoc(t, pkgPath)
	doc["planRef"] = filepath.Join(dir, "plan.json")
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))
	return dir, pkgPath
}

// extractZip unpacks an archive into its own directory, which is the only way to observe
// this defect: the archive LISTING is correct, so asserting on entry names proves nothing.
func extractZip(t *testing.T, archive, dest string) {
	t.Helper()
	r, err := zip.OpenReader(archive)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	for _, f := range r.File {
		require.False(t, filepath.IsAbs(f.Name) || strings.Contains(f.Name, ".."),
			"archive entry %q must stay inside the extraction directory", f.Name)
		target := filepath.Join(dest, filepath.FromSlash(f.Name))
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
		rc, openErr := f.Open()
		require.NoError(t, openErr)
		body, readErr := io.ReadAll(rc)
		_ = rc.Close()
		require.NoError(t, readErr)
		require.NoError(t, os.WriteFile(target, body, 0o600))
	}
}

// The archive must not be internally inconsistent in silence: the bytes travelled under a
// relative name while the package still names the producing machine's path.
func TestEvidenceBundle_ReportsAReferenceTheExtractedPackageCannotResolve(t *testing.T) {
	dir, pkgPath := absolutePlanRefTree(t)
	before, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	archive := filepath.Join(dir, "boe.zip")

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err, "an absolute in-subtree ref is reported, not refused")

	assert.Contains(t, stderr, "planRef", "the report must name the field that records it")
	assert.Contains(t, stderr, "will not resolve",
		"and must say the extracted copy will not resolve it")

	// Rewriting nothing is the point of this card: the archived package is the input.
	entries := zipEntries(t, archive)
	assert.Equal(t, before, entries["pkg.json"],
		"the archived package must be byte-identical to the input package")
}

// The externalEvidence sibling of ReportsAReferenceTheExtractedPackageCannotResolve. An
// in-package artifact IS carried, so an absolutely-recorded externalEvidence uri has the
// same defect a document reference does — and this half of the report went in by widening
// one condition, which no test covered until this one.
func TestEvidenceBundle_ReportsExternalEvidenceTheExtractedPackageCannotResolve(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "logs"), 0o750))
	artifact := filepath.Join(dir, "logs", "audit.ndjson")
	require.NoError(t, os.WriteFile(artifact, []byte("{\"message\":\"audit\"}\n"), 0o600))
	_, _, err := executeCommand("evidence", "add-evidence", pkgPath,
		"--uri", artifact, "--format", "ecs", "-o", pkgPath)
	require.NoError(t, err)
	// add-evidence now normalizes, so the bad state is written directly — it still arrives
	// by hand editing and from other producers.
	recordAbsoluteExternalURI(t, pkgPath, artifact)
	before, err := os.ReadFile(pkgPath)
	require.NoError(t, err)

	archive := filepath.Join(dir, "boe.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err, "an absolute in-package external uri is reported, not refused")

	assert.Contains(t, stderr, "externalEvidence",
		"the report must name the field that records it")
	assert.Contains(t, stderr, "will not resolve",
		"and say the extracted copy will not resolve it")
	// Anchored on "carried as ", because the RECORDED absolute path printed earlier in the
	// same line ends with "logs/audit.ndjson" — so the bare substring passes even when the
	// code prints a wrong entry name. Same trap the checksum-mismatch test anchors against.
	// Terminated with ", so" as well as prefixed with "carried as ": without the terminator
	// an appended suffix ("logs/audit.ndjson-BOGUS") still satisfies the assertion, and
	// without the prefix the recorded absolute path ending in the same substring does.
	assert.Contains(t, stderr, "carried as logs/audit.ndjson, so",
		"and name the entry it was actually carried as, exactly")

	entries := zipEntries(t, archive)
	assert.Contains(t, entries, "logs/audit.ndjson", "the artifact still travels")
	assert.Equal(t, before, entries["pkg.json"],
		"and the archived package is byte-identical to the input")
}

// The card's named test. A relative reference survives extraction into an unrelated
// directory, and completeness is checked there — which is what the defect silently cost.
func TestEvidenceBundle_TheExtractedPackageResolvesItsOwnReferences(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	require.Equal(t, "plan.json", readEvidenceDoc(t, pkgPath)["planRef"],
		"precondition: build records a package-relative planRef")
	// External evidence travels too, so it belongs in the good-path check: added with an
	// ABSOLUTE in-package path, which add-evidence now records relatively.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "logs"), 0o750))
	artifact := filepath.Join(dir, "logs", "audit.ndjson")
	require.NoError(t, os.WriteFile(artifact, []byte("{\"message\":\"audit\"}\n"), 0o600))
	_, _, addErr := executeCommand("evidence", "add-evidence", pkgPath,
		"--uri", artifact, "--format", "ecs", "-o", pkgPath)
	require.NoError(t, addErr)
	require.Equal(t, "logs/audit.ndjson",
		firstExternalURI(t, pkgPath), "precondition: recorded relative to the package")
	archive := filepath.Join(dir, "boe.zip")
	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)

	dest := t.TempDir() // unrelated to dir
	extractZip(t, archive, dest)

	extracted := filepath.Join(dest, "pkg.json")
	assert.Equal(t, "plan.json", readEvidenceDoc(t, extracted)["planRef"],
		"the extracted package names the carried file, not a path on the producing machine")

	_, stderr, verifyErr := executeCommand("evidence", "info", "--verify", extracted)
	require.NoError(t, verifyErr, "the extracted copy verifies where it was extracted")
	// Positive and negative: the absence alone cannot tell a check that RAN from a line the
	// code simply stopped printing.
	assert.Contains(t, stderr, "Completeness check passed",
		"completeness must actually run in the extraction directory, not merely not-skip")
	assert.NotContains(t, stderr, "completeness was not checked",
		"completeness must be checked in the extraction directory")
	assert.NotContains(t, stderr, "not reachable here",
		"and no reference may be unreachable there")
}

// recordAbsoluteExternalURI rewrites the package's first externalEvidence uri to an
// absolute path, AFTER add-evidence has computed a real checksum for the artifact.
// add-evidence now normalizes an in-package absolute uri to a relative one, so a package
// in this state can no longer be produced by that command — but it still arrives by hand
// editing and from other producers, and the tests below exist to pin that a message quotes
// the uri the PACKAGE RECORDS rather than a ref derived from it. That distinction is only
// observable while the two differ, which is why the state is written here directly.
func recordAbsoluteExternalURI(t *testing.T, pkgPath, abs string) {
	t.Helper()
	doc := readEvidenceDoc(t, pkgPath)
	ext, ok := doc["externalEvidence"].([]interface{})
	require.True(t, ok, "precondition: the package records external evidence")
	require.NotEmpty(t, ext)
	entry, ok := ext[0].(map[string]interface{})
	require.True(t, ok)
	entry["uri"] = filepath.ToSlash(abs)
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))
}

// firstExternalURI returns the package's first externalEvidence uri.
func firstExternalURI(t *testing.T, pkgPath string) string {
	t.Helper()
	ext := readEvidenceDoc(t, pkgPath)["externalEvidence"]
	list, ok := ext.([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, list)
	entry, ok := list[0].(map[string]interface{})
	require.True(t, ok)
	uri, _ := entry["uri"].(string)
	return uri
}

// The Long help made a claim about blake3 that the tooling falsified, and the test that
// had asserted on this paragraph was removed with the behaviour it described — leaving the
// stale sentence unguarded in the highest-visibility place in the command. This pins what
// the paragraph now guarantees so the next change to either has to touch both.
func TestEvidenceBundle_HelpDescribesChecksumVerificationAccurately(t *testing.T) {
	stdout, _, err := executeCommand("evidence", "bundle", "--help")
	require.NoError(t, err)
	// Whitespace-collapsed before matching: the help is hard-wrapped, so a sentence spans
	// a newline. Matching the raw text would make the NotContains assertions below pass
	// for a stale sentence that merely happens to wrap across the phrase — a false green
	// in exactly the direction this test exists to catch.
	help := strings.Join(strings.Fields(stdout), " ")

	assert.Contains(t, help, "this build computes every algorithm Hash_Algorithm admits",
		"the help must state the guarantee the tooling actually provides")
	assert.Contains(t, help, "Three kinds cannot be verified",
		"no checksum at all, an empty value, and a reference that cannot travel")
	// The specific falsehoods this guards against returning. Note what went wrong here
	// once: this guard asserted the COUNT as an exact string, so when a later card made
	// bundle report a third kind, the stale "Two kinds" stayed pinned and the test went on
	// passing — a prose guard is also a LOCK on that prose, and it passing is not evidence
	// the prose is accurate. The NotContains lines below are the half that actually bites,
	// because each names a specific claim that must never come back.
	assert.NotContains(t, help, "neither Go nor Node implements",
		"blake3 is computed now, so the help must not say otherwise")
	assert.NotContains(t, help, "algorithm this build cannot compute",
		"no longer a reachable case through this command")
	assert.NotContains(t, help, "travels silently",
		"bundle reports an entry with no checksum; nothing it carries travels unmentioned")
	assert.NotContains(t, help, "Two kinds cannot be verified",
		"the count moved to three and must not regress")
	// Both of these were asserted TRUE by an earlier draft of this paragraph and are
	// false: the third kind is defined as a reference that cannot travel, so a sentence
	// claiming every kind travels contradicts its own list. Measured in
	// TestEvidenceBundle_TheThreeUnverifiableKindsBehaveAsTheHelpSays.
	assert.NotContains(t, help, "All three travel",
		"the third kind does not travel; it is reported as not carried")
	assert.NotContains(t, help, "Both travel",
		"the predecessor of the same false claim, when there were two kinds")
	// Third strengthening-into-falsehood in this paragraph: bundle COUNTS the two kinds
	// that travel and names only the third, while verify names each entry. Measured in
	// TestEvidenceBundle_TheThreeUnverifiableKindsBehaveAsTheHelpSays.
	assert.NotContains(t, help, "Every one of them is named on stderr",
		"the two travelling kinds are counted, not named")
	// Fourth strengthening-into-falsehood in this paragraph, and the one that finally
	// showed the shape of the habit: an unqualified cross-command claim. When .16 shipped,
	// verify named each CONTENT entry and reported no externalEvidence at all, so "names
	// each entry individually" was false for part of the population the sentence it
	// followed had just counted.
	//
	// THE GUARD ON THAT PHRASE IS NOW GONE, DELIBERATELY. 52n0c.36 made verify report
	// externalEvidence, so the unqualified claim became TRUE and the NotContains was
	// pointing the lock the wrong way — forbidding the only accurate wording. This is the
	// forward-dated case: a sentence measured true, and a guard protecting it, both
	// falsified on a schedule set by a card already filed. What is forbidden now is the
	// claim .36 retired, which is the qualification itself.
	assert.NotContains(t, help, "does not report externalEvidence",
		"verify reports both arrays since 52n0c.36; the qualification is the stale claim now")
	assert.NotContains(t, help, "an entry verify will not name",
		"the same retired claim in its other phrasing")
	assert.Contains(t, help, "in contents[] and in externalEvidence[] alike",
		"the paragraph must say verify's coverage spans both arrays")
	// This claim has now been through three states, and each NotContains below marks one
	// that was measured false rather than merely reworded.
	//
	// It began as an unqualified "a count here has a named counterpart there" — false for
	// a root reference field, which bundle counted and the verification surface never
	// named. It was then corrected to state that asymmetry openly. 52n0c.40 REMOVED the
	// asymmetry itself: the count no longer covers reference fields, so both surfaces are
	// over the same population and the counts reconcile for every package shape. Stating
	// an asymmetry that no longer exists would now be the false claim, so the guard that
	// pinned that sentence is retired with it.
	assert.NotContains(t, help, "has a named counterpart there",
		"the first version: unqualified, and false for a root reference field")
	assert.NotContains(t, help, "can still exceed what that command names",
		"the second: true when bundle counted reference fields, false since 52n0c.40")
	assert.Contains(t, help, "The two counts reconcile",
		"and the measured truth: 2/2 for a package with no root ref, with a systemRef, "+
			"and with a planRef")
	// WIDENED, because the version of this guard that pinned only the two-word form was
	// GREEN while the help it had just read said "Verify additionally checks …" — the
	// message asserted a claim the check could not enforce. Three hand sweeps each missed
	// what their own query could not see (a bare subject, a capitalised one, a name split
	// across a line break); a regexp over the RENDERED help is what stops a fourth.
	//
	// Legitimate forms are the flag (--verify) and inflections (verified, verifies,
	// verification). What is forbidden is the bare command name in any case, which is the
	// only shape that tells a reader to run something that exits 1.
	// THE SENTENCES THEMSELVES, not just the absence of a word. The regexp below holds
	// "no bare command name"; the defect class in this paragraph is "the sentence became
	// false or broken", and those are not the same set. Proof: fixing a bare command name
	// here made the replacement 26 characters longer, "for the shape of" was dropped to
	// hold the line width, and the help shipped reading "neither refuses a package one:" —
	// inside the class the guard was built for and outside the class it checks. A long
	// prose paragraph in a raw-string literal, hand-edited under a width constraint, eats
	// adjacent phrases.
	//
	// WHAT THIS HOLDS, stated exactly, because a check whose message claims more than it
	// enforces is the defect it replaced: one anchor at the OPENING of each sentence and
	// one at the TAIL. The openings alone were not enough — a width-driven trim lands at
	// a LINE boundary, which is in the tail, and a review mutant deleted "— is reported by
	// both" at exactly such a boundary with all four opening anchors still green. The tail
	// anchors are the clauses that carry each sentence's actual claim: that BOTH commands
	// report an out-of-package reference, the bundle-versus-verification asymmetry that
	// 52n0c.16 and .36 were each filed over, and the second of the two guards behind
	// "nothing outside the package directory is read", which is a security claim.
	//
	// It still does not hold the whole class — only these eight points. The layout change
	// that removes the mechanism rather than narrowing the window is carded separately,
	// deliberately NOT folded in here: this paragraph has been edited five times under
	// review pressure, and a sixth edit in the same commit as its own fix is how the
	// "package one:" break happened.
	for _, claim := range []string{
		// Openings.
		"neither refuses a package for the shape of one",
		"Verification additionally checks completeness, which bundle does not",
		"Both honour the checksum algorithm the package records",
		"Nothing outside the package directory is read",
		// Tails — where the trims actually land.
		"is reported by both",
		"so it can still fail a package bundle accepts",
		"a symlink that leaves the package is refused at the read boundary",
	} {
		assert.Contains(t, help, claim,
			"a claim this paragraph must carry went missing — check for a phrase eaten by a reflow")
	}

	bareVerify := regexp.MustCompile(`(?i)(^|[^-\w])verify\b`)
	if loc := bareVerify.FindStringIndex(help); loc != nil {
		start := loc[0] - 60
		if start < 0 {
			start = 0
		}
		end := loc[1] + 60
		if end > len(help) {
			end = len(help)
		}
		t.Errorf("printed help names the removed command as a bare word: ...%s...\n"+
			"Use the flag (--verify) or an inflection (verified/verifies/verification); "+
			"`hdf evidence verify` exits 1.", help[start:end])
	}
}

// Content_Reference requires type and uri but NOT checksum, so a schema-valid package can
// carry a document nothing vouches for. `evidence info --verify` already says so — "- <uri> (no
// checksum)" and a skipped count — while bundle carried it under an absolute extent claim
// and said nothing, so the two commands disagreed about whether the operator should be
// told. The maintainer's decision is REPORT: the archive is still written, because refusing
// would reject a document the schema admits, but the gap is stated. Deliberately distinct
// from the recorded-but-BLANK case, which has its own message: one records a checksum and
// leaves it empty, the other records none, and an operator fixing them does different work.
func TestEvidenceBundle_ReportsAnEntryWithNoChecksumAtAll(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.json"), src, 0o600))

	pkg, err := json.Marshal(map[string]any{
		"name": "no-sum",
		// No checksum key at all — not an empty object, not a blank value.
		"contents": []map[string]any{{"type": "hdf-results", "uri": "r.json"}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	archive := filepath.Join(dir, "n.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err, "reporting, not refusing: the schema admits this package")
	// FileExists proves an ARCHIVE was written, not what is inside it — the stronger
	// assertion is below, and the comment says only what the check shows.
	assert.FileExists(t, archive, "the archive is still written; the point is that the gap is stated")
	names := make([]string, 0, 2)
	for name := range zipEntries(t, archive) {
		names = append(names, name)
	}
	assert.Contains(t, names, "r.json", "and the unvouched document does travel, rather than being dropped")

	assert.Contains(t, stderr, "1 reference(s) record no checksum",
		"an unvouched document must not travel under a silent extent claim")
	assert.NotContains(t, stderr, "record an empty checksum value",
		"this entry records no checksum at all, which is a different fix from an empty value")
}

// The two unverifiable shapes are counted separately, so a package carrying one of each
// reports both rather than collapsing them into one number an operator cannot act on.
func TestEvidenceBundle_SeparatesNoChecksumFromAnEmptyChecksumValue(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	for _, n := range []string{"none.json", "blank.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), src, 0o600))
	}

	pkg, err := json.Marshal(map[string]any{
		"name": "both",
		"contents": []map[string]any{
			{"type": "hdf-results", "uri": "none.json"},
			{"type": "hdf-results", "uri": "blank.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": ""}},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "b.zip"))
	require.NoError(t, err)
	assert.Contains(t, stderr, "1 reference(s) record no checksum")
	assert.Contains(t, stderr, "1 reference(s) record an empty checksum value")
}

// The counter is shared across contents[] and externalEvidence[], so an unchecksummed
// in-tree external artifact is counted too. The CHANGELOG asserts that; nothing enforced
// it, and a later narrowing of the count to contents[] would have left the entry false
// with every test still green.
func TestEvidenceBundle_CountsAnUnchecksummedExternalEvidenceEntry(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "audit.ndjson"), []byte("log\n"), 0o600))

	doc := updatedPackage(t, pkgPath)
	doc["externalEvidence"] = []any{
		// In-tree and with NO checksum: it travels, and must be counted as unverified.
		map[string]any{"uri": "scans/audit.ndjson", "format": "raw-log"},
	}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	archive := filepath.Join(dir, "x.zip")
	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
	require.NoError(t, err)
	assert.Contains(t, stderr, "record no checksum",
		"an unchecksummed external evidence artifact is counted, not only a contents entry")

	names := make([]string, 0, 4)
	for name := range zipEntries(t, archive) {
		names = append(names, name)
	}
	assert.Contains(t, names, "scans/audit.ndjson", "and the in-tree artifact still travels")
}

// The help paragraph above makes POSITIVE behavioural claims — which kinds cannot be
// verified, which of them travel, and that each is named on stderr. Substring guards
// cannot check any of that: a Contains asserts the sentence's own words back at it, which
// is how "Two kinds cannot be verified" and then "All three travel" each stayed green
// while false. These assertions come from RUNS instead: one package per kind, asserting
// the line the operator actually sees and whether the document is actually in the archive.
//
// The honest limit, so this is not oversold the way its predecessors were: a BEHAVIOUR
// test catches behaviour drifting from the documented claim. It cannot catch prose
// drifting while behaviour stands still, which is how both previous falsehoods arose. What
// closes that gap is the NotContains half of the help guard, naming each claim already
// found false — a regression lock on corrections, not a check on new prose. Writing a new
// positive claim into that paragraph still requires measuring it, and nothing here will
// stop someone who does not.
func TestEvidenceBundle_TheThreeUnverifiableKindsBehaveAsTheHelpSays(t *testing.T) {
	for _, tc := range []struct {
		name     string
		uri      string
		checksum map[string]string
		wantLine string
		travels  bool
	}{
		{
			name: "no checksum at all", uri: "extra.json", checksum: nil,
			wantLine: "record no checksum", travels: true,
		},
		{
			name: "empty checksum value", uri: "extra.json",
			checksum: map[string]string{"algorithm": "sha256", "value": ""},
			wantLine: "record an empty checksum value", travels: true,
		},
		{
			// A reference that cannot travel. Checksummed, so it is excluded by its
			// REACHABILITY rather than by anything about its checksum.
			name: "reference that cannot travel", uri: "https://example.com/remote.json",
			checksum: map[string]string{"algorithm": "sha256", "value": strings.Repeat("a", 64)},
			wantLine: "not carried", travels: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
			require.NoError(t, err)
			for _, n := range []string{"doc.json", "extra.json"} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, n), src, 0o600))
			}
			sum := sha256.Sum256(src)
			good := map[string]any{"type": "hdf-results", "uri": "doc.json",
				"checksum": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])}}
			extra := map[string]any{"type": "hdf-results", "uri": tc.uri}
			if tc.checksum != nil {
				extra["checksum"] = tc.checksum
			}

			pkg, marshalErr := json.Marshal(map[string]any{"name": "kinds", "contents": []map[string]any{good, extra}})
			require.NoError(t, marshalErr)
			pkgPath := filepath.Join(dir, "pkg.json")
			require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

			archive := filepath.Join(dir, "k.zip")
			_, stderr, bundleErr := executeCommand("evidence", "bundle", pkgPath, "-o", archive)
			require.NoError(t, bundleErr, "none of the three kinds fails the command")
			assert.Contains(t, stderr, tc.wantLine, "the operator is told about this kind")

			names := make([]string, 0, 3)
			for name := range zipEntries(t, archive) {
				names = append(names, name)
			}
			if tc.travels {
				assert.Contains(t, names, "extra.json", "the help says this kind travels")
			} else {
				// ElementsMatch rather than Len: a count passes for ANY two entries,
				// including a pair that does not include the package. The NotContains
				// below is close to vacuous on its own — a remote uri is diverted before
				// collect, so no code path can produce an entry by that name — so this
				// identity assertion is what actually carries the non-travel claim.
				assert.ElementsMatch(t, []string{"pkg.json", "doc.json"}, names,
					"the help says this kind does not travel: the archive is the package and the one carried document")
				assert.NotContains(t, names, "remote.json", "and nothing named for the remote reference")
			}
		})
	}
}

// bundleHelpClaims returns the CLAIMS in bundle's Long help: the lines that start at
// column zero. The layout is one claim per line with its continuations indented, so a
// claim's start is a visible boundary and a reflow inside one claim cannot push text
// into the next. Derived from the RENDERED help rather than the source literal, because
// what a reader sees is the thing under test.
func bundleHelpClaims(t *testing.T) []string {
	t.Helper()
	help, _, err := executeCommand("evidence", "bundle", "--help")
	require.NoError(t, err)
	// Everything before the Examples block and cobra's own sections. Those are command
	// invocations and flag tables, not prose claims — an example is verified by RUNNING
	// it, which other tests here do, and anchoring it would assert its spelling instead.
	for _, boundary := range []string{"\nExamples:", "\nUsage:"} {
		if i := strings.Index(help, boundary); i > 0 {
			help = help[:i]
		}
	}
	claims := make([]string, 0, 32)
	for _, line := range strings.Split(help, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, " ") {
			// A continuation of the claim above, NOT a claim of its own. Folded in, never
			// skipped: the first version of this helper dropped every space-prefixed line,
			// so the coverage check below only ever saw claim OPENINGS — and a continuation
			// is exactly where a width-driven trim lands, which is how 52n0c.16, .36 and
			// .39 each lost a clause. 22 of 25 claims had no protection on their
			// continuation text at all.
			if len(claims) == 0 {
				t.Fatalf("help begins with an indented line, so the claim structure is broken: %q", line)
			}
			claims[len(claims)-1] += " " + strings.TrimSpace(line)
			continue
		}
		claims = append(claims, strings.TrimSpace(line))
	}
	return claims
}

// bundleHelpLineWidths returns the width of every rendered help line before the Examples
// and Usage sections, so AC 1's width property is ASSERTED rather than left to the
// author's prose. Nothing stopped a future edit re-widening a line past the limit.
func bundleHelpLineWidths(t *testing.T) []int {
	t.Helper()
	help, _, err := executeCommand("evidence", "bundle", "--help")
	require.NoError(t, err)
	for _, boundary := range []string{"\nExamples:", "\nUsage:"} {
		if i := strings.Index(help, boundary); i > 0 {
			help = help[:i]
		}
	}
	widths := make([]int, 0, 80)
	for _, line := range strings.Split(help, "\n") {
		if line != "" {
			widths = append(widths, len([]rune(line)))
		}
	}
	return widths
}

// EVERY claim carries an anchor, and every anchor matches a claim. This is the assertion
// set that cannot silently fall behind the text: a claim added without an anchor fails
// here, and an anchor whose claim was deleted or reworded fails too. The sentence-level
// anchors elsewhere in this file hold eight specific points; this holds the whole
// paragraph, which is what four rounds of review on 52n0c.39 could not do by eye.
//
// The layout exists because the defect class is mechanical: this paragraph was edited
// five times and shipped wrong four of them, every time because an edit changed a
// token's length, the line had to rewrap, and a neighbouring phrase was lost or a name
// was left straddling a newline. One claim per line removes the boundary a phrase can
// fall off.
func TestEvidenceBundle_HelpIsOneClaimPerLine(t *testing.T) {
	claims := bundleHelpClaims(t)
	require.NotEmpty(t, claims, "the derivation must find claims, or it proves nothing")

	// Each anchor is a distinctive fragment of one claim. Short enough to survive a
	// reword, long enough to identify the claim it belongs to.
	anchors := []string{
		"Write an evidence package and all of its referenced documents",
		"The archive root IS the package's own directory",
		"A reference recorded as an ABSOLUTE path inside the package is the exception",
		"Every reference that travels is covered",
		"That is reported here and never repaired by rewriting the package",
		"'hdf evidence set' (systemRef, planRef)",
		"Bundle and 'hdf evidence info --verify' resolve references identically",
		"Verification additionally checks completeness",
		"Both honour the checksum algorithm the package records",
		"Nothing outside the package directory is read",
		"What travels: the package",
		"Anything that cannot travel is reported on stderr",
		"A reference whose document would TRAVEL",
		"Everything stays recorded in the package",
		"Every recorded checksum is verified before anything is written",
		"Three kinds cannot be verified",
		"The first two DO travel",
		"The third does not travel at all",
		"Every one is reported on stderr",
		"'hdf evidence info --verify' names every entry too",
		"The two counts reconcile",
		"A mismatch or a missing document fails the command",
		"-o refuses a path naming the package",
		"It also refuses a path that already exists",
		"--overwrite does not lift the refusals above it",
		"Under --overwrite a failed run leaves whatever was already at that path",
	}

	// Every claim is anchored. A claim with no anchor means the assertion set fell behind
	// the text, which is how a broken sentence ships unnoticed.
	for _, claim := range claims {
		matched := false
		for _, a := range anchors {
			if strings.HasPrefix(claim, a) {
				matched = true
				break
			}
		}
		assert.True(t, matched, "no anchor covers this claim, so nothing would notice if it "+
			"broke:\n  %s", claim)
	}

	// And every anchor still matches something. An anchor matching nothing means its
	// claim was deleted or reworded — which is the direction a reflow eats a phrase.
	for _, a := range anchors {
		found := false
		for _, claim := range claims {
			if strings.HasPrefix(claim, a) {
				found = true
				break
			}
		}
		assert.True(t, found, "this anchor matches no claim — the claim it names was "+
			"deleted or reworded: %q", a)
	}
}

// EVERY WORD OF EVERY CLAIM IS COVERED, not just the opening line each anchor matches.
// The anchors above are PREFIXES, so a clause dropped from the middle or tail of a
// claim's continuation lines satisfies them — and a continuation is exactly where a
// width-driven trim lands. That is how 52n0c.16, .36 and .39 each lost a clause, and
// the first version of this test could not have seen any of them.
//
// Asserted as a token count per claim, because the defect class is LOSS: a phrase eaten
// by a reflow changes its claim's length, wherever in the claim it sat. A deliberate
// reword updates the number, which is the point — it makes the edit visible. Meaning is
// held separately by the sentence anchors and the bare-command-name regexp; neither of
// those can see a length change, and this cannot see a same-length reword.
func TestEvidenceBundle_EveryClaimKeepsItsWholeText(t *testing.T) {
	claims := bundleHelpClaims(t)

	// {token count, the claim's opening words, for naming the failure}.
	want := []struct {
		tokens int
		opens  string
	}{
		{24, "Write an evidence package and all"},
		{47, "The archive root IS the package's"},
		{36, "A reference recorded as an ABSOLUTE"},
		{12, "Every reference that travels is covered,"},
		{11, "That is reported here and never"},
		{18, "'hdf evidence set' (systemRef, planRef) and"},
		{47, "Bundle and 'hdf evidence info --verify'"},
		{33, "Verification additionally checks completeness, which bundle"},
		{8, "Both honour the checksum algorithm the"},
		{29, "Nothing outside the package directory is"},
		{39, "What travels: the package, the documents"},
		{30, "Anything that cannot travel is reported"},
		{70, "A reference whose document would TRAVEL"},
		{16, "Everything stays recorded in the package,"},
		{16, "Every recorded checksum is verified before"},
		{31, "Three kinds cannot be verified: one"},
		{26, "The first two DO travel, and"},
		{13, "The third does not travel at"},
		{17, "Every one is reported on stderr NAMING"},
		{24, "'hdf evidence info --verify' names every entry"},
		{30, "The two counts reconcile: both are over"},
		{25, "A mismatch or a missing document"},
		{20, "-o refuses a path naming the"},
		{22, "It also refuses a path that"},
		{20, "--overwrite does not lift the refusals"},
		{25, "Under --overwrite a failed run leaves"},
	}

	require.Len(t, claims, len(want),
		"the number of claims changed; add or remove an entry deliberately rather than "+
			"letting the table fall behind the help")
	for i, w := range want {
		got := len(strings.Fields(claims[i]))
		assert.Equal(t, w.tokens, got,
			"claim %d lost or gained text — check for a phrase eaten by a reflow:\n  %s...\n  %s",
			i+1, w.opens, claims[i])
	}
}

// AC 1's width property, asserted rather than left to the author's word. The layout only
// bounds a reflow while every line stays inside the limit; nothing else stopped a future
// edit re-widening one.
func TestEvidenceBundle_HelpLinesStayWithinTheWidth(t *testing.T) {
	const limit = 92 // the width the surrounding help was already hand-wrapped to
	widths := bundleHelpLineWidths(t)
	require.NotEmpty(t, widths, "the derivation must find lines, or it proves nothing")
	for i, w := range widths {
		assert.LessOrEqual(t, w, limit,
			"rendered help line %d is %d characters, over the %d-character limit the "+
				"one-claim-per-line layout depends on", i+1, w, limit)
	}
}

// A reference FIELD is not an unchecksummed entry. systemRef and planRef are bare
// uri-reference strings — the schema gives neither a checksum property — so counting
// them under "records no checksum" put something in the number that an operator has
// nowhere to fix, and made bundle's count diverge from the verification surface's for
// every package that names a system.
func TestEvidenceBundle_DoesNotCountAReferenceFieldThatCannotCarryAChecksum(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"rhel9-results.json", "system.json"} {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, f))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), src, 0o600))
	}
	results, rerr := os.ReadFile(filepath.Join(dir, "rhel9-results.json"))
	require.NoError(t, rerr)
	sum := sha256.Sum256(results)

	// The ONLY checksum-less thing here is the systemRef. Every checksum-bearing entry
	// records one, so a correct count is zero.
	pkg, err := json.Marshal(map[string]any{
		"name":      "ref-field",
		"systemRef": "system.json",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "rhel9-results.json",
			"checksum": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])},
		}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "r.zip"))
	require.NoError(t, err)
	assert.NotContains(t, stderr, "record no checksum",
		"a systemRef has nowhere to record a checksum, so it cannot be missing one")
}

// And the count reconciles with the verification surface for a package that names a
// system — not only for one that does not. The old count was right for a system-less
// package and wrong for every other, which is why a single-shape pin did not catch it.
func TestEvidenceBundle_CountReconcilesWithVerificationWhenASystemIsNamed(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"rhel9-results.json", "system.json"} {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, f))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), src, 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.ndjson"), []byte("log\n"), 0o600))

	// Two checksum-bearing entries record nothing; the systemRef is a third reference
	// but not a third unchecksummed entry.
	pkg, err := json.Marshal(map[string]any{
		"name":      "reconcile",
		"systemRef": "system.json",
		"contents":  []map[string]any{{"type": "hdf-results", "uri": "rhel9-results.json"}},
		"externalEvidence": []map[string]any{
			{"uri": "audit.ndjson", "format": "raw-log"},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, bundleErr, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "r.zip"))
	require.NoError(t, err)
	assert.Contains(t, bundleErr, "2 reference(s) record no checksum",
		"the two checksum-bearing entries, and not the systemRef")

	verifyOut, _, verr := executeCommand("evidence", "info", pkgPath, "--verify")
	require.NoError(t, verr)
	assert.Contains(t, verifyOut, "2 skipped",
		"both surfaces must report the same population for the same package")
}

// The canRecordChecksum flag is derived from the SCHEMA, with no exceptions and no
// hand-kept list: a reference field can record a checksum exactly when its resolved
// type declares a checksum property. Asserted against the schema itself so adding a
// checksum to a field that lacks one — or a new reference field — fails here instead of
// silently moving a count nobody is watching.
// resolveToObject follows a schema node to the object type it denotes: through an
// array's items, through a $ref local or into primitives, and through an allOf, which is
// how Raw_Source_Artifact inherits External_Reference's checksum rather than declaring
// one. Returns the node and the document it now lives in, since a primitive $ref changes
// which $defs a later local $ref resolves against.
func resolveToObject(t *testing.T, load func(string) map[string]any,
	node, cur map[string]any,
) (map[string]any, map[string]any) {
	t.Helper()
	primitiveRef := regexp.MustCompile(`primitives/([a-z-]+)/v[\d.]+#/\$defs/(\w+)`)
	localRef := regexp.MustCompile(`^#/\$defs/(\w+)$`)
	for range 8 {
		if node == nil {
			return nil, cur
		}
		if items, ok := node["items"].(map[string]any); ok {
			node = items
			continue
		}
		if _, hasProps := node["properties"]; !hasProps {
			if branches, ok := node["allOf"].([]any); ok {
				// The branch that carries the properties: the others constrain.
				var next map[string]any
				for _, b := range branches {
					branch, _ := b.(map[string]any)
					if branch == nil {
						continue
					}
					if _, isRef := branch["$ref"]; isRef {
						next = branch
						break
					}
					if _, p := branch["properties"]; p {
						next = branch
						break
					}
				}
				if next != nil {
					node = next
					continue
				}
			}
		}
		ref, ok := node["$ref"].(string)
		if !ok {
			return node, cur
		}
		if m := localRef.FindStringSubmatch(ref); m != nil {
			defs, _ := cur["$defs"].(map[string]any)
			node, _ = defs[m[1]].(map[string]any)
			continue
		}
		m := primitiveRef.FindStringSubmatch(ref)
		if m == nil {
			return node, cur
		}
		cur = load(filepath.Join("primitives", m[1]+".schema.json"))
		defs, _ := cur["$defs"].(map[string]any)
		node, _ = defs[m[2]].(map[string]any)
	}
	return node, cur
}

func TestEvidenceBundle_ChecksumBearingFieldsMatchTheSchema(t *testing.T) {
	schemaDir := filepath.Join("..", "..", "..", "..", "hdf-schema", "src", "schemas")
	load := func(rel string) map[string]any {
		raw, err := os.ReadFile(filepath.Join(schemaDir, rel))
		require.NoError(t, err, "the schema is the authority for what can record a checksum")
		var doc map[string]any
		require.NoError(t, json.Unmarshal(raw, &doc))
		return doc
	}
	root := load("hdf-evidence-package.schema.json")

	// Resolve a top-level property to the object type a reference actually is: step
	// through an array's items and follow $refs, local or into primitives.
	// Resolves a DOTTED path too. The first version could only address a top-level
	// property, so "extensions.rawSourceArtifacts" fell out of the comparison entirely
	// and its flag sat wrong — unchecked rather than checked and wrong, which is worse.
	declaresChecksum := func(field string) bool {
		cur := root
		props, _ := root["properties"].(map[string]any)
		segments := strings.Split(field, ".")
		node, _ := props[segments[0]].(map[string]any)
		for _, seg := range segments[1:] {
			node, cur = resolveToObject(t, load, node, cur)
			if node == nil {
				return false
			}
			inner, _ := node["properties"].(map[string]any)
			node, _ = inner[seg].(map[string]any)
		}
		node, _ = resolveToObject(t, load, node, cur)
		if node == nil {
			return false
		}
		typeProps, _ := node["properties"].(map[string]any)
		_, has := typeProps["checksum"]
		return has
	}

	// A package naming every reference field, so recordedRefs yields one of each.
	pkg, err := json.Marshal(map[string]any{
		"name":               "schema-parity",
		"systemRef":          "system.json",
		"planRef":            "plan.json",
		"contents":           []map[string]any{{"type": "hdf-results", "uri": "r.json"}},
		"externalEvidence":   []map[string]any{{"uri": "audit.ndjson", "format": "raw-log"}},
		"externalReferences": []map[string]any{{"href": "https://example.com/a", "type": "advisory"}},
		"extensions": map[string]any{
			"rawSourceArtifacts": []map[string]any{{"href": "raw.xml", "sourceName": "nessus"}},
		},
	})
	require.NoError(t, err)
	var contents []hdfengine.EvidenceContent
	require.NoError(t, json.Unmarshal([]byte(`[{"type":"hdf-results","uri":"r.json"}]`), &contents))
	refs, err := recordedRefs(pkg, contents)
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, r := range refs {
		if r.uri == "" {
			continue
		}
		seen[r.field] = true
		assert.Equal(t, declaresChecksum(r.field), r.canRecordChecksum,
			"field %q: the schema and the flag disagree about whether it can record a checksum", r.field)
	}
	// And the derivation reached every field, so a pass cannot mean "checked nothing".
	for _, f := range []string{"systemRef", "planRef", "contents", "externalEvidence",
		"externalReferences", "extensions.rawSourceArtifacts"} {
		assert.True(t, seen[f], "recordedRefs yielded no %q, so that field went unchecked", f)
	}
}

// Narrowing the COUNT must not narrow what -o refuses to overwrite. Those are different
// questions over the same enumeration: whether a reference can record a checksum, and
// whether the archive would clobber a document the package points at. A systemRef
// answers no to the first and yes to the second, so it is the case that tells them
// apart — and the reason recordedRefs stays complete rather than being filtered.
func TestEvidenceBundle_RefusesOutputOverASystemRefItNoLongerCounts(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"rhel9-results.json", "system.json"} {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, f))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), src, 0o600))
	}
	pkg, err := json.Marshal(map[string]any{
		"name":      "guard",
		"systemRef": "system.json",
		"contents":  []map[string]any{{"type": "hdf-results", "uri": "rhel9-results.json"}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	// The archive would be written over the very document systemRef names. --overwrite is
	// passed deliberately: without it this path also trips the "already exists" refusal,
	// whose message names the same file, so the test would pass even with systemRef
	// dropped from the enumeration entirely — it did, until a mutant showed it could not
	// tell the two refusals apart. The REASON is the assertion, not the filename.
	_, _, err = executeCommand("evidence", "bundle", pkgPath,
		"-o", filepath.Join(dir, "system.json"), "--overwrite")
	require.Error(t, err, "-o must still refuse a path naming a reference the count now ignores")
	assert.Contains(t, err.Error(), "the system reference this package records",
		"the refusal must come from the reference enumeration, not from the file existing")
}

// Each unverifiable reference is NAMED, not just counted. bundle already named the kind
// that cannot travel; the two kinds an operator can actually act on were the two it
// reduced to a number, so a large package told them how many to fix and not which.
//
// The vocabulary is 'hdf evidence info's, via one shared function rather than a copy of
// its strings: recordedChecksumState's own comment calls this "the same distinction
// evidence bundle counts separately", so the phrases were already canonical somewhere
// else in the tree.
func TestEvidenceBundle_NamesEachUnchecksummedReference(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	for _, n := range []string{"a.json", "b.json", "c.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), src, 0o600))
	}

	pkg, err := json.Marshal(map[string]any{
		"name": "named",
		"contents": []map[string]any{
			{"type": "hdf-results", "uri": "a.json"},
			{"type": "hdf-results", "uri": "b.json"},
			// Recorded but blank — schema-valid, and a different fix from the two above.
			{"type": "hdf-results", "uri": "c.json",
				"checksum": map[string]any{"algorithm": "sha256", "value": ""}},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "n.zip"))
	require.NoError(t, err)

	assert.Contains(t, stderr, "a.json (no checksum recorded)", "the first must be named")
	assert.Contains(t, stderr, "b.json (no checksum recorded)",
		"and so must the second — naming one and counting the rest is the defect")
	assert.Contains(t, stderr, "c.json (checksum recorded but empty)",
		"the two kinds stay distinguishable because the remedy differs")
}

// A pathological package must not bury the rest of the report, and the truncation says
// how many it withheld rather than trailing off. Bounded through the same LimitSlice the
// repo already uses, not a second mechanism.
func TestEvidenceBundle_BoundsTheNamesAndSaysHowManyAreOmitted(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	const total = maxNamedUnverifiable + 7
	entries := make([]map[string]any, 0, total)
	for i := range total {
		name := fmt.Sprintf("r%02d.json", i)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), src, 0o600))
		entries = append(entries, map[string]any{"type": "hdf-results", "uri": name})
	}
	pkg, err := json.Marshal(map[string]any{"name": "many", "contents": entries})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, stderr, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "m.zip"))
	require.NoError(t, err)

	named := strings.Count(stderr, "(no checksum recorded)")
	assert.Equal(t, maxNamedUnverifiable, named, "the list is bounded at the stated limit")
	assert.Contains(t, stderr, fmt.Sprintf("... and %d more, not listed", total-maxNamedUnverifiable),
		"and the number withheld is stated, so the list cannot quietly appear complete")
	assert.Contains(t, stderr, fmt.Sprintf("%d reference(s) record no checksum", total),
		"while the COUNT still covers every one of them")
}

// The two surfaces describe one entry the same way. They reach it by different routes —
// bundle from the reference enumeration, verification from the engine's results — so
// nothing but a shared vocabulary keeps them from drifting, and drifting is what they
// did before 52n0c.36. Derived from RUNS of both commands on one package, never from
// substrings of either one's help.
func TestEvidenceBundleAndInfo_DescribeAnUnchecksummedEntryConsistently(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), src, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), src, 0o600))

	pkg, err := json.Marshal(map[string]any{
		"name": "consistent",
		"contents": []map[string]any{
			{"type": "hdf-results", "uri": "a.json"},
			{"type": "hdf-results", "uri": "b.json",
				"checksum": map[string]any{"algorithm": "sha256", "value": ""}},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	_, bundleErr, err := executeCommand("evidence", "bundle", pkgPath, "-o", filepath.Join(dir, "c.zip"))
	require.NoError(t, err)
	infoOut, _, err := executeCommand("evidence", "info", pkgPath)
	require.NoError(t, err)

	// One vocabulary, two commands: the phrase each prints for an entry comes from
	// checksumStateFrom, so a reword in one surface cannot leave the other behind.
	for _, want := range []string{"no checksum recorded", "checksum recorded but empty"} {
		assert.Contains(t, bundleErr, want, "bundle must use the shared phrase")
		assert.Contains(t, infoOut, want, "and info must use the same one for the same entry")
	}
}

// -o refuses to overwrite a referenced document even when the reference is ESCAPED.
//
// The guard built its candidate path from the RAW reference, so for "my%20scans/q4.json"
// it compared against a path no file occupies and let the archive be written over the
// evidence. DATA LOSS, not a wrong message: the file was replaced by a zip. --overwrite
// is required to get past the separate exists-check, and bundle's own help says
// --overwrite does not lift the refusals above it — so this was that promise failing for
// any reference needing a percent-escape.
//
// Found by auditing every comparison primitive after a reviewer showed my first
// enumeration had missed one; this was the twenty-first site, and the only one with
// consequences beyond a misleading report.
func TestEvidenceBundle_RefusesOutputOverAnEscapedReference(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "my scans"), 0o750))
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	evidence := filepath.Join(dir, "my scans", "q4.json")
	require.NoError(t, os.WriteFile(evidence, src, 0o600))

	pkg, err := json.Marshal(map[string]any{
		"name": "guard",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": "my%20scans/q4.json",
			"checksum": map[string]any{"algorithm": evidenceDigestAlgo, "value": evidenceDigestHex(src)},
		}},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	// --overwrite deliberately: it lifts the exists-check and must NOT lift this one.
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", evidence, "--overwrite")
	require.Error(t, err, "bundling must not destroy the evidence it is packaging")
	assert.Contains(t, err.Error(), "the content reference this package records")

	after, err := os.ReadFile(evidence)
	require.NoError(t, err)
	assert.Equal(t, src, after, "and the evidence file must be byte-identical afterwards")
}
