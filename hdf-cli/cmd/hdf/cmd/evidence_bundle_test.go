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

	_, _, verifyErr := executeCommand("evidence", "verify", filepath.Join(dest, "pkg.json"))
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
	require.NoError(t, runEvidenceBundle(pkgPath, filepath.Join(dir, "seam.zip"),
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

	t.Run("an absolute uri is refused", func(t *testing.T) {
		// Root-anchored, NOT a full absolute path: filepath.Join(pkgDir, "/scans/x")
		// resolves back INSIDE the package, so SafePath accepts the read and the
		// only thing standing between it and an absolute archive entry is the shape
		// check. A full absolute path would leave the base and fail on a missing
		// file instead, which would pass this test without exercising the guard.
		abs := "/scans/rhel9-results.json"
		pkgPath := write("abs.json", abs, sum(filepath.Join("scans", "rhel9-results.json")))
		out := filepath.Join(dir, "abs.zip")
		_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", out)
		require.Error(t, err, "an absolute ref must not become an absolute archive entry")
		assert.Contains(t, err.Error(), abs, "and the error must name the offending reference")
		assert.NoFileExists(t, out)
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
// archive with exit 0 under the claim "nothing else" — and `evidence verify` does
// not check external evidence either, so bundle is the only place those bytes are
// ever captured.
func TestEvidenceBundle_VerifiesExternalEvidenceChecksums(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	artifact := filepath.Join(dir, "scans", "audit.ndjson")
	require.NoError(t, os.WriteFile(artifact, []byte(`{"event":"ok"}`+"\n"), 0o600))
	// The uri is ABSOLUTE because add-evidence resolves it against the process CWD,
	// not the package directory: a package-relative uri here records no checksum at
	// all, which made an earlier version of this test vacuous — it "passed" a
	// tampered artifact because there was nothing to verify.
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

	for _, tc := range []struct {
		algorithm, value, wantErr string
	}{
		{"sha384", hex.EncodeToString(sum384[:]), ""},
		{"sha512", hex.EncodeToString(sum512[:]), ""},
		{"sha512", strings.Repeat("b", 128), "checksum mismatch"},
		// No stdlib blake3. Refused honestly rather than reported as a mismatch.
		{"blake3", strings.Repeat("c", 64), "cannot verify a blake3 checksum"},
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
// with nothing in it. There is nothing to verify against, and `evidence verify`
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
		".externalEvidence[].uri",
		".externalReferences[].href",
		".planRef",
		".systemRef",
	}, paths,
		"the schema's reference fields changed. Add the new one to recordedRefs (which the "+
			"-o guard and the collection loop both derive from) and to this list, then add it "+
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
		"sys.json":           "system reference",
		"meta/plan.json":     "plan reference",
		"scans/r.json":       "content reference",
		"scans/audit.ndjson": "external evidence",
		"scans/runbook.json": "external reference",
	}, got, "every reference field the schema declares must reach recordedRefs")
}

// An archive must be self-sufficient: `evidence verify` reads planRef for its
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
	_, _, err = executeCommand("evidence", "verify", filepath.Join(extracted, "pkg.json"))
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
