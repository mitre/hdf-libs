package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updatablePackage builds a package with one results document, and returns the base
// directory plus the package path. The results document sits in scans/ so the
// package-relative reference is exercised rather than a flat basename.
func updatablePackage(t *testing.T) (dir, pkgPath string) {
	t.Helper()
	dir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
	copyIn := func(fixture, dest string) {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, fixture))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, dest), src, 0o600))
	}
	copyIn("system.json", "system.json")
	copyIn("rhel9-results.json", filepath.Join("scans", "rhel9.json"))

	pkgPath = filepath.Join(dir, "pkg.json")
	_, _, err := executeCommand("evidence", "build",
		"--system", filepath.Join(dir, "system.json"),
		"--results", filepath.Join(dir, "scans", "rhel9.json"),
		"-o", pkgPath)
	require.NoError(t, err)
	return dir, pkgPath
}

func updatedPackage(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc
}

// contentURIs lists the contents[] references in order.
func contentURIs(t *testing.T, doc map[string]any) []string {
	t.Helper()
	entries, ok := doc["contents"].([]any)
	require.True(t, ok)
	uris := make([]string, 0, len(entries))
	for _, e := range entries {
		uris = append(uris, e.(map[string]any)["uri"].(string))
	}
	return uris
}

// writeScan copies a fixture to scans/<name> and returns its path.
func writeScan(t *testing.T, dir, fixture, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, fixture))
	require.NoError(t, err)
	path := filepath.Join(dir, "scans", name)
	require.NoError(t, os.WriteFile(path, src, 0o600))
	return path
}

// A results file refreshed IN PLACE — same path, new bytes — replaces that entry and
// nothing else, and the package keeps its identity. This is the only case where update
// replaces: the entry is the same slot.
func TestEvidenceUpdate_ReplacesResultsAndKeepsIdentity(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	before := updatedPackage(t, pkgPath)
	beforeURIs := contentURIs(t, before)

	// Give the package an identity and attachments that must survive.
	_, _, err := executeCommand("evidence", "set", pkgPath,
		"--name", "Portal Q3", "--description", "quarterly body of evidence", "-o", pkgPath)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-reference", pkgPath,
		"--source-name", "cve", "--external-id", "CVE-2021-44228", "-o", pkgPath)
	require.NoError(t, err)
	stamped := updatedPackage(t, pkgPath)

	// Refresh the SAME file with different bytes, so its checksum must change.
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9.json"), src, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, _, err = executeCommand("evidence", "update", pkgPath,
		"--results", filepath.Join(dir, "scans", "rhel9.json"), "-o", out)
	require.NoError(t, err)

	after := updatedPackage(t, out)
	assert.Equal(t, beforeURIs, contentURIs(t, after),
		"a same-path refresh replaces the entry in place — no entry added, none removed")

	// Identity and attachments survive.
	assert.Equal(t, stamped["packageId"], after["packageId"], "packageId must survive")
	assert.Equal(t, "Portal Q3", after["name"], "name must survive")
	assert.Equal(t, "quarterly body of evidence", after["description"], "description must survive")
	assert.Equal(t, stamped["externalReferences"], after["externalReferences"],
		"attachments must not be dropped because they were not passed on the command line")

	// The refreshed entry's checksum reflects the new bytes.
	var oldSum, newSum string
	for _, e := range before["contents"].([]any) {
		if entry := e.(map[string]any); entry["uri"] == "scans/rhel9.json" {
			oldSum = entry["checksum"].(map[string]any)["value"].(string)
		}
	}
	for _, e := range after["contents"].([]any) {
		if entry := e.(map[string]any); entry["uri"] == "scans/rhel9.json" {
			newSum = entry["checksum"].(map[string]any)["value"].(string)
		}
	}
	require.NotEmpty(t, oldSum)
	require.NotEmpty(t, newSum)
	assert.NotEqual(t, oldSum, newSum, "the replaced entry must record the new bytes")

	_, _, err = executeCommand("validate", out)
	require.NoError(t, err, "the updated package must validate")
}

// The load-bearing case. A second scan at a DIFFERENT path covering a baseline the
// package already covers is ADDED, not replaced — a baseline is a requirement set that
// applies to many components, so one baseline appearing twice is normal. Keying
// replacement on baseline name would delete the first component's evidence, and the
// completeness check would still read green because the baseline remains covered.
func TestEvidenceUpdate_AddsASecondScanOfTheSameBaseline(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	host2 := writeScan(t, dir, "rhel9-results.json", "rhel9-host2.json")

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", host2, "-o", out)
	require.NoError(t, err)

	uris := contentURIs(t, updatedPackage(t, out))
	assert.Contains(t, uris, "scans/rhel9.json", "the first scan must survive")
	assert.Contains(t, uris, "scans/rhel9-host2.json", "and the second must be added beside it")

	assert.Contains(t, stderr, "added scans/rhel9-host2.json")
	assert.Contains(t, stderr, "also covered by an existing entry: RHEL9-STIG")
	assert.Contains(t, stderr, "both are kept")
	// This fixture carries neither field, which is the COMMON case in HDF, so both
	// absences must be named rather than implied.
	assert.Contains(t, stderr, "no timestamp recorded")
	assert.Contains(t, stderr, "no target components recorded")
}

// When the distinguishing facts ARE present, they are reported rather than the absences.
func TestEvidenceUpdate_ReportsTimestampAndTargetWhenTheDocumentCarriesThem(t *testing.T) {
	dir, pkgPath := updatablePackage(t)

	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(src, &doc))
	doc["timestamp"] = "2026-09-28T12:00:00Z"
	doc["components"] = []map[string]any{{"type": "host", "name": "web-02"}}
	enriched, err := json.Marshal(doc)
	require.NoError(t, err)
	host2 := filepath.Join(dir, "scans", "rhel9-web02.json")
	require.NoError(t, os.WriteFile(host2, enriched, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", host2, "-o", out)
	require.NoError(t, err)

	assert.Contains(t, stderr, "assessed 2026-09-28T12:00:00Z", "a recorded timestamp must be reported")
	assert.Contains(t, stderr, "targets web-02", "and the targeted component named")
	assert.NotContains(t, stderr, "no timestamp recorded")
	assert.NotContains(t, stderr, "no target components recorded")
}

// update never removes a results entry. The package is meant to hold the scan history.
func TestEvidenceUpdate_NeverRemovesAnEntry(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	before := contentURIs(t, updatedPackage(t, pkgPath))

	current := pkgPath
	for i, fixture := range []string{"postgres-results.json", "rhel9-results.json"} {
		scan := writeScan(t, dir, fixture, fmt.Sprintf("run%d.json", i))
		next := filepath.Join(dir, fmt.Sprintf("pkg%d.json", i))
		_, _, err := executeCommand("evidence", "update", current, "--results", scan, "-o", next)
		require.NoError(t, err)
		current = next
	}

	after := contentURIs(t, updatedPackage(t, current))
	for _, uri := range before {
		assert.Contains(t, after, uri, "%s was dropped; update must never remove an entry", uri)
	}
	assert.Len(t, after, len(before)+2, "both new scans accumulate")
}

// completenessCheck is recomputed from the POST-update content. Carrying it forward would
// let a package claim coverage it no longer has.
func TestEvidenceUpdate_RecomputesCompletenessRatherThanCarryingItForward(t *testing.T) {
	dir, pkgPath := updatablePackage(t)

	// Poison the recorded check so a carried-forward value is unmistakable.
	doc := updatedPackage(t, pkgPath)
	doc["completenessCheck"] = map[string]any{
		"allBaselinesAssessed": true, "allComponentsCovered": true, "compliancePercent": 99.0,
	}
	poisoned, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, poisoned, 0o600))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "updated.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	// Asserted against the RECOMPUTED value, not merely "different from the poison". An
	// inequality pins that something changed, never that the result is right — the same
	// shape this card's checksum AC was written to forbid.
	cc := updatedPackage(t, out)["completenessCheck"].(map[string]any)
	assert.InDelta(t, 100.0, cc["compliancePercent"], 0.001,
		"completeness is recomputed from the post-update content, and these fixtures all pass")
	assert.Equal(t, true, cc["allBaselinesAssessed"],
		"and every other field is recomputed too, not carried forward selectively")
}

// preparedAt is refreshed; an existing preparedBy is preserved, because who prepared the
// package is not something an update knows.
func TestEvidenceUpdate_RefreshesPreparedAtAndKeepsPreparedBy(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	doc := updatedPackage(t, pkgPath)
	doc["preparedAt"] = "2020-01-01T00:00:00Z"
	doc["preparedBy"] = map[string]any{"identifier": "ci-pipeline", "type": "system"}
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, seeded, 0o600))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "updated.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	after := updatedPackage(t, out)
	assert.NotEqual(t, "2020-01-01T00:00:00Z", after["preparedAt"], "preparedAt must be refreshed")
	assert.Equal(t, map[string]any{"identifier": "ci-pipeline", "type": "system"}, after["preparedBy"],
		"preparedBy must be preserved — an update does not know who prepared the package")
}

// An evidence package is an attestation, so neither -o nor --overwrite means refuse,
// naming both ways forward. The opposite of add-evidence and add-reference, which only
// append and so default to overwriting the input.
func TestEvidenceUpdate_RefusesToRewriteAnAttestationByDefault(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	before, err := os.ReadFile(pkgPath)
	require.NoError(t, err)

	t.Run("neither flag refuses, naming both options", func(t *testing.T) {
		_, _, updErr := executeCommand("evidence", "update", pkgPath, "--results", scan)
		require.Error(t, updErr)
		assert.Contains(t, updErr.Error(), "-o")
		assert.Contains(t, updErr.Error(), "--overwrite")
		after, readErr := os.ReadFile(pkgPath)
		require.NoError(t, readErr)
		assert.Equal(t, before, after, "and the package must be untouched")
	})

	t.Run("--overwrite replaces the input deliberately", func(t *testing.T) {
		_, _, updErr := executeCommand("evidence", "update", pkgPath, "--results", scan, "--overwrite")
		require.NoError(t, updErr)
		after, readErr := os.ReadFile(pkgPath)
		require.NoError(t, readErr)
		assert.NotEqual(t, before, after, "the input is replaced when asked")
		assert.Contains(t, contentURIs(t, updatedPackage(t, pkgPath)), "scans/pg.json")
	})

	t.Run("both flags together are refused rather than ranked", func(t *testing.T) {
		_, _, updErr := executeCommand("evidence", "update", pkgPath,
			"--results", scan, "-o", filepath.Join(dir, "x.json"), "--overwrite")
		require.Error(t, updErr)
		assert.Contains(t, updErr.Error(), "pass one")
		assert.NoFileExists(t, filepath.Join(dir, "x.json"))
	})
}

// --dry-run reports what would change and writes nothing — including no output file.
func TestEvidenceUpdate_DryRunWritesNothing(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	before, err := os.ReadFile(pkgPath)
	require.NoError(t, err)

	out := filepath.Join(dir, "would-be.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", scan, "-o", out, "--dry-run")
	require.NoError(t, err)

	assert.Contains(t, stderr, "added scans/pg.json", "it must report what would change")
	assert.Contains(t, stderr, "Dry run: nothing written")
	assert.NoFileExists(t, out, "and write no output")
	after, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "nor touch the input")
}

// --results is required, and refused before any work.
func TestEvidenceUpdate_RequiresResults(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	_, _, err := executeCommand("evidence", "update", pkgPath, "-o", filepath.Join(dir, "x.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--results is required")
	assert.NoFileExists(t, filepath.Join(dir, "x.json"))
}

// The updated package must validate before it is written, as every evidence subcommand
// guarantees. Driven from a VALID package whose write makes it invalid — the input gate
// and the pre-write gate mask each other otherwise, which is the trap card .9 fell into.
// A filename that needs escaping is RECORDED ESCAPED, and the package stays valid.
//
// This test used to assert the opposite: that "bad%zzname.json" "cannot be expressed in
// contents[]", and that the pre-write gate therefore refused the write. That premise died
// with 52n0c.31 — the field is a uri-reference, so such a name IS expressible, as
// "bad%25zzname.json", and refusing it was the tooling declining to write a reference it
// simply had not escaped. The pre-write gate itself is still pinned, by
// TestEvidenceAddReference_RefusesToWriteAnInvalidPackage, whose trigger is a malformed
// href rather than an unescaped name.
func TestEvidenceUpdate_RecordsAnEscapedReferenceForAnAwkwardName(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	_, _, err := executeCommand("validate", pkgPath)
	require.NoError(t, err, "the input must be valid, or this pins the wrong thing")

	odd := filepath.Join(dir, "scans", "bad%zzname.json")
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(odd, src, 0o600))

	out := filepath.Join(dir, "written.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", odd, "-o", out)
	require.NoError(t, err, "an escapable name is expressible, so the write must succeed")

	uris := contentURIs(t, updatedPackage(t, out))
	assert.Contains(t, uris, "scans/bad%25zzname.json",
		"the percent is escaped, which is the only legal way to record this name")
	assert.NotContains(t, uris, "scans/bad%zzname.json",
		"the raw spelling is not a valid uri-reference and must never be recorded")

	// The written package is valid, and resolves back to the file it names.
	_, _, err = executeCommand("validate", out)
	require.NoError(t, err, "what was written must be schema-valid")
	vOut, _, vErr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	require.NoError(t, vErr, "and must verify, which means the escape resolved back")
	assert.Contains(t, vOut, "checksums valid")
}

// The type was asserted from the FLAG NAME, so --results on a system document overwrote
// the package's only hdf-system entry and re-typed it as results — destroying content the
// help promises is never removed, with schema validation passing in silence. Weaker than
// the filename guess this repo already forbids. Now fingerprinted through the shared
// requireDetectedType, the same guard evidence build uses.
func TestEvidenceUpdate_RefusesADocumentThatIsNotResults(t *testing.T) {
	for _, tc := range []struct{ fixture, wantType string }{
		{"system.json", "system"},
		{"plan.json", "plan"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			dir, pkgPath := updatablePackage(t)
			before, err := os.ReadFile(pkgPath)
			require.NoError(t, err)
			src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, tc.fixture))
			require.NoError(t, err)
			path := filepath.Join(dir, tc.fixture)
			require.NoError(t, os.WriteFile(path, src, 0o600))

			out := filepath.Join(dir, "out.json")
			_, _, err = executeCommand("evidence", "update", pkgPath, "--results", path, "-o", out)
			require.Error(t, err, "a %s document passed as --results must be refused", tc.wantType)
			assert.Contains(t, err.Error(), "is an HDF "+tc.wantType+" document, expected results")
			assert.NoFileExists(t, out)

			after, err := os.ReadFile(pkgPath)
			require.NoError(t, err)
			assert.Equal(t, before, after, "and the package must be untouched")
		})
	}
}

// Even a genuine results document must not take over a reference an entry of another type
// holds: retyping it would silently remove the package's declaration of that document.
func TestEvidenceUpdate_RefusesToRetypeAnExistingEntry(t *testing.T) {
	dir, pkgPath := updatablePackage(t)

	// Put a real results document at the path the hdf-system entry already claims.
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "system.json"), src, 0o600))

	out := filepath.Join(dir, "out.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", filepath.Join(dir, "system.json"), "-o", out)
	require.Error(t, err, "the reference is held by an hdf-system entry")
	assert.Contains(t, err.Error(), "already recorded in this package with type hdf-system")
	assert.Contains(t, err.Error(), "will not retype an existing one")
	assert.NoFileExists(t, out)
}

// The same document named twice in one invocation is recorded once, and reported as named
// twice — not as "refreshed in place", which was false: the second pass was finding the
// first pass's own append, for a reference that was not in the package when the run began.
func TestEvidenceUpdate_ReportsADocumentNamedTwiceRatherThanReplacingIt(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := writeScan(t, dir, "postgres-results.json", "pg.json")

	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", scan, "--results", scan, "-o", out)
	require.NoError(t, err)

	assert.Contains(t, stderr, "named more than once; recorded once")
	assert.NotContains(t, stderr, "refreshed in place",
		"nothing was refreshed — the reference was created by this same invocation")

	uris := contentURIs(t, updatedPackage(t, out))
	count := 0
	for _, u := range uris {
		if u == "scans/pg.json" {
			count++
		}
	}
	assert.Equal(t, 1, count, "recorded exactly once")
}

// A dry run must be a preview of the real run: it validates, and it rejects the same
// misuse. Both checks used to be skipped, so a dry run green-lit a write the real run
// refused and accepted contradictory flags.
func TestEvidenceUpdate_DryRunIsAPreviewOfTheRealRun(t *testing.T) {
	dir, pkgPath := updatablePackage(t)

	// The branch this subtest exists for was provably uncovered: every other --dry-run test
	// in this file passes a destination, which is the SAME blind spot that produced the
	// defect it fixes — a dry run used to require one, and that hid because no test ran
	// without it. Removing the branch leaves the suite green and regresses this command's
	// own third documented example to a hard refusal.
	t.Run("it needs no destination, since it writes nothing", func(t *testing.T) {
		scan := writeScan(t, dir, "postgres-results.json", "solo.json")
		before, readErr := os.ReadFile(pkgPath)
		require.NoError(t, readErr)

		_, stderr, dryErr := executeCommand("evidence", "update", pkgPath, "--results", scan, "--dry-run")
		require.NoError(t, dryErr,
			"a dry run writes nothing, so neither -o nor --overwrite is required — this is the "+
				"command's own documented example")
		assert.Contains(t, stderr, "added scans/solo.json")
		assert.Contains(t, stderr, "Dry run: nothing written")

		after, readErr := os.ReadFile(pkgPath)
		require.NoError(t, readErr)
		assert.Equal(t, before, after, "and the package is untouched")
	})

	t.Run("it refuses contradictory flags", func(t *testing.T) {
		scan := writeScan(t, dir, "postgres-results.json", "pg.json")
		_, _, err := executeCommand("evidence", "update", pkgPath, "--results", scan,
			"-o", filepath.Join(dir, "x.json"), "--overwrite", "--dry-run")
		require.Error(t, err, "misuse is misuse whether or not anything is written")
		assert.Contains(t, err.Error(), "pass one")
	})

	// The property is that a dry run and a real run agree about refusing, so the trigger
	// only has to be something update genuinely refuses. It used to be a filename with an
	// unescaped percent, which 52n0c.31 made expressible — the reference is a
	// uri-reference, so such a name is recorded escaped and the write succeeds. A results
	// document outside the package's directory is still refused, by both paths, and the
	// pre-write gate keeps its own coverage in
	// TestEvidenceAddReference_RefusesToWriteAnInvalidPackage.
	t.Run("it refuses what the real run would refuse", func(t *testing.T) {
		elsewhere := filepath.Join(t.TempDir(), "outside-results.json")
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(elsewhere, src, 0o600))

		_, _, dryErr := executeCommand("evidence", "update", pkgPath, "--results", elsewhere,
			"-o", filepath.Join(dir, "y.json"), "--dry-run")
		require.Error(t, dryErr, "a dry run must not report a change the real run would reject")

		_, _, realErr := executeCommand("evidence", "update", pkgPath, "--results", elsewhere,
			"-o", filepath.Join(dir, "z.json"))
		require.Error(t, realErr, "and the real run refuses it too")
		assert.Equal(t, realErr.Error(), dryErr.Error(),
			"the two must refuse for the SAME stated reason, which is the whole property")
		assert.NoFileExists(t, filepath.Join(dir, "y.json"))
		assert.NoFileExists(t, filepath.Join(dir, "z.json"))
	})
}

// completenessCheck must not claim full baseline coverage when no system document could be
// resolved. computeCompleteness sets allBaselinesAssessed from the results alone, so an
// absent or remote systemRef would mint a green verdict from nothing.
func TestEvidenceUpdate_WillNotClaimCoverageWithNoSystemDocument(t *testing.T) {
	for _, tc := range []struct{ name, ref string }{
		{"absent systemRef", ""},
		{"remote systemRef, which is never fetched", "https://example.invalid/system.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, pkgPath := updatablePackage(t)
			doc := updatedPackage(t, pkgPath)
			if tc.ref == "" {
				delete(doc, "systemRef")
			} else {
				doc["systemRef"] = tc.ref
			}
			// Drop the system content entry too, so the package stays coherent.
			kept := []any{}
			for _, e := range doc["contents"].([]any) {
				if e.(map[string]any)["type"] != "hdf-system" {
					kept = append(kept, e)
				}
			}
			doc["contents"] = kept
			seeded, err := json.Marshal(doc)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(pkgPath, seeded, 0o600))

			scan := writeScan(t, dir, "postgres-results.json", "pg.json")
			out := filepath.Join(dir, "out.json")
			_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
			require.NoError(t, err)

			cc := updatedPackage(t, out)["completenessCheck"].(map[string]any)
			assert.Equal(t, false, cc["allBaselinesAssessed"],
				"with no system document there is nothing to assess against, so this cannot be true")
			assert.Contains(t, stderr, "no system document resolved",
				"and the operator must be told why")
		})
	}
}

// A results reference that escapes the package directory is refused by SafePath when
// completeness is recomputed over the post-update content. Nothing asserted that
// confinement, and it is the security-relevant half of resolving a recorded reference.
func TestEvidenceUpdate_RefusesAnEscapingResultsReference(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	doc := updatedPackage(t, pkgPath)
	doc["contents"] = append(doc["contents"].([]any),
		map[string]any{"type": "hdf-results", "uri": "../outside.json"})
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, seeded, 0o600))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "out.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.Error(t, err, "a recorded reference outside the package must not be resolved")
	assert.Contains(t, err.Error(), "cannot be resolved")
	assert.NoFileExists(t, out)
}

// Overlap is detected across EVERY pre-existing results entry, not just the first. The
// whole suite otherwise built coveredBefore from a single entry, so stopping at the first
// went unnoticed.
func TestEvidenceUpdate_DetectsOverlapAgainstEveryExistingEntry(t *testing.T) {
	dir, pkgPath := updatablePackage(t)

	// Add a second, DIFFERENT baseline so the RHEL9 entry is no longer first.
	pg := writeScan(t, dir, "postgres-results.json", "pg.json")
	twoEntries := filepath.Join(dir, "two.json")
	_, _, err := executeCommand("evidence", "update", pkgPath, "--results", pg, "-o", twoEntries)
	require.NoError(t, err)

	// Now a scan covering the baseline held by the LATER entry.
	pg2 := writeScan(t, dir, "postgres-results.json", "pg-host2.json")
	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", twoEntries, "--results", pg2, "-o", out)
	require.NoError(t, err)

	assert.Contains(t, stderr, "also covered by an existing entry: PostgreSQL-STIG",
		"overlap must be found even when the covering entry is not the first results entry")
}

// References are normalised on BOTH sides. Normalising only the incoming path left a stored
// "./scans/x.json" invisible to the replacement match AND to the type-conflict guard, so the
// same file could be declared under two types, and a genuine refresh added a second entry
// while the first kept a stale checksum — producing a package that fails its own verify.
func TestEvidenceUpdate_NormalisesTheStoredReferenceToo(t *testing.T) {
	t.Run("a non-normal stored ref is refreshed, not duplicated", func(t *testing.T) {
		dir, pkgPath := updatablePackage(t)
		doc := updatedPackage(t, pkgPath)
		for _, e := range doc["contents"].([]any) {
			if entry := e.(map[string]any); entry["uri"] == "scans/rhel9.json" {
				entry["uri"] = "./scans/rhel9.json" // schema-valid, not in normal form
			}
		}
		seeded, err := json.Marshal(doc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(pkgPath, seeded, 0o600))
		_, _, err = executeCommand("validate", pkgPath)
		require.NoError(t, err, "the seeded package must be valid, or this pins nothing")

		// Refresh the file the stored ref points at.
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9.json"), src, 0o600))

		out := filepath.Join(dir, "out.json")
		_, stderr, err := executeCommand("evidence", "update", pkgPath,
			"--results", filepath.Join(dir, "scans", "rhel9.json"), "-o", out)
		require.NoError(t, err)
		assert.Contains(t, stderr, "refreshed in place", "the stored ref names the same entry")

		uris := contentURIs(t, updatedPackage(t, out))
		count := 0
		for _, u := range uris {
			if normalizedRef(u) == "scans/rhel9.json" {
				count++
			}
		}
		assert.Equal(t, 1, count, "one slot, not two — a duplicate leaves the old entry with a stale checksum")

		// The real proof: the package still verifies, which it cannot with a stale entry.
		_, _, err = executeCommand("evidence", "info", "--verify", out)
		require.NoError(t, err, "a duplicated slot would leave a stale checksum and fail verify")
	})

	t.Run("the type-conflict guard is not evadable by a non-normal stored ref", func(t *testing.T) {
		dir, pkgPath := updatablePackage(t)
		bom := writeScan(t, dir, "postgres-results.json", "sbom.json")
		doc := updatedPackage(t, pkgPath)
		doc["contents"] = append(doc["contents"].([]any),
			map[string]any{"type": "bom", "uri": "./scans/sbom.json"})
		seeded, err := json.Marshal(doc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(pkgPath, seeded, 0o600))

		out := filepath.Join(dir, "out.json")
		_, _, err = executeCommand("evidence", "update", pkgPath, "--results", bom, "-o", out)
		require.Error(t, err, "the ref is held by a bom entry, whatever form it is stored in")
		assert.Contains(t, err.Error(), "with type bom")
		assert.NoFileExists(t, out)
	})
}

// The recorded checksum must be the file's real digest. The only checksum assertion in this file
// pinned that it CHANGED, never that it was CORRECT — so a reimplementation of
// contentEntryFromBytes recording any other value passed the whole suite, and the output
// failed its own verification.
func TestEvidenceUpdate_RecordsTheRealChecksum(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	body, err := os.ReadFile(scan)
	require.NoError(t, err)

	out := filepath.Join(dir, "out.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	var recorded string
	for _, e := range updatedPackage(t, out)["contents"].([]any) {
		if entry := e.(map[string]any); entry["uri"] == "scans/pg.json" {
			recorded = entry["checksum"].(map[string]any)["value"].(string)
		}
	}
	assert.Equal(t, evidenceDigestHex(body), recorded,
		"the recorded digest must be the file's real digest, not merely a different value")

	// And the end-to-end consequence: a wrong digest makes the package fail its own verify.
	_, _, err = executeCommand("evidence", "info", "--verify", out)
	require.NoError(t, err, "the updated package must verify against its own recorded checksums")
}

// Glob support is documented in the flag help, a long-help example and the README, and had
// zero coverage.
func TestEvidenceUpdate_ExpandsGlobs(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	writeScan(t, dir, "postgres-results.json", "pg.json")
	writeScan(t, dir, "rhel9-results.json", "extra.json")

	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", filepath.Join(dir, "scans", "*.json"), "-o", out)
	require.NoError(t, err)

	uris := contentURIs(t, updatedPackage(t, out))
	for _, want := range []string{"scans/rhel9.json", "scans/pg.json", "scans/extra.json"} {
		assert.Contains(t, uris, want, "the glob must expand to %s", want)
	}
	assert.Contains(t, stderr, "replaced scans/rhel9.json",
		"the already-referenced member of the glob is refreshed, not duplicated")

	t.Run("a glob matching nothing is an error, not a silent no-op", func(t *testing.T) {
		_, _, globErr := executeCommand("evidence", "update", pkgPath,
			"--results", filepath.Join(dir, "scans", "zz*.json"), "-o", filepath.Join(dir, "x.json"))
		require.Error(t, globErr)
		assert.Contains(t, globErr.Error(), "no files matched pattern")
	})
}

// Overlap must be found against EVERY existing entry, first or last. The earlier test only
// probed the last one, so the mirror image — losing the overlap report for a scan matching
// the FIRST entry — went unnoticed.
func TestEvidenceUpdate_DetectsOverlapAgainstTheFirstEntryToo(t *testing.T) {
	dir, pkgPath := updatablePackage(t)

	// Existing: [rhel9 (RHEL9-STIG), pg (PostgreSQL-STIG)]. Incoming overlaps the FIRST.
	pg := writeScan(t, dir, "postgres-results.json", "pg.json")
	two := filepath.Join(dir, "two.json")
	_, _, err := executeCommand("evidence", "update", pkgPath, "--results", pg, "-o", two)
	require.NoError(t, err)

	rhel2 := writeScan(t, dir, "rhel9-results.json", "rhel9-host2.json")
	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", two, "--results", rhel2, "-o", out)
	require.NoError(t, err)
	assert.Contains(t, stderr, "also covered by an existing entry: RHEL9-STIG",
		"overlap against the FIRST existing entry must be reported")
}

// Two same-baseline scans added in ONE invocation must both be reported — the documented
// pipeline shape is a glob, and a snapshot taken before the loop said nothing about them.
func TestEvidenceUpdate_ReportsOverlapBetweenDocumentsAddedTogether(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	a := writeScan(t, dir, "postgres-results.json", "pg-a.json")
	b := writeScan(t, dir, "postgres-results.json", "pg-b.json")

	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", a, "--results", b, "-o", out)
	require.NoError(t, err)

	assert.Contains(t, stderr, "added scans/pg-b.json")
	assert.Contains(t, stderr, "also covered by an existing entry: PostgreSQL-STIG",
		"the second document added in this same run overlaps the first, and must be reported")
}

// A non-results entry whose uri escapes the package must not be resolved by an update that
// has nothing to do with it — the type filter in resultsPathsInPackage is load-bearing, not
// defence in depth. (An earlier note on this card wrongly claimed it had no observable
// consequence; the AC review disproved that.)
func TestEvidenceUpdate_IgnoresANonResultsEntryWhenRecomputingCompleteness(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	doc := updatedPackage(t, pkgPath)
	doc["contents"] = append(doc["contents"].([]any),
		map[string]any{"type": "bom", "uri": "../outside-sbom.json"})
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, seeded, 0o600))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "out.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err,
		"a bom entry's uri is not a results reference and must not be resolved when recomputing completeness")
	assert.FileExists(t, out)
}

// A document covering a baseline nothing else covers must NOT report an overlap. Recording
// added entries into the overlap map (so two documents in one run are compared) put each
// entry's own baselines into the union, so every new scan claimed to overlap "an existing
// entry" — and the first-entry overlap test passed because of it, not despite it.
func TestEvidenceUpdate_ReportsNoOverlapForANewBaseline(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	// The package covers RHEL9-STIG only; this covers PostgreSQL-STIG.
	pg := writeScan(t, dir, "postgres-results.json", "pg.json")

	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", pg, "-o", out)
	require.NoError(t, err)

	assert.Contains(t, stderr, "added scans/pg.json")
	assert.NotContains(t, stderr, "also covered by an existing entry",
		"nothing else covers PostgreSQL-STIG, so there is no overlap to report")
	assert.NotContains(t, stderr, "both are kept",
		"and no distinguishing facts to offer")
}

// systemDocForPackage's sibling branches (absent, remote, escaping) are all pinned; the
// unmarshal failure was not, so swallowing it left the suite green — and that is the branch
// where an unreadable system document would otherwise pass silently and let completeness be
// computed against nothing.
func TestEvidenceUpdate_RefusesAnUnreadableSystemDocument(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	// The systemRef target exists and is readable, but is not JSON.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "system.json"), []byte("only a sentence\n"), 0o600))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "out.json")
	_, _, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.Error(t, err, "a systemRef that cannot be parsed must not be silently treated as absent")
	assert.Contains(t, err.Error(), "is not readable JSON")
	assert.NoFileExists(t, out, "and nothing may be written")
}

// The distinguishing-facts fallback must say it could not read the document, rather than
// implying the two scans are indistinguishable for a substantive reason. Reachable with a
// document that fingerprints as results but carries an unparseable typed field.
func TestEvidenceUpdate_SaysWhenItCannotReadTheDistinguishingFacts(t *testing.T) {
	dir, pkgPath := updatablePackage(t)

	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(src, &doc))
	doc["timestamp"] = "yesterday afternoon" // fingerprints as results; not a date-time
	broken, err := json.Marshal(doc)
	require.NoError(t, err)
	path := filepath.Join(dir, "scans", "vague.json")
	require.NoError(t, os.WriteFile(path, broken, 0o600))

	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", path, "-o", out)
	require.NoError(t, err)
	assert.Contains(t, stderr, "also covered by an existing entry: RHEL9-STIG")
	assert.Contains(t, stderr, "could not be read to say what distinguishes them",
		"the fallback must name its own failure, not imply the scans are alike")
}

// A package can reference a results document that has since been deleted, and can carry an
// entry with an empty uri (schema-valid — uri has no minLength). Neither should stop an
// update that has nothing to do with them: the missing document is `evidence info --verify`'s to
// report, and an entry naming nothing names nothing. This also exercises the skip paths in
// baselinesByRef, resultsPathsInPackage and normalizedRef, which the card's >90% coverage
// requirement otherwise leaves short.
func TestEvidenceUpdate_ToleratesAMissingOrUnnamedExistingEntry(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	doc := updatedPackage(t, pkgPath)

	// An entry naming nothing, and one whose document is gone.
	doc["contents"] = append(doc["contents"].([]any),
		map[string]any{"type": "hdf-results", "uri": ""},
		map[string]any{"type": "hdf-results", "uri": "scans/deleted.json"})
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, seeded, 0o600))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err,
		"a missing or unnamed pre-existing entry is not this command's to refuse")

	uris := contentURIs(t, updatedPackage(t, out))
	assert.Contains(t, uris, "scans/pg.json", "the new document is still recorded")
	assert.Contains(t, uris, "scans/deleted.json", "and nothing is removed, as ever")
	assert.NotContains(t, stderr, "cannot be resolved",
		"a deleted document is verify's to report, not update's to fail on")
}

// A results document whose own baselines cannot be read is skipped when building the overlap
// map, rather than failing the update — the same soft-fail as a deleted one.
func TestEvidenceUpdate_SkipsAnExistingEntryWhoseBaselinesCannotBeRead(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	// Break the bytes of the already-referenced results document. Its checksum will no
	// longer match either, which is verify's business, not update's.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "rhel9.json"), []byte("{oops\n"), 0o600))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "out.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err, "an unparseable existing entry must not fail an unrelated update")
	assert.NotContains(t, stderr, "also covered by an existing entry",
		"its baselines are unknown, so no overlap can be claimed against it")
	assert.Contains(t, contentURIs(t, updatedPackage(t, out)), "scans/pg.json")
}

// A systemRef naming a document that is not there must fail loudly: completeness would
// otherwise be computed against nothing, which is the verdict-from-nothing this command
// refuses to mint. Distinct from an ABSENT systemRef, which is legitimate and handled by
// forcing allBaselinesAssessed false.
func TestEvidenceUpdate_RefusesAMissingSystemDocument(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	require.NoError(t, os.Remove(filepath.Join(dir, "system.json")))

	scan := writeScan(t, dir, "postgres-results.json", "pg.json")
	out := filepath.Join(dir, "out.json")
	_, _, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.Error(t, err, "a systemRef that names nothing is not the same as no systemRef")
	assert.Contains(t, err.Error(), "is referenced but could not be read")
	assert.NoFileExists(t, out)
}

// systemDocForPackage's doc comment worries that an UNRESOLVABLE systemRef would mint
// a green verdict from nothing. The sharper failure is the opposite: SafePath JOINS, so
// a root-anchored "/system.json" re-roots to <pkgDir>/system.json and the reference
// RESOLVES — to a different document than it names. Completeness is then computed
// against a document the package never pointed at, which is worse than not computing
// it, because the verdict looks earned.
//
// The relative case is the CONTROL and is what makes the assertion mean anything: both
// packages carry results for both planned baselines, so a resolving systemRef yields
// allBaselinesAssessed=true. An earlier version of this test supplied only ONE results
// document, so false was true for an unrelated reason and the test passed before the fix.
func TestEvidenceUpdate_DoesNotResolveSystemRefOntoADifferentDocument(t *testing.T) {
	for _, tc := range []struct {
		name, systemRef string
		wantAssessed    bool
		// wantNamed: the run must print the reference the package records. An absent or
		// unrecorded systemRef has no reference to name.
		wantNamed bool
	}{
		{name: "relative reference resolves", systemRef: "system.json", wantAssessed: true, wantNamed: false},
		{name: "root-anchored reference must not re-root", systemRef: "/system.json", wantAssessed: false, wantNamed: true},
		// These two aborted the run by NAME before references were classified here.
		// Classifying them turned the abort into a success, and without these rows the
		// suite stayed green while the reference vanished from the output entirely — the
		// regression was invisible because nothing covered a non-root-anchored reject.
		{name: "parent traversal is named, not silent", systemRef: "../system.json", wantAssessed: false, wantNamed: true},
		{name: "absolute outside the package is named, not silent", systemRef: "/etc/hosts", wantAssessed: false, wantNamed: true},
		// The contrast case: a systemRef the package never recorded is NOT a rejected
		// reference, and the two must not read identically on stderr.
		{name: "absent systemRef reports no reference", systemRef: "", wantAssessed: false, wantNamed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, n := range []string{"system.json", "rhel9-results.json", "postgres-results.json"} {
				body, err := os.ReadFile(filepath.Join("testdata", "evidence-verify", n))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(dir, n), body, 0o600))
			}
			pkg := map[string]interface{}{
				"name": "reroot",
				"contents": []map[string]interface{}{
					{"type": "hdf-results", "uri": "rhel9-results.json"},
					{"type": "hdf-results", "uri": "postgres-results.json"},
				},
			}
			if tc.systemRef != "" {
				pkg["systemRef"] = tc.systemRef
			}
			raw, err := json.Marshal(pkg)
			require.NoError(t, err)
			pkgPath := filepath.Join(dir, "pkg.json")
			require.NoError(t, os.WriteFile(pkgPath, raw, 0o600))
			out := filepath.Join(dir, "updated.json")

			_, stderr, updateErr := executeCommand("evidence", "update", pkgPath,
				"--results", filepath.Join(dir, "rhel9-results.json"), "-o", out)
			require.NoError(t, updateErr)

			if tc.wantNamed {
				assert.Contains(t, stderr, tc.systemRef,
					"a systemRef the package records and this run rejected must be named, "+
						"not reduced to a generic no-system-document line")
			} else {
				assert.NotContains(t, stderr, "does not resolve inside",
					"a resolving or absent systemRef must not be reported as rejected")
			}

			data, readErr := os.ReadFile(out)
			require.NoError(t, readErr)
			var updated map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &updated))
			check, ok := updated["completenessCheck"].(map[string]interface{})
			require.True(t, ok, "update records a completenessCheck")
			assert.Equal(t, tc.wantAssessed, check["allBaselinesAssessed"],
				"a systemRef that does not resolve inside the package must not be substituted "+
					"by a same-basename document that happens to be there")
		})
	}
}

// caseInsensitiveFS reports whether this filesystem folds case, by PROBING rather than
// assuming — the platform is not a reliable predictor and an unguarded assumption makes a
// test that silently proves nothing on the other kind.
func caseInsensitiveFS(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe")
	require.NoError(t, os.WriteFile(probe, []byte("x"), 0o600))
	defer func() { _ = os.Remove(probe) }()
	_, err := os.Stat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

// A stored reference differing from the file only in case names ONE file on a
// case-insensitive filesystem, so a refresh must refresh that entry rather than adding a
// second one. Two entries for one file is not merely untidy: the next update refreshes
// only the spelling it matched, the other keeps a stale checksum, and the package then
// fails its own verification — which is verbatim the failure hdf-libs-52n0c.5's AC
// was written to eliminate.
//
// Matching is by filesystem identity (os.SameFile via samePath), which is correct on BOTH
// filesystem kinds: on a case-sensitive one the two spellings are different files and
// correctly do not match. The stored spelling is kept, never rewritten — it is a recorded
// reference in an attestation — and the difference is reported instead.
func TestEvidenceUpdate_MatchesAReferenceDifferingOnlyInCase(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if !caseInsensitiveFS(t, dir) {
		t.Skip("filesystem is case-sensitive; these two spellings are different files here")
	}

	// Re-record the stored reference under a different case. `build` CAN produce this: it
	// derives the reference from the path as typed (filepath.Abs + EvalSymlinks, neither of
	// which canonicalizes case), so one mistyped case on the command line is enough.
	stored := rewriteStoredRef(t, pkgPath, "rhel9.json", "RHEL9.json")

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", filepath.Join(dir, "scans", "rhel9.json"), "-o", out)
	require.NoError(t, err)

	uris := contentURIs(t, updatedPackage(t, out))
	assert.Contains(t, uris, stored, "the stored spelling survives; an attestation is not rewritten")
	assert.NotContains(t, uris, "scans/rhel9.json",
		"and no second entry is added for the same file")
	assert.Len(t, uris, len(contentURIs(t, updatedPackage(t, pkgPath))),
		"the entry count is unchanged — refreshed in place, not appended")
	assert.Contains(t, stderr, "written differently",
		"the difference is reported rather than silently kept")
}

// The complement of the test above, and the half this platform cannot run. On a
// case-sensitive filesystem two case-differing references name DIFFERENT files, so they
// must NOT be matched — the incoming document is a new entry, not a refresh. Skipped here
// and executed by CI's Linux leg, which is case-sensitive; without it the identity match
// would be unverified on exactly the filesystem where getting it wrong would silently
// merge two distinct scans into one.
func TestEvidenceUpdate_ACaseDifferingReferenceIsADifferentFileWhenTheFSSaysSo(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if caseInsensitiveFS(t, dir) {
		t.Skip("filesystem folds case; these two spellings are one file here")
	}

	// Both spellings exist as genuinely different files.
	src, err := os.ReadFile(filepath.Join(dir, "scans", "rhel9.json"))
	require.NoError(t, err)
	other := filepath.Join(dir, "scans", "RHEL9.json")
	require.NoError(t, os.WriteFile(other, src, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", other, "-o", out)
	require.NoError(t, err)

	uris := contentURIs(t, updatedPackage(t, out))
	assert.Contains(t, uris, "scans/rhel9.json", "the original entry is untouched")
	assert.Contains(t, uris, "scans/RHEL9.json", "and the different file is a NEW entry")
	assert.NotContains(t, stderr, "written differently",
		"nothing differs in case here: they are two files, correctly treated as two")
}

// The assertion the first version of this test was missing, and the one the card is
// actually about: the matched entry's CHECKSUM must be refreshed. Asserting the spelling,
// the entry count and the note left a mutant that matches, reports "refreshed in place"
// and never refreshes passing the whole suite — while producing a package that fails its
// own verify in a single update.
func TestEvidenceUpdate_RefreshesTheChecksumOfACaseDifferingMatch(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if !caseInsensitiveFS(t, dir) {
		t.Skip("filesystem is case-sensitive; these two spellings are different files here")
	}
	stored := rewriteStoredRef(t, pkgPath, "rhel9.json", "RHEL9.json")
	before := checksumOf(t, updatedPackage(t, pkgPath), stored)
	require.NotEmpty(t, before)

	// The scan is re-run, so the bytes change. Without this the two checksums are equal
	// and the test cannot tell refreshed from untouched.
	scan := filepath.Join(dir, "scans", "rhel9.json")
	body, err := os.ReadFile(scan)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))
	doc["__rescanned"] = true
	rewritten, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(scan, rewritten, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	after := checksumOf(t, updatedPackage(t, out), stored)
	require.NotEmpty(t, after, "the entry survives under its stored spelling")
	assert.NotEqual(t, before, after, "and its checksum is REFRESHED, not left stale")
	sum := evidenceDigestSum(rewritten)
	assert.Equal(t, hex.EncodeToString(sum[:]), after, "to the digest of the new bytes")
}

// A package the PREVIOUS release wrote can hold two entries whose uris differ only in case
// but name one file. Refreshing only the first left the other stale, so update exited 0
// saying "refreshed in place" while verify exited 1 — the AC's own definition of the
// defect, on the migration case this card exists to clean up.
func TestEvidenceUpdate_RefreshesEveryEntryNamingTheSameFile(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if !caseInsensitiveFS(t, dir) {
		t.Skip("filesystem is case-sensitive; these two spellings are different files here")
	}

	// Hand-build the duplicate the old code produced: two entries, one file.
	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	var dup map[string]any
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if uri, _ := entry["uri"].(string); uri == "scans/rhel9.json" {
			dup = map[string]any{}
			for k, v := range entry {
				dup[k] = v
			}
			dup["uri"] = "scans/RHEL9.json"
		}
	}
	require.NotNil(t, dup, "precondition: the package records scans/rhel9.json")
	doc["contents"] = append(contents, dup)
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	// Captured BEFORE the update: the duplicate was built by copying, so the two recorded
	// digests start EQUAL and asserting only Equal(lower, upper) is true in the broken
	// world as well as the fixed one — it passes when NEITHER entry is refreshed.
	stale := checksumOf(t, updatedPackage(t, pkgPath), "scans/RHEL9.json")
	require.NotEmpty(t, stale)

	scan := filepath.Join(dir, "scans", "rhel9.json")
	body := []byte(`{"baselines":[],"__rescanned":true}`)
	require.NoError(t, os.WriteFile(scan, body, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	updated := updatedPackage(t, out)
	lower := checksumOf(t, updated, "scans/rhel9.json")
	upper := checksumOf(t, updated, "scans/RHEL9.json")
	require.NotEmpty(t, lower)
	require.NotEmpty(t, upper)
	sum := evidenceDigestSum(body)
	want := hex.EncodeToString(sum[:])
	assert.Equal(t, want, lower, "the matched entry carries the new digest")
	assert.Equal(t, want, upper, "and so does the OTHER entry naming the same file")
	assert.NotEqual(t, stale, upper, "which means it was refreshed, not merely left equal")
	assert.Contains(t, stderr, "name one file", "and the report says more than one reference was refreshed")
}

// rewriteStoredRef replaces a stored contents[] uri with another spelling of it — a
// different case, a different Unicode normalization, or an absolute path — and returns the
// spelling it wrote.
func rewriteStoredRef(t *testing.T, pkgPath, from, to string) string {
	t.Helper()
	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	var stored string
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if uri, _ := entry["uri"].(string); strings.HasSuffix(uri, from) {
			stored = strings.Replace(uri, from, to, 1)
			entry["uri"] = stored
		}
	}
	require.NotEmpty(t, stored, "precondition: the package records a uri ending %s", from)
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))
	return stored
}

// checksumOf returns the recorded checksum value for a contents[] uri, or "".
func checksumOf(t *testing.T, doc map[string]any, uri string) string {
	t.Helper()
	contents, _ := doc["contents"].([]any)
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if got, _ := entry["uri"].(string); got != uri {
			continue
		}
		cs, _ := entry["checksum"].(map[string]any)
		if cs == nil {
			return ""
		}
		v, _ := cs["value"].(string)
		return v
	}
	return ""
}

// NFC and NFD are one NAME in two encodings, not two names — os.SameFile says one file on
// APFS — so they must match. A case-fold alone does not see it (EqualFold(NFC, NFD) is
// false), which reopened this card's P1 for an input class that is ordinary on macOS:
// readdir and extracted archives yield NFD, shell completion yields NFC, and `build`
// records whichever it was handed.
func TestEvidenceUpdate_MatchesAReferenceDifferingOnlyInUnicodeNormalization(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	const nfc = "café.json"  // é as one rune
	const nfd = "café.json" // e + combining acute
	scan := filepath.Join(dir, "scans", nfc)
	src, err := os.ReadFile(filepath.Join(dir, "scans", "rhel9.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(scan, src, 0o600))
	if _, statErr := os.Stat(filepath.Join(dir, "scans", nfd)); statErr != nil {
		t.Skip("filesystem does not fold Unicode normalization; these are two files here")
	}

	// Record the NFD spelling, then refresh using the NFC one.
	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	entry, _ := contents[len(contents)-1].(map[string]any)
	stored := "scans/" + nfd
	entry["uri"] = stored
	entry["checksum"] = map[string]any{"algorithm": "sha256", "value": strings.Repeat("0", 64)}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	updated := updatedPackage(t, out)
	uris := contentURIs(t, updated)
	assert.Contains(t, uris, stored, "the stored NFD spelling survives")
	assert.NotContains(t, uris, "scans/"+nfc, "and no second entry is appended for one file")
	sum := evidenceDigestSum(src)
	assert.Equal(t, hex.EncodeToString(sum[:]), checksumOf(t, updated, stored),
		"and its checksum is refreshed, so the package does not fail its own verify")
}

// One file named twice in ONE invocation under two spellings must be recorded once. The
// duplicate guard was keyed on the reference STRING, so two case spellings evaded it: the
// same entry was reported twice, and — worse — pass 2 matched pass 1's own append and
// called it "refreshed in place", which is verbatim the falsehood that guard's comment
// says it exists to prevent.
func TestEvidenceUpdate_OneFileNamedTwiceInOneInvocationIsRecordedOnce(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if !caseInsensitiveFS(t, dir) {
		t.Skip("filesystem is case-sensitive; these two spellings are different files here")
	}
	// A file the package does NOT yet record, so pass 1 appends and pass 2 must not then
	// claim to have refreshed it.
	src, err := os.ReadFile(filepath.Join(dir, "scans", "rhel9.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scans", "new.json"), src, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", filepath.Join(dir, "scans", "new.json"),
		"--results", filepath.Join(dir, "scans", "NEW.json"), "-o", out)
	require.NoError(t, err)

	uris := contentURIs(t, updatedPackage(t, out))
	var named int
	for _, u := range uris {
		if strings.EqualFold(u, "scans/new.json") {
			named++
		}
	}
	assert.Equal(t, 1, named, "one file, one entry")
	assert.NotContains(t, stderr, "refreshed in place",
		"an entry this invocation APPENDED was never refreshed in place")
	assert.Equal(t, 1, strings.Count(stderr, "added "), "and it is reported once, as added")
}

// The maintainer decided twice that a hardlink and an absolute-versus-relative spelling
// stay SEPARATE references: they are two names for one file, not one name written two
// ways, and merging them silently would discard a reference the operator recorded. Nothing
// guarded that decision — reverting the spelling predicate to a bare samePath identity
// test passed the whole suite while merging a hardlink into the recorded entry and
// announcing it as one name written differently.
func TestEvidenceUpdate_TwoNamesForOneFileStaySeparateReferences(t *testing.T) {
	t.Run("a hardlink is a second name, not a second spelling", func(t *testing.T) {
		dir, pkgPath := updatablePackage(t)
		scan := filepath.Join(dir, "scans", "rhel9.json")
		link := filepath.Join(dir, "scans", "hard.json")
		if err := os.Link(scan, link); err != nil {
			t.Skipf("filesystem does not support hardlinks here: %v", err)
		}
		require.True(t, sameFileOnDisk(t, scan, link), "precondition: one file, two names")

		out := filepath.Join(dir, "updated.json")
		_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", link, "-o", out)
		require.NoError(t, err)

		uris := contentURIs(t, updatedPackage(t, out))
		assert.Contains(t, uris, "scans/rhel9.json", "the recorded reference is untouched")
		assert.Contains(t, uris, "scans/hard.json", "and the other name is its own reference")
		assert.NotContains(t, stderr, "written differently",
			"nothing is written differently here: these are two names")
	})

	t.Run("an absolute stored reference is a second name, not a second spelling", func(t *testing.T) {
		dir, pkgPath := updatablePackage(t)
		scan := filepath.Join(dir, "scans", "rhel9.json")
		// The shared helper, not a second copy of it: rewriteStoredRef already replaces a
		// stored uri with any other spelling, and an absolute path is just another spelling.
		rewriteStoredRef(t, pkgPath, "scans/rhel9.json", scan)

		out := filepath.Join(dir, "updated.json")
		_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
		require.NoError(t, err)

		uris := contentURIs(t, updatedPackage(t, out))
		assert.Contains(t, uris, scan, "the absolute reference is untouched")
		assert.Contains(t, uris, "scans/rhel9.json", "and the relative one is its own reference")
		assert.NotContains(t, stderr, "written differently",
			"an absolute and a relative reference are two names for one file")
	})
}

// sameFileOnDisk reports whether two paths are one file, so a precondition can be asserted
// rather than assumed.
func sameFileOnDisk(t *testing.T, a, b string) bool {
	t.Helper()
	ia, err := os.Stat(a)
	require.NoError(t, err)
	ib, err := os.Stat(b)
	require.NoError(t, err)
	return os.SameFile(ia, ib)
}

// The refusal has to name the entry the operator must go and remove, which is the spelling
// the PACKAGE records. A conflict is reachable by a spelling that merely names the same
// file, and naming the incoming one told them to remove a reference not in their package.
func TestEvidenceUpdate_RetypeRefusalNamesTheStoredSpelling(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if !caseInsensitiveFS(t, dir) {
		t.Skip("needs a case-insensitive filesystem for the two spellings to name one file")
	}

	// The hdf-system entry is recorded under a different case than the file on disk.
	stored := rewriteStoredRef(t, pkgPath, "system.json", "System.json")
	require.Equal(t, "System.json", stored)

	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "system.json"), src, 0o600))

	out := filepath.Join(dir, "out.json")
	// Absolute, as the sibling test does: a bare relative name resolves against the working
	// directory, not the package. It normalizes to the package-relative "system.json",
	// which is a different spelling from the stored "System.json".
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", filepath.Join(dir, "system.json"), "-o", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "System.json is already recorded",
		"the refusal names the stored spelling, which is the entry to remove")
	assert.NoFileExists(t, out)
}

// update REPORTS that the incoming file is already named by a reference it deliberately
// did not match. Two different names for one file — a hardlink, or an absolute reference
// beside a relative one — are two references the operator recorded, and merging them
// would discard one; that stays settled and is guarded by
// TestEvidenceUpdate_TwoNamesForOneFileStaySeparateReferences.
//
// What was wrong was the SILENCE. update appended a second entry, left the first carrying
// a stale checksum, and exited 0; the operator found out one command later when
// verification failed and bundle refused the package, with nothing pointing at the cause.
// Reported at update time, while they can still act on it.
func TestEvidenceUpdate_ReportsAnotherReferenceNamingTheSameFile(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	// The package records the ABSOLUTE spelling, which is what build writes when handed a
	// --results outside the package directory. packageRelativeRef turns the incoming path
	// into "scans/rhel9.json", so the two are one file under two names.
	stored := rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"), scan)

	// The scan is re-run, so the recorded checksum on the absolute entry goes stale.
	require.NoError(t, os.WriteFile(scan, []byte(`{"baselines":[],"x":1}`), 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err, "reported, not refused: the schema admits a package naming one file twice")

	assert.Contains(t, stderr, stored,
		"the report must name the OTHER reference, which is the entry the operator has to fix")
	// The CONSEQUENCE, not the mechanism. This assertion used to look for the word
	// "stale", which stopped being the right word once the report learned to measure:
	// an uppercase-but-correct digest is not stale, yet verification still fails it.
	// "verification will fail" is the claim an operator acts on and the one the report
	// is accountable for.
	assert.Contains(t, stderr, "verification will fail on it",
		"and state the consequence, which is why this is worth saying at all")

	// And the two stay separate, which is the settled decision this card does not reopen.
	contents, _ := updatedPackage(t, out)["contents"].([]any)
	spellings := make([]string, 0, len(contents))
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if docType, _ := entry["type"].(string); docType == "hdf-results" {
			uri, _ := entry["uri"].(string)
			spellings = append(spellings, uri)
		}
	}
	assert.Contains(t, spellings, stored, "the absolute entry survives under its own spelling")
	assert.Contains(t, spellings, filepath.ToSlash(filepath.Join("scans", "rhel9.json")),
		"and the incoming one is added rather than merged into it")
}

// The report does NOT fire for a case or normalization difference: that pair IS matched
// and refreshed in place, so no entry is left stale and there is nothing to warn about.
// Firing there would train an operator to ignore the message.
func TestEvidenceUpdate_DoesNotReportTheCaseDifferingPairItRefreshes(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if !caseInsensitiveFS(t, dir) {
		t.Skip("filesystem is case-sensitive; these two spellings are different files here")
	}
	rewriteStoredRef(t, pkgPath, "rhel9.json", "RHEL9.json")
	scan := filepath.Join(dir, "scans", "rhel9.json")
	require.NoError(t, os.WriteFile(scan, []byte(`{"baselines":[],"x":2}`), 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)
	assert.NotContains(t, stderr, "already names this same file",
		"a spelling difference is refreshed in place, so no entry is left stale")
}

// A HARDLINK pair reports the same way, because it is the same condition reached by a
// different route: two names, one inode, so samePath says one file while the names differ.
// Tested separately from the absolute-versus-relative case because a fix proven on one
// spelling difference says nothing about the other — samePath's inode comparison is what
// both rely on, and only a hardlink exercises it where the strings share no suffix.
func TestEvidenceUpdate_ReportsAHardlinkNamingTheSameFile(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	linked := filepath.Join(dir, "scans", "other-name.json")
	if err := os.Link(scan, linked); err != nil {
		t.Skipf("filesystem does not support hard links: %v", err)
	}
	// The package records the LINK; the command is given the original. Two names, one
	// inode, and no shared suffix for a string comparison to fall back on.
	stored := rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"),
		filepath.ToSlash(filepath.Join("scans", "other-name.json")))
	require.NoError(t, os.WriteFile(scan, []byte(`{"baselines":[],"x":3}`), 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	assert.Contains(t, stderr, stored, "the hard-linked spelling must be named")
	assert.Contains(t, stderr, "verification will fail on it",
		"with the same consequence stated as for an absolute-versus-relative pair")
}

// The warning must not fire for an entry THIS invocation just added. Two spellings of one
// file given in one command — here a hardlink pair, neither recorded before — both get
// appended with fresh checksums, so nothing is stale and verification passes. Warning
// about it would be a false claim, and the card's own reasoning says a warning that cries
// wolf is worse than silence.
//
// The cause was already recorded in this file for the spelling-pair case: contents is
// mutated in-loop, so the second argument sees the FIRST argument's own append and cannot
// tell it from an entry the package held when the command started. I reintroduced that
// exact trap in a new form, and a reviewer found it by running the CLI rather than by any
// assertion here — which is why this test exists at all.
func TestEvidenceUpdate_DoesNotCallAnEntryItJustAddedStale(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	src, err := os.ReadFile(filepath.Join(dir, "scans", "rhel9.json"))
	require.NoError(t, err)
	fresh := filepath.Join(dir, "scans", "new.json")
	require.NoError(t, os.WriteFile(fresh, src, 0o600))
	linked := filepath.Join(dir, "scans", "new-link.json")
	if err := os.Link(fresh, linked); err != nil {
		t.Skipf("filesystem does not support hard links: %v", err)
	}

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", fresh, "--results", linked, "-o", out)
	require.NoError(t, err)

	// NOT a search for "stale": t.TempDir() embeds the test's NAME in the path, the path
	// is printed, and this test's name contains the word — so that assertion matched its
	// own directory and failed against correct output. The warning's own sentence is the
	// thing to look for, and no path can contain it.
	assert.NotContains(t, stderr, "already names this same file",
		"both entries were added in this run with fresh checksums; neither is stale")

	// And the claim the warning WOULD have made is false here, asserted by running the
	// thing it predicts rather than by reading the message.
	verifyOut, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	require.NoError(t, verr, "verification must pass, which is what makes the warning false")
	assert.Contains(t, verifyOut, "checksums valid")
}

// Nor may it call an entry stale that it REFRESHED earlier in this same invocation. A
// pre-existing entry matched by the first --results keeps its index when replaced, so a
// positional "did this exist before the run" test cannot tell it from one still carrying
// its old checksum — and a later argument naming the same file under another spelling
// re-flagged it as stale when it had just been rewritten.
//
// The first fix guarded "added this run" and missed "replaced this run", because I
// reasoned about WHERE an entry sits rather than WHAT happened to it. The predicate is
// now the fact itself: has this entry already been given a fresh checksum here.
func TestEvidenceUpdate_DoesNotCallAnEntryItJustRefreshedStale(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	linked := filepath.Join(dir, "scans", "hard.json")
	if err := os.Link(scan, linked); err != nil {
		t.Skipf("filesystem does not support hard links: %v", err)
	}
	// The package records only the hard-linked name, which shares no suffix with the other
	// — so the two are one file under two names, matched by inode and nothing else.
	rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"),
		filepath.ToSlash(filepath.Join("scans", "hard.json")))

	out := filepath.Join(dir, "updated.json")
	// The first argument refreshes the recorded entry in place; the second names the same
	// file under the other spelling and is added.
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", linked, "--results", scan, "-o", out)
	require.NoError(t, err)

	assert.NotContains(t, stderr, "already names this same file",
		"the recorded entry was refreshed by the first argument, so it is not stale")

	// Asserted on the PREDICTION, not the wording: what made the warning wrong is that
	// the failure it forecasts does not happen.
	verifyOut, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	require.NoError(t, verr, "verification must pass, which is what makes the warning false")
	assert.Contains(t, verifyOut, "checksums valid")
}

// And it may not call an untouched entry stale when the bytes never changed. Re-running
// update on an unmodified file, or adding a second name for one, leaves the other-named
// entry's recorded checksum CORRECT — it was computed over bytes that still exist.
//
// This is the third false positive on this one warning and the only one that was not a
// bookkeeping error. The first two had the code wrong about whether an entry had been
// touched this run; this one had it right and drew a false conclusion from it. "Not
// refreshed here" means stale only if the bytes diverged, and the bytes are in hand — so
// the warning now compares them instead of inferring, under the entry's OWN recorded
// algorithm, which is also what verification will use.
func TestEvidenceUpdate_DoesNotCallAnUnchangedEntryStale(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	// The package records the absolute spelling; the file is NOT modified.
	rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"), scan)

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	assert.NotContains(t, stderr, "already names this same file",
		"the other entry's checksum is of bytes that never changed, so it is not stale")

	verifyOut, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	require.NoError(t, verr, "verification passes, which is what makes the warning false")
	assert.Contains(t, verifyOut, "checksums valid")
}

// An other-named entry recording a BLANK checksum value is not stale either: there is
// nothing recorded to have gone stale, and verification reports such an entry as SKIPPED
// rather than failed — so claiming "verification will fail on it" would overclaim in a
// fourth way. Written because a mutant removing this branch killed no test: I had the
// behaviour right and nothing pinned it.
func TestEvidenceUpdate_DoesNotCallABlankChecksumStale(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	stored := rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"), scan)

	// Blank the recorded value on that absolute entry, which the schema permits
	// (Checksum.value has no minLength), and change the bytes so only the blank value
	// stands between this and a measured divergence.
	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if uri, _ := entry["uri"].(string); uri == stored {
			entry["checksum"] = map[string]any{"algorithm": evidenceDigestAlgo, "value": ""}
		}
	}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))
	require.NoError(t, os.WriteFile(scan, []byte(`{"baselines":[],"x":7}`), 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	assert.NotContains(t, stderr, "already names this same file",
		"a blank recorded value has nothing to go stale")

	// And the prediction the warning would have made is false: verification SKIPS it.
	verifyOut, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	require.NoError(t, verr, "an unverifiable entry is reported, not failed")
	assert.Contains(t, verifyOut, "skipped")
}

// The warning must agree with VERIFICATION, which compares the recorded checksum
// EXACTLY. hdfengine.VerifyChecksums uses actual == recorded against a lowercase hex
// digest, so an uppercase-but-mathematically-correct value FAILS there — and this report
// exists to predict that failure. Comparing case-insensitively here made the prediction
// disagree with the thing it predicts: update went silent while 'info --verify' exited 1.
//
// The invariant is that one comparison mirrors the other. That is what this test pins,
// not a preference about hex casing.
func TestEvidenceUpdate_AgreesWithVerificationOnCasedHex(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	stored := rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"), scan)

	// The recorded value is the CORRECT digest, uppercased. The file is never modified.
	src, err := os.ReadFile(scan)
	require.NoError(t, err)
	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if uri, _ := entry["uri"].(string); uri == stored {
			entry["checksum"] = map[string]any{
				"algorithm": evidenceDigestAlgo,
				"value":     strings.ToUpper(evidenceDigestHex(src)),
			}
		}
	}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	// Verification is the authority. Whatever it does, the warning must have predicted.
	_, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	warned := strings.Contains(stderr, "already names this same file")
	if verr != nil {
		assert.True(t, warned,
			"verification fails on this entry, so update had to say so — it stayed silent, "+
				"which is the prediction disagreeing with the thing predicted")
	} else {
		assert.False(t, warned, "verification passes, so the warning would be a false claim")
	}
}

// The other half of mirroring verification: the comparison uses the ENTRY'S OWN recorded
// algorithm, not the one this build writes. An older package records sha256 while
// authoring now writes sha512 (52n0c.30), so computing under the default would find a
// difference where verification — which reads each entry's algorithm — finds a match, and
// the report would warn about an entry that verifies perfectly.
//
// Written because a mutant replacing the entry's algorithm with the default killed NO
// test: the behaviour was right and nothing held it there. Second branch on this card
// found that way rather than by a reviewer.
func TestEvidenceUpdate_ComparesUnderTheEntrysOwnAlgorithm(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	stored := rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"), scan)

	// A correct sha256 digest — what a package authored before 52n0c.30 carries. The file
	// is never modified, so verification will match it and the report must stay silent.
	src, err := os.ReadFile(scan)
	require.NoError(t, err)
	legacy := sha256.Sum256(src)
	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if uri, _ := entry["uri"].(string); uri == stored {
			entry["checksum"] = map[string]any{
				"algorithm": "sha256", "value": hex.EncodeToString(legacy[:]),
			}
		}
	}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	assert.NotContains(t, stderr, "already names this same file",
		"a correct sha256 entry is not divergent; only computing under the wrong algorithm "+
			"would make it look that way")

	// And verification agrees, which is the authority this report answers to.
	verifyOut, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	require.NoError(t, verr)
	assert.Contains(t, verifyOut, "sha256 match",
		"verification reads the entry's own algorithm too, which is the invariant")
}

// A WHITESPACE-ONLY recorded value is not "nothing to diverge". VerifyChecksums skips
// only an exactly-empty checksum (c.Checksum == ""), so "   " is fetched, hashed and
// reported as a MISMATCH — while this report trimmed it, called it blank, and stayed
// silent. The same disagreement as the fold-versus-exact one, on the blank branch.
//
// Schema-valid, so reachable: Checksum.value carries no pattern and no minLength.
func TestEvidenceUpdate_AgreesWithVerificationOnAWhitespaceChecksum(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	stored := rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"), scan)

	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if uri, _ := entry["uri"].(string); uri == stored {
			entry["checksum"] = map[string]any{"algorithm": evidenceDigestAlgo, "value": "   "}
		}
	}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	// Verification is the authority; the report must have predicted whatever it does.
	_, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	warned := strings.Contains(stderr, "already names this same file")
	if verr != nil {
		assert.True(t, warned,
			"verification fails this entry, so update had to say so")
	} else {
		assert.False(t, warned, "verification passes, so the warning would be a false claim")
	}
}

// 52n0c.29's other-name report compares against the bytes verification will fetch, which
// for a BOM-carrying document it did not until 52n0c.42: it was fed BOM-stripped bytes
// while verification re-reads raw, so the comparison could not be right whatever it
// compared. Pinned here because it is the one half of that mirroring this file could not
// fix from inside itself.
func TestEvidenceUpdate_ComparesTheBytesVerificationWillFetch(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	stored := rewriteStoredRef(t, pkgPath, filepath.Join("scans", "rhel9.json"), scan)

	// A BOM-carrying document, with the other entry recording the correct digest of the
	// bytes ON DISK. Nothing is stale, so the report must stay silent — and it will only
	// agree if it hashes the same bytes verification does.
	src, err := os.ReadFile(scan)
	require.NoError(t, err)
	raw := append([]byte{0xEF, 0xBB, 0xBF}, src...)
	require.NoError(t, os.WriteFile(scan, raw, 0o600))
	doc := updatedPackage(t, pkgPath)
	contents, _ := doc["contents"].([]any)
	for _, e := range contents {
		entry, _ := e.(map[string]any)
		if uri, _ := entry["uri"].(string); uri == stored {
			entry["checksum"] = map[string]any{
				"algorithm": evidenceDigestAlgo, "value": evidenceDigestHex(raw),
			}
		}
	}
	patched, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, patched, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, stderr, err := executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	_, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	warned := strings.Contains(stderr, "already names this same file")
	if verr != nil {
		assert.True(t, warned, "verification fails this entry, so update had to say so")
	} else {
		assert.False(t, warned, "verification passes, so the warning would be a false claim")
	}
}

// update records the digest of the bytes ON DISK. Pinned on the recorded value rather
// than on whether verification passes, because a mutant that makes update hash the
// stripped bytes ALSO makes verification fail — so a test that only asks "did the report
// agree with verification" flips both sides at once and still passes. That is exactly
// how TestEvidenceUpdate_ComparesTheBytesVerificationWillFetch passed under that mutant,
// and why this test asserts the bytes themselves.
func TestEvidenceUpdate_RecordsTheDigestOfTheBytesOnDisk(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	scan := filepath.Join(dir, "scans", "rhel9.json")
	src, err := os.ReadFile(scan)
	require.NoError(t, err)
	raw := append([]byte{0xEF, 0xBB, 0xBF}, src...)
	require.NoError(t, os.WriteFile(scan, raw, 0o600))

	out := filepath.Join(dir, "updated.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", scan, "-o", out)
	require.NoError(t, err)

	assert.Equal(t, evidenceDigestHex(raw),
		checksumOf(t, updatedPackage(t, out), filepath.ToSlash(filepath.Join("scans", "rhel9.json"))),
		"the refreshed entry must record the digest of the file as it exists")

	_, _, verr := executeCommand("evidence", "info", "--verify", out, "--checksums-only")
	require.NoError(t, verr, "and the updated package verifies")
}

// Naming ONE file twice in one invocation is detected even when the reference needs
// escaping. The within-invocation duplicate check compared references with refPath
// WITHOUT decoding, while every other comparison in this file decodes first — so for any
// path containing a space, a # or a %, the two spellings stopped resolving to one file
// and each argument was treated as new. The second then matched the first's own
// just-appended entry, producing "replaced ... refreshed in place" AND "added" for one
// file: exactly the falsehood the comment above that loop says it exists to prevent,
// reintroduced for precisely the character class 52n0c.31 is about.
//
// Found by an AC reviewer after I had enumerated nineteen call sites and missed the
// twentieth — in the same function I had just edited.
func TestEvidenceUpdate_DedupesOneFileNamedTwiceWhenTheRefNeedsEscaping(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	if !caseInsensitiveFS(t, dir) {
		t.Skip("filesystem is case-sensitive; these two spellings are different files here")
	}
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "my scans"), 0o750))
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
	require.NoError(t, err)
	scan := filepath.Join(dir, "my scans", "q4.json")
	require.NoError(t, os.WriteFile(scan, src, 0o600))

	// The same file, named twice, under spellings that differ only in case — which the
	// filesystem resolves to one file and an undecoded comparison does not.
	_, stderr, err := executeCommand("evidence", "update", pkgPath,
		"--results", scan,
		"--results", filepath.Join(dir, "my scans", "Q4.JSON"),
		"-o", filepath.Join(dir, "out.json"))
	require.NoError(t, err)

	assert.Contains(t, stderr, "named more than once; recorded once",
		"one file given twice is one reference, whatever its spelling needs escaped")
	assert.NotContains(t, stderr, "refreshed in place",
		"nothing was refreshed: neither spelling was in the package when the command started")

	uris := contentURIs(t, updatedPackage(t, filepath.Join(dir, "out.json")))
	assert.Equal(t, 1, countMatching(uris, "my%20scans/"),
		"exactly one entry for one file, recorded escaped")
}

// countMatching counts how many of uris have the given prefix.
func countMatching(uris []string, prefix string) int {
	n := 0
	for _, u := range uris {
		if strings.HasPrefix(u, prefix) {
			n++
		}
	}
	return n
}
