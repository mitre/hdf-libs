package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
func TestEvidenceUpdate_RefusesToWriteAnInvalidPackage(t *testing.T) {
	dir, pkgPath := updatablePackage(t)
	_, _, err := executeCommand("validate", pkgPath)
	require.NoError(t, err, "the input must be valid, or this pins the wrong gate")

	// A results document whose package-relative reference is not a valid uri-reference
	// cannot be expressed in contents[], so the write invalidates a package that was
	// valid when read. A malformed percent-escape is the least exotic way to get there.
	odd := filepath.Join(dir, "scans", "bad%zzname.json")
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(odd, src, 0o600))

	out := filepath.Join(dir, "written.json")
	_, _, err = executeCommand("evidence", "update", pkgPath, "--results", odd, "-o", out)
	require.Error(t, err, "a reference the schema cannot express must not be written")
	assert.Contains(t, err.Error(), "failed validation before write",
		"the PRE-WRITE gate must be what refuses — an input-gate refusal would pin the wrong thing")
	assert.NoFileExists(t, out, "and nothing may be written")
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

	t.Run("it refuses what the real run would refuse", func(t *testing.T) {
		odd := filepath.Join(dir, "scans", "bad%zzname.json")
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "postgres-results.json"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(odd, src, 0o600))

		_, _, err = executeCommand("evidence", "update", pkgPath, "--results", odd,
			"-o", filepath.Join(dir, "y.json"), "--dry-run")
		require.Error(t, err, "a dry run must not report a change the real run would reject")
		assert.Contains(t, err.Error(), "failed validation before write")
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
		_, _, err = executeCommand("evidence", "verify", out)
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

// The recorded checksum must be the file's sha256. The only checksum assertion in this file
// pinned that it CHANGED, never that it was CORRECT — so a reimplementation of
// contentEntryFromBytes recording any other value passed the whole suite, and the output
// failed its own evidence verify.
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
	assert.Equal(t, fmt.Sprintf("%x", sha256.Sum256(body)), recorded,
		"the recorded digest must be the file's real sha256, not merely a different value")

	// And the end-to-end consequence: a wrong digest makes the package fail its own verify.
	_, _, err = executeCommand("evidence", "verify", out)
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
// update that has nothing to do with them: the missing document is `evidence verify`'s to
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
