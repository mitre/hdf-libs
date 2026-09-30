//nolint:dupl
package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const evidenceFixtureDir = "testdata/evidence-verify"

func TestEvidenceVerify_ChecksumsPass(t *testing.T) {
	_, _, err := executeCommand("evidence", "verify",
		filepath.Join(evidenceFixtureDir, "evidence.json"), "--checksums-only")
	require.NoError(t, err)
}

func TestEvidenceVerify_CompletenessPass(t *testing.T) {
	// Default mode: plan has RHEL9-STIG and PostgreSQL-STIG,
	// evidence package has results for both.
	_, _, err := executeCommand("evidence", "verify",
		filepath.Join(evidenceFixtureDir, "evidence.json"))
	require.NoError(t, err)
}

func TestEvidenceVerify_CompletenessFail(t *testing.T) {
	// Evidence package missing PostgreSQL-STIG results.
	incomplete := `{
		"name": "Incomplete Evidence",
		"planRef": "plan.json",
		"contents": [
			{"type": "hdf-results", "uri": "rhel9-results.json"}
		]
	}`
	// Write to the fixture dir so plan.json and results resolve
	path := filepath.Join(evidenceFixtureDir, "incomplete-evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(incomplete), 0o644))
	t.Cleanup(func() { _ = os.Remove(path) })

	_, _, err := executeCommand("evidence", "verify", path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PostgreSQL-STIG")
}

func TestEvidenceVerify_NoPlanRef(t *testing.T) {
	// Without planRef, verify should warn and fall back to checksums.
	noPlan := `{
		"name": "No Plan Evidence",
		"contents": [
			{"type": "hdf-results", "uri": "rhel9-results.json"}
		]
	}`
	path := filepath.Join(evidenceFixtureDir, "noplan-evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(noPlan), 0o644))
	t.Cleanup(func() { _ = os.Remove(path) })

	_, stderr, err := executeCommand("evidence", "verify", path)
	require.NoError(t, err)
	assert.Contains(t, stderr, "no planRef")
}

// The evidence package is read through the size-gated boundary (readInputFile),
// so --max-size is honored instead of an unbounded os.ReadFile.
func TestEvidenceVerify_RejectsOversizeInput(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(pkg, make([]byte, 2*1024*1024), 0o600)) // 2 MB
	_, _, err := executeCommand("evidence", "verify", pkg, "--max-size", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

// Files the package REFERENCES go through the same size-gated boundary as the
// package itself — an in-package reference is still untrusted input.
func TestEvidenceVerify_RejectsOversizeReferencedFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big-results.json"), make([]byte, 2*1024*1024), 0o600))
	pkg := `{
		"name": "Oversize Reference",
		"contents": [
			{"type": "hdf-results", "uri": "big-results.json",
			 "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}}
		]
	}`
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(pkg), 0o600))

	_, _, err := executeCommand("evidence", "verify", path, "--checksums-only", "--max-size", "1")
	require.Error(t, err)
	// Gated: the read fails outright (an error), rather than hashing 2 MB into a mismatch.
	assert.Contains(t, err.Error(), "0 checksum mismatches, 1 errors")
}

// The plan a package points at is read through the same boundary.
func TestEvidenceVerify_RejectsOversizePlan(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plan.json"), make([]byte, 2*1024*1024), 0o600))
	pkg := `{
		"name": "Oversize Plan",
		"planRef": "plan.json",
		"contents": [
			{"type": "hdf-results", "uri": "rhel9-results.json"}
		]
	}`
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(pkg), 0o600))

	_, _, err := executeCommand("evidence", "verify", path, "--max-size", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read plan")
	assert.Contains(t, err.Error(), "too large")
}

// Export reads package-referenced documents through the same gated boundary.
func TestEvidenceExport_RejectsOversizeReferencedFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big-results.json"), make([]byte, 2*1024*1024), 0o600))
	pkg := `{
		"name": "Oversize Reference",
		"contents": [
			{"type": "hdf-results", "uri": "big-results.json",
			 "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}}
		]
	}`
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(pkg), 0o600))

	_, stderr, err := executeCommand("evidence", "export", path, "-o", filepath.Join(dir, "out"), "--max-size", "1")
	require.NoError(t, err)
	assert.Contains(t, stderr, "could not read")
	assert.Contains(t, stderr, "too large")
}

// An absolute content ref must never be re-rooted under the package directory:
// "/etc/passwd" silently becoming "<pkgdir>/etc/passwd" made verify report on a
// different file than the reference named. It is now classified as unreachable
// instead, which is honest about both the reference and what was read.
// An evidence package may record a reference to something it does not contain, so
// an unreachable one is reported rather than refusing the package. The property
// that must NOT move is containment: nothing outside the package directory is ever
// read. Each case below plants a real file at the escaping location and records its
// CORRECT checksum, so a status of "match" would prove the file was read. Only
// "unreachable" passes.
func TestEvidenceVerify_ReportsAnUnreachableReferenceWithoutReadingIt(t *testing.T) {
	for _, tc := range []struct {
		name, uri, wantReason string
		plantOutside          bool
	}{
		{name: "absolute path outside the package", uri: "", wantReason: "outside the package's directory", plantOutside: true},
		{name: "parent traversal", uri: "../escape.json", wantReason: "outside the package's directory"},
		{name: "root-anchored path", uri: "/scans/rhel9-results.json", wantReason: "outside the package's directory"},
		{name: "remote", uri: "https://example.com/results.json", wantReason: "remote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			outside := t.TempDir()
			body := []byte(`{"planted":"must never be read"}`)
			plantedSum := fmt.Sprintf("%x", sha256.Sum256(body))

			uri := tc.uri
			if tc.plantOutside {
				planted := filepath.Join(outside, "escape.json")
				require.NoError(t, os.WriteFile(planted, body, 0o600))
				uri = planted
			} else {
				// Plant at the traversal/root-anchored target too where it is expressible,
				// so a read would succeed and be visible as a match.
				require.NoError(t, os.WriteFile(filepath.Join(outside, "escape.json"), body, 0o600))
			}

			pkg := map[string]interface{}{
				"name": "unreachable",
				"contents": []map[string]interface{}{{
					"type": "hdf-results", "uri": uri,
					"checksum": map[string]string{"algorithm": "sha256", "value": plantedSum},
				}},
			}
			raw, err := json.Marshal(pkg)
			require.NoError(t, err)
			pkgPath := filepath.Join(dir, "pkg.json")
			require.NoError(t, os.WriteFile(pkgPath, raw, 0o600))

			stdout, _, verifyErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only", "--json")
			require.NoError(t, verifyErr, "an unreachable reference is reported, not a package-level refusal")

			var parsed struct {
				Results []struct {
					URI    string `json:"uri"`
					Status string `json:"status"`
					Error  string `json:"error"`
				} `json:"results"`
				UnreachableReferences []struct {
					Field    string `json:"field"`
					Recorded string `json:"recorded"`
					Reason   string `json:"reason"`
				} `json:"unreachableReferences"`
			}
			require.NoError(t, json.Unmarshal([]byte(stdout), &parsed))
			require.Len(t, parsed.Results, 1)

			assert.Equal(t, "unreachable", parsed.Results[0].Status,
				"a match here would mean the file outside the package was read")
			assert.Equal(t, tc.wantReason, parsed.Results[0].Error)
			require.Len(t, parsed.UnreachableReferences, 1)
			assert.Equal(t, "contents", parsed.UnreachableReferences[0].Field)
			assert.Equal(t, tc.wantReason, parsed.UnreachableReferences[0].Reason)
		})
	}
}

// --require-reachable is the opt-in that turns the report above into a failure, for
// an assessor who needs the package self-contained.
func TestEvidenceVerify_RequireReachableFailsOnAnUnreachableReference(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"u","contents":[{"type":"hdf-results","uri":"https://example.com/r.json"}]}`
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, []byte(pkg), 0o600))

	_, _, err := executeCommand("evidence", "verify", pkgPath, "--checksums-only")
	require.NoError(t, err, "the default reports and succeeds")

	_, _, strictErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only", "--require-reachable")
	require.Error(t, strictErr, "--require-reachable must fail on the same package")
	assert.Contains(t, strictErr.Error(), "--require-reachable",
		"the error must name the flag that caused the failure")
}

// externalEvidence with absolute or remote URIs, and a bundled document's own
// externalReferences as bare URIs, are correct and common — and neither is ever
// resolved or downloaded. This is the shape that always had the posture the rest of
// the package's references were brought to: recorded, reported, never fetched.
func TestEvidenceVerify_AllowsRemoteExternalEvidenceAndDocumentRefs(t *testing.T) {
	dir := t.TempDir()

	// A real results document, given its own externalReferences with a bare URI.
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	var results map[string]interface{}
	require.NoError(t, json.Unmarshal(src, &results))
	results["externalReferences"] = []interface{}{
		map[string]interface{}{
			"sourceName": "cve",
			"externalId": "CVE-2021-44228",
			"href":       "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		},
	}
	withRefs, err := json.Marshal(results)
	require.NoError(t, err)
	resultsPath := filepath.Join(dir, "rhel9-results.json")
	require.NoError(t, os.WriteFile(resultsPath, withRefs, 0o600))

	pkg := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkg, []byte(`{
		"name": "Remote External Evidence Package",
		"contents": [{"type": "hdf-results", "uri": "rhel9-results.json"}],
		"externalEvidence": [
			{"uri": "https://logs.example.com/corpus.ndjson", "format": "ecs"},
			{"uri": "/mnt/archive/threat-intel.json", "format": "x-stix"}
		]
	}`), 0o600))

	_, _, verifyErr := executeCommand("evidence", "verify", pkg, "--checksums-only")
	require.NoError(t, verifyErr,
		"remote externalEvidence and a document's own externalReferences must not be refused")
}

// The human line named a fixed "sha256" regardless of what the entry recorded.
// Once the engine honoured the recorded algorithm that label became a false
// statement — a sha512 verification reported as "(sha256 match)". Live testing
// caught it; this test keeps it caught, and pins the --json field beside it.
func TestEvidenceVerify_NamesTheAlgorithmItActuallyVerifiedWith(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}
	// Real documents, so the recorded digests are of real bytes.
	for _, n := range []string{"system.json", "rhel9-results.json"} {
		body, readErr := os.ReadFile(filepath.Join(evidenceFixtureDir, n))
		require.NoError(t, readErr)
		write(n, string(body))
	}
	sum := func(name, algorithm string) string {
		body, readErr := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, readErr)
		h, hashErr := hdfengine.ChecksumHex(algorithm, body)
		require.NoError(t, hashErr)
		return h
	}

	pkg := map[string]interface{}{
		"name": "algorithm-labels",
		"contents": []map[string]interface{}{
			{"type": "hdf-system", "uri": "system.json",
				"checksum": map[string]string{"algorithm": "sha512", "value": sum("system.json", "sha512")}},
			{"type": "hdf-results", "uri": "rhel9-results.json",
				"checksum": map[string]string{"algorithm": "sha384", "value": sum("rhel9-results.json", "sha384")}},
		},
	}
	body, marshalErr := json.Marshal(pkg)
	require.NoError(t, marshalErr)
	pkgPath := write("pkg.json", string(body))

	stdout, _, err := executeCommand("evidence", "verify", pkgPath, "--checksums-only")
	require.NoError(t, err)
	assert.Contains(t, stdout, "(sha512 match)", "the line must name the algorithm the entry recorded")
	assert.Contains(t, stdout, "(sha384 match)")
	assert.NotContains(t, stdout, "(sha256 match)",
		"neither entry recorded sha256, so no line may claim it")

	jsonOut, _, jsonErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only", "--json")
	require.NoError(t, jsonErr)
	var parsed struct {
		Results []struct {
			URI       string `json:"uri"`
			Algorithm string `json:"algorithm"`
			Status    string `json:"status"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &parsed))
	require.Len(t, parsed.Results, 2)
	assert.Equal(t, "sha512", parsed.Results[0].Algorithm)
	assert.Equal(t, "sha384", parsed.Results[1].Algorithm)
	assert.Equal(t, "match", parsed.Results[0].Status)
	assert.Equal(t, "match", parsed.Results[1].Status)
}

// An evidence package may reference artifacts it does not contain — an absolute
// local path, or a URI on another system. Carrying copies is expected but not
// required, so a reference a consumer cannot reach is a legitimate shape, not a
// malformed package. bundle already has that posture for externalEvidence (it
// reports "not carried" and succeeds); verify refused whole packages on the shape
// of a reference before reading anything. This table pins that the two commands
// reach the SAME verdict on every shape either one accepts.
func TestEvidence_BundleAndVerifyAgreeOnTheSamePackage(t *testing.T) {
	fixture := func(t *testing.T, name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(evidenceFixtureDir, name))
		require.NoError(t, err)
		return b
	}

	for _, field := range []string{"planRef", "systemRef", "contents", "externalEvidence"} {
		// parentTraversal is here because its absence hid a real divergence: the first
		// version of this table tested absolute and remote shapes only, and a "../" ref
		// still made verify exit 1 where bundle exited 0.
		for _, shape := range []string{"relative", "absoluteInside", "absoluteOutside", "remote", "parentTraversal"} {
			t.Run(field+"/"+shape, func(t *testing.T) {
				dir := t.TempDir()
				outside := t.TempDir()
				// postgres-results.json is carried because plan.json names TWO baselines;
				// without it completeness fails for a reason unrelated to references, which
				// is what the default-path assertion below would otherwise be measuring.
				for _, n := range []string{"system.json", "rhel9-results.json", "postgres-results.json", "plan.json"} {
					require.NoError(t, os.WriteFile(filepath.Join(dir, n), fixture(t, n), 0o600))
				}
				require.NoError(t, os.WriteFile(filepath.Join(outside, "plan.json"), fixture(t, "plan.json"), 0o600))

				var ref string
				switch shape {
				case "relative":
					ref = "plan.json"
				case "absoluteInside":
					ref = filepath.Join(dir, "plan.json")
				case "absoluteOutside":
					ref = filepath.Join(outside, "plan.json")
				case "remote":
					ref = "https://example.com/plan.json"
				case "parentTraversal":
					ref = filepath.Join("..", filepath.Base(outside), "plan.json")
				}

				pkg := map[string]interface{}{
					"name": "agreement",
					"contents": []map[string]interface{}{
						{"type": "hdf-system", "uri": "system.json"},
						{"type": "hdf-results", "uri": "rhel9-results.json"},
						{"type": "hdf-results", "uri": "postgres-results.json"},
					},
				}
				switch field {
				case "planRef", "systemRef":
					pkg[field] = ref
				case "contents":
					// Typed hdf-results, NOT hdf-plan: verifyCompleteness reads only
					// hdf-results entries, so a plan-typed reference never reaches the
					// resolution the completeness path performs. Typing it hdf-plan is why
					// an earlier version of this table still failed to pin that path.
					pkg["contents"] = append(pkg["contents"].([]map[string]interface{}),
						map[string]interface{}{"type": "hdf-results", "uri": ref})
				case "externalEvidence":
					pkg["externalEvidence"] = []map[string]interface{}{
						{"uri": ref, "format": "raw-log", "description": "a corpus kept elsewhere"},
					}
				}
				body, err := json.Marshal(pkg)
				require.NoError(t, err)
				pkgPath := filepath.Join(dir, "pkg.json")
				require.NoError(t, os.WriteFile(pkgPath, body, 0o600))

				// Both commands must accept it. A shape one takes and the other refuses is
				// the defect this card closes, whichever direction it runs in.
				//
				// BOTH verify paths are exercised. --checksums-only returns before the
				// completeness check, and the completeness path was where the two commands
				// still disagreed after the first fix — a table running only the short path
				// could not see it. The default run carries a planRef whose plan names two
				// baselines, both covered by the two results documents above, so the only
				// thing that can fail it is reference handling.
				_, _, checksumErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only")
				_, _, bundleErr := executeCommand("evidence", "bundle", pkgPath,
					"-o", filepath.Join(dir, "out.tar.gz"))
				assert.NoError(t, checksumErr, "verify --checksums-only refused a legitimate shape")
				assert.NoError(t, bundleErr, "bundle refused a shape the package may legitimately record")

				if field != "planRef" {
					// planRef is the shape under test in those rows, so pointing it at the
					// plan as well would not be testing the same thing.
					pkg["planRef"] = "plan.json"
					withPlan, marshalErr := json.Marshal(pkg)
					require.NoError(t, marshalErr)
					planPath := filepath.Join(dir, "with-plan.json")
					require.NoError(t, os.WriteFile(planPath, withPlan, 0o600))

					_, _, fullErr := executeCommand("evidence", "verify", planPath)
					_, _, fullBundleErr := executeCommand("evidence", "bundle", planPath,
						"-o", filepath.Join(dir, "with-plan.tar.gz"))
					assert.NoError(t, fullErr,
						"verify refused a legitimate shape on the default (completeness) path")
					assert.NoError(t, fullBundleErr, "bundle refused it on the same package")
				}
			})
		}
	}
}

// The completeness check must not credit a baseline from a document the same run
// reported as unreachable. It did: SafePath joins a root-anchored "/results.json"
// back under the package directory, so completeness read <pkgDir>/results.json — a
// file the reference never named — and printed "Completeness check passed" directly
// beneath "not reachable here: /results.json". A verdict that contradicts itself in
// the same output is worse than either answer alone.
func TestEvidenceVerify_CompletenessNeverCreditsAnUnreachableDocument(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"system.json", "rhel9-results.json", "postgres-results.json", "plan.json"} {
		body, err := os.ReadFile(filepath.Join(evidenceFixtureDir, n))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), body, 0o600))
	}

	// Root-anchored, so a naive filepath.Join re-roots it back inside the package and
	// finds the real rhel9-results.json. Only resolving the reference the same way the
	// checksum path does keeps that file from being read.
	pkg := map[string]interface{}{
		"name":    "reroot",
		"planRef": "plan.json",
		"contents": []map[string]interface{}{
			{"type": "hdf-results", "uri": "/rhel9-results.json"},
			{"type": "hdf-results", "uri": "postgres-results.json"},
		},
	}
	body, err := json.Marshal(pkg)
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, body, 0o600))

	stdout, stderr, verifyErr := executeCommand("evidence", "verify", pkgPath)

	// RHEL9-STIG is planned, and its only results document is unreachable, so
	// completeness must FAIL rather than pass on a file the reference never named.
	require.Error(t, verifyErr, "a planned baseline whose results are unreachable is not covered")
	combined := stdout + stderr
	assert.Contains(t, combined, "not reachable here: /rhel9-results.json")
	assert.Contains(t, combined, "Missing results for baseline: RHEL9-STIG")
	assert.NotContains(t, combined, "Completeness check passed",
		"the run must not report completeness passing beside a reference it could not reach")
}

// A recorded algorithm this build cannot compute is reported, not fatal — the same
// posture as a reference it cannot reach, because both are claims the tool cannot
// check and the bytes may be perfectly intact. What must NOT happen is the entry
// disappearing: when the engine gained a distinct status, every consumer switch that
// did not handle it dropped the entry from the per-entry list AND from every count,
// so a package with an unverifiable checksum reported "0/0 valid" and exited 0 with
// no mention of it at all. Silence is worse than either verdict.
func TestEvidenceVerify_ReportsAnUncomputableAlgorithmWithoutFailing(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"system.json", "rhel9-results.json", "postgres-results.json", "plan.json"} {
		body, err := os.ReadFile(filepath.Join(evidenceFixtureDir, n))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), body, 0o600))
	}
	pkg := map[string]interface{}{
		// Deliberately NOT named after the algorithm: the header line prints the package
		// name, so calling it "blake3" made the assertion below pass whether or not the
		// entry was ever rendered.
		"name":    "unverifiable-algorithm",
		"planRef": "plan.json",
		"contents": []map[string]interface{}{
			// A published BLAKE3 vector for the empty input, so the value is a real
			// blake3 digest rather than an invented hex string. It cannot match this
			// file, but nothing computes it, so no comparison ever happens.
			{"type": "hdf-system", "uri": "system.json", "checksum": map[string]string{
				"algorithm": "blake3",
				"value":     "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
			}},
			{"type": "hdf-results", "uri": "rhel9-results.json"},
			{"type": "hdf-results", "uri": "postgres-results.json"},
		},
	}
	body, err := json.Marshal(pkg)
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, body, 0o600))

	stdout, _, verifyErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only")
	require.NoError(t, verifyErr, "an uncomputable algorithm is reported, not fatal")
	assert.Contains(t, stdout, "system.json",
		"the entry must still appear; vanishing from the output is the fail-open this pins")
	assert.Contains(t, stdout, "blake3", "and the line must name the algorithm it could not compute")

	jsonOut, _, jsonErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only", "--json")
	require.NoError(t, jsonErr)
	var parsed struct {
		Results []struct {
			URI    string `json:"uri"`
			Status string `json:"status"`
		} `json:"results"`
		Unsupported int `json:"unsupported"`
	}
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &parsed))
	require.Len(t, parsed.Results, 3, "every contents entry must be listed, including the unverifiable one")
	assert.Equal(t, "unsupported", parsed.Results[0].Status)
	assert.Equal(t, 1, parsed.Unsupported, "and it must be counted, not silently dropped")

	// The opt-in that an assessor needing everything verified would use.
	_, _, strictErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only", "--require-reachable")
	require.Error(t, strictErr, "--require-reachable must fail on an unverifiable checksum too")
	assert.Contains(t, strictErr.Error(), "1 checksum(s) name an algorithm this build cannot compute",
		"the message must name what actually happened")
	assert.NotContains(t, strictErr.Error(), "0 recorded reference(s)",
		"and must not name a count of zero, which sends the operator hunting a reference fault")
}
