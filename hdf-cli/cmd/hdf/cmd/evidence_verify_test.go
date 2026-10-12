//nolint:dupl
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
	// Gated: the read fails outright (an error), rather than hashing 2 MB into a
	// mismatch. The message names only what happened — it used to read "0 checksum
	// mismatches, 1 errors", which invited the operator to look for a checksum fault
	// that was not there, the same noise --require-reachable's message avoids.
	assert.Contains(t, err.Error(), "1 reference(s) could not be read")
	assert.NotContains(t, err.Error(), "0 checksum mismatches",
		"a count of zero is not a finding and must not be reported as one")
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
	for _, n := range []string{"system.json", "rhel9-results.json", "plan.json"} {
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
			// blake3 belongs here on the same terms as the others now that it is computed:
			// a correct digest must verify AND the line must name the algorithm, which is
			// what an operator reads to know what was actually checked.
			{"type": "hdf-plan", "uri": "plan.json",
				"checksum": map[string]string{"algorithm": "blake3", "value": sum("plan.json", "blake3")}},
		},
	}
	body, marshalErr := json.Marshal(pkg)
	require.NoError(t, marshalErr)
	pkgPath := write("pkg.json", string(body))

	stdout, _, err := executeCommand("evidence", "verify", pkgPath, "--checksums-only")
	require.NoError(t, err)
	assert.Contains(t, stdout, "(sha512 match)", "the line must name the algorithm the entry recorded")
	assert.Contains(t, stdout, "(sha384 match)")
	assert.Contains(t, stdout, "(blake3 match)", "a correct blake3 verifies and is named as such")
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
	require.Len(t, parsed.Results, 3)
	assert.Equal(t, "sha512", parsed.Results[0].Algorithm)
	assert.Equal(t, "sha384", parsed.Results[1].Algorithm)
	assert.Equal(t, "blake3", parsed.Results[2].Algorithm)
	assert.Equal(t, "match", parsed.Results[2].Status)
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

// Every algorithm Hash_Algorithm admits is computed by this build, and the CLI
// schema-validates a package before verifying it — so an algorithm it cannot compute has
// no route in at all. The unsupported status is still reachable for a LIBRARY consumer
// that hands contents straight to the engine, which hdf-engine's own tests cover; through
// the CLI it is refused here, at validation, naming the algorithm and the admitted set.
func TestEvidenceVerify_RefusesAnOffSchemaChecksumAlgorithm(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"system.json", "plan.json", "rhel9-results.json", "postgres-results.json"} {
		body, err := os.ReadFile(filepath.Join(evidenceFixtureDir, n))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), body, 0o600))
	}
	pkg := map[string]interface{}{
		"name":    "off-schema-algorithm",
		"planRef": "plan.json",
		"contents": []map[string]interface{}{
			{"type": "hdf-system", "uri": "system.json", "checksum": map[string]string{
				"algorithm": "md5",
				"value":     "d41d8cd98f00b204e9800998ecf8427e",
			}},
			{"type": "hdf-results", "uri": "rhel9-results.json"},
		},
	}
	body, err := json.Marshal(pkg)
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, body, 0o600))

	_, _, verifyErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only")
	require.Error(t, verifyErr, "an off-schema algorithm is refused, not silently carried")
	// The validator names the ADMITTED SET rather than the offending value, so that is
	// what is asserted. blake3 appearing in it is the load-bearing part here: the set the
	// schema admits and the set this build computes are now the same.
	assert.Contains(t, verifyErr.Error(), "contents.0.checksum.algorithm",
		"the refusal points at the offending field")
	assert.Contains(t, verifyErr.Error(), "blake3",
		"and lists the admitted set, which includes blake3 because this build computes it")
}

// The point of computing blake3 rather than reporting it: a WRONG blake3 has to fail the
// command. Before this it was waved through as unverifiable, so a tampered file behind a
// blake3 checksum travelled undetected where the same tampering behind sha256 failed.
func TestEvidenceVerify_FailsAWrongBlake3Checksum(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"system.json", "rhel9-results.json"} {
		body, err := os.ReadFile(filepath.Join(evidenceFixtureDir, n))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), body, 0o600))
	}
	body, err := os.ReadFile(filepath.Join(dir, "system.json"))
	require.NoError(t, err)
	correct, err := hdfengine.ChecksumHex("blake3", body)
	require.NoError(t, err)

	// A real blake3 digest of DIFFERENT bytes, so the value is well-formed and of the
	// right length — an invented hex string could fail for its shape instead.
	wrong, err := hdfengine.ChecksumHex("blake3", append(body, '\n'))
	require.NoError(t, err)
	require.NotEqual(t, correct, wrong)

	pkg, err := json.Marshal(map[string]interface{}{
		"name": "wrong-blake3",
		"contents": []map[string]interface{}{
			{"type": "hdf-system", "uri": "system.json",
				"checksum": map[string]string{"algorithm": "blake3", "value": wrong}},
		},
	})
	require.NoError(t, err)
	pkgPath := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkgPath, pkg, 0o600))

	stdout, _, verifyErr := executeCommand("evidence", "verify", pkgPath, "--checksums-only")
	require.Error(t, verifyErr, "a wrong blake3 must fail, exactly as a wrong sha256 does")
	assert.Contains(t, verifyErr.Error(), "mismatch")
	assert.Contains(t, stdout, "blake3", "and the report names the algorithm it verified with")
}

// externalEvidenceVerifyPackage builds a package whose contents[] checksum is correct
// and whose externalEvidence[0] checksum is wrong, which is the shape that made the two
// commands disagree: bundle refused it while verify reported every checksum valid.
func externalEvidenceVerifyPackage(t *testing.T, recordedChecksum string) (dir, pkgPath string) {
	t.Helper()
	dir, pkgPath = referencePackage(t)
	artifact := []byte("log\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.ndjson"), artifact, 0o600))

	pkg := readPackage(t, pkgPath)
	entry := map[string]any{"uri": "audit.ndjson", "format": "raw-log"}
	if recordedChecksum != "" {
		entry["checksum"] = map[string]any{"algorithm": "sha256", "value": recordedChecksum}
	}
	pkg["externalEvidence"] = []any{entry}
	out, err := json.MarshalIndent(pkg, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, out, 0o600))
	return dir, pkgPath
}

// verify examined contents[] only, so a wrong externalEvidence checksum passed at exit 0
// while `bundle` refused the very same package. The command whose job is verification was
// the one that missed it.
func TestEvidenceVerify_VerifiesExternalEvidenceChecksums(t *testing.T) {
	_, pkgPath := externalEvidenceVerifyPackage(t, strings.Repeat("0", 64))

	stdout, _, err := executeCommand("evidence", "verify", pkgPath)
	require.Error(t, err, "a wrong externalEvidence checksum must fail verify, as it already fails bundle")
	assert.Contains(t, err.Error(), "mismatch")
	assert.Contains(t, stdout, "audit.ndjson", "the mismatching artifact must be named")
	assert.Contains(t, stdout, "MISMATCH", "and named as a mismatch, not merely listed")
	assert.NotContains(t, stdout, "Verified: 3/3 checksums valid",
		"the package must not be reported as fully verified")
}

// The correct checksum must still pass, in both arrays — the regression direction.
func TestEvidenceVerify_CorrectExternalEvidenceChecksumStillPasses(t *testing.T) {
	sum := sha256.Sum256([]byte("log\n"))
	_, pkgPath := externalEvidenceVerifyPackage(t, hex.EncodeToString(sum[:]))

	stdout, _, err := executeCommand("evidence", "verify", pkgPath)
	require.NoError(t, err, "a correct externalEvidence checksum must verify")
	assert.Contains(t, stdout, "audit.ndjson", "a verified external artifact is named like any other")
	// Two contents[] entries plus the one externalEvidence artifact: the total spans
	// both arrays, which is the count that has to reconcile with bundle's.
	assert.Contains(t, stdout, "Verified: 3/3 checksums valid",
		"both arrays count toward the verdict, so the total spans them")
}

// The counts must reconcile with bundle's, which is the specific discrepancy
// hdf-libs-52n0c.16 documented: verify said 1 skipped where bundle said 2, because
// bundle's count spanned both arrays and verify's spanned one.
func TestEvidenceVerify_UnchecksummedExternalEvidenceIsCountedLikeBundleCountsIt(t *testing.T) {
	_, pkgPath := externalEvidenceVerifyPackage(t, "")

	stdout, _, err := executeCommand("evidence", "verify", pkgPath)
	require.NoError(t, err, "an entry recording no checksum is reported, not refused")
	assert.Contains(t, stdout, "audit.ndjson",
		"an externalEvidence entry with no checksum must be named, not silently omitted")
	assert.Contains(t, stdout, "no checksum",
		"and reported under the same words contents[] uses for the same shape")
}

// --require-checksums-match defaults TRUE, unlike the other --require-* flags, because
// a contents[] mismatch already failed before the flag existed: a false default would
// not have added a valve, it would have stopped a tampered document from failing.
func TestEvidenceVerify_RequireChecksumsMatchDefaultsToFailing(t *testing.T) {
	_, pkgPath := externalEvidenceVerifyPackage(t, strings.Repeat("0", 64))

	// Default: no flag at all.
	_, _, err := executeCommand("evidence", "verify", pkgPath)
	require.Error(t, err, "the default must fail on a mismatch")

	// And passing it explicitly true is the same thing, not a different mode.
	_, _, explicitErr := executeCommand("evidence", "verify", pkgPath, "--require-checksums-match=true")
	require.Error(t, explicitErr)
	assert.Equal(t, err.Error(), explicitErr.Error(), "the default and the explicit true must agree")
}

// The valve lets a pipeline proceed past known drift — and must not go quiet doing it.
// A fail-open switch that also suppresses the finding is how a package passes for
// months without anyone learning the artifact changed.
func TestEvidenceVerify_RequireChecksumsMatchFalseTolerToleratesButStillReports(t *testing.T) {
	_, pkgPath := externalEvidenceVerifyPackage(t, strings.Repeat("0", 64))

	stdout, stderr, err := executeCommand("evidence", "verify", pkgPath, "--require-checksums-match=false")
	require.NoError(t, err, "the valve must let the run proceed")

	// Named, with the status, exactly as it is when the flag is on.
	assert.Contains(t, stdout, "audit.ndjson")
	assert.Contains(t, stdout, "MISMATCH", "a tolerated mismatch is still reported as a mismatch")
	// Counted in the summary, so the verdict line cannot read as clean.
	assert.Contains(t, stdout, "1 failed", "the count must stay visible in the summary")
	assert.NotContains(t, stdout, "Verified: 3/3 checksums valid")
	// And said outright, so nobody reads exit 0 as intact.
	assert.Contains(t, stderr, "tolerated")
	assert.Contains(t, stderr, "NOT intact")
}

// A fetch error is not a mismatch and the valve does not cover it: the package named an
// artifact this run could not read at all, which is a different fact from one that was
// read and disagreed.
func TestEvidenceVerify_TheValveDoesNotTolerateAnUnreadableArtifact(t *testing.T) {
	dir, pkgPath := externalEvidenceVerifyPackage(t, strings.Repeat("0", 64))
	require.NoError(t, os.Remove(filepath.Join(dir, "audit.ndjson")))

	_, _, err := executeCommand("evidence", "verify", pkgPath, "--require-checksums-match=false")
	require.Error(t, err, "an unreadable artifact still fails, flag or no flag")
	assert.Contains(t, err.Error(), "could not be read")
	assert.NotContains(t, err.Error(), "mismatch",
		"nothing was hashed, so this must not be reported as drift")
}

// AC: whether --require-reachable covers externalEvidence is ESTABLISHED by measurement
// rather than assumed. It does. Recorded as a test because the answer is load-bearing
// for a pipeline: externalEvidence is BY DEFINITION an artifact held elsewhere, so a
// package using it as designed can never pass that flag — accepted deliberately, and
// worth failing loudly if it ever changes.
func TestEvidenceVerify_RequireReachableCoversExternalEvidence(t *testing.T) {
	dir, pkgPath := referencePackage(t)
	_ = dir
	pkg := readPackage(t, pkgPath)
	pkg["externalEvidence"] = []any{map[string]any{
		"uri": "https://logs.example.gov/audit.ndjson", "format": "raw-log",
		"checksum": map[string]any{"algorithm": "sha256", "value": strings.Repeat("0", 64)},
	}}
	out, err := json.MarshalIndent(pkg, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, out, 0o600))

	// Default: reported, not failed — and NOT hashed, so the wrong checksum beside a
	// remote URI is never reported as drift in an artifact nobody fetched.
	stdout, _, defErr := executeCommand("evidence", "verify", pkgPath)
	require.NoError(t, defErr, "a remote external artifact is reported, not refused")
	assert.Contains(t, stdout, "not reachable here")
	assert.NotContains(t, stdout, "MISMATCH",
		"nothing was fetched, so nothing may be called a mismatch")

	// With the flag: it fails, so the flag's reach spans both arrays.
	_, _, flagErr := executeCommand("evidence", "verify", pkgPath, "--require-reachable")
	require.Error(t, flagErr, "--require-reachable covers externalEvidence")
	assert.Contains(t, flagErr.Error(), "could not be resolved")
}

// The counts must RECONCILE with bundle's, which is the specific discrepancy
// hdf-libs-52n0c.16 recorded: one unchecksummed entry in each array made verify say
// 1 skipped and bundle say 2, because bundle's count spanned both arrays and verify's
// spanned one. Asserted across the two commands on ONE package, because agreement
// between them is the property — either command alone cannot show it.
//
// The package deliberately records NO systemRef, which hdf-libs-52n0c.17 made
// possible. With one, bundle counts 3 where verify counts 2, because bundle's count
// includes the root REFERENCE FIELDS and systemRef carries no checksum — the schema
// gives it no checksum property at all, so it can never have one. That is a separate
// divergence from the one this card closes, it is pinned in the sub-test below so it
// cannot change unnoticed, and it is carded.
func TestEvidenceVerifyAndBundle_CountUnverifiableEntriesTheSame(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"system.json", "rhel9-results.json"} {
		src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), src, 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.ndjson"), []byte("log\n"), 0o600))
	pkgPath := filepath.Join(dir, "pkg.json")
	_, _, buildErr := executeCommand("evidence", "build",
		"--results", filepath.Join(dir, "rhel9-results.json"), "-o", pkgPath)
	require.NoError(t, buildErr)

	// One unchecksummed entry in each array: drop the one checksum build wrote, and add
	// an external entry that records none.
	pkg := readPackage(t, pkgPath)
	entries, ok := pkg["contents"].([]any)
	require.True(t, ok)
	require.Len(t, entries, 1)
	first, ok := entries[0].(map[string]any)
	require.True(t, ok)
	delete(first, "checksum")
	pkg["externalEvidence"] = []any{map[string]any{"uri": "audit.ndjson", "format": "raw-log"}}
	out, err := json.MarshalIndent(pkg, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkgPath, out, 0o600))

	verifyOut, _, verifyErr := executeCommand("evidence", "verify", pkgPath)
	require.NoError(t, verifyErr)
	_, bundleStderr, bundleErr := executeCommand("evidence", "bundle", pkgPath,
		"-o", filepath.Join(dir, "out.zip"))
	require.NoError(t, bundleErr)

	assert.Contains(t, verifyOut, "2 skipped", "verify's count must span both arrays")
	assert.Contains(t, bundleStderr, "2 reference(s) record no checksum",
		"bundle's count already spanned both arrays; this is the number verify must match")
	assert.NotContains(t, verifyOut, "1 skipped",
		"the pre-fix count, which covered contents[] only")

	// The residual divergence, measured and pinned for BOTH root reference fields
	// rather than left to surprise someone. planRef matters more than systemRef here:
	// it is the field verify's DEFAULT mode needs, so the only shape where the counts
	// reconcile is one verify cannot run its primary check on. Carded as 52n0c.40.
	for _, tc := range []struct{ name, field, value string }{
		{"a systemRef adds to bundle's count only", "systemRef", "system.json"},
		{"and so does a planRef, which verify's default mode needs", "planRef", "plan.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, rErr := os.ReadFile(filepath.Join(evidenceFixtureDir, "plan.json"))
			require.NoError(t, rErr)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "plan.json"), src, 0o600))

			// Built fresh per case so the two fields are measured independently; sharing
			// one package would leave the second case counting both.
			withRef := map[string]any{}
			for k, v := range pkg {
				withRef[k] = v
			}
			withRef[tc.field] = tc.value
			encoded, mErr := json.MarshalIndent(withRef, "", " ")
			require.NoError(t, mErr)
			refPath := filepath.Join(dir, tc.field+".json")
			require.NoError(t, os.WriteFile(refPath, encoded, 0o600))

			// --checksums-only for both cases, because the variable under measurement is
			// the unverifiable-CHECKSUM count. Without it the planRef case fails on
			// completeness against the fixture plan's uncovered baseline — correct
			// behaviour, and itself the reviewer's point: the shape where the counts
			// reconcile is one verify cannot run its default check on at all.
			vOut, _, vErr := executeCommand("evidence", "verify", refPath, "--checksums-only")
			require.NoError(t, vErr)
			_, bStderr, bErr := executeCommand("evidence", "bundle", refPath,
				"-o", filepath.Join(dir, tc.field+".zip"))
			require.NoError(t, bErr)

			assert.Contains(t, vOut, "2 skipped",
				"a root reference field is not a checksummed entry, so verify is unmoved")
			assert.Contains(t, bStderr, "3 reference(s) record no checksum",
				"bundle counts the root reference field, which the schema gives no checksum property")
		})
	}
}
