//nolint:dupl
package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEvidencePackage = `{
	"name": "Test Evidence",
	"contents": [
		{
			"type": "hdf-results",
			"uri": "results.json",
			"checksum": {"algorithm": "sha256", "value": "abc"}
		}
	]
}`

func writeTestEvidence(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(testEvidencePackage), 0o644))
	return path
}

func TestEvidenceSet_Name(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path, "--name", "Q2 Evidence")
	require.NoError(t, err)

	data, _ := os.ReadFile(path)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "Q2 Evidence", doc["name"])
}

func TestEvidenceSet_PackageID(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path, "--package-id", "550e8400-e29b-41d4-a716-446655440000")
	require.NoError(t, err)

	data, _ := os.ReadFile(path)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", doc["packageId"])
}

func TestEvidenceSet_UnsetRequired(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path, "--unset", "contents")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required field")
}

func TestEvidenceSet_NoFlags(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path)
	assert.Error(t, err)
}

// A reference is data read by whoever opens the package, not a path on the machine that
// wrote it. `build` already records an in-subtree document as a package-relative ref;
// `set` stored whatever string it was handed, which is how an absolute path reached a
// package and then survived into a bundled archive that could not resolve it.
func TestEvidenceSet_NormalizesAnInSubtreeAbsoluteRef(t *testing.T) {
	path := writeTestEvidence(t)
	dir := filepath.Dir(path)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plan.json"), []byte(`{}`), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "docs"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docs", "system.json"), []byte(`{}`), 0o600))

	_, _, err := executeCommand("evidence", "set", path,
		"--plan-ref", filepath.Join(dir, "plan.json"),
		"--system-ref", filepath.Join(dir, "docs", "system.json"))
	require.NoError(t, err)

	doc := readEvidenceDoc(t, path)
	assert.Equal(t, "plan.json", doc["planRef"], "a sibling document becomes a bare relative ref")
	assert.Equal(t, "docs/system.json", doc["systemRef"],
		"a subdirectory document keeps its subdirectory, with forward slashes")
}

// Anything bundle would NOT carry must be recorded exactly as given: normalizing it would
// claim the artifact is somewhere it is not. This is the standing contract — a package may
// legitimately reference what it does not contain.
func TestEvidenceSet_LeavesAReferenceItCannotResolveExactlyAsGiven(t *testing.T) {
	for _, tc := range []struct {
		name, ref string
	}{
		{"absolute outside the package", filepath.Join(string(filepath.Separator), "etc", "hosts")},
		{"parent traversal", filepath.Join("..", "shared", "plan.json")},
		{"remote uri", "https://portal.example/plans/q3.json"},
		{"already package-relative", "scans/plan.json"},
		// These two pin the IsAbs gate. Cleaning would rewrite both, so without the gate
		// this card would quietly change how RELATIVE references are recorded — out of
		// scope, and an unrequested change to what the operator typed.
		{"relative with a leading dot", "./plan.json"},
		{"relative through a subdirectory", "docs/../plan.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestEvidence(t)
			_, _, err := executeCommand("evidence", "set", path, "--plan-ref", tc.ref)
			require.NoError(t, err)
			assert.Equal(t, tc.ref, readEvidenceDoc(t, path)["planRef"],
				"recorded verbatim; rewriting it would misdescribe where the artifact is")
		})
	}
}

func readEvidenceDoc(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc
}

// -o is the difference between amending a package in place and producing a new one, and
// the branch had no evidence-side coverage at all: neutering it left the whole suite green
// except one `plan set` test, so an evidence-specific regression here would have silently
// overwritten an operator's input. Both behaviours are asserted, so neither stands in for
// the other.
func TestEvidenceSet_OutputPathLeavesTheInputUntouched(t *testing.T) {
	t.Run("-o writes elsewhere and the input is byte-identical", func(t *testing.T) {
		path := writeTestEvidence(t)
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		out := filepath.Join(filepath.Dir(path), "elsewhere.json")

		_, _, err = executeCommand("evidence", "set", path, "--name", "Q3 Evidence", "-o", out)
		require.NoError(t, err)

		assert.Equal(t, "Q3 Evidence", readEvidenceDoc(t, out)["name"],
			"the named output carries the change")
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, before, after, "and the input is untouched")
	})

	t.Run("without -o the input is replaced in place", func(t *testing.T) {
		path := writeTestEvidence(t)
		_, _, err := executeCommand("evidence", "set", path, "--name", "Q3 Evidence")
		require.NoError(t, err)
		assert.Equal(t, "Q3 Evidence", readEvidenceDoc(t, path)["name"],
			"the default is to amend in place")
	})
}

// A RELATIVE --system-ref is recorded as given, which is the documented contract and not
// an oversight. Pinned because the alternative — encoding it — would double-encode an
// operator's correct "my%20scans/sys.json" into "my%2520scans/sys.json", and telling a
// raw path from an encoded reference requires inferring from whether the value contains a
// %, which 52n0c.31 forbids. An ABSOLUTE value is a path and IS encoded; that branch is
// covered by TestEvidenceRecording_EveryCommandEncodesTheReferenceItWrites.
//
// Maintainer decision 2026-10-13, after measuring that all three shapes resolve: the cost
// accepted is that a relative value may be recorded in a spelling uri-reference does not
// admit, and the operator owns that because they supplied a reference rather than a path.
func TestEvidenceSet_RelativeReferenceIsRecordedAsGiven(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)

	for _, given := range []string{"my scans/sys.json", "my%20scans/sys.json"} {
		out := filepath.Join(dir, "set-out.json")
		_, _, err := executeCommand("evidence", "set", pkg, "--system-ref", given, "-o", out)
		require.NoError(t, err)

		raw, err := os.ReadFile(out)
		require.NoError(t, err)
		var doc struct {
			SystemRef string `json:"systemRef"`
		}
		require.NoError(t, json.Unmarshal(raw, &doc))
		assert.Equal(t, given, doc.SystemRef,
			"a relative value is a reference already and is recorded unchanged — encoding it "+
				"would turn the correct escaped spelling into a double-encoded one")
	}
}
