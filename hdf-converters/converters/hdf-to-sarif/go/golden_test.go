package hdftosarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	"github.com/stretchr/testify/require"
)

// testVersion keeps the converter version out of the goldens' way: the real one
// changes every release, and it reaches the output through the conversion object
// and the shared HDF block.
const testVersion = "0.0.0"

// goldenInputs are the converted documents frozen byte-for-byte. The TypeScript
// peer asserts against the SAME files, which is what makes the byte-identical
// claim an assertion rather than a hope.
var goldenInputs = []string{"flawfinder", "grype-cve", "minimal"}

func loadGoldenInput(t *testing.T, name string) []byte {
	t.Helper()
	if name == "minimal" {
		return fixtures.Results.Minimal
	}
	path := filepath.Join("..", "fixtures", "input", name+".hdf.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err, "read input %s", path)
	return raw
}

// TestGoldenParity asserts byte-for-byte output against frozen goldens.
// Regenerate with: UPDATE_GOLDEN=1 go test ./converters/hdf-to-sarif/go/
func TestGoldenParity(t *testing.T) {
	for _, name := range goldenInputs {
		out, err := ConvertHDFToSARIF(loadGoldenInput(t, name), testVersion)
		require.NoError(t, err)
		path := filepath.Join("..", "fixtures", "expected", name+".sarif.json")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.WriteFile(path, out, 0o600))
			continue
		}
		golden, err := os.ReadFile(path) // #nosec G304 -- repo-relative golden
		require.NoError(t, err, "read golden %s (regenerate with UPDATE_GOLDEN=1)", path)
		require.Equal(t, string(golden), string(out), "golden mismatch for %s", name)
	}
}

// corpusRejected marks a corpus case the converter refuses; the two languages
// must agree on rejection as well as on output.
const corpusRejected = "REJECTED"

// TestCorpusGoldenParity freezes what this converter emits for every adversarial
// corpus input, including which ones it rejects. The sparse and malformed inputs
// are where two implementations drift, and no happy-path golden reaches them.
// Go owns regeneration; TypeScript only verifies.
func TestCorpusGoldenParity(t *testing.T) {
	outputs := make(map[string]string, len(corpus.ResultsCorpus()))
	for _, c := range corpus.ResultsCorpus() {
		out, err := corpus.ConvertNoPanic(func(in []byte) ([]byte, error) {
			return ConvertHDFToSARIF(in, testVersion)
		}, c.Input)
		if err != nil {
			outputs[c.Name] = corpusRejected
			continue
		}
		outputs[c.Name] = string(out)
	}

	actual, err := json.MarshalIndent(outputs, "", "  ")
	require.NoError(t, err)
	actual = append(actual, '\n')

	path := filepath.Join("..", "fixtures", "expected", "corpus-outputs.json")
	if shared.UpdateSnapshots() {
		require.NoError(t, os.WriteFile(path, actual, 0o600))
		t.Logf("updated %s", path)
		return
	}
	expected, err := os.ReadFile(path) // #nosec G304 -- repo-relative golden
	require.NoError(t, err, "missing corpus output golden; regenerate with -update")
	require.JSONEq(t, string(expected), string(actual),
		"corpus output changed; if intentional regenerate with: go test ./converters/hdf-to-sarif/go/ -update")
}
