package semgrep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseFixture(t *testing.T, name string) any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	var parsed any
	require.NoError(t, json.Unmarshal(data, &parsed))
	return parsed
}

func semgrepFP(t *testing.T) registry.ConverterFingerprint {
	t.Helper()
	fp := registry.GetFingerprint("semgrep-to-hdf")
	require.NotNil(t, fp, "semgrep-to-hdf fingerprint not registered")
	return *fp
}

func TestFingerprintRegistered(t *testing.T) {
	fp := semgrepFP(t)
	assert.Equal(t, "Semgrep", fp.Label)
	assert.Equal(t, registry.DirectionIngest, fp.Direction)
	assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
	assert.Equal(t, registry.OutputResults, fp.OutputType)
}

func TestFingerprintMatchesRealScan(t *testing.T) {
	fp := semgrepFP(t)
	assert.Equal(t, 1.0, fp.Fingerprint(parseFixture(t, "real.json")))
	assert.Equal(t, 1.0, fp.Fingerprint(parseFixture(t, "errors.json")))
}

func TestFingerprintMatchesEmptyScan(t *testing.T) {
	fp := semgrepFP(t)
	// No finding to corroborate, so the engine marker carries it.
	assert.Equal(t, 0.9, fp.Fingerprint(parseFixture(t, "empty.json")))
}

func TestFingerprintWithoutEngineMarker(t *testing.T) {
	assert.Equal(t, 0.7, fingerprintObject(map[string]any{
		"results": []any{},
		"errors":  []any{},
		"paths":   map[string]any{"scanned": []any{}},
	}))
}

func TestFingerprintRejectsNonSemgrepShapes(t *testing.T) {
	fp := semgrepFP(t)
	cases := map[string]any{
		"not an object":       "a string",
		"nil":                 nil,
		"array of hdf reqs":   []any{map[string]any{"id": "x", "results": []any{}}},
		"missing errors":      map[string]any{"results": []any{}, "paths": map[string]any{"scanned": []any{}}},
		"missing results":     map[string]any{"errors": []any{}, "paths": map[string]any{"scanned": []any{}}},
		"missing paths":       map[string]any{"results": []any{}, "errors": []any{}},
		"paths not an object": map[string]any{"results": []any{}, "errors": []any{}, "paths": "nope"},
		"paths without scanned": map[string]any{
			"results": []any{}, "errors": []any{}, "paths": map[string]any{"skipped": []any{}},
		},
		"sarif": map[string]any{"$schema": "x", "version": "2.1.0", "runs": []any{}},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, 0.0, fp.Fingerprint(input))
		})
	}
}

func TestFingerprintFindingWithoutExtraIsNotStrong(t *testing.T) {
	// check_id present but no extra envelope: still semgrep-shaped overall, but
	// not the strong signal.
	score := fingerprintObject(map[string]any{
		"results":          []any{map[string]any{"check_id": "rule"}},
		"errors":           []any{},
		"paths":            map[string]any{"scanned": []any{}},
		"engine_requested": "OSS",
	})
	assert.Equal(t, 0.9, score)
}

func TestDetectVersion(t *testing.T) {
	fp := semgrepFP(t)
	require.NotNil(t, fp.DetectVersion)
	assert.Equal(t, "1.174.0", fp.DetectVersion(parseFixture(t, "real.json")))
	assert.Equal(t, "", fp.DetectVersion("not an object"))
	assert.Equal(t, "", fp.DetectVersion(map[string]any{"version": 3}))
}
