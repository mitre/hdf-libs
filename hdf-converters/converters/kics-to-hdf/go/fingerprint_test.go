package kics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parsed(t *testing.T, name string) any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	var v any
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

func kicsFP(t *testing.T) registry.ConverterFingerprint {
	t.Helper()
	fp := registry.GetFingerprint("kics-to-hdf")
	require.NotNil(t, fp, "kics-to-hdf fingerprint not registered")
	return *fp
}

func TestFingerprintRegistered(t *testing.T) {
	fp := kicsFP(t)
	assert.Equal(t, "KICS", fp.Label)
	assert.Equal(t, registry.DirectionIngest, fp.Direction)
	assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
	assert.Equal(t, registry.OutputResults, fp.OutputType)
}

func TestFingerprintMatchesRealScans(t *testing.T) {
	fp := kicsFP(t)
	for _, n := range []string{"findings.json", "minimal.json", "zero-findings.json"} {
		assert.Equal(t, 1.0, fp.Fingerprint(parsed(t, n)), n)
	}
}

func TestFingerprintWithoutSeverityCounters(t *testing.T) {
	assert.Equal(t, 0.8, fingerprintObject(map[string]any{
		"queries": []any{}, "kics_version": "v2.1.20",
	}))
}

func TestFingerprintRejectsOtherShapes(t *testing.T) {
	fp := kicsFP(t)
	cases := map[string]any{
		"not an object":        "a string",
		"nil":                  nil,
		"array of hdf reqs":    []any{map[string]any{"id": "x", "results": []any{}}},
		"no queries":           map[string]any{"kics_version": "v1"},
		"no kics_version":      map[string]any{"queries": []any{}},
		"queries not an array": map[string]any{"queries": "nope", "kics_version": "v1"},
		"version not a string": map[string]any{"queries": []any{}, "kics_version": 2},
		"semgrep-shaped":       map[string]any{"results": []any{}, "errors": []any{}, "paths": map[string]any{"scanned": []any{}}},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) { assert.Equal(t, 0.0, fp.Fingerprint(in)) })
	}
}

func TestDetectVersion(t *testing.T) {
	fp := kicsFP(t)
	require.NotNil(t, fp.DetectVersion)
	assert.NotEmpty(t, fp.DetectVersion(parsed(t, "findings.json")))
	assert.Equal(t, "", fp.DetectVersion("not an object"))
	assert.Equal(t, "", fp.DetectVersion(map[string]any{"kics_version": 3}))
}
