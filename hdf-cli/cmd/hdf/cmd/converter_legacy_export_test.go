package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyFixture returns the path to a legacy HDF v1 (InSpec exec-json) fixture.
func legacyFixture(t *testing.T) string {
	return converterFixturePath(t, "legacyhdf-to-hdf", "input/minimal.json")
}

// convertOK runs `hdf convert <args> <input> -o <out>` and returns the output bytes.
func convertOK(t *testing.T, input string, args ...string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	full := append(append([]string{"convert"}, args...), input, "-o", out)
	cmd := NewRootCmd()
	cmd.SetArgs(full)
	require.NoError(t, cmd.Execute(), "convert %v", args)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	return data
}

// Legacy HDF v1 input (no `baselines`) is upgraded to modern HDF before any
// non-hdf export converter runs, so a single-step conversion succeeds where it
// previously failed with "missing baselines field" (issue #104).
func TestConvertLegacyHDFToOSCALSAR_ExplicitVersion(t *testing.T) {
	out := convertOK(t, legacyFixture(t), "--from", "hdf@1", "--to", "oscal-sar")

	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Contains(t, doc, "assessment-results", "should produce an OSCAL SAR document")
}

func TestConvertLegacyHDFToOSCALSAR_AutoDetect(t *testing.T) {
	out := convertOK(t, legacyFixture(t), "--to", "oscal-sar")

	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Contains(t, doc, "assessment-results")
}

// The upgrade is content-driven, so even `--from hdf` (no version) on legacy
// input is handled rather than failing on the missing baselines field.
func TestConvertLegacyHDFToOSCALSAR_FromHDFNoVersion(t *testing.T) {
	out := convertOK(t, legacyFixture(t), "--from", "hdf", "--to", "oscal-sar")
	assert.Contains(t, string(out), "assessment-results")
}

// The gap was systemic — legacy input must reach every hdf-export target, not
// just oscal-sar.
func TestConvertLegacyHDFToOtherExports(t *testing.T) {
	for _, target := range []string{"ckl", "xccdf", "csv"} {
		t.Run(target, func(t *testing.T) {
			out := convertOK(t, legacyFixture(t), "--from", "hdf@1", "--to", target)
			assert.NotEmpty(t, out)
		})
	}
}

// Modern HDF (already carrying baselines) must be passed through untouched.
func TestConvertModernHDFToOSCALSAR_Unaffected(t *testing.T) {
	modern := converterFixturePath(t, "legacyhdf-to-hdf", "expected/minimal.json")
	out := convertOK(t, modern, "--from", "hdf", "--to", "oscal-sar")
	assert.Contains(t, string(out), "assessment-results")
}

// normalizeLegacyHDFInput unit coverage: legacy upgrades to modern hdf; modern
// and non-hdf sources are returned unchanged.
func TestNormalizeLegacyHDFInput(t *testing.T) {
	legacy, err := os.ReadFile(legacyFixture(t))
	require.NoError(t, err)
	modern, err := os.ReadFile(converterFixturePath(t, "legacyhdf-to-hdf", "expected/minimal.json"))
	require.NoError(t, err)

	t.Run("legacy input is upgraded and source rewritten to hdf", func(t *testing.T) {
		data, from, ver, err := normalizeLegacyHDFInput(legacy, "hdf", "1", "oscal-sar")
		require.NoError(t, err)
		assert.Equal(t, "hdf", from)
		assert.Empty(t, ver)
		var d map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &d))
		assert.Contains(t, d, "baselines", "upgraded output must be modern HDF")
	})

	t.Run("auto-detected legacyhdf source is upgraded", func(t *testing.T) {
		data, from, _, err := normalizeLegacyHDFInput(legacy, "legacyhdf", "", "ckl")
		require.NoError(t, err)
		assert.Equal(t, "hdf", from)
		assert.Contains(t, string(data), "baselines")
	})

	t.Run("modern HDF is left untouched", func(t *testing.T) {
		data, from, ver, err := normalizeLegacyHDFInput(modern, "hdf", "", "oscal-sar")
		require.NoError(t, err)
		assert.Equal(t, "hdf", from)
		assert.Empty(t, ver)
		assert.Equal(t, modern, data)
	})

	t.Run("hdf target is left untouched even for legacy input", func(t *testing.T) {
		data, from, ver, err := normalizeLegacyHDFInput(legacy, "hdf", "1", "hdf")
		require.NoError(t, err)
		assert.Equal(t, "hdf", from)
		assert.Equal(t, "1", ver)
		assert.Equal(t, legacy, data)
	})

	t.Run("non-hdf source is left untouched", func(t *testing.T) {
		sarif := []byte(`{"runs":[]}`)
		data, from, _, err := normalizeLegacyHDFInput(sarif, "sarif", "", "hdf")
		require.NoError(t, err)
		assert.Equal(t, "sarif", from)
		assert.Equal(t, sarif, data)
	})
}
