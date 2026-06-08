package cyclonedxvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_MatchesCycloneDXVEX(t *testing.T) {
	t.Parallel()
	fp := registry.GetFingerprint("cyclonedx-vex-to-hdf")
	require.NotNil(t, fp)
	assert.Equal(t, registry.OutputAmendments, fp.OutputType)

	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "case1-vex-not_affected.json"))
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(data, &obj))
	assert.InDelta(t, 1.0, fp.Fingerprint(obj), 0.01)
}

func TestFingerprint_RejectsPlainSBOM(t *testing.T) {
	t.Parallel()
	fp := registry.GetFingerprint("cyclonedx-vex-to-hdf")
	require.NotNil(t, fp)

	plainSBOM := map[string]any{
		"bomFormat": "CycloneDX",
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-2024-1"}, // no analysis -> not a VEX statement
		},
	}
	assert.InDelta(t, 0.0, fp.Fingerprint(plainSBOM), 0.01)
}

func TestFingerprint_RejectsNonCycloneDX(t *testing.T) {
	t.Parallel()
	fp := registry.GetFingerprint("cyclonedx-vex-to-hdf")
	require.NotNil(t, fp)
	assert.InDelta(t, 0.0, fp.Fingerprint(map[string]any{"bomFormat": "SPDX"}), 0.01)
	assert.InDelta(t, 0.0, fp.Fingerprint(map[string]any{"bomFormat": "CycloneDX"}), 0.01,
		"no vulnerabilities array -> not a VEX")
	assert.InDelta(t, 0.0, fp.Fingerprint("not-a-map"), 0.01)
}
