package spdxvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_MatchesSPDX3Security(t *testing.T) {
	t.Parallel()
	fp := registry.GetFingerprint("spdx-vex-to-hdf")
	require.NotNil(t, fp)
	assert.Equal(t, registry.OutputAmendments, fp.OutputType)

	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "sample.spdx.json"))
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(data, &obj))
	assert.InDelta(t, 1.0, fp.Fingerprint(obj), 0.01)
}

func TestFingerprint_RejectsNonSecuritySPDX(t *testing.T) {
	t.Parallel()
	fp := registry.GetFingerprint("spdx-vex-to-hdf")
	require.NotNil(t, fp)

	// SPDX-3 AI/dataset (no VEX assessment) must not match.
	assert.InDelta(t, 0.0, fp.Fingerprint(map[string]any{
		"@context": "x",
		"@graph":   []any{map[string]any{"type": "ai_AIPackage"}},
	}), 0.01)

	// SPDX 2.x must not match.
	assert.InDelta(t, 0.0, fp.Fingerprint(map[string]any{"spdxVersion": "SPDX-2.3"}), 0.01)

	// Non-map input.
	assert.InDelta(t, 0.0, fp.Fingerprint("not-a-map"), 0.01)
}
