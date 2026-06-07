package openvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_MatchesOpenVEXDocs(t *testing.T) {
	t.Parallel()
	fp := registry.GetFingerprint("openvex-to-hdf")
	require.NotNil(t, fp)
	assert.Equal(t, registry.OutputAmendments, fp.OutputType)

	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "spring-boot-log4j.openvex.json"))
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(data, &obj))
	assert.InDelta(t, 1.0, fp.Fingerprint(obj), 0.01)
}

func TestFingerprint_RejectsNonOpenVEX(t *testing.T) {
	t.Parallel()
	fp := registry.GetFingerprint("openvex-to-hdf")
	require.NotNil(t, fp)

	assert.InDelta(t, 0.0, fp.Fingerprint(map[string]any{"foo": "bar"}), 0.01)
	assert.InDelta(t, 0.0, fp.Fingerprint(map[string]any{
		"@context":   "https://cyclonedx.org/schema",
		"statements": []any{},
	}), 0.01, "non-openvex context should not match")
	assert.InDelta(t, 0.0, fp.Fingerprint(map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
	}), 0.01, "must have statements")
	assert.InDelta(t, 0.0, fp.Fingerprint("not-a-map"), 0.01)
}
