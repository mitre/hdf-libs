package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStampConvertOutput(t *testing.T) {
	input := `{
	  "timestamp": "2026-07-01T00:00:00Z",
	  "baselines": [{"name": "b", "requirements": [
	    {"id": "R1", "impact": 0.5, "tags": {}, "descriptions": [],
	     "results": [{"status": "failed", "codeDesc": "t", "startTime": "2025-01-01T00:00:00Z"}]}
	  ]}]
	}`

	out, err := stampConvertOutput([]byte(input))
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))
	reqs := doc["baselines"].([]interface{})[0].(map[string]interface{})["requirements"].([]interface{})
	req := reqs[0].(map[string]interface{})
	cs, ok := req["effectiveChecksum"].(map[string]interface{})
	require.True(t, ok, "converted requirement must carry effectiveChecksum")
	assert.Equal(t, "sha256", cs["algorithm"])
	// sha256 of {"status":"failed","impact":0.5,"disposition":null} — same
	// pinned vector as the hdf-diff Go and TS suites.
	assert.Equal(t, "704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021", cs["value"])
}

func TestStampConvertOutput_LegacyShapeUntouched(t *testing.T) {
	// Legacy v2 output (profiles, no baselines) has no stampable arrays; the
	// stamper must pass it through structurally unchanged.
	input := `{"profiles": [{"name": "p", "controls": [{"id": "c1"}]}], "version": "5.22.3"}`
	out, err := stampConvertOutput([]byte(input))
	require.NoError(t, err)
	assert.JSONEq(t, input, string(out))
}

func TestStampConvertOutput_InvalidJSON(t *testing.T) {
	_, err := stampConvertOutput([]byte("not json"))
	assert.Error(t, err)
}
