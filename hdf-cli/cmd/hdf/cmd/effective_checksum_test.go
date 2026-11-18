package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
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

func TestStampConvertOutput_BaselineShapeUntouched(t *testing.T) {
	input := fixtures.Baseline.Win2022Stig
	out, err := stampConvertOutput(input)
	require.NoError(t, err)
	assert.JSONEq(t, string(input), string(out), "baseline definitions must not acquire evaluated-result checksums")
}

func TestStampConvertOutput_InvalidJSON(t *testing.T) {
	_, err := stampConvertOutput([]byte("not json"))
	assert.Error(t, err)
}

// topLevelKeys returns the root object's keys in document order.
func topLevelKeys(t *testing.T, data []byte) []string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var keys []string
	depth, expectKey := 0, false
	for {
		token, err := decoder.Token()
		if err != nil {
			return keys
		}
		switch tok := token.(type) {
		case json.Delim:
			if tok == '{' || tok == '[' {
				depth++
			} else {
				depth--
			}
			expectKey = depth == 1
		default:
			if depth == 1 && expectKey {
				keys = append(keys, tok.(string))
			}
			expectKey = depth == 1 && !expectKey
		}
	}
}

func TestStampConvertOutput_BaselineKeysComeBackSorted(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/benchmark-minimal-1.1.xml"),
	)
	require.NoError(t, err)
	converter, err := GetConverter("xccdf-benchmark", "hdf")
	require.NoError(t, err)
	converted, err := converter.Convert(inputData)
	require.NoError(t, err)

	out, err := stampConvertOutput(converted)
	require.NoError(t, err)
	keys := topLevelKeys(t, out)
	require.Greater(t, len(keys), 1)
	assert.True(t, sort.StringsAreSorted(keys), "top-level keys must be sorted, got %v", keys)
	assert.NotContains(t, string(out), "effectiveChecksum")
}
