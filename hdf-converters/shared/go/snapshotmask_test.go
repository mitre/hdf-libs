package shared

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The snapshot harness masks only the keys in the per-fixture mask set: timestamp
// is always volatile, but startTime is asserted for fixtures whose source carries
// a scan time and masked only for fixtures that synthesize it.
func TestNormalizeVolatileFields_MasksOnlyGivenKeys(t *testing.T) {
	t.Parallel()
	doc := `{"timestamp":"2026-07-12T00:00:00.5Z","baselines":[{"requirements":[{"results":[{"startTime":"2022-02-18T23:31:42Z","status":"failed"}]}]}]}`

	startTimeOf := func(b []byte) (string, string) {
		var got map[string]interface{}
		require.NoError(t, json.Unmarshal(b, &got))
		res := got["baselines"].([]interface{})[0].(map[string]interface{})["requirements"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})[0].(map[string]interface{})
		return got["timestamp"].(string), res["startTime"].(string)
	}

	// Input-derived fixture: timestamp masked, startTime ASSERTED.
	ts, st := startTimeOf(normalizeVolatileFields([]byte(doc), map[string]bool{"timestamp": true}))
	assert.Equal(t, "(normalized)", ts)
	assert.Equal(t, "2022-02-18T23:31:42Z", st, "startTime must survive when not in the mask")

	// Synthesized fixture: both masked.
	ts2, st2 := startTimeOf(normalizeVolatileFields([]byte(doc), map[string]bool{"timestamp": true, "startTime": true}))
	assert.Equal(t, "(normalized)", ts2)
	assert.Equal(t, "(normalized)", st2)
}
