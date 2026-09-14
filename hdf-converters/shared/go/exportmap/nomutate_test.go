package exportmap

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EncodeLine must not edit the map it is handed: an exporter that encodes an
// event and then reads it back would otherwise see a value it never set.
func TestEncodeLineDoesNotMutateCaller(t *testing.T) {
	nested := map[string]interface{}{"deep": math.Copysign(0, -1)}
	arg := map[string]interface{}{
		"impact": math.Copysign(0, -1),
		"list":   []interface{}{math.Copysign(0, -1)},
		"nested": nested,
	}
	line, err := EncodeLine(arg)
	require.NoError(t, err)
	assert.Equal(t, "{\"impact\":0,\"list\":[0],\"nested\":{\"deep\":0}}\n", string(line))

	assert.True(t, math.Signbit(arg["impact"].(float64)), "caller's top-level value was mutated")
	assert.True(t, math.Signbit(arg["list"].([]interface{})[0].(float64)), "caller's slice was mutated")
	assert.True(t, math.Signbit(nested["deep"].(float64)), "caller's nested map was mutated")
}

// A cyclic map is legal to construct, and encoding/json rejects it with an
// error. The negative-zero walk must not turn that returned error into a stack
// overflow, which is what an uncapped recursion did.
func TestEncodeLineReportsCyclesInsteadOfCrashing(t *testing.T) {
	m := map[string]interface{}{"a": 1.0}
	m["self"] = m

	_, err := EncodeLine(m)
	require.Error(t, err, "a cyclic map must come back as an error, not a crash")
	assert.Contains(t, err.Error(), "cycle")
}

// Depth below the cap is still normalized, so the guard cannot be satisfied by
// simply refusing to descend.
func TestEncodeLineNormalizesBelowTheDepthCap(t *testing.T) {
	leaf := map[string]interface{}{"impact": math.Copysign(0, -1)}
	node := interface{}(leaf)
	for i := 0; i < 50; i++ {
		node = map[string]interface{}{"child": node}
	}
	line, err := EncodeLine(node)
	require.NoError(t, err)
	assert.Contains(t, string(line), `"impact":0`)
	assert.NotContains(t, string(line), `"impact":-0`)
}
