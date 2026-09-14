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
