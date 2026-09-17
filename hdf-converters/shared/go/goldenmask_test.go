package shared

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mask(t *testing.T, doc string, volatile ...string) interface{} {
	t.Helper()
	out, err := MaskVolatileJSON([]byte(doc), volatile)
	require.NoError(t, err)
	return out
}

func TestMaskVolatileJSON_UUIDsBecomeOrdinals(t *testing.T) {
	t.Parallel()
	got := mask(t, `{"a":"11111111-1111-1111-1111-111111111111","b":"22222222-2222-2222-2222-222222222222"}`)
	assert.Equal(t, map[string]interface{}{"a": "uuid-1", "b": "uuid-2"}, got)
}

func TestMaskVolatileJSON_SameUUIDKeepsSameOrdinal(t *testing.T) {
	t.Parallel()
	// The party uuid reappears under responsible-parties; the reference must survive masking.
	got := mask(t, `{"parties":[{"uuid":"11111111-1111-1111-1111-111111111111"}],
	                "responsible":{"party-uuids":["11111111-1111-1111-1111-111111111111"]}}`)
	b, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, `{"parties":[{"uuid":"uuid-1"}],"responsible":{"party-uuids":["uuid-1"]}}`, string(b))
}

// The property that makes ordinal masking worth the complexity: two documents whose
// UUIDs are wired up DIFFERENTLY must not compare equal. A single-constant mask would
// flatten both to the same thing and let a broken reference graph pass.
func TestMaskVolatileJSON_DifferentWiringDoesNotCompareEqual(t *testing.T) {
	t.Parallel()
	linked := mask(t, `{"a":{"uuid":"11111111-1111-1111-1111-111111111111"},
	                    "b":{"ref":"11111111-1111-1111-1111-111111111111"}}`)
	unlinked := mask(t, `{"a":{"uuid":"11111111-1111-1111-1111-111111111111"},
	                      "b":{"ref":"22222222-2222-2222-2222-222222222222"}}`)
	assert.NotEqual(t, linked, unlinked, "a document whose uuids point elsewhere must not mask to the same value")
}

func TestMaskVolatileJSON_FragmentReferenceSharesOrdinal(t *testing.T) {
	t.Parallel()
	got := mask(t, `{"a":{"href":"#11111111-1111-1111-1111-111111111111"},"b":{"uuid":"11111111-1111-1111-1111-111111111111"},"c":"#SV-1"}`)
	assert.Equal(t, map[string]interface{}{
		"a": map[string]interface{}{"href": "#uuid-1"},
		"b": map[string]interface{}{"uuid": "uuid-1"},
		"c": "#SV-1",
	}, got)
}

func TestMaskVolatileJSON_VolatileKeysBlanked(t *testing.T) {
	t.Parallel()
	got := mask(t, `{"last-modified":"2026-07-12T00:00:00Z","title":"keep me"}`, "last-modified")
	assert.Equal(t, map[string]interface{}{"last-modified": "(normalized)", "title": "keep me"}, got)
}

func TestMaskVolatileJSON_NonVolatileDatesSurvive(t *testing.T) {
	t.Parallel()
	// Input-derived dates (a milestone deadline) must still be asserted, not blanked.
	got := mask(t, `{"deadline":"2026-02-01T00:00:00Z"}`, "last-modified")
	assert.Equal(t, map[string]interface{}{"deadline": "2026-02-01T00:00:00Z"}, got)
}

func TestMaskVolatileJSON_NonUUIDStringsUntouched(t *testing.T) {
	t.Parallel()
	got := mask(t, `{"id":"SV-204393","near":"1111-11-11-1111"}`)
	assert.Equal(t, map[string]interface{}{"id": "SV-204393", "near": "1111-11-11-1111"}, got)
}

func TestMaskVolatileJSON_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := MaskVolatileJSON([]byte("not json"), nil)
	assert.Error(t, err)
}
