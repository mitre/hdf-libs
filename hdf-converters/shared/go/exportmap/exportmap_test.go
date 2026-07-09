package exportmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mkResults(statuses ...string) map[string]interface{} {
	var results []interface{}
	for _, s := range statuses {
		results = append(results, map[string]interface{}{"status": s})
	}
	return map[string]interface{}{"results": results}
}

func TestWorstOfResults(t *testing.T) {
	assert.Equal(t, "failed", WorstOfResults(mkResults("passed", "failed")))
	assert.Equal(t, "passed", WorstOfResults(mkResults("passed", "passed")))
	assert.Equal(t, "error", WorstOfResults(mkResults("error", "passed")))
	assert.Equal(t, "notApplicable", WorstOfResults(mkResults("notApplicable")))
	assert.Equal(t, "notReviewed", WorstOfResults(mkResults()))
}

func TestStatusOf(t *testing.T) {
	// no override: rollup == raw, not overridden
	st := StatusOf(mkResults("failed"))
	assert.Equal(t, "failed", st.Raw)
	assert.Equal(t, "failed", st.Rollup)
	assert.Equal(t, "", st.Effective)
	assert.False(t, st.Overridden)

	// effectiveStatus present: rollup follows it, overridden true
	req := mkResults("failed")
	req["effectiveStatus"] = "passed"
	st = StatusOf(req)
	assert.Equal(t, "failed", st.Raw, "raw stays the lossless results roll-up")
	assert.Equal(t, "passed", st.Effective)
	assert.Equal(t, "passed", st.Rollup)
	assert.True(t, st.Overridden)

	// statusOverrides present without effectiveStatus: overridden true, rollup == raw
	req2 := mkResults("failed")
	req2["statusOverrides"] = []interface{}{map[string]interface{}{"type": "waiver"}}
	st = StatusOf(req2)
	assert.True(t, st.Overridden)
	assert.Equal(t, "failed", st.Rollup)
}

func TestGenericAccess(t *testing.T) {
	m, ok := AsMap(map[string]interface{}{"a": 1})
	assert.True(t, ok)
	assert.Equal(t, "", GetStr(m, "a")) // non-string -> ""
	assert.Equal(t, "", GetStr(nil, "x"))

	_, ok = AsMap([]interface{}{})
	assert.False(t, ok)
	s, ok := AsSlice([]interface{}{1, 2})
	assert.True(t, ok)
	assert.Len(t, s, 2)

	dst := map[string]interface{}{}
	SetIf(dst, "keep", "v")
	SetIf(dst, "drop", "")
	assert.Equal(t, map[string]interface{}{"keep": "v"}, dst)

	assert.Equal(t, []string{"x"}, StringSlice("x"))
	assert.Equal(t, []string{"a", "b"}, StringSlice([]interface{}{"a", 1, "b"}))
	assert.Nil(t, StringSlice(42))
}

func TestExtraction(t *testing.T) {
	doc := map[string]interface{}{"components": []interface{}{map[string]interface{}{"name": "web"}}}
	assert.Equal(t, "web", GetStr(FirstComponent(doc), "name"))
	assert.Nil(t, FirstComponent(map[string]interface{}{}))

	req := map[string]interface{}{
		"results":      []interface{}{map[string]interface{}{"startTime": "2024-01-01T00:00:00Z"}},
		"descriptions": []interface{}{map[string]interface{}{"label": "default", "data": "desc"}},
		"refs":         []interface{}{map[string]interface{}{"url": "https://x"}},
	}
	assert.Equal(t, "2024-01-01T00:00:00Z", FirstResultStartTime(req, "fb"))
	assert.Equal(t, "fb", FirstResultStartTime(map[string]interface{}{}, "fb"))
	assert.Equal(t, "desc", DefaultDescription(req))
	assert.Equal(t, "https://x", FirstRefURL(req))

	comp := map[string]interface{}{"componentId": "c1"}
	assert.Equal(t, "c1|base|V-1", EventID(comp, "base", "V-1"))
	assert.Equal(t, "|base|V-1", EventID(nil, "base", "V-1"))
}

func TestEncodeLine(t *testing.T) {
	// key-sorted, HTML not escaped, trailing newline
	line, err := EncodeLine(map[string]interface{}{"b": 1, "a": "x&y"})
	require.NoError(t, err)
	assert.Equal(t, "{\"a\":\"x&y\",\"b\":1}\n", string(line))
}
