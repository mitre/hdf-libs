package exportmap

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFloatToken(t *testing.T) {
	assert.Equal(t, json.Number("0.0"), FloatToken(0))
	assert.Equal(t, json.Number("7.5"), FloatToken(7.5))
	assert.Equal(t, json.Number("8.0"), FloatToken(8))
	assert.Equal(t, json.Number("10.0"), FloatToken(10))
	assert.Equal(t, json.Number("9.8"), FloatToken(9.8))
	// renders as a bare decimal token (not a quoted string, not an integer)
	line, err := EncodeLine(map[string]interface{}{"base_score": FloatToken(10)})
	require.NoError(t, err)
	assert.Equal(t, "{\"base_score\":10.0}\n", string(line))
}

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
	// no override: rollup == raw, not overridden, not suppressed
	st := StatusOf(mkResults("failed"))
	assert.Equal(t, "failed", st.Raw)
	assert.Equal(t, "failed", st.Rollup)
	assert.Equal(t, "", st.Effective)
	assert.False(t, st.Overridden)
	assert.False(t, st.Suppressed)

	// effectiveStatus present: rollup follows it, overridden true, suppressed true
	req := mkResults("failed")
	req["effectiveStatus"] = "passed"
	st = StatusOf(req)
	assert.Equal(t, "failed", st.Raw, "raw stays the lossless results roll-up")
	assert.Equal(t, "passed", st.Effective)
	assert.Equal(t, "passed", st.Rollup)
	assert.True(t, st.Overridden)
	assert.True(t, st.Suppressed, "raw-failing driven non-failing → suppressed")

	// statusOverrides present without effectiveStatus: overridden true, rollup ==
	// raw, NOT suppressed (can't suppress without a non-failing effective status)
	req2 := mkResults("failed")
	req2["statusOverrides"] = []interface{}{map[string]interface{}{"type": "waiver"}}
	st = StatusOf(req2)
	assert.True(t, st.Overridden)
	assert.Equal(t, "failed", st.Rollup)
	assert.False(t, st.Suppressed)
}

// TestStatusOf_SuppressedMatrix pins the acceptance axis across dispositions:
// suppressing overrides (waiver/falsePositive/attestation drive effectiveStatus
// non-failing) → Suppressed; risk-response overrides that keep the finding
// failing (riskAdjustment/operationalRequirement/poam) → NOT suppressed.
func TestStatusOf_SuppressedMatrix(t *testing.T) {
	suppressing := []string{"passed", "notApplicable"} // effective verdicts a waiver/FP yields
	for _, eff := range suppressing {
		req := mkResults("failed")
		req["effectiveStatus"] = eff
		assert.True(t, StatusOf(req).Suppressed, "raw failed + effective %s → suppressed", eff)
	}

	// riskAdjustment / operationalRequirement / poam: effectiveStatus stays failed
	req := mkResults("failed")
	req["effectiveStatus"] = "failed"
	req["statusOverrides"] = []interface{}{map[string]interface{}{"type": "riskAdjustment", "impact": map[string]interface{}{"value": 0.2}}}
	st := StatusOf(req)
	assert.True(t, st.Overridden)
	assert.False(t, st.Suppressed, "risk-adjusted failure stays actionable")

	// a passing finding is never suppressed regardless of overrides
	pass := mkResults("passed")
	pass["effectiveStatus"] = "passed"
	assert.False(t, StatusOf(pass).Suppressed)

	// an errored finding driven to passed is not suppressed (error isn't failing)
	erf := mkResults("error")
	erf["effectiveStatus"] = "passed"
	assert.False(t, StatusOf(erf).Suppressed)

	assert.True(t, IsFailing("failed"))
	assert.False(t, IsFailing("error"))
	assert.False(t, IsFailing("passed"))
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

func TestExport_Driver(t *testing.T) {
	// two baselines × requirements fan out to one line per requirement, in order,
	// each a canonical (key-sorted, newline-terminated) EncodeLine.
	input := []byte(`{"timestamp":"2024-01-01T00:00:00Z","baselines":[` +
		`{"name":"b1","requirements":[{"id":"A"},{"id":"B"}]},` +
		`{"name":"b2","requirements":[{"id":"C"}]}]}`)
	out, err := Export(input, "test-exporter",
		func(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}) map[string]interface{} {
			return map[string]interface{}{"id": GetStr(req, "id"), "baseline": GetStr(baseline, "name"), "ts": docTimestamp}
		})
	require.NoError(t, err)
	assert.Equal(t,
		"{\"baseline\":\"b1\",\"id\":\"A\",\"ts\":\"2024-01-01T00:00:00Z\"}\n"+
			"{\"baseline\":\"b1\",\"id\":\"B\",\"ts\":\"2024-01-01T00:00:00Z\"}\n"+
			"{\"baseline\":\"b2\",\"id\":\"C\",\"ts\":\"2024-01-01T00:00:00Z\"}\n",
		string(out))

	// doc-level context is threaded to the builder
	ctxSeen := false
	_, err = Export([]byte(`{"tool":{"name":"t"},"components":[{"name":"h"}],"baselines":[{"requirements":[{"id":"X"}]}]}`), "x",
		func(_, _ map[string]interface{}, _ string, tool, _, component map[string]interface{}) map[string]interface{} {
			assert.Equal(t, "t", GetStr(tool, "name"))
			assert.Equal(t, "h", GetStr(component, "name"))
			ctxSeen = true
			return map[string]interface{}{}
		})
	require.NoError(t, err)
	assert.True(t, ctxSeen)

	noop := func(_, _ map[string]interface{}, _ string, _, _, _ map[string]interface{}) map[string]interface{} {
		return nil
	}
	_, err = Export([]byte(""), "x", noop)
	assert.Error(t, err, "empty input")
	_, err = Export([]byte("not json"), "x", noop)
	assert.Error(t, err, "invalid JSON")
	_, err = Export([]byte(`{"foo":1}`), "x", noop)
	assert.Error(t, err, "missing baselines")
	// empty baselines -> empty output, no error
	out, err = Export([]byte(`{"baselines":[]}`), "x", noop)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestFirstCVE(t *testing.T) {
	list := []interface{}{
		map[string]interface{}{"source": "GHSA-xxxx"},
		map[string]interface{}{"source": "cve-2024-1234"}, // case-insensitive prefix
	}
	assert.Equal(t, "cve-2024-1234", FirstCVE(list))
	assert.Equal(t, "", FirstCVE([]interface{}{map[string]interface{}{"source": "NOTCVE"}}))
	assert.Equal(t, "", FirstCVE([]interface{}{map[string]interface{}{"source": "CVE"}})) // too short
	assert.Equal(t, "", FirstCVE(nil))
}

func TestEpochHelpers(t *testing.T) {
	sec, ok := EpochSeconds("2024-01-01T00:00:00Z")
	require.True(t, ok)
	assert.Equal(t, int64(1704067200), sec)
	_, ok = EpochSeconds("")
	assert.False(t, ok)

	ms, ok := EpochMillis("2024-01-01T00:00:00Z")
	require.True(t, ok)
	assert.Equal(t, int64(1704067200000), ms)
	_, ok = EpochMillis("")
	assert.False(t, ok)
}

func TestEncodeLine_NonBMPKeyOrder(t *testing.T) {
	// Keys sort bytewise (UTF-8 == code-point): a < U+E000 < U+1F600. The TS
	// canonicalize must reproduce this exact order (see exportmap.test.ts) — a
	// supplementary-plane key is where JS's default UTF-16 sort diverges.
	line, err := EncodeLine(map[string]interface{}{"a": 1, "": 2, "\U0001F600": 3})
	require.NoError(t, err)
	assert.Equal(t, "{\"a\":1,\"\":2,\"\U0001F600\":3}\n", string(line))
}

func TestEncodeLine_JSONPEscaping(t *testing.T) {
	// Go escapes U+2028/U+2029 in string values (JSONP safety); TS stringifyLine
	// mirrors this so the two stay byte-identical.
	line, err := EncodeLine(map[string]interface{}{"k": "line sep end"})
	require.NoError(t, err)
	assert.Equal(t, "{\"k\":\"line\\u2028sep\\u2029end\"}\n", string(line))
}

func TestBuildHDFBlock(t *testing.T) {
	req := map[string]interface{}{
		"id":               "V-1",
		"effectiveStatus":  "passed",
		"effectiveImpact":  0.3,
		"impact":           0.7,
		"severity":         "high",
		"disposition":      "waiver",
		"tags":             map[string]interface{}{"nist": []interface{}{"AC-6"}, "cci": []interface{}{"CCI-1"}},
		"cvss":             []interface{}{map[string]interface{}{"baseScore": 7.5}},
		"cwe":              []interface{}{"CWE-79"},
		"epss":             0.1,
		"kev":              true,
		"affectedPackages": []interface{}{"pkg"},
		"descriptions":     []interface{}{map[string]interface{}{"label": "default", "data": "d"}},
		"results":          []interface{}{map[string]interface{}{"status": "failed"}},
		"statusOverrides":  []interface{}{map[string]interface{}{"type": "waiver"}},
		"poams":            []interface{}{map[string]interface{}{"id": "P-1"}},
		"code":             "control code",
		"refs":             []interface{}{map[string]interface{}{"url": "https://x"}},
	}
	baseline := map[string]interface{}{"name": "b1"}
	gen := map[string]interface{}{"name": "g"}
	tool := map[string]interface{}{"name": "t"}
	hdf := BuildHDFBlock(req, baseline, "failed", true, true, gen, tool, "0.1.0")

	assert.Equal(t, "failed", hdf["status"])
	assert.Equal(t, true, hdf["overridden"])
	assert.Equal(t, true, hdf["suppressed"])
	assert.Equal(t, "0.1.0", hdf["exporter_version"])
	assert.Equal(t, "V-1", hdf["control_id"])
	assert.Equal(t, "b1", hdf["baseline"])
	assert.Equal(t, "passed", hdf["effective_status"])
	assert.Equal(t, 0.3, hdf["effective_impact"])
	assert.Equal(t, 0.7, hdf["impact"])
	assert.Equal(t, "high", hdf["severity"])
	assert.Equal(t, "waiver", hdf["disposition"])
	assert.Equal(t, []interface{}{"AC-6"}, hdf["nist"])
	assert.Equal(t, []interface{}{"CCI-1"}, hdf["cci"])
	for _, k := range []string{"tags", "cvss", "cwe", "epss", "kev", "affected_packages", "descriptions", "results", "status_overrides", "poams", "refs"} {
		assert.Contains(t, hdf, k, "passthrough key %q present", k)
	}
	assert.Equal(t, "control code", hdf["code"])
	assert.Equal(t, gen, hdf["generator"])
	assert.Equal(t, tool, hdf["tool"])

	// minimal req: optionals + generator/tool absent, empty id skipped by SetIf
	minimal := BuildHDFBlock(map[string]interface{}{}, map[string]interface{}{}, "passed", false, false, nil, nil, "0.1.0")
	assert.Equal(t, "passed", minimal["status"])
	assert.Equal(t, false, minimal["suppressed"])
	assert.NotContains(t, minimal, "effective_status")
	assert.NotContains(t, minimal, "generator")
	assert.NotContains(t, minimal, "tool")
	assert.NotContains(t, minimal, "control_id")
	assert.NotContains(t, minimal, "nist")
}
