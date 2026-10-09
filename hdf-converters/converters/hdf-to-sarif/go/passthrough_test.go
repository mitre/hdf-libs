package hdftosarif

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// carriedDoc builds a document carrying the given addressed bags. Built here
// rather than committed as a fixture: no importer writes this block yet, so a
// committed file would assert about data no tool has produced.
func carriedDoc(t *testing.T, bags ...map[string]interface{}) map[string]interface{} {
	t.Helper()
	doc := map[string]interface{}{
		"baselines": []interface{}{map[string]interface{}{
			"name": "run-one",
			"requirements": []interface{}{map[string]interface{}{
				"id":             "V-1",
				"impact":         0.5,
				"tags":           map[string]interface{}{},
				"descriptions":   []interface{}{map[string]interface{}{"label": "default", "data": "d"}},
				"sourceLocation": map[string]interface{}{"ref": "a.c", "line": 7},
				"results": []interface{}{
					map[string]interface{}{"status": "failed", "codeDesc": "first", "startTime": "2020-01-01T00:00:00Z"},
					map[string]interface{}{"status": "failed", "codeDesc": "second", "startTime": "2020-01-01T00:00:00Z"},
				},
			}},
		}},
		"extensions": map[string]interface{}{
			"passthrough": map[string]interface{}{
				"sarif": map[string]interface{}{
					"schemaVersion": PassthroughSchemaVersion,
					"propertyBags":  toAny(bags),
				},
			},
		},
	}
	input, err := json.Marshal(doc)
	require.NoError(t, err)
	out, err := ConvertHDFToSARIF(input, testVersion)
	require.NoError(t, err)
	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &log))
	return log
}

func toAny(bags []map[string]interface{}) []interface{} {
	out := make([]interface{}, 0, len(bags))
	for _, b := range bags {
		out = append(out, b)
	}
	return out
}

func props(t *testing.T, obj map[string]interface{}) map[string]interface{} {
	t.Helper()
	p, _ := obj["properties"].(map[string]interface{})
	return p
}

// Each addressed bag reaches the one object its address names. The address is
// built from the HDF identities that survive conversion — never array position,
// which HDF reorders and deduplicates.
func TestCarriedBags_ReachTheObjectTheirAddressNames(t *testing.T) {
	log := carriedDoc(t,
		map[string]interface{}{"on": "log", "properties": map[string]interface{}{"logKey": "logValue"}},
		map[string]interface{}{"on": "run", "baseline": "run-one", "properties": map[string]interface{}{"columnKind": "utf16CodeUnits"}},
		map[string]interface{}{"on": "driver", "baseline": "run-one", "properties": map[string]interface{}{"driverKey": 1.0}},
		map[string]interface{}{"on": "conversion", "baseline": "run-one", "properties": map[string]interface{}{"convKey": true}},
		map[string]interface{}{"on": "rule", "baseline": "run-one", "ruleId": "V-1", "properties": map[string]interface{}{"ruleKey": "r"}},
		map[string]interface{}{"on": "result", "baseline": "run-one", "ruleId": "V-1", "ordinal": 1, "properties": map[string]interface{}{"rank": 3.0}},
		map[string]interface{}{"on": "location", "baseline": "run-one", "ruleId": "V-1", "properties": map[string]interface{}{"locKey": "l"}},
	)

	assert.Equal(t, "logValue", props(t, log)["logKey"])

	run := run0(t, log)
	assert.Equal(t, "utf16CodeUnits", props(t, run)["columnKind"])

	tool, _ := run["tool"].(map[string]interface{})
	driver, _ := tool["driver"].(map[string]interface{})
	assert.InDelta(t, 1.0, props(t, driver)["driverKey"], 0)

	conv, _ := run["conversion"].(map[string]interface{})
	assert.Equal(t, true, props(t, conv)["convKey"])

	assert.Equal(t, "r", props(t, rule0(t, log))["ruleKey"])

	res := results0(t, log)
	require.Len(t, res, 2)
	first, _ := res[0].(map[string]interface{})
	second, _ := res[1].(map[string]interface{})
	assert.NotContains(t, props(t, first), "rank", "the bag is addressed to ordinal 1, not 0")
	assert.InDelta(t, 3.0, props(t, second)["rank"], 0)

	locs, _ := first["locations"].([]interface{})
	require.Len(t, locs, 1)
	loc, _ := locs[0].(map[string]interface{})
	assert.Equal(t, "l", props(t, loc)["locKey"])
}

// Verbatim carriage buys bookkeeping fidelity; mapping buys semantic fidelity.
// A carried key never overwrites one this converter derived from an HDF field.
func TestCarriedBags_NeverOverwriteAMappedValue(t *testing.T) {
	log := carriedDoc(t, map[string]interface{}{
		"on": "rule", "baseline": "run-one", "ruleId": "V-1",
		"properties": map[string]interface{}{
			hdfBagKey:           "hijacked",
			"security-severity": "0.0",
			"ownKey":            "kept",
		},
	})
	p := props(t, rule0(t, log))
	block, isMap := p[hdfBagKey].(map[string]interface{})
	require.True(t, isMap, "the exporter's own HDF block wins over a carried key of the same name")
	assert.Equal(t, "V-1", block["control_id"])
	assert.Equal(t, "kept", p["ownKey"], "a key the exporter does not set is carried")
	assert.Equal(t, "0.0", p["security-severity"],
		"this requirement carries no CVSS, so the exporter sets nothing and the carried value stands")
}

// propertyBag tags carries uniqueItems, so the two sides union rather than
// append, and both languages must agree on the order.
func TestCarriedBags_TagsAreUnioned(t *testing.T) {
	log := carriedDoc(t, map[string]interface{}{
		"on": "rule", "baseline": "run-one", "ruleId": "V-1",
		"properties": map[string]interface{}{
			"tags": []interface{}{"security", "external/cwe/cwe-79", "security"},
		},
	})
	assert.Equal(t, []interface{}{"external/cwe/cwe-79", "security"}, props(t, rule0(t, log))["tags"])
}

// An entry addressing an object this exporter does not emit is not re-emitted
// anywhere, and never lands on the wrong object (ADR-0014 §3.4's rule).
func TestCarriedBags_UnmatchedAddressIsNotReEmitted(t *testing.T) {
	log := carriedDoc(t,
		map[string]interface{}{"on": "rule", "baseline": "other-baseline", "ruleId": "V-1", "properties": map[string]interface{}{"stray": 1.0}},
		map[string]interface{}{"on": "rule", "baseline": "run-one", "ruleId": "V-999", "properties": map[string]interface{}{"stray": 2.0}},
		map[string]interface{}{"on": "taxonomy", "baseline": "run-one", "properties": map[string]interface{}{"stray": 3.0}},
	)
	out, err := json.Marshal(log)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "stray")
}

// Carriage is bookkeeping: a malformed entry must not cost the document its
// findings.
func TestCarriedBags_MalformedEntriesAreSkipped(t *testing.T) {
	log := carriedDoc(t,
		map[string]interface{}{"on": "rule"},                                         // no properties
		map[string]interface{}{"on": "rule", "properties": map[string]interface{}{}}, // empty bag
		map[string]interface{}{"properties": map[string]interface{}{"x": 1.0}},       // no address
	)
	require.Len(t, results0(t, log), 2, "the findings survive")
	assert.NotContains(t, props(t, rule0(t, log)), "x")
}

func TestRemainingExtensions_CarriesOnlyWhatWasNotConsumed(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[` +
		`{"id":"V-1","impact":0.5,"tags":{},"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}],` +
		`"extensions":{"passthrough":{"baselineVendor":{"b":1}}}}],` +
		`"extensions":{"passthrough":{"sarif":{"propertyBags":[]},"docVendor":{"d":2}}}}`)
	out, err := ConvertHDFToSARIF(input, testVersion)
	require.NoError(t, err)

	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &log))

	docBlock, _ := props(t, log)[hdfBagKey].(map[string]interface{})
	ext, _ := docBlock["extensions"].(map[string]interface{})
	passthrough, _ := ext["passthrough"].(map[string]interface{})
	assert.Contains(t, passthrough, "docVendor")
	assert.NotContains(t, passthrough, "sarif", "the consumed namespace is not echoed back")

	runBlock, _ := props(t, run0(t, log))[hdfBagKey].(map[string]interface{})
	ext, _ = runBlock["extensions"].(map[string]interface{})
	passthrough, _ = ext["passthrough"].(map[string]interface{})
	assert.Contains(t, passthrough, "baselineVendor")
}
