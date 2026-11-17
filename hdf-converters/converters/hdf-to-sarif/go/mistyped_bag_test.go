package hdftosarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mistypedBagCase struct {
	On    string      `json:"on"`
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
	Why   string      `json:"why"`
}

// Every value in the shared table must be dropped: the document converts exactly as if
// the key were absent, and it validates. typescript/mistyped-bag.test.ts reads the same
// table, so the two languages are held to one list rather than two that drift.
func TestRoundTrip_HDFToSarifToHDF_DropsEveryMistypedBagValue(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "mistyped-bag-cases.json")) // #nosec G304 -- repo-relative test table
	require.NoError(t, err)
	var table struct {
		Cases []mistypedBagCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)

	sarifBytes, err := ConvertHDFToSARIF(seededOverrideHDF(t), roundTripVersion)
	require.NoError(t, err)

	for _, c := range table.Cases {
		encodedValue, err := json.Marshal(c.Value)
		require.NoError(t, err)
		t.Run(c.On+"/"+c.Key+"="+string(encodedValue), func(t *testing.T) {
			start := time.Now().Add(-time.Second)
			mangled := mistypedBagDoc(t, sarifBytes, c, true)
			absent := mistypedBagDoc(t, sarifBytes, c, false)

			got, err := sarif.ConvertSarifToHDF(mangled, roundTripVersion, "")
			require.NoError(t, err, "a mistyped bag value must never fail the conversion")
			want, err := sarif.ConvertSarifToHDF(absent, roundTripVersion, "")
			require.NoError(t, err)
			end := time.Now().Add(time.Second)

			gotBytes, err := json.Marshal(got)
			require.NoError(t, err)
			validation := validators.ValidateResults(gotBytes)
			require.True(t, validation.Valid, "%s: %v", c.Why, validation.Errors)

			wantBytes, err := json.Marshal(want)
			require.NoError(t, err)
			assert.Empty(t, diffPaths("", comparableBaseline(t, wantBytes, start, end),
				comparableBaseline(t, gotBytes, start, end)), c.Why)
		})
	}
}

// seededOverrideHDF is the grype exporter fixture with a waiver on its first requirement,
// so the exported SARIF carries a suppression and status_overrides in that rule's bag.
func seededOverrideHDF(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "grype-cve.hdf.json")) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))
	b := doc["baselines"].([]interface{})[0].(map[string]interface{})
	req := b["requirements"].([]interface{})[0].(map[string]interface{})
	req["statusOverrides"] = []interface{}{map[string]interface{}{
		"type": "waiver", "status": "passed", "reason": "ISSM accepted",
		"appliedBy": map[string]interface{}{"type": "username", "identifier": "jane.doe"},
		"appliedAt": "2026-01-15T00:00:00Z",
		"expiresAt": "2099-12-31T00:00:00Z",
	}}
	seeded, err := json.Marshal(doc)
	require.NoError(t, err)
	return seeded
}

// mistypedBagDoc returns the exported SARIF with the case's key set to its value, or
// removed when set is false. The rule and result addressed are the first rule's.
func mistypedBagDoc(t *testing.T, sarifBytes []byte, c mistypedBagCase, set bool) []byte {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(sarifBytes, &doc))
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	var bag map[string]interface{}
	switch c.On {
	case "run":
		bag = run["properties"].(map[string]interface{})[hdfBagKey].(map[string]interface{})
	case "rule", "result":
		rule := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})[0].(map[string]interface{})
		if c.On == "rule" {
			bag = rule["properties"].(map[string]interface{})[hdfBagKey].(map[string]interface{})
			break
		}
		for _, r := range run["results"].([]interface{}) {
			res := r.(map[string]interface{})
			if res["ruleId"] == rule["id"] {
				bag = res["properties"].(map[string]interface{})[hdfBagKey].(map[string]interface{})["result"].(map[string]interface{})
				break
			}
		}
	}
	require.NotNil(t, bag, "no %s bag to mangle", c.On)
	if set {
		bag[c.Key] = c.Value
	} else {
		delete(bag, c.Key)
	}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// comparableBaseline is the converted baseline with what legitimately differs between
// two conversions taken out: resultsChecksum and each rawSourceRecord cover the differing
// input bytes, and any time the converter stamps from its own clock (a fallback
// startTime, an invented appliedAt, the default expiry a year on) becomes a marker.
func comparableBaseline(t *testing.T, hdfBytes []byte, start, end time.Time) interface{} {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(hdfBytes, &doc))
	b := doc["baselines"].([]interface{})[0].(map[string]interface{})
	delete(b, "resultsChecksum")
	return maskConversionTimes(b, start, end)
}

func maskConversionTimes(v interface{}, start, end time.Time) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		delete(x, "rawSourceRecord")
		for k, e := range x {
			x[k] = maskConversionTimes(e, start, end)
		}
	case []interface{}:
		for i, e := range x {
			x[i] = maskConversionTimes(e, start, end)
		}
	case string:
		ts := hdfutil.ParseTimestamp(x)
		if ts.IsZero() {
			return x
		}
		for _, offset := range []int{0, 1} {
			if !ts.Before(start.AddDate(offset, 0, 0)) && !ts.After(end.AddDate(offset, 0, 0)) {
				return "<conversion time>"
			}
		}
	}
	return v
}

// diffPaths lists the paths at which two decoded JSON values differ, so a failure names
// the field rather than printing two whole baselines.
func diffPaths(at string, want, got interface{}) []string {
	wm, wok := want.(map[string]interface{})
	gm, gok := got.(map[string]interface{})
	if wok && gok {
		var out []string
		for k := range wm {
			out = append(out, diffPaths(at+"/"+k, wm[k], gm[k])...)
		}
		for k := range gm {
			if _, seen := wm[k]; !seen {
				out = append(out, at+"/"+k)
			}
		}
		return out
	}
	wa, wok := want.([]interface{})
	ga, gok := got.([]interface{})
	if wok && gok && len(wa) == len(ga) {
		var out []string
		for i := range wa {
			out = append(out, diffPaths(at+"/"+itoa(i), wa[i], ga[i])...)
		}
		return out
	}
	if reflect.DeepEqual(want, got) {
		return nil
	}
	return []string{at}
}
