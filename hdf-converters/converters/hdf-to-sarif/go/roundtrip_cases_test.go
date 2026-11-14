package hdftosarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripCases is fixtures/roundtrip-cases.json; typescript/roundtrip-cases.test.ts
// reads the same table.
type roundTripCases struct {
	MultiLocation struct {
		Source      string                   `json:"source"`
		Run         int                      `json:"run"`
		KeepRules   int                      `json:"keepRules"`
		KeepResults []int                    `json:"keepResults"`
		ResultBags  []map[string]interface{} `json:"resultBags"`
	} `json:"multiLocation"`
	LevelAgainstSecuritySeverity struct {
		WantLevel string          `json:"wantLevel"`
		Sarif     json.RawMessage `json:"sarif"`
	} `json:"levelAgainstSecuritySeverity"`
}

func loadRoundTripCases(t *testing.T) roundTripCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "roundtrip-cases.json")) // #nosec G304 -- repo-relative test table
	require.NoError(t, err)
	var cases roundTripCases
	require.NoError(t, json.Unmarshal(raw, &cases))
	return cases
}

// multiLocationInput trims the table's source document to the kept elements and
// writes the table's bags onto the kept results.
func multiLocationInput(t *testing.T, cases roundTripCases) []byte {
	t.Helper()
	c := cases.MultiLocation
	raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(c.Source))) // #nosec G304 -- repo-relative fixture
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))
	run := doc["runs"].([]interface{})[c.Run].(map[string]interface{})
	driver := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	driver["rules"] = driver["rules"].([]interface{})[:c.KeepRules]
	all := run["results"].([]interface{})
	kept := make([]interface{}, 0, len(c.KeepResults))
	for pos, idx := range c.KeepResults {
		res := all[idx].(map[string]interface{})
		if pos < len(c.ResultBags) && c.ResultBags[pos] != nil {
			res["properties"] = c.ResultBags[pos]
		}
		kept = append(kept, res)
	}
	run["results"] = kept
	doc["runs"] = []interface{}{run}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// sarifRoundTrip also holds both ends to the vendored SARIF schema, so a case in
// the table cannot drift into a shape SARIF does not admit.
func sarifRoundTrip(t *testing.T, in []byte) map[string]interface{} {
	t.Helper()
	schema := sarifSchema(t)
	requireValidSARIF(t, schema, "input", in)
	hdfDoc, err := sarif.ConvertSarifToHDF(in, roundTripVersion, "")
	require.NoError(t, err, "import leg")
	hdfBytes, err := json.Marshal(hdfDoc)
	require.NoError(t, err)
	out, err := ConvertHDFToSARIF(hdfBytes, roundTripVersion)
	require.NoError(t, err, "export leg")
	requireValidSARIF(t, schema, "output", out)
	var after map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &after))
	return after
}

type sourceRow struct {
	location map[string]interface{}
	bag      map[string]interface{}
}

// A result at N locations becomes N results, and each must come back at the
// location it was expanded from and with the bag of the result it came from.
func TestRoundTrip_SarifToHDFToSarif_ExpandedResultsKeepTheirOwnLocationAndBag(t *testing.T) {
	cases := loadRoundTripCases(t)
	in := multiLocationInput(t, cases)

	var before map[string]interface{}
	require.NoError(t, json.Unmarshal(in, &before))
	var want []sourceRow
	for _, raw := range before["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{}) {
		res := raw.(map[string]interface{})
		bag, _ := res["properties"].(map[string]interface{})
		locs := res["locations"].([]interface{})
		for _, loc := range locs {
			want = append(want, sourceRow{location: loc.(map[string]interface{}), bag: bag})
		}
	}
	require.Greater(t, len(want), len(cases.MultiLocation.KeepResults),
		"the case must hold a result with more than one location")

	after := sarifRoundTrip(t, in)
	got := after["runs"].([]interface{})[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, got, len(want))
	for i, raw := range got {
		res := raw.(map[string]interface{})
		gotLocs, _ := res["locations"].([]interface{})
		require.Len(t, gotLocs, 1, "result %d", i)
		gotPhys := gotLocs[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})
		wantPhys := want[i].location["physicalLocation"].(map[string]interface{})
		assert.Equal(t, wantPhys["region"], gotPhys["region"], "result %d: region", i)
		assert.Equal(t, wantPhys["artifactLocation"].(map[string]interface{})["uri"],
			gotPhys["artifactLocation"].(map[string]interface{})["uri"], "result %d: uri", i)

		gotBag, _ := res["properties"].(map[string]interface{})
		for k, v := range want[i].bag {
			assert.Equal(t, v, gotBag[k], "result %d: bag key %q", i, k)
		}
		for _, other := range cases.MultiLocation.ResultBags {
			for k := range other {
				if _, mine := want[i].bag[k]; !mine {
					assert.NotContains(t, gotBag, k, "result %d carries another result's bag", i)
				}
			}
		}
	}
}

// Impact derives from security-severity on import, so re-deriving the level from
// impact on export rewrites a rule level the tool stated.
func TestRoundTrip_SarifToHDFToSarif_RuleLevelSurvivesADisagreeingSecuritySeverity(t *testing.T) {
	c := loadRoundTripCases(t).LevelAgainstSecuritySeverity
	after := sarifRoundTrip(t, c.Sarif)
	run := after["runs"].([]interface{})[0].(map[string]interface{})
	rule := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})[0].(map[string]interface{})
	config, _ := rule["defaultConfiguration"].(map[string]interface{})
	assert.Equal(t, c.WantLevel, config["level"], "rule defaultConfiguration.level")
	res := run["results"].([]interface{})[0].(map[string]interface{})
	gotDefault, _ := config["level"].(string)
	assert.Equal(t, c.WantLevel, resolvedLevel(res, gotDefault), "resolved result level")
}
