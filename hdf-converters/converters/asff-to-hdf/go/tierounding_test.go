package asff

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fmt's %.Nf rounds halves to EVEN and JavaScript's toFixed rounds them AWAY
// FROM ZERO, so any value whose exact binary expansion ends in a 5 at the cut
// point rendered differently in the two languages. 7.25 and 0.03125 are exactly
// representable and tie at 1 and 4 decimals, the precisions this converter uses.
//
// Derived from the committed unknown-producer fixture with only those two
// numbers overridden, so the document keeps its real shape and no new fixture
// claims to be sample data it is not. The TypeScript peer does the same.
func tieRoundingInput(t *testing.T) []byte {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(loadFixture(t, "unknown-producer.json"), &doc))

	findings, ok := doc["Findings"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		vulns, ok := f.(map[string]interface{})["Vulnerabilities"].([]interface{})
		if !ok || len(vulns) == 0 {
			continue
		}
		v := vulns[0].(map[string]interface{})
		v["EpssScore"] = 0.03125
		if cvss, ok := v["Cvss"].([]interface{}); ok && len(cvss) > 0 {
			cvss[0].(map[string]interface{})["BaseScore"] = 7.25
		}
		out, err := json.Marshal(doc)
		require.NoError(t, err)
		return out
	}
	t.Fatal("no finding with Vulnerabilities[] to override")
	return nil
}

func TestVulnerabilitySummaryRendersTiesLikeToFixed(t *testing.T) {
	results, err := ConvertAsffToHDF(tieRoundingInput(t), converterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)

	var text strings.Builder
	for _, req := range results.Baselines[0].Requirements {
		for _, r := range req.Results {
			if r.Message != nil {
				text.WriteString(*r.Message)
				text.WriteString("\n")
			}
		}
	}
	out := text.String()
	require.NotEmpty(t, out, "no result message carried the vulnerability summary")

	assert.Contains(t, out, "CVSS 3.1 7.3", "7.25 at one decimal must round away from zero, as toFixed does")
	assert.Contains(t, out, "EPSS 0.0313", "0.03125 at four decimals must round away from zero, as toFixed does")
	assert.NotContains(t, out, "CVSS 3.1 7.2", "round-half-to-even leaked through")
	assert.NotContains(t, out, "EPSS 0.0312", "round-half-to-even leaked through")
}
