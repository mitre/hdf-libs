package asff

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fmt's %.Nf rounds halves to EVEN and JavaScript's toFixed rounds them AWAY
// FROM ZERO, so any value whose exact binary expansion ends in a 5 at the cut
// point rendered differently in the two languages. 7.25 and 0.03125 are exactly
// representable and tie at 1 and 4 decimals, the precisions this converter uses.
// The TypeScript peer asserts the same two strings on the same fixture.
func TestVulnerabilitySummaryRendersTiesLikeToFixed(t *testing.T) {
	results, err := ConvertAsffToHDF(loadFixture(t, "tie-rounding.json"), converterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)
	require.NotEmpty(t, results.Baselines[0].Requirements)

	// The summary is folded into the result message, not the descriptions.
	var text strings.Builder
	for _, r := range results.Baselines[0].Requirements[0].Results {
		if r.Message != nil {
			text.WriteString(*r.Message)
			text.WriteString("\n")
		}
	}
	out := text.String()
	require.NotEmpty(t, out, "no result message carried the vulnerability summary")

	assert.Contains(t, out, "CVSS 3.1 7.3", "7.25 at one decimal must round away from zero, as toFixed does")
	assert.Contains(t, out, "EPSS 0.0313", "0.03125 at four decimals must round away from zero, as toFixed does")
	assert.NotContains(t, out, "CVSS 3.1 7.2", "round-half-to-even leaked through")
	assert.NotContains(t, out, "EPSS 0.0312", "round-half-to-even leaked through")
}
