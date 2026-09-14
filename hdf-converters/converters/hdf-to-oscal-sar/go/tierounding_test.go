package hdftooscalsar

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Impact 0.25 is exactly representable and ties at one decimal, where fmt's
// %.1f rounds to even ("0.2") and JavaScript's toFixed rounds away from zero
// ("0.3"). The TypeScript peer asserts the same string on the same fixture.
func TestRiskImpactTextRendersTiesLikeToFixed(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "tie-rounding.json"))
	require.NoError(t, err)
	out, err := ConvertHDFToOSCALSAR(in, "0.1.0")
	require.NoError(t, err)

	assert.Contains(t, string(out), "Impact: 0.3 (", "0.25 at one decimal must round away from zero, as toFixed does")
	assert.NotContains(t, string(out), "Impact: 0.2 (", "round-half-to-even leaked through")
}
