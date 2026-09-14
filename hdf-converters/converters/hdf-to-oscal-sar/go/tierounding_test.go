package hdftooscalsar

import (
	"encoding/json"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Impact 0.25 is exactly representable and ties at one decimal, where fmt's
// %.1f rounds to even ("0.2") and JavaScript's toFixed rounds away from zero
// ("0.3"). Built with the testhdf builder rather than a committed fixture: the
// document asserts nothing about real-world data shape, only about how one
// number renders. The TypeScript peer asserts the same string on the same shape.
func TestRiskImpactTextRendersTiesLikeToFixed(t *testing.T) {
	in, err := json.Marshal(testhdf.Doc(testhdf.Baseline("tie",
		testhdf.Req("AC-1",
			testhdf.Impact(0.25),
			testhdf.Tag("nist", []interface{}{"AC-1"}),
			testhdf.Desc("impact 0.25 ties at one decimal"),
			testhdf.Status(hdf.Failed),
		))))
	require.NoError(t, err)

	out, err := ConvertHDFToOSCALSAR(in, "0.1.0")
	require.NoError(t, err)

	assert.Contains(t, string(out), "Impact: 0.3 (", "0.25 at one decimal must round away from zero, as toFixed does")
	assert.NotContains(t, string(out), "Impact: 0.2 (", "round-half-to-even leaked through")
}
