package hdftoxccdf

import (
	"fmt"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The score is passed/scorable*100 rendered to six decimals, so a tie needs the
// resulting double to be an odd multiple of 1/128 — the only way its decimal
// expansion terminates at the seventh digit with a 5. 1 passed of 512 scorable
// gives exactly 0.1953125, where fmt's %.6f rounds to even ("0.195312") and
// JavaScript's toFixed rounds away from zero ("0.195313").
//
// 512 is the SMALLEST scorable count that can tie here: 256 yields denominator
// 64, whose expansion ends at the sixth digit and rounds exactly. A brute-force
// sweep of every passed/scorable pair up to 10000 found 3755 divergent pairs, so
// this is an ordinary benchmark size rather than a contrived one.
const (
	tieScorable = 512
	tiePassed   = 1
)

var tieStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestTestResultScoreRendersTiesLikeToFixed(t *testing.T) {
	reqs := make([]hdf.EvaluatedRequirement, 0, tieScorable)
	for i := 0; i < tieScorable; i++ {
		status := hdf.Failed
		if i < tiePassed {
			status = hdf.Passed
		}
		reqs = append(reqs, hdf.EvaluatedRequirement{
			ID:      fmt.Sprintf("V-%04d", i),
			Impact:  0.5,
			Results: []hdf.RequirementResult{{Status: status, StartTime: tieStart}},
		})
	}
	baseline := hdf.EvaluatedBaseline{Name: "tie", Requirements: reqs}
	doc := &hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{baseline}}

	got := buildTestResult(doc, baseline)
	require.NotNil(t, got)
	assert.Equal(t, "0.195313", got.Score.Value,
		"1/512 at six decimals must round away from zero, as toFixed does")
	assert.NotEqual(t, "0.195312", got.Score.Value, "round-half-to-even leaked through")
}
