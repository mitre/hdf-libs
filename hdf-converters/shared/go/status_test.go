package shared

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func statusPtr(s hdf.ResultStatus) *hdf.ResultStatus { return &s }

func mustTime(t *testing.T, v string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, v)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// The Go twin of requirementEffectiveStatus (status.ts) walks the same ladder
// as computeEffectiveStatus with no reference time: override, error roll-up,
// impact-0, worst-wins.
func TestRequirementEffectiveStatus_Ladder(t *testing.T) {
	failed := []hdf.RequirementResult{{Status: hdf.Failed}}
	cases := []struct {
		name string
		req  hdf.EvaluatedRequirement
		want string
	}{
		{"worst-wins roll-up", hdf.EvaluatedRequirement{Impact: 0.5, Results: []hdf.RequirementResult{{Status: hdf.Passed}, {Status: hdf.Failed}}}, "failed"},
		{"empty results roll up to notReviewed", hdf.EvaluatedRequirement{Impact: 0.5}, "notReviewed"},
		{"impact 0 is notApplicable", hdf.EvaluatedRequirement{Impact: 0, Results: failed}, "notApplicable"},
		{"error beats impact 0", hdf.EvaluatedRequirement{Impact: 0, Results: []hdf.RequirementResult{{Status: hdf.Error}}}, "error"},
		{"governing override wins", hdf.EvaluatedRequirement{Impact: 0.5, Results: failed, StatusOverrides: []hdf.StatusOverride{
			{Status: statusPtr(hdf.Passed), AppliedAt: mustTime(t, "2025-01-01T00:00:00Z")},
		}}, "passed"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, RequirementEffectiveStatus(c.req), c.name)
	}
}

// With no reference time the override window is judged against the clock: a
// far-future expiry still governs, a past expiry no longer does.
func TestRequirementEffectiveStatus_OverrideExpiryAgainstNow(t *testing.T) {
	base := hdf.EvaluatedRequirement{Impact: 0.5, Results: []hdf.RequirementResult{{Status: hdf.Failed}}}

	live := base
	live.StatusOverrides = []hdf.StatusOverride{{
		Status: statusPtr(hdf.Passed), AppliedAt: mustTime(t, "2025-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2099-12-31T00:00:00Z"),
	}}
	assert.Equal(t, "passed", RequirementEffectiveStatus(live))

	expired := base
	expired.StatusOverrides = []hdf.StatusOverride{{
		Status: statusPtr(hdf.Passed), AppliedAt: mustTime(t, "2019-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2020-01-01T00:00:00Z"),
	}}
	assert.Equal(t, "failed", RequirementEffectiveStatus(expired))
}
