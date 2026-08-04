package hdfengine

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resultsWith(statuses ...hdf.ResultStatus) []hdf.RequirementResult {
	rs := make([]hdf.RequirementResult, len(statuses))
	for i, s := range statuses {
		rs[i] = hdf.RequirementResult{Status: s}
	}
	return rs
}

// TestOverallStatus_DelegatesToWorstStatus pins the roll-up to hdfutil.WorstStatus
// (no local rank switch) across all five statuses + the empty case. Any divergent
// local switch would fail the WorstStatus-equivalence assertion.
func TestOverallStatus_DelegatesToWorstStatus(t *testing.T) {
	cases := []struct {
		name string
		in   []hdf.RequirementResult
		want hdf.ResultStatus
	}{
		{"empty", nil, hdf.NotReviewed},
		{"passed", resultsWith(hdf.Passed), hdf.Passed},
		{"failed", resultsWith(hdf.Failed), hdf.Failed},
		{"error", resultsWith(hdf.Error), hdf.Error},
		{"notApplicable", resultsWith(hdf.NotApplicable), hdf.NotApplicable},
		{"notReviewed", resultsWith(hdf.NotReviewed), hdf.NotReviewed},
		{"error beats failed", resultsWith(hdf.Failed, hdf.Error), hdf.Error},
		{"failed beats passed", resultsWith(hdf.Passed, hdf.Failed), hdf.Failed},
		{"passed beats notApplicable", resultsWith(hdf.NotApplicable, hdf.Passed), hdf.Passed},
		{"na beats notReviewed", resultsWith(hdf.NotReviewed, hdf.NotApplicable), hdf.NotApplicable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := overallStatus(tc.in)
			assert.Equal(t, tc.want, got, "expected value")
			// Equivalence to the shared roll-up (proves delegation, no local switch).
			statuses := make([]string, len(tc.in))
			for i, r := range tc.in {
				statuses[i] = string(r.Status)
			}
			assert.Equal(t, hdf.ResultStatus(hdfutil.WorstStatus(statuses)), got, "must equal hdfutil.WorstStatus")
		})
	}
}

// TestCompliance_CountsAndPercentage is the Go side of the cross-language parity
// contract; src/compliance.test.ts mirrors it over the same fixture.
func TestCompliance_CountsAndPercentage(t *testing.T) {
	counts := CountControlsByStatusSeverity(loadQueryFixture(t))

	assert.Equal(t, 1, counts.Passed.Total)
	assert.Equal(t, 1, counts.Passed.High)
	assert.Equal(t, 1, counts.Failed.Total)
	assert.Equal(t, 1, counts.Failed.Critical)
	assert.Equal(t, 1, counts.Skipped.Total)
	assert.Equal(t, 1, counts.Skipped.Low)
	assert.Equal(t, 1, counts.Error.Total)
	assert.Equal(t, 1, counts.Error.None)
	assert.Equal(t, 1, counts.NoImpact.Total)
	assert.Equal(t, 1, counts.NoImpact.Medium)

	// passed / (passed+failed+skipped+error) = 1/4 = 25.0; notApplicable excluded.
	assert.Equal(t, 25.0, CalculateCompliance(counts))
}

func TestCalculateCompliance_EmptyIsZero(t *testing.T) {
	assert.Equal(t, 0.0, CalculateCompliance(&StatusCounts{}))
}

func ptrInt(i int) *int           { return &i }
func ptrFloat(f float64) *float64 { return &f }

func TestValidateThresholds(t *testing.T) {
	results := loadQueryFixture(t)
	counts := CountControlsByStatusSeverity(results)
	compliance := CalculateCompliance(counts) // 25.0
	controlMap := MapControlIDs(results)

	t.Run("compliance below min → violation", func(t *testing.T) {
		v := ValidateThresholds(&ThresholdConfig{Compliance: &ComplianceBound{Min: ptrFloat(90)}}, counts, compliance, controlMap)
		require.Len(t, v, 1)
		assert.Contains(t, v[0], "compliance 25.00% is below minimum 90.00%")
	})
	t.Run("compliance meets min → no violation", func(t *testing.T) {
		v := ValidateThresholds(&ThresholdConfig{Compliance: &ComplianceBound{Min: ptrFloat(20)}}, counts, compliance, controlMap)
		assert.Empty(t, v)
	})
	t.Run("failed.critical.max exceeded → violation", func(t *testing.T) {
		cfg := &ThresholdConfig{Failed: &ThresholdSeverity{Critical: &ThresholdBound{Max: ptrInt(0)}}}
		v := ValidateThresholds(cfg, counts, compliance, controlMap)
		require.Len(t, v, 1)
		assert.Contains(t, v[0], "failed.critical: 1 exceeds maximum 0")
	})
	t.Run("passed.total.min met → no violation", func(t *testing.T) {
		cfg := &ThresholdConfig{Passed: &ThresholdSeverity{Total: &ThresholdBound{Min: ptrInt(1)}}}
		assert.Empty(t, ValidateThresholds(cfg, counts, compliance, controlMap))
	})
	t.Run("expected control present with right status/severity → no violation", func(t *testing.T) {
		cfg := &ThresholdConfig{Failed: &ThresholdSeverity{Critical: &ThresholdBound{Controls: []string{"SV-230221"}}}}
		assert.Empty(t, ValidateThresholds(cfg, counts, compliance, controlMap))
	})
	t.Run("expected control missing → violation", func(t *testing.T) {
		cfg := &ThresholdConfig{Failed: &ThresholdSeverity{Critical: &ThresholdBound{Controls: []string{"SV-999999"}}}}
		v := ValidateThresholds(cfg, counts, compliance, controlMap)
		require.Len(t, v, 1)
		assert.Contains(t, v[0], "expected control SV-999999 not found")
	})
}
