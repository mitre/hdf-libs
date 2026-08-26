package hdfengine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// loadAgentOverrideFixture reads the shared agent-override fixture (also read by
// src/compliance.test.ts) so the detective-surface primitives are parity-tested.
func loadAgentOverrideFixture(t *testing.T) hdf.HDFResults {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "agent-overrides-fixture.json"))
	require.NoError(t, err)
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &results))
	return results
}

// effectiveStatusOf resolves a requirement's effective status through the shared
// computation. excludeAgent drops appliedBy.type=="agent" overrides first — the
// basis for the agent-override compliance delta. The same resolver logic runs in
// src/compliance.test.ts so CountControlsByStatus is parity-tested.
func effectiveStatusOf(excludeAgent bool) func(hdf.EvaluatedRequirement) string {
	return func(req hdf.EvaluatedRequirement) string {
		if excludeAgent {
			kept := make([]hdf.StatusOverride, 0, len(req.StatusOverrides))
			for _, o := range req.StatusOverrides {
				if o.AppliedBy.Type != hdf.Agent {
					kept = append(kept, o)
				}
			}
			req.StatusOverrides = kept
		}
		return hdfutil.ComputeEffectiveStatus(statusInput(req), time.Time{})
	}
}

// statusInput builds the effective-status input from a requirement — the test's
// injected mapping, mirroring shared.RequirementStatusInput that the production
// MCP tool injects into CountControlsByStatus.
func statusInput(req hdf.EvaluatedRequirement) hdfutil.EffectiveStatusInput {
	in := hdfutil.EffectiveStatusInput{Impact: req.Impact}
	if req.EffectiveStatus != nil {
		in.EffectiveStatus = string(*req.EffectiveStatus)
	}
	for _, o := range req.StatusOverrides {
		soi := hdfutil.StatusOverrideInput{AppliedAt: o.AppliedAt, ExpiresAt: o.ExpiresAt}
		if o.Status != nil {
			soi.Status = string(*o.Status)
		}
		in.Overrides = append(in.Overrides, soi)
	}
	for _, r := range req.Results {
		in.ResultStatuses = append(in.ResultStatuses, string(r.Status))
	}
	return in
}

// TestAgentOverrideCount_CountsAgentAttributedOnly is the Go side of the parity
// contract for the §3 detective count; src/compliance.test.ts mirrors it.
func TestAgentOverrideCount_CountsAgentAttributedOnly(t *testing.T) {
	results := loadAgentOverrideFixture(t)
	// One agent override (V-AGENT-A); the system/from_vex override (V-SYSTEM-B) is excluded.
	assert.Equal(t, 1, AgentOverrideCount(results))
}

// TestCountControlsByStatus_EffectiveWithAndWithoutAgent proves the injected-
// resolver counting yields the effective-compliance delta agent overrides cause.
func TestCountControlsByStatus_EffectiveWithAndWithoutAgent(t *testing.T) {
	results := loadAgentOverrideFixture(t)

	withAgent := CalculateCompliance(CountControlsByStatus(results, effectiveStatusOf(false)))
	withoutAgent := CalculateCompliance(CountControlsByStatus(results, effectiveStatusOf(true)))

	// With all overrides: A,B,C passed, D failed → 3/4 = 75%.
	assert.Equal(t, 75.0, withAgent)
	// Stripping the agent override: A reverts to failed, B stays passed (system) → 2/4 = 50%.
	assert.Equal(t, 50.0, withoutAgent)
	// The agent-attributed overrides account for +25 points.
	assert.Equal(t, 25.0, withAgent-withoutAgent)

	// A nil resolver counts everything as skipped → 0% compliance.
	assert.Equal(t, 0.0, CalculateCompliance(CountControlsByStatus(results, nil)))
}

// TestMapControlIDsByStatus_UsesInjectedResolver proves the injected-resolver
// twin maps a control's ID to its resolved status, diverging from the raw
// MapControlIDs where they disagree. An impact-0 notReviewed control is skipped
// under raw counting but no_impact under the effective-status resolver.
// src/compliance.test.ts mirrors this.
func TestMapControlIDsByStatus_UsesInjectedResolver(t *testing.T) {
	na := hdf.EvaluatedRequirement{ID: "SV-NA", Impact: 0.0, Results: resultsWith(hdf.NotReviewed)}
	results := hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{{Requirements: []hdf.EvaluatedRequirement{na}}}}

	raw := MapControlIDs(results)
	require.Len(t, raw, 1)
	assert.Equal(t, ThresholdSkipped, raw[0].Status, "raw mapping counts impact-0 notReviewed as skipped")

	eff := MapControlIDsByStatus(results, func(req hdf.EvaluatedRequirement) string {
		return hdfutil.ComputeEffectiveStatus(statusInput(req), time.Time{})
	})
	require.Len(t, eff, 1)
	assert.Equal(t, "SV-NA", eff[0].ID)
	assert.Equal(t, ThresholdNoImpact, eff[0].Status, "effective resolver maps impact-0 to no_impact")

	// A nil resolver maps everything to skipped.
	nilMapped := MapControlIDsByStatus(results, nil)
	require.Len(t, nilMapped, 1)
	assert.Equal(t, ThresholdSkipped, nilMapped[0].Status)
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
