package hdfengine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
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
	// Was counts.Error.None before the two spellings were unified.
	assert.Equal(t, 1, counts.Error.Informational)
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

// TestMapControlIDsByStatus_ImpactZeroErrorIsError pins the impact-0 error escape: a crashed
// check at impact 0 must surface as error so hdf threshold's error.total gate
// sees it — never no_impact. src/compliance.test.ts mirrors this.
func TestMapControlIDsByStatus_ImpactZeroErrorIsError(t *testing.T) {
	errored := hdf.EvaluatedRequirement{ID: "SV-ERR", Impact: 0.0, Results: resultsWith(hdf.Error)}
	results := hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{{Requirements: []hdf.EvaluatedRequirement{errored}}}}

	resolver := func(req hdf.EvaluatedRequirement) string {
		return hdfutil.ComputeEffectiveStatus(statusInput(req), time.Time{})
	}

	eff := MapControlIDsByStatus(results, resolver)
	require.Len(t, eff, 1)
	assert.Equal(t, "SV-ERR", eff[0].ID)
	assert.Equal(t, ThresholdError, eff[0].Status, "impact-0 errored control resolves to error, not no_impact")

	counts := CountControlsByStatus(results, resolver)
	assert.Equal(t, 1, counts.Error.Total)
	assert.Equal(t, 0, counts.NoImpact.Total)
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

// DeriveSeverity must not route an explicit informational and an impact-derived
// one to different buckets — that split is what let a generated template fail
// against the document it came from.
func TestDeriveSeverity_ExplicitAndDerivedInformationalAgree(t *testing.T) {
	explicit := hdf.Severity("informational")
	assert.Equal(t, "informational", DeriveSeverity(0.0, &explicit))
	assert.Equal(t, "informational", DeriveSeverity(0.0, nil), "impact 0 derives informational")
}

// The catch-all is unreachable through the CLI, which schema-validates first, so
// it is pinned here: a library caller constructing a requirement by hand still
// gets the severity counted rather than dropped.
func TestAddCount_SeverityOutsideTheEnumCountsAsInformational(t *testing.T) {
	var counts StatusCounts
	addCount(&counts, hdf.Failed, "sev-9")
	assert.Equal(t, 1, counts.Failed.Informational, "an unrecognized severity is counted, not dropped")
	assert.Equal(t, 1, counts.Failed.Total)
}

// A spec naming both spellings of one bucket is refused rather than silently
// resolved, so a bound the author wrote is never dropped.
func TestValidateThresholds_BothNoneAndInformationalIsRefused(t *testing.T) {
	two := 2
	config := &ThresholdConfig{NoImpact: &ThresholdSeverity{
		Informational: &ThresholdBound{Max: &two},
		None:          &ThresholdBound{Max: &two},
	}}
	violations := ValidateThresholds(config, &StatusCounts{}, 100, nil)
	require.NotEmpty(t, violations)
	assert.Contains(t, violations[0], "pre-3.7 spelling")
}

// The legacy spelling resolves to the same bucket it always meant.
func TestValidateThresholds_LegacyNoneNormalizesToInformational(t *testing.T) {
	zero := 0
	config := &ThresholdConfig{NoImpact: &ThresholdSeverity{None: &ThresholdBound{Max: &zero}}}
	counts := StatusCounts{}
	counts.NoImpact.Informational = 3
	counts.NoImpact.Total = 3

	violations := ValidateThresholds(config, &counts, 100, nil)
	require.Len(t, violations, 1, "the legacy bound must still be applied")
	assert.Contains(t, violations[0], "no_impact.informational")
}

// loadMultilayeredFixture reads the shared real InSpec multi-overlay run from
// @mitre/hdf-fixtures (test/compliance.test.ts reads the same document). A
// requirement id names the requirement, not one finding, so an overlay chain
// re-reports the same id in every layer it touches — 534 of this run's ids
// appear more than once, 406 of them with differing statuses.
func loadMultilayeredFixture(t *testing.T) hdf.HDFResults {
	t.Helper()
	res, err := Load(fixtures.Results.InspecMultilayered, 0)
	require.NoError(t, err)
	require.True(t, res.Valid, "fixture must be schema-valid: %s", res.ParseError)
	return *res.Results
}

// Duplicate ids are counted per entry, as they always were: the numeric bounds
// count requirements, and this pins that the named-control fix did not move them.
func TestCountControls_DuplicateIDsCountPerEntry(t *testing.T) {
	counts := CountControlsByStatusSeverity(loadMultilayeredFixture(t))

	// 1603 requirement entries over 534 distinct ids: every entry is counted.
	assert.Equal(t, 1196, counts.Skipped.Total)
	assert.Equal(t, 885, counts.Skipped.Medium)
	assert.Equal(t, 273, counts.Failed.Total)
	assert.Equal(t, 246, counts.Failed.Medium)
	assert.Equal(t, 134, counts.Passed.Total)
	assert.Equal(t, 1603, counts.Passed.Total+counts.Failed.Total+counts.Skipped.Total+counts.Error.Total+counts.NoImpact.Total)
}

// A threshold naming a control id must hold for EVERY entry carrying that id.
// Resolving the id to one arbitrary entry let a gate pass because the last
// duplicate happened to satisfy it while an earlier one did not.
// Parity: test/compliance.test.ts 'named-control assertions over duplicate ids'.
func TestValidateThresholds_NamedControlMustHoldForEveryEntry(t *testing.T) {
	results := loadMultilayeredFixture(t)
	counts := CountControlsByStatusSeverity(results)
	compliance := CalculateCompliance(counts)
	controlMap := MapControlIDs(results)

	validate := func(cfg *ThresholdConfig) []string {
		return ValidateThresholds(cfg, counts, compliance, controlMap)
	}
	// namedControl builds a spec asserting one control id under one
	// status/severity bucket — test code, not fixture data.
	namedControl := func(status, severity, id string) *ThresholdConfig {
		b := &ThresholdBound{Controls: []string{id}}
		ts := &ThresholdSeverity{}
		switch severity {
		case "critical":
			ts.Critical = b
		case "high":
			ts.High = b
		case "medium":
			ts.Medium = b
		case "informational":
			ts.Informational = b
		}
		cfg := &ThresholdConfig{}
		switch status {
		case ThresholdPassed:
			cfg.Passed = ts
		case ThresholdFailed:
			cfg.Failed = ts
		case ThresholdSkipped:
			cfg.Skipped = ts
		}
		return cfg
	}

	// V-242399 is notReviewed in the two wrapper layers and passed in the
	// k8s-node layer, so the last entry alone satisfies passed/medium.
	t.Run("a passing last entry no longer greens a gate its earlier entries fail", func(t *testing.T) {
		v := validate(namedControl(ThresholdPassed, "medium", "V-242399"))
		require.Len(t, v, 2)
		assert.Equal(t, "passed.medium: control V-242399 expected passed/medium but found skipped/medium (entry 1 of 3)", v[0])
		assert.Equal(t, "passed.medium: control V-242399 expected passed/medium but found skipped/medium (entry 2 of 3)", v[1])
	})

	// The mirror: the FIRST entries satisfy skipped/medium and the last does
	// not. A first-wins resolution would pass this; fail-closed must not.
	t.Run("a satisfying first entry does not rescue an unsatisfying last", func(t *testing.T) {
		v := validate(namedControl(ThresholdSkipped, "medium", "V-242399"))
		require.Len(t, v, 1)
		assert.Equal(t, "skipped.medium: control V-242399 expected skipped/medium but found passed/medium (entry 3 of 3)", v[0])
	})

	// V-242387: notReviewed, notReviewed, failed across three baselines.
	t.Run("a failing last entry no longer greens a failed-control gate", func(t *testing.T) {
		v := validate(namedControl(ThresholdFailed, "high", "V-242387"))
		require.Len(t, v, 2)
		assert.Equal(t, "failed.high: control V-242387 expected failed/high but found skipped/high (entry 1 of 3)", v[0])
		assert.Equal(t, "failed.high: control V-242387 expected failed/high but found skipped/high (entry 2 of 3)", v[1])
	})

	// The id's three entries live in three different baselines, so resolution
	// spans the whole document rather than any one baseline.
	t.Run("every baseline carrying the id contributes an entry", func(t *testing.T) {
		n := 0
		for _, m := range controlMap {
			if m.ID == "V-242387" {
				n++
			}
		}
		assert.Equal(t, 3, n)
		perBaseline := 0
		for _, b := range results.Baselines {
			for _, req := range b.Requirements {
				if req.ID == "V-242387" {
					perBaseline++
					break
				}
			}
		}
		assert.Equal(t, 3, perBaseline, "one entry in each of three baselines")
	})

	// SV-257777 is reported twice within ONE baseline (and again in two
	// others): duplication inside a single baseline resolves the same way.
	t.Run("duplicate entries within one baseline are resolved too", func(t *testing.T) {
		v := validate(namedControl(ThresholdSkipped, "informational", "SV-257777"))
		require.Len(t, v, 2)
		assert.Equal(t, "skipped.informational: control SV-257777 expected skipped/informational but found failed/informational (entry 3 of 5)", v[0])
		assert.Equal(t, "skipped.informational: control SV-257777 expected skipped/informational but found failed/informational (entry 4 of 5)", v[1])
	})

	// Severity is checked per entry alongside status: V-242387 is impact 0.7
	// (high) in every layer, so a critical assertion mismatches all three.
	t.Run("severity is checked on every entry", func(t *testing.T) {
		v := validate(namedControl(ThresholdFailed, "critical", "V-242387"))
		require.Len(t, v, 3)
		assert.Equal(t, "failed.critical: control V-242387 expected failed/critical but found skipped/high (entry 1 of 3)", v[0])
		assert.Equal(t, "failed.critical: control V-242387 expected failed/critical but found failed/high (entry 3 of 3)", v[2])
	})

	// V-242376 is notReviewed at impact 0 in all three layers.
	t.Run("duplicate entries that all satisfy the assertion pass", func(t *testing.T) {
		assert.Empty(t, validate(namedControl(ThresholdSkipped, "informational", "V-242376")))
	})

	t.Run("an id in no entry is still reported missing", func(t *testing.T) {
		v := validate(namedControl(ThresholdFailed, "high", "V-999999"))
		require.Len(t, v, 1)
		assert.Equal(t, "failed.high: expected control V-999999 not found in results", v[0])
	})

	// The single-entry contract — identical verdict AND identical message text,
	// with no entry-index suffix — is pinned by TestValidateThresholds above,
	// whose fixture carries each id exactly once. Every id in this document is
	// duplicated, so it cannot be asserted here.
}
