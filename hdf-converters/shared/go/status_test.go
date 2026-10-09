package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// The impact twin of the ladder test above. It is the schema-typed wrapper an
// external consumer reaches for, so it is tested directly rather than only
// through the engine's own copy of the mapping — and it must never read the
// stored effectiveImpact field, which every case here leaves absent or wrong on
// purpose. Parity: requirementEffectiveImpact in shared/typescript/status.ts.
func TestRequirementEffectiveImpact_Ladder(t *testing.T) {
	adjust := func(v float64) *hdf.ImpactOverride { return &hdf.ImpactOverride{Value: v} }
	stale := 0.99
	cases := []struct {
		name string
		req  hdf.EvaluatedRequirement
		want float64
	}{
		{"no overrides falls back to the requirement's own impact",
			hdf.EvaluatedRequirement{Impact: 0.9}, 0.9},
		{"a governing adjustment wins",
			hdf.EvaluatedRequirement{Impact: 0.9, StatusOverrides: []hdf.StatusOverride{
				{Type: hdf.RiskAdjustment, AppliedAt: mustTime(t, "2025-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2099-12-31T00:00:00Z"), Impact: adjust(0.3)},
			}}, 0.3},
		{"an expired adjustment does not",
			hdf.EvaluatedRequirement{Impact: 0.9, StatusOverrides: []hdf.StatusOverride{
				{Type: hdf.RiskAdjustment, AppliedAt: mustTime(t, "2019-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2020-01-01T00:00:00Z"), Impact: adjust(0.3)},
			}}, 0.9},
		{"a newer status-only override does not displace an older re-score",
			hdf.EvaluatedRequirement{Impact: 0.9, StatusOverrides: []hdf.StatusOverride{
				{Type: hdf.RiskAdjustment, AppliedAt: mustTime(t, "2025-01-01T00:00:00Z"), Impact: adjust(0.3)},
				{Type: hdf.OverrideTypeWaiver, AppliedAt: mustTime(t, "2025-06-01T00:00:00Z"), Status: statusPtr(hdf.Passed)},
			}}, 0.3},
		{"an adjustment to zero is honoured, not read as absent",
			hdf.EvaluatedRequirement{Impact: 0.9, StatusOverrides: []hdf.StatusOverride{
				{Type: hdf.RiskAdjustment, AppliedAt: mustTime(t, "2025-01-01T00:00:00Z"), Impact: adjust(0)},
			}}, 0},
		{"the stored effectiveImpact cache is never read",
			hdf.EvaluatedRequirement{Impact: 0.9, EffectiveImpact: &stale}, 0.9},
	}
	for _, c := range cases {
		assert.InDelta(t, c.want, RequirementEffectiveImpact(c.req), 1e-9, c.name)
	}
}

// Array position is not recency. The schema's description says the most recent
// override "should be first", but nothing sorts and this repo's own writers
// append (hdf-diff amend.go, shared enrich_stix.go), so on a document our own
// tooling amended twice the newest override is LAST. A reader that takes
// overrides[0] gets the oldest.
func TestGoverningOverrideIndex_IsByAppliedAtNotPosition(t *testing.T) {
	older := hdf.StatusOverride{
		Type: hdf.OverrideTypeWaiver, Status: statusPtr(hdf.Passed),
		AppliedAt: mustTime(t, "2024-06-01T00:00:00Z"), ExpiresAt: mustTime(t, "2099-12-31T00:00:00Z"),
	}
	newer := hdf.StatusOverride{
		Type:      hdf.RiskAdjustment,
		AppliedAt: mustTime(t, "2025-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2099-12-31T00:00:00Z"),
		Impact: &hdf.ImpactOverride{Value: 0.3},
	}
	expired := hdf.StatusOverride{
		Type:      hdf.RiskAdjustment,
		AppliedAt: mustTime(t, "2026-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2020-01-01T00:00:00Z"),
		Impact: &hdf.ImpactOverride{Value: 0.1},
	}
	ref := mustTime(t, "2026-06-01T00:00:00Z")

	// The order our own writers produce: append, so newest last.
	appended := []hdf.StatusOverride{older, newer}
	assert.Equal(t, 1, GoverningOverrideIndex(appended, ref),
		"the newest override governs even when it is last, which is where append puts it")

	// The order the schema's description asks for. Same answer either way —
	// that is the point: resolution must not depend on array order.
	prepended := []hdf.StatusOverride{newer, older}
	assert.Equal(t, 0, GoverningOverrideIndex(prepended, ref))

	// Recency never beats expiry: the most recently applied is expired here.
	assert.Equal(t, 1, GoverningOverrideIndex([]hdf.StatusOverride{older, newer, expired}, ref),
		"an expired override does not govern however recently it was applied")

	assert.Equal(t, -1, GoverningOverrideIndex(nil, ref), "nothing governs an empty list")
}

// The disposition twin of RequirementEffectiveStatus / RequirementEffectiveImpact.
// Exporters read the STORED disposition field, which this project treats as an
// output cache: it can disagree with the overrides, or be absent entirely on a
// document whose producer never stamped it.
func TestRequirementDisposition(t *testing.T) {
	waiver := hdf.StatusOverride{
		Type: hdf.OverrideTypeWaiver, Status: statusPtr(hdf.Passed),
		AppliedAt: mustTime(t, "2024-06-01T00:00:00Z"), ExpiresAt: mustTime(t, "2099-12-31T00:00:00Z"),
	}
	adjustment := hdf.StatusOverride{
		Type:      hdf.RiskAdjustment,
		AppliedAt: mustTime(t, "2025-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2099-12-31T00:00:00Z"),
		Impact: &hdf.ImpactOverride{Value: 0.3},
	}
	expiredWaiver := hdf.StatusOverride{
		Type: hdf.OverrideTypeWaiver, Status: statusPtr(hdf.Passed),
		AppliedAt: mustTime(t, "2024-06-01T00:00:00Z"), ExpiresAt: mustTime(t, "2020-01-01T00:00:00Z"),
	}
	stored := hdf.OverrideTypeWaiver

	cases := []struct {
		name string
		req  hdf.EvaluatedRequirement
		want string
	}{
		{"no overrides and no stored field", hdf.EvaluatedRequirement{}, ""},
		{"the governing override's type",
			hdf.EvaluatedRequirement{StatusOverrides: []hdf.StatusOverride{waiver, adjustment}}, "riskAdjustment"},
		{"array order does not decide it",
			hdf.EvaluatedRequirement{StatusOverrides: []hdf.StatusOverride{adjustment, waiver}}, "riskAdjustment"},
		{"an expired override governs nothing",
			hdf.EvaluatedRequirement{StatusOverrides: []hdf.StatusOverride{expiredWaiver}}, ""},
		{"the stored field is never read when overrides are present",
			hdf.EvaluatedRequirement{Disposition: &stored, StatusOverrides: []hdf.StatusOverride{adjustment}}, "riskAdjustment"},
		// The one exception, and it is a tested export contract: with NO overrides
		// the stored field is the only evidence the document carries, so dropping
		// it would lose the disposition of every document whose producer recorded
		// the verdict without the override detail.
		{"but it is the fallback when the requirement carries no overrides at all",
			hdf.EvaluatedRequirement{Disposition: &stored}, "waiver"},
		{"and an EXPIRED override still suppresses that fallback — the document does carry overrides",
			hdf.EvaluatedRequirement{Disposition: &stored, StatusOverrides: []hdf.StatusOverride{expiredWaiver}}, ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, RequirementDisposition(c.req, time.Time{}), c.name)
	}
}

// A type-less override is schema-invalid but reaches the exporters, which check
// their input structurally rather than schema-validating it. Both languages must
// yield the empty string — TypeScript's String(undefined) would emit the literal
// "undefined" into an exported document.
func TestRequirementDisposition_TypelessOverrideYieldsEmpty(t *testing.T) {
	req := hdf.EvaluatedRequirement{StatusOverrides: []hdf.StatusOverride{{
		Reason:    "r",
		AppliedAt: mustTime(t, "2025-01-01T00:00:00Z"), ExpiresAt: mustTime(t, "2099-12-31T00:00:00Z"),
	}}}
	assert.Equal(t, "", RequirementDisposition(req, time.Time{}))
}

type statusExpiryCase struct {
	Name        string                   `json:"name"`
	Note        string                   `json:"note"`
	Want        string                   `json:"want"`
	Requirement hdf.EvaluatedRequirement `json:"requirement"`
}

func loadStatusExpiryCases(t *testing.T) []statusExpiryCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "status-expiry-cases.json"))
	require.NoError(t, err)
	var doc struct {
		Cases []statusExpiryCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Cases)
	return doc.Cases
}

// The shared case table pins both bridges to the same expiry verdicts. The Go
// zero time is the load-bearing case: StatusOverride.ExpiresAt is a non-pointer
// time.Time, so an absent expiry round-trips as 0001-01-01T00:00:00Z and has to
// read back as "never expires" rather than as an expiry in year 1.
func TestRequirementEffectiveStatus_SharedExpiryCaseTable(t *testing.T) {
	for _, c := range loadStatusExpiryCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			assert.Equal(t, c.Want, RequirementEffectiveStatus(c.Requirement), c.Note)
		})
	}
}

// The export disposition names an override TYPE and reads statusOverrides
// only; a plan is carried separately by the exporters, so a governing POA&M
// must not surface here as "poam" the way hdf-engine and hdf-diff report it.
func TestRequirementDisposition_DoesNotReadPoams(t *testing.T) {
	far := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	req := hdf.EvaluatedRequirement{ID: "V-1", Impact: 0.5, Poams: []hdf.PoamElement{{AppliedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: far}}}
	assert.Equal(t, "", RequirementDisposition(req, time.Time{}), "a plan alone governs no export disposition")
	stored := hdf.OverrideType("waiver")
	req.Disposition = &stored
	assert.Equal(t, "waiver", RequirementDisposition(req, time.Time{}), "with no overrides the stored field is the fallback, plan or not")
}

// Parity: 'a reference time governs expiry' in status.test.ts.
func TestRequirementEffectiveImpactAt_JudgesExpiryAtRef(t *testing.T) {
	req := hdf.EvaluatedRequirement{ID: "V-1", Impact: 0.9, StatusOverrides: []hdf.StatusOverride{{
		Type: hdf.RiskAdjustment, AppliedAt: time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
		Impact: &hdf.ImpactOverride{Value: 0.1},
	}}}
	assert.InDelta(t, 0.1, RequirementEffectiveImpactAt(req, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)), 1e-9, "in force at the reference time")
	assert.InDelta(t, 0.9, RequirementEffectiveImpactAt(req, time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)), 1e-9, "expired by the reference time")
	assert.InDelta(t, 0.9, RequirementEffectiveImpact(req), 1e-9, "and the clock form reads it as expired today")
}
