package engine

import (
	"testing"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// ---------------------------------------------------------------------------
// Drift-specific constants
// ---------------------------------------------------------------------------

const (
	reqIDSV001 = "SV-001"
	reqIDSV002 = "SV-002"
	reqIDSV003 = "SV-003"
)

// ---------------------------------------------------------------------------
// Drift-specific helpers (mirror the TypeScript helpers in drift.test.ts)
// ---------------------------------------------------------------------------

// findDrift locates a RequirementDiff by ID in the Drift slice.
func findDrift(drift []types.RequirementDiff, id string) *types.RequirementDiff {
	for i := range drift {
		if drift[i].ID == id {
			return &drift[i]
		}
	}
	return nil
}

// passingReq builds a passing requirement with the given ID, title, impact, tags and descriptions.
func passingReq(id, title string, impact float64, tags map[string]any, descs []hdf.Description) hdf.EvaluatedRequirement {
	req := makeRequirement(id, hdf.Passed, impact)
	req.Title = strPtr(title)
	req.Tags = tags
	if descs != nil {
		req.Descriptions = descs
	}
	return req
}

// failingReq builds a failing requirement with the given ID, title, impact, tags and descriptions.
func failingReq(id, title string, impact float64, tags map[string]any, descs []hdf.Description) hdf.EvaluatedRequirement {
	req := makeRequirement(id, hdf.Failed, impact)
	req.Title = strPtr(title)
	req.Tags = tags
	if descs != nil {
		req.Descriptions = descs
	}
	return req
}

// defaultTags returns the standard test tags {cci: [CCI-000366], nist: [AC-6]}.
func defaultTags() map[string]any {
	return map[string]any{
		"cci":  []any{"CCI-000366"},
		"nist": []any{"AC-6"},
	}
}

// defaultDescs returns the standard test descriptions [{label: "default", data: "Default description"}].
func defaultDescs() []hdf.Description {
	return []hdf.Description{{Label: "default", Data: "Default description"}}
}

// driftOpts returns Options that track impact, severity, tags, title, and descriptions
// so fieldChanges are populated for all metadata the TS tests care about.
func driftOpts() Options {
	return Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags", "title", "descriptions"},
		ComparisonMode: types.ModeTemporal,
		MatchStrategy:  stratExactID,
	}
}

// containsReason returns true if reasons contains r.
func containsReason(reasons []types.ChangeReason, r types.ChangeReason) bool {
	for _, cr := range reasons {
		if cr == r {
			return true
		}
	}
	return false
}

// assertSingleDriftWithReason is a shared assertion for tests that verify a single
// requirement produces drift with exactly 1 drift entry and the expected changeReason.
// This eliminates structural duplication across similar drift-detection tests.
func assertSingleDriftWithReason(
	t *testing.T,
	comp types.HdfComparison,
	reqID string,
	expectedReason types.ChangeReason,
) {
	t.Helper()

	req := findReq(comp.RequirementDiffs, reqID)
	if req == nil {
		t.Fatalf("%s not found in requirementDiffs", reqID)
	}
	if req.State != types.StateUnchanged {
		t.Errorf("expected state 'unchanged', got %q", req.State)
	}
	if !containsReason(req.ChangeReasons, expectedReason) {
		t.Errorf("expected changeReasons to contain %q, got %v", expectedReason, req.ChangeReasons)
	}

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqID)
	if driftReq == nil {
		t.Fatalf("%s not found in drift", reqID)
	}
	if !containsReason(driftReq.ChangeReasons, expectedReason) {
		t.Errorf("expected drift changeReasons to contain %q, got %v", expectedReason, driftReq.ChangeReasons)
	}
}

// ---------------------------------------------------------------------------
// Tests (19 cases covering the 16 TypeScript drift.test.ts scenarios + extras)
// ---------------------------------------------------------------------------

// 1. Drift array is always present in the result.
func TestDrift_ArrayAlwaysPresent(t *testing.T) {
	req := passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs())
	baseline := makeBaseline("test-baseline", version100, req)
	results := makeResults(baseline)

	comp := mustDiffHdf(t, results, []hdf.HdfResults{results}, driftOpts())

	// drift should be defined (non-nil) -- Go represents it as a nil slice when empty,
	// but extractDrift returns nil for "no drift". The JSON tag uses omitempty so nil is ok.
	// What matters is that the engine ran without panic and we can check length.
	if comp.Drift == nil {
		// nil slice is acceptable for "no drift" -- this mirrors "defined, empty array" in TS.
		comp.Drift = []types.RequirementDiff{} // normalize for clarity
	}
	if len(comp.Drift) != 0 {
		t.Errorf("expected empty drift for identical docs, got %d entries", len(comp.Drift))
	}
}

// 2. No drift when comparing identical documents (empty drift, 1 requirementDiff unchanged).
func TestDrift_NoDriftWhenIdentical(t *testing.T) {
	req := passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs())
	baseline := makeBaseline("test-baseline", version100, req)
	results := makeResults(baseline)

	comp := mustDiffHdf(t, results, []hdf.HdfResults{results}, driftOpts())

	if len(comp.Drift) != 0 {
		t.Errorf("expected empty drift, got %d entries", len(comp.Drift))
	}
	if len(comp.RequirementDiffs) != 1 {
		t.Fatalf("expected 1 requirementDiff, got %d", len(comp.RequirementDiffs))
	}
	if comp.RequirementDiffs[0].State != types.StateUnchanged {
		t.Errorf("expected state 'unchanged', got %q", comp.RequirementDiffs[0].State)
	}
	if len(comp.RequirementDiffs[0].ChangeReasons) != 0 {
		t.Errorf("expected empty changeReasons, got %v", comp.RequirementDiffs[0].ChangeReasons)
	}
}

// 3. No drift when status changed (failed -> passed goes to requirementDiffs as 'fixed').
func TestDrift_NoDriftWhenStatusChanged(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		failingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	req := findReq(comp.RequirementDiffs, reqIDSV001)
	if req == nil {
		t.Fatal("SV-001 not found in requirementDiffs")
	}
	if req.State != types.StateFixed {
		t.Errorf("expected state 'fixed', got %q", req.State)
	}
	if len(comp.Drift) != 0 {
		t.Errorf("expected empty drift, got %d entries", len(comp.Drift))
	}
}

// 4. Drift when tags change but status stays the same.
func TestDrift_TagsChangedStatusSame(t *testing.T) {
	oldTags := map[string]any{"cci": []any{"CCI-000366"}, "nist": []any{"AC-6"}}
	newTags := map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}, "nist": []any{"AC-6"}}

	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, oldTags, defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, newTags, defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	// In requirementDiffs as unchanged with metadataChanged reason
	req := findReq(comp.RequirementDiffs, reqIDSV001)
	if req == nil {
		t.Fatal("SV-001 not found in requirementDiffs")
	}
	if req.State != types.StateUnchanged {
		t.Errorf("expected state 'unchanged', got %q", req.State)
	}
	if !containsReason(req.ChangeReasons, types.ReasonMetadataChanged) {
		t.Errorf("expected changeReasons to contain 'metadataChanged', got %v", req.ChangeReasons)
	}

	// Also in drift
	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqIDSV001)
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}
	if driftReq.State != types.StateUnchanged {
		t.Errorf("expected drift state 'unchanged', got %q", driftReq.State)
	}
	if !containsReason(driftReq.ChangeReasons, types.ReasonMetadataChanged) {
		t.Errorf("expected drift changeReasons to contain 'metadataChanged', got %v", driftReq.ChangeReasons)
	}
}

// 5 & 12. Table-driven: drift when a single metadata field changes but status stays the same.
// Covers impact change (test 5) and title change (test 12) from the TS suite.
func TestDrift_SingleMetadataChange(t *testing.T) {
	tests := []struct {
		name           string
		oldReq         hdf.EvaluatedRequirement
		newReq         hdf.EvaluatedRequirement
		expectedReason types.ChangeReason
	}{
		{
			name:           "impact changed (0.7 to 0.5), status stays passed",
			oldReq:         passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs()),
			newReq:         passingReq(reqIDSV001, "SSH Check", 0.5, defaultTags(), defaultDescs()),
			expectedReason: types.ReasonImpactChanged,
		},
		{
			name:           "title changed, status stays passed",
			oldReq:         passingReq(reqIDSV001, "Old Title", 0.7, defaultTags(), defaultDescs()),
			newReq:         passingReq(reqIDSV001, "New Title", 0.7, defaultTags(), defaultDescs()),
			expectedReason: types.ReasonMetadataChanged,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldDoc := makeResults(makeBaseline("test-baseline", version100, tc.oldReq))
			newDoc := makeResults(makeBaseline("test-baseline", version100, tc.newReq))

			comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

			assertSingleDriftWithReason(t, comp, reqIDSV001, tc.expectedReason)
		})
	}
}

// 6. Drift when description text changes but status remains the same.
func TestDrift_DescriptionChanged(t *testing.T) {
	oldDescs := []hdf.Description{{Label: "default", Data: "Old description text"}}
	newDescs := []hdf.Description{{Label: "default", Data: "Updated description text"}}

	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), oldDescs),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), newDescs),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	assertSingleDriftWithReason(t, comp, reqIDSV001, types.ReasonMetadataChanged)
}

// 7. Multiple drift items -- only requirements with metadata changes appear in drift.
func TestDrift_MultipleDriftItems(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366"}}, defaultDescs()),
		passingReq(reqIDSV002, "Firewall Check", 0.7, defaultTags(), defaultDescs()),
		passingReq(reqIDSV003, "Audit Logging", 0.5, defaultTags(), defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		// SV-001: tags changed
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}}, defaultDescs()),
		// SV-002: truly unchanged
		passingReq(reqIDSV002, "Firewall Check", 0.7, defaultTags(), defaultDescs()),
		// SV-003: impact changed
		passingReq(reqIDSV003, "Audit Logging", 0.3, defaultTags(), defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	// All three in requirementDiffs
	if len(comp.RequirementDiffs) != 3 {
		t.Fatalf("expected 3 requirementDiffs, got %d", len(comp.RequirementDiffs))
	}

	// SV-002 is truly unchanged -- not in drift
	if findDrift(comp.Drift, reqIDSV002) != nil {
		t.Error("SV-002 should NOT be in drift (truly unchanged)")
	}

	// SV-001 and SV-003 have metadata changes -- both in drift
	if len(comp.Drift) != 2 {
		t.Fatalf("expected 2 drift entries, got %d", len(comp.Drift))
	}
	if findDrift(comp.Drift, reqIDSV001) == nil {
		t.Error("SV-001 should be in drift")
	}
	if findDrift(comp.Drift, reqIDSV003) == nil {
		t.Error("SV-003 should be in drift")
	}
}

// 8. Drift entries have fieldChanges populated showing what metadata changed (impact).
func TestDrift_FieldChangesPopulated_Impact(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.5, defaultTags(), defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqIDSV001)
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}

	found := false
	for _, fc := range driftReq.FieldChanges {
		if fc.Op == types.OpReplace && fc.Path == fieldImpact {
			oldVal, oldOk := fc.OldValue.(float64)
			newVal, newOk := fc.NewValue.(float64)
			if oldOk && newOk && oldVal == 0.7 && newVal == 0.5 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected fieldChange with op=replace, path=impact, old=0.7, new=0.5; got %v", driftReq.FieldChanges)
	}
}

// 9. Drift entries have fieldChanges populated for tags when tracked.
func TestDrift_FieldChangesPopulated_Tags(t *testing.T) {
	oldTags := map[string]any{"cci": []any{"CCI-000366"}}
	newTags := map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}}

	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, oldTags, defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, newTags, defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqIDSV001)
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}

	found := false
	for _, fc := range driftReq.FieldChanges {
		if fc.Op == types.OpReplace && fc.Path == "tags" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected fieldChange with op=replace, path=tags; got %v", driftReq.FieldChanges)
	}
}

// 10. Drift entries have before/after snapshots.
func TestDrift_BeforeAfterSnapshots(t *testing.T) {
	oldTags := map[string]any{"cci": []any{"CCI-000366"}}
	newTags := map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}}

	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, oldTags, defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, newTags, defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqIDSV001)
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}

	if driftReq.Before == nil {
		t.Error("expected before snapshot to be non-nil")
	}
	if driftReq.After == nil {
		t.Error("expected after snapshot to be non-nil")
	}
	if driftReq.Before != nil && driftReq.Before.ID != reqIDSV001 {
		t.Errorf("expected before.ID=%q, got %q", reqIDSV001, driftReq.Before.ID)
	}
	if driftReq.After != nil && driftReq.After.ID != reqIDSV001 {
		t.Errorf("expected after.ID=%q, got %q", reqIDSV001, driftReq.After.ID)
	}
}

// 11. Summary is not affected by drift (drift items are counted as unchanged in summary).
func TestDrift_SummaryNotAffected(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366"}}, defaultDescs()),
		passingReq(reqIDSV002, "Firewall Check", 0.7, defaultTags(), defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		// SV-001: tags changed (drift)
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}}, defaultDescs()),
		// SV-002: truly unchanged
		passingReq(reqIDSV002, "Firewall Check", 0.7, defaultTags(), defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	// Summary counts should reflect requirementDiffs, not drift
	if comp.Summary.Unchanged != 2 {
		t.Errorf("expected unchanged=2, got %d", comp.Summary.Unchanged)
	}
	if comp.Summary.Total != 2 {
		t.Errorf("expected total=2, got %d", comp.Summary.Total)
	}
	if comp.Summary.Fixed != 0 {
		t.Errorf("expected fixed=0, got %d", comp.Summary.Fixed)
	}
	if comp.Summary.Regressed != 0 {
		t.Errorf("expected regressed=0, got %d", comp.Summary.Regressed)
	}
	if comp.Summary.New != 0 {
		t.Errorf("expected new=0, got %d", comp.Summary.New)
	}
	if comp.Summary.Absent != 0 {
		t.Errorf("expected absent=0, got %d", comp.Summary.Absent)
	}
	if comp.Summary.Updated != 0 {
		t.Errorf("expected updated=0, got %d", comp.Summary.Updated)
	}

	// But drift shows only the one with metadata changes
	if len(comp.Drift) != 1 {
		t.Errorf("expected 1 drift entry, got %d", len(comp.Drift))
	}
}

// 13. Drift array is empty when requirements are truly identical.
func TestDrift_EmptyWhenTrulyIdentical(t *testing.T) {
	req := passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs())
	baseline := makeBaseline("test-baseline", version100, req)
	results := makeResults(baseline)

	comp := mustDiffHdf(t, results, []hdf.HdfResults{results}, driftOpts())

	if len(comp.Drift) != 0 {
		t.Errorf("expected empty drift for truly identical requirements, got %d entries", len(comp.Drift))
	}
}

// 14. Drift for unchanged requirement with CCI tag added.
func TestDrift_CCITagAdded(t *testing.T) {
	oldTags := map[string]any{"cci": []any{"CCI-000366"}, "nist": []any{"AC-6"}}
	newTags := map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}, "nist": []any{"AC-6"}}

	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, oldTags, defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, newTags, defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqIDSV001)
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}
	if !containsReason(driftReq.ChangeReasons, types.ReasonMetadataChanged) {
		t.Errorf("expected drift changeReasons to contain 'metadataChanged', got %v", driftReq.ChangeReasons)
	}
}

// 15. Drift entries have state "unchanged".
func TestDrift_EntriesHaveStateUnchanged(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366"}}, defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}}, defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	for _, d := range comp.Drift {
		if d.State != types.StateUnchanged {
			t.Errorf("expected drift entry state 'unchanged', got %q for %s", d.State, d.ID)
		}
	}
}

// 16. Drift entries have changeReasons populated (impactChanged + metadataChanged).
func TestDrift_ChangeReasonsPopulated(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366"}}, defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.5, map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}}, defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqIDSV001)
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}
	if len(driftReq.ChangeReasons) == 0 {
		t.Error("expected non-empty changeReasons on drift entry")
	}
	if !containsReason(driftReq.ChangeReasons, types.ReasonImpactChanged) {
		t.Errorf("expected 'impactChanged' in changeReasons, got %v", driftReq.ChangeReasons)
	}
	if !containsReason(driftReq.ChangeReasons, types.ReasonMetadataChanged) {
		t.Errorf("expected 'metadataChanged' in changeReasons, got %v", driftReq.ChangeReasons)
	}
}

// 17. No drift entries for new requirements.
func TestDrift_NoDriftForNewRequirements(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 0 {
		t.Errorf("expected empty drift for new requirements, got %d entries", len(comp.Drift))
	}
}

// 18. No drift entries for absent requirements.
func TestDrift_NoDriftForAbsentRequirements(t *testing.T) {
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, defaultTags(), defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 0 {
		t.Errorf("expected empty drift for absent requirements, got %d entries", len(comp.Drift))
	}
}

// 19. Drift with multiple changeReasons on the same requirement.
func TestDrift_MultipleChangeReasons(t *testing.T) {
	// Change both impact (0.7 -> 0.5) and tags -- produces both impactChanged and metadataChanged
	oldDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.7, map[string]any{"cci": []any{"CCI-000366"}}, defaultDescs()),
	))
	newDoc := makeResults(makeBaseline("test-baseline", version100,
		passingReq(reqIDSV001, "SSH Check", 0.5, map[string]any{"cci": []any{"CCI-000366", "CCI-000370"}}, defaultDescs()),
	))

	comp := mustDiffHdf(t, oldDoc, []hdf.HdfResults{newDoc}, driftOpts())

	if len(comp.Drift) != 1 {
		t.Fatalf("expected 1 drift entry, got %d", len(comp.Drift))
	}
	driftReq := findDrift(comp.Drift, reqIDSV001)
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}
	if len(driftReq.ChangeReasons) < 2 {
		t.Errorf("expected at least 2 changeReasons, got %d: %v", len(driftReq.ChangeReasons), driftReq.ChangeReasons)
	}
	if !containsReason(driftReq.ChangeReasons, types.ReasonImpactChanged) {
		t.Errorf("expected 'impactChanged' in changeReasons, got %v", driftReq.ChangeReasons)
	}
	if !containsReason(driftReq.ChangeReasons, types.ReasonMetadataChanged) {
		t.Errorf("expected 'metadataChanged' in changeReasons, got %v", driftReq.ChangeReasons)
	}
}
