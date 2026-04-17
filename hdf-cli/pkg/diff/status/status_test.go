package status

import (
	"testing"
	"time"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// Test-level status string constants to avoid goconst duplication.
const (
	statusPassed      = string(hdf.Passed)
	statusNotReviewed = string(hdf.NotReviewed)
	statusFailed      = "failed"
	statusError       = "error"
	statusNotAppl     = "notApplicable"
)

// ---------------------------------------------------------------------------
// Helpers to build minimal HDF requirement structures
// ---------------------------------------------------------------------------

func makeResult(status hdf.ResultStatus) hdf.RequirementResult {
	s := status
	return hdf.RequirementResult{
		Status:    &s,
		CodeDesc:  "test",
		StartTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func makeOverride(opts struct {
	Type      string
	Status    hdf.ResultStatus
	Reason    string
	AppliedAt time.Time
	ExpiresAt time.Time
}) hdf.StatusOverride {
	overrideType := hdf.Waiver
	if opts.Type == "attestation" {
		overrideType = hdf.Attestation
	}
	status := opts.Status
	if status == "" {
		status = hdf.Passed
	}
	reason := opts.Reason
	if reason == "" {
		reason = "approved by team lead"
	}
	appliedAt := opts.AppliedAt
	if appliedAt.IsZero() {
		appliedAt = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	expiresAt := opts.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	return hdf.StatusOverride{
		Type:      overrideType,
		Status:    &status,
		Reason:    reason,
		AppliedBy: hdf.Identity{Identifier: "admin"},
		AppliedAt: appliedAt,
		ExpiresAt: expiresAt,
	}
}

func makeRequirement(overrides ...func(*hdf.EvaluatedRequirement)) hdf.EvaluatedRequirement {
	impact := 0.7
	req := hdf.EvaluatedRequirement{
		ID:           "SV-100001",
		Impact:       impact,
		Results:      []hdf.RequirementResult{},
		Tags:         map[string]any{},
		Descriptions: []hdf.Description{},
	}
	for _, o := range overrides {
		o(&req)
	}
	return req
}

func ptrString(s string) *string {
	return &s
}

func ptrResultStatus(s hdf.ResultStatus) *hdf.ResultStatus {
	return &s
}

// ---------------------------------------------------------------------------
// ComputeEffectiveStatus
// ---------------------------------------------------------------------------

func TestComputeEffectiveStatus(t *testing.T) {
	tests := []struct {
		name               string
		req                hdf.EvaluatedRequirement
		referenceTimestamp string
		expected           string
	}{
		{
			name: "returns passed for a single passing result with no overrides",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			expected: statusPassed,
		},
		{
			name: "returns failed for a single failing result with no overrides",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			expected: statusFailed,
		},
		{
			name: "returns error for a single error result with no overrides",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Error)}
			}),
			expected: statusError,
		},
		{
			name: "returns failed when results contain one passed and one failed (worst wins)",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{
					makeResult(hdf.Passed),
					makeResult(hdf.Failed),
				}
			}),
			expected: statusFailed,
		},
		{
			name: "returns error when results contain one error and one failed (worst wins)",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{
					makeResult(hdf.Error),
					makeResult(hdf.Failed),
				}
			}),
			expected: statusError,
		},
		{
			name: "returns notReviewed for an empty results array",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{}
			}),
			expected: statusNotReviewed,
		},
		{
			name: "returns notApplicable when impact is 0 and there are no results",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0
				r.Results = []hdf.RequirementResult{}
			}),
			expected: statusNotAppl,
		},
		{
			name: "uses non-expired waiver override status instead of result status",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{
						Status:    hdf.Passed,
						ExpiresAt: time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
					}),
				}
			}),
			referenceTimestamp: "2025-06-01T00:00:00Z",
			expected:           statusPassed,
		},
		{
			name: "falls back to results when waiver override is expired",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{
						Status:    hdf.Passed,
						ExpiresAt: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
					}),
				}
			}),
			referenceTimestamp: "2025-06-01T00:00:00Z",
			expected:           statusFailed,
		},
		{
			name: "uses the first non-expired override when multiple overrides exist",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					// First override: expired
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{
						Status:    hdf.Passed,
						AppliedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
						ExpiresAt: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
					}),
					// Second override: still valid
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{
						Type:      "attestation",
						Status:    hdf.NotReviewed,
						AppliedAt: time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
						ExpiresAt: time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
					}),
				}
			}),
			referenceTimestamp: "2025-06-01T00:00:00Z",
			expected:           statusNotReviewed,
		},
		{
			name: "uses effectiveStatus field directly when present and no overrides exist",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.EffectiveStatus = ptrResultStatus(hdf.Passed)
			}),
			expected: statusPassed,
		},
		{
			name: "returns notApplicable when impact is 0 regardless of results",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0
				r.Results = []hdf.RequirementResult{
					makeResult(hdf.Passed),
					makeResult(hdf.Failed),
				}
			}),
			expected: statusNotAppl,
		},
		{
			name: "uses now when overrides exist but no referenceTimestamp provided",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{
						Status:    hdf.Passed,
						ExpiresAt: time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
					}),
				}
			}),
			// No referenceTimestamp — should use time.Now() and the override is far in the future
			expected: statusPassed,
		},
		{
			name: "uses effectiveStatus when overrides array is empty",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.EffectiveStatus = ptrResultStatus(hdf.Passed)
				r.StatusOverrides = []hdf.StatusOverride{}
			}),
			expected: statusPassed,
		},
		{
			name: "returns notReviewed when results slice is nil",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = nil
			}),
			expected: statusNotReviewed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeEffectiveStatus(tc.req, tc.referenceTimestamp)
			if got != tc.expected {
				t.Errorf("ComputeEffectiveStatus() = %q, want %q", got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ClassifyChangeReasons
// ---------------------------------------------------------------------------

func TestClassifyChangeReasons(t *testing.T) {
	tests := []struct {
		name         string
		oldReq       hdf.EvaluatedRequirement
		newReq       hdf.EvaluatedRequirement
		oldTimestamp string
		newTimestamp string
		expected     []types.ChangeReason
		mustContain  []types.ChangeReason
		minLen       int
	}{
		{
			name: "returns empty slice when old and new requirements are identical",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			expected: []types.ChangeReason{},
		},
		{
			name: "returns resultChanged when result statuses differ",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			expected: []types.ChangeReason{types.ReasonResultChanged},
		},
		{
			name: "returns overrideAdded when an override is added in the new requirement",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{Status: hdf.Passed}),
				}
			}),
			mustContain: []types.ChangeReason{types.ReasonOverrideAdded},
		},
		{
			name: "returns overrideExpired when an override expires between scans",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{
						Status:    hdf.Passed,
						ExpiresAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
					}),
				}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{
						Status:    hdf.Passed,
						ExpiresAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
					}),
				}
			}),
			oldTimestamp: "2025-05-01T00:00:00Z",
			newTimestamp: "2025-07-01T00:00:00Z",
			mustContain:  []types.ChangeReason{types.ReasonOverrideExpired},
		},
		{
			name: "returns overrideRemoved when an override is removed in the new requirement",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{Status: hdf.Passed}),
				}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			mustContain: []types.ChangeReason{types.ReasonOverrideRemoved},
		},
		{
			name: "returns impactChanged when impact differs",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.7
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.0
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			mustContain: []types.ChangeReason{types.ReasonImpactChanged},
		},
		{
			name: "returns metadataChanged when tags differ",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Tags = map[string]any{"cci": []string{"CCI-000001"}}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Tags = map[string]any{"cci": []string{"CCI-000002"}}
			}),
			mustContain: []types.ChangeReason{types.ReasonMetadataChanged},
		},
		{
			name: "returns multiple reasons when result changed AND impact changed",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.7
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.3
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			mustContain: []types.ChangeReason{types.ReasonResultChanged, types.ReasonImpactChanged},
			minLen:      2,
		},
		{
			name: "returns multiple reasons when override added AND result changed",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					makeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{Status: hdf.Passed}),
				}
			}),
			mustContain: []types.ChangeReason{types.ReasonOverrideAdded, types.ReasonResultChanged},
			minLen:      2,
		},
		{
			name: "handles nil results on old requirement gracefully",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = nil
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			mustContain: []types.ChangeReason{types.ReasonResultChanged},
		},
		{
			name: "handles nil results on new requirement gracefully",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = nil
			}),
			mustContain: []types.ChangeReason{types.ReasonResultChanged},
		},
		{
			name: "handles nil tags and descriptions gracefully",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Tags = nil
				r.Descriptions = nil
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Tags = nil
				r.Descriptions = nil
			}),
			expected: []types.ChangeReason{},
		},
		{
			name: "detects metadataChanged when descriptions differ",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Descriptions = []hdf.Description{{Label: "default", Data: "old description"}}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Descriptions = []hdf.Description{{Label: "default", Data: "new description"}}
			}),
			mustContain: []types.ChangeReason{types.ReasonMetadataChanged},
		},
		{
			name: "detects metadataChanged when title differs",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Title = ptrString("Old Title")
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Title = ptrString("New Title")
			}),
			mustContain: []types.ChangeReason{types.ReasonMetadataChanged},
		},
		{
			name: "detects dispositionChanged when disposition differs",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				d := hdf.Waiver
				r.Disposition = &d
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				d := hdf.RiskAdjustment
				r.Disposition = &d
			}),
			mustContain: []types.ChangeReason{types.ReasonDispositionChanged},
		},
		{
			name: "detects dispositionChanged when disposition added",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				d := hdf.FalsePositive
				r.Disposition = &d
			}),
			mustContain: []types.ChangeReason{types.ReasonDispositionChanged},
		},
		{
			name: "no dispositionChanged when disposition is the same",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				d := hdf.Waiver
				r.Disposition = &d
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				d := hdf.Waiver
				r.Disposition = &d
			}),
			expected: []types.ChangeReason{},
		},
		{
			name: "detects effectiveImpactChanged when effectiveImpact differs",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				ei := 0.7
				r.EffectiveImpact = &ei
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			mustContain: []types.ChangeReason{types.ReasonEffectiveImpactChanged},
		},
		{
			name: "detects effectiveImpactChanged when effectiveImpact added",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			mustContain: []types.ChangeReason{types.ReasonEffectiveImpactChanged},
		},
		{
			name: "no effectiveImpactChanged when effectiveImpact is the same",
			oldReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			expected: []types.ChangeReason{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyChangeReasons(tc.oldReq, tc.newReq, tc.oldTimestamp, tc.newTimestamp)

			if tc.expected != nil {
				if len(tc.expected) == 0 && len(got) == 0 {
					// Both empty — pass
					return
				}
				if len(got) != len(tc.expected) {
					t.Errorf("ClassifyChangeReasons() returned %d reasons %v, want %d reasons %v",
						len(got), got, len(tc.expected), tc.expected)
					return
				}
				for i, reason := range tc.expected {
					if got[i] != reason {
						t.Errorf("ClassifyChangeReasons()[%d] = %q, want %q", i, got[i], reason)
					}
				}
			}

			for _, mustHave := range tc.mustContain {
				found := false
				for _, r := range got {
					if r == mustHave {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ClassifyChangeReasons() = %v, expected to contain %q", got, mustHave)
				}
			}

			if tc.minLen > 0 && len(got) < tc.minLen {
				t.Errorf("ClassifyChangeReasons() returned %d reasons, want at least %d", len(got), tc.minLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ClassifyDiffStatus
// ---------------------------------------------------------------------------

func TestClassifyDiffStatus(t *testing.T) {
	tests := []struct {
		name     string
		oldStat  string
		newStat  string
		expected types.RequirementState
	}{
		{
			name:     "fixed when failed -> passed",
			oldStat:  statusFailed,
			newStat:  statusPassed,
			expected: types.StateFixed,
		},
		{
			name:     "fixed when error -> passed",
			oldStat:  statusError,
			newStat:  statusPassed,
			expected: types.StateFixed,
		},
		{
			name:     "regressed when passed -> failed",
			oldStat:  statusPassed,
			newStat:  statusFailed,
			expected: types.StateRegressed,
		},
		{
			name:     "regressed when passed -> error",
			oldStat:  statusPassed,
			newStat:  statusError,
			expected: types.StateRegressed,
		},
		{
			name:     "unchanged when passed -> passed",
			oldStat:  statusPassed,
			newStat:  statusPassed,
			expected: types.StateUnchanged,
		},
		{
			name:     "unchanged when failed -> failed",
			oldStat:  statusFailed,
			newStat:  statusFailed,
			expected: types.StateUnchanged,
		},
		{
			name:     "updated when notReviewed -> notApplicable",
			oldStat:  statusNotReviewed,
			newStat:  statusNotAppl,
			expected: types.StateUpdated,
		},
		{
			name:     "updated when failed -> notApplicable",
			oldStat:  statusFailed,
			newStat:  statusNotAppl,
			expected: types.StateUpdated,
		},
		{
			name:     "fixed when notReviewed -> passed (notReviewed is failing)",
			oldStat:  statusNotReviewed,
			newStat:  statusPassed,
			expected: types.StateFixed,
		},
		{
			name:     "regressed when passed -> notReviewed",
			oldStat:  statusPassed,
			newStat:  statusNotReviewed,
			expected: types.StateRegressed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyDiffStatus(tc.oldStat, tc.newStat)
			if got != tc.expected {
				t.Errorf("ClassifyDiffStatus(%q, %q) = %q, want %q",
					tc.oldStat, tc.newStat, got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Coverage: severityIndex — all statuses and unknown
// ---------------------------------------------------------------------------

func TestSeverityIndex_AllStatuses(t *testing.T) {
	tests := []struct {
		status   string
		expected int
	}{
		{statusNotAppl, 0},
		{statusNotReviewed, 1},
		{statusPassed, 2},
		{statusFailed, 3},
		{statusError, 4},
		{"unknownStatus", -1},
		{"", -1},
	}
	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			got := severityIndex(tc.status)
			if got != tc.expected {
				t.Errorf("severityIndex(%q) = %d, want %d", tc.status, got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Coverage: ComputeEffectiveStatus — bad referenceTimestamp falls back to now
// ---------------------------------------------------------------------------

func TestComputeEffectiveStatus_BadReferenceTimestamp(t *testing.T) {
	req := makeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
		r.StatusOverrides = []hdf.StatusOverride{
			makeOverride(struct {
				Type      string
				Status    hdf.ResultStatus
				Reason    string
				AppliedAt time.Time
				ExpiresAt time.Time
			}{
				Status:    hdf.Passed,
				ExpiresAt: time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
			}),
		}
	})
	// Bad timestamp string — should fall back to time.Now(); override is far future so passes
	got := ComputeEffectiveStatus(req, "not-valid-RFC3339")
	if got != statusPassed {
		t.Errorf("ComputeEffectiveStatus with bad timestamp = %q, want %q", got, statusPassed)
	}
}

// ---------------------------------------------------------------------------
// Coverage: ComputeEffectiveStatus — result with nil status is skipped
// ---------------------------------------------------------------------------

func TestComputeEffectiveStatus_ResultWithNilStatus(t *testing.T) {
	req := makeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Results = []hdf.RequirementResult{
			{Status: nil, CodeDesc: "nil status"},
			makeResult(hdf.Passed),
		}
	})
	got := ComputeEffectiveStatus(req, "")
	if got != statusPassed {
		t.Errorf("expected %q, got %q", statusPassed, got)
	}
}

// ---------------------------------------------------------------------------
// Coverage: ComputeEffectiveStatus — result with unknown status
// ---------------------------------------------------------------------------

func TestComputeEffectiveStatus_UnknownResultStatus(t *testing.T) {
	unknownStatus := hdf.ResultStatus("customUnknown")
	req := makeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Results = []hdf.RequirementResult{
			{Status: &unknownStatus, CodeDesc: "unknown", StartTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		}
	})
	// Unknown status has severityIndex = -1, so worstIndex starts at -1 and this ties.
	// The function uses > so unknown stays at -1 and worstStatus defaults to statusNotReviewed.
	got := ComputeEffectiveStatus(req, "")
	if got != statusNotReviewed {
		t.Errorf("expected %q for unknown result status, got %q", statusNotReviewed, got)
	}
}

// jsonMarshalOrEmpty was removed in favor of reflect.DeepEqual.
// See ClassifyChangeReasons implementation for the replacement.

// ---------------------------------------------------------------------------
// Coverage: stringSlicesEqual — different lengths and same lengths different content
// ---------------------------------------------------------------------------

func TestStringSlicesEqual_DifferentLengths(t *testing.T) {
	if stringSlicesEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("expected false for different lengths")
	}
}

func TestStringSlicesEqual_SameLengthDifferentContent(t *testing.T) {
	if stringSlicesEqual([]string{"a", "b"}, []string{"a", "c"}) {
		t.Error("expected false for different content")
	}
}

func TestStringSlicesEqual_BothEmpty(t *testing.T) {
	if !stringSlicesEqual([]string{}, []string{}) {
		t.Error("expected true for both empty")
	}
}

func TestStringSlicesEqual_Identical(t *testing.T) {
	if !stringSlicesEqual([]string{"x", "y"}, []string{"x", "y"}) {
		t.Error("expected true for identical slices")
	}
}

// ---------------------------------------------------------------------------
// Coverage: extractSortedStatuses — nil results, mixed statuses
// ---------------------------------------------------------------------------

func TestExtractSortedStatuses_NilResults(t *testing.T) {
	statuses := extractSortedStatuses(nil)
	if len(statuses) != 0 {
		t.Errorf("expected empty, got %v", statuses)
	}
}

func TestExtractSortedStatuses_MixedStatuses(t *testing.T) {
	statuses := extractSortedStatuses([]hdf.RequirementResult{
		makeResult(hdf.Failed),
		makeResult(hdf.Passed),
		makeResult(hdf.Error),
	})
	if len(statuses) != 3 {
		t.Fatalf("expected 3, got %d", len(statuses))
	}
	// Should be sorted
	if statuses[0] != statusError {
		t.Errorf("expected sorted[0]=%q, got %q", statusError, statuses[0])
	}
	if statuses[1] != statusFailed {
		t.Errorf("expected sorted[1]=%q, got %q", statusFailed, statuses[1])
	}
	if statuses[2] != statusPassed {
		t.Errorf("expected sorted[2]=%q, got %q", statusPassed, statuses[2])
	}
}

func TestExtractSortedStatuses_NilStatusSkipped(t *testing.T) {
	statuses := extractSortedStatuses([]hdf.RequirementResult{
		{Status: nil},
		makeResult(hdf.Passed),
	})
	if len(statuses) != 1 {
		t.Fatalf("expected 1 (nil skipped), got %d", len(statuses))
	}
	if statuses[0] != statusPassed {
		t.Errorf("expected %q, got %q", statusPassed, statuses[0])
	}
}
