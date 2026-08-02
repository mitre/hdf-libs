package diff

import (
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// Test-level status string constants to avoid goconst duplication.
const (
	stStatusPassed    = string(hdf.Passed)
	stStatusFailed    = "failed"
	statusError       = "error"
	statusNotAppl     = "notApplicable"
	statusNotReviewed = "notReviewed"
)

// ---------------------------------------------------------------------------
// Helpers to build minimal HDF requirement structures
// ---------------------------------------------------------------------------

func stMakeResult(status hdf.ResultStatus) hdf.RequirementResult {
	s := status
	return hdf.RequirementResult{
		Status:    s,
		CodeDesc:  "test",
		StartTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func stMakeOverride(opts struct {
	Type      string
	Status    hdf.ResultStatus
	Reason    string
	AppliedAt time.Time
	ExpiresAt time.Time
}) hdf.StatusOverride {
	overrideType := hdf.OverrideTypeWaiver
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
		AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
		AppliedAt: appliedAt,
		ExpiresAt: expiresAt,
	}
}

func stMakeRequirement(overrides ...func(*hdf.EvaluatedRequirement)) hdf.EvaluatedRequirement {
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

func stPtrString(s string) *string {
	return &s
}

func stPtrResultStatus(s hdf.ResultStatus) *hdf.ResultStatus {
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
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			expected: stStatusPassed,
		},
		{
			name: "returns failed for a single failing result with no overrides",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			expected: stStatusFailed,
		},
		{
			name: "returns error for a single error result with no overrides",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Error)}
			}),
			expected: statusError,
		},
		{
			name: "returns failed when results contain one passed and one failed (worst wins)",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{
					stMakeResult(hdf.Passed),
					stMakeResult(hdf.Failed),
				}
			}),
			expected: stStatusFailed,
		},
		{
			name: "returns error when results contain one error and one failed (worst wins)",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{
					stMakeResult(hdf.Error),
					stMakeResult(hdf.Failed),
				}
			}),
			expected: statusError,
		},
		{
			name: "returns notReviewed for an empty results array",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{}
			}),
			expected: statusNotReviewed,
		},
		{
			name: "returns notApplicable when impact is 0 and there are no results",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0
				r.Results = []hdf.RequirementResult{}
			}),
			expected: statusNotAppl,
		},
		{
			name: "uses non-expired waiver override status instead of result status",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
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
			expected:           stStatusPassed,
		},
		{
			name: "falls back to results when waiver override is expired",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
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
			expected:           stStatusFailed,
		},
		{
			name: "uses the governing non-expired override when multiple overrides exist",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					// First override: expired
					stMakeOverride(struct {
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
					stMakeOverride(struct {
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
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.EffectiveStatus = stPtrResultStatus(hdf.Passed)
			}),
			expected: stStatusPassed,
		},
		{
			name: "returns notApplicable when impact is 0 regardless of results",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0
				r.Results = []hdf.RequirementResult{
					stMakeResult(hdf.Passed),
					stMakeResult(hdf.Failed),
				}
			}),
			expected: statusNotAppl,
		},
		{
			name: "uses now when overrides exist but no referenceTimestamp provided",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
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
			expected: stStatusPassed,
		},
		{
			name: "uses effectiveStatus when overrides array is empty",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.EffectiveStatus = stPtrResultStatus(hdf.Passed)
				r.StatusOverrides = []hdf.StatusOverride{}
			}),
			expected: stStatusPassed,
		},
		{
			name: "returns notReviewed when results slice is nil",
			req: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
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
		expected     []ChangeReason
		mustContain  []ChangeReason
		minLen       int
	}{
		{
			name: "returns empty slice when old and new requirements are identical",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			expected: []ChangeReason{},
		},
		{
			name: "returns resultChanged when result statuses differ",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			expected: []ChangeReason{ReasonResultChanged},
		},
		{
			name: "returns overrideAdded when an override is added in the new requirement",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{Status: hdf.Passed}),
				}
			}),
			mustContain: []ChangeReason{ReasonOverrideAdded},
		},
		{
			name: "returns overrideExpired when an override expires between scans",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
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
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
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
			mustContain:  []ChangeReason{ReasonOverrideExpired},
		},
		{
			name: "returns overrideRemoved when an override is removed in the new requirement",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{Status: hdf.Passed}),
				}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			mustContain: []ChangeReason{ReasonOverrideRemoved},
		},
		{
			name: "returns impactChanged when impact differs",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.7
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.0
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			mustContain: []ChangeReason{ReasonImpactChanged},
		},
		{
			name: "returns metadataChanged when tags differ",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Tags = map[string]any{"cci": []string{"CCI-000001"}}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Tags = map[string]any{"cci": []string{"CCI-000002"}}
			}),
			mustContain: []ChangeReason{ReasonMetadataChanged},
		},
		{
			name: "returns multiple reasons when result changed AND impact changed",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.7
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0.3
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			mustContain: []ChangeReason{ReasonResultChanged, ReasonImpactChanged},
			minLen:      2,
		},
		{
			name: "returns multiple reasons when override added AND result changed",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				r.StatusOverrides = []hdf.StatusOverride{
					stMakeOverride(struct {
						Type      string
						Status    hdf.ResultStatus
						Reason    string
						AppliedAt time.Time
						ExpiresAt time.Time
					}{Status: hdf.Passed}),
				}
			}),
			mustContain: []ChangeReason{ReasonOverrideAdded, ReasonResultChanged},
			minLen:      2,
		},
		{
			name: "handles nil results on old requirement gracefully",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = nil
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			mustContain: []ChangeReason{ReasonResultChanged},
		},
		{
			name: "handles nil results on new requirement gracefully",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = nil
			}),
			mustContain: []ChangeReason{ReasonResultChanged},
		},
		{
			name: "handles nil tags and descriptions gracefully",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Tags = nil
				r.Descriptions = nil
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Tags = nil
				r.Descriptions = nil
			}),
			expected: []ChangeReason{},
		},
		{
			name: "detects metadataChanged when descriptions differ",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Descriptions = []hdf.Description{{Label: "default", Data: "old description"}}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Descriptions = []hdf.Description{{Label: "default", Data: "new description"}}
			}),
			mustContain: []ChangeReason{ReasonMetadataChanged},
		},
		{
			name: "detects metadataChanged when title differs",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Title = stPtrString("Old Title")
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
				r.Title = stPtrString("New Title")
			}),
			mustContain: []ChangeReason{ReasonMetadataChanged},
		},
		{
			name: "detects dispositionChanged when disposition differs",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				d := hdf.OverrideTypeWaiver
				r.Disposition = &d
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				d := hdf.RiskAdjustment
				r.Disposition = &d
			}),
			mustContain: []ChangeReason{ReasonDispositionChanged},
		},
		{
			name: "detects dispositionChanged when disposition added",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				d := hdf.FalsePositive
				r.Disposition = &d
			}),
			mustContain: []ChangeReason{ReasonDispositionChanged},
		},
		{
			name: "no dispositionChanged when disposition is the same",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				d := hdf.OverrideTypeWaiver
				r.Disposition = &d
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				d := hdf.OverrideTypeWaiver
				r.Disposition = &d
			}),
			expected: []ChangeReason{},
		},
		{
			name: "detects effectiveImpactChanged when effectiveImpact differs",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				ei := 0.7
				r.EffectiveImpact = &ei
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			mustContain: []ChangeReason{ReasonEffectiveImpactChanged},
		},
		{
			name: "detects effectiveImpactChanged when effectiveImpact added",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			mustContain: []ChangeReason{ReasonEffectiveImpactChanged},
		},
		{
			name: "no effectiveImpactChanged when effectiveImpact is the same",
			oldReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			newReq: stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
				ei := 0.3
				r.EffectiveImpact = &ei
			}),
			expected: []ChangeReason{},
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
		expected RequirementState
	}{
		{
			name:     "fixed when failed -> passed",
			oldStat:  stStatusFailed,
			newStat:  stStatusPassed,
			expected: StateFixed,
		},
		{
			name:     "fixed when error -> passed",
			oldStat:  statusError,
			newStat:  stStatusPassed,
			expected: StateFixed,
		},
		{
			name:     "regressed when passed -> failed",
			oldStat:  stStatusPassed,
			newStat:  stStatusFailed,
			expected: StateRegressed,
		},
		{
			name:     "regressed when passed -> error",
			oldStat:  stStatusPassed,
			newStat:  statusError,
			expected: StateRegressed,
		},
		{
			name:     "unchanged when passed -> passed",
			oldStat:  stStatusPassed,
			newStat:  stStatusPassed,
			expected: StateUnchanged,
		},
		{
			name:     "unchanged when failed -> failed",
			oldStat:  stStatusFailed,
			newStat:  stStatusFailed,
			expected: StateUnchanged,
		},
		{
			name:     "updated when notReviewed -> notApplicable",
			oldStat:  statusNotReviewed,
			newStat:  statusNotAppl,
			expected: StateUpdated,
		},
		{
			name:     "updated when failed -> notApplicable",
			oldStat:  stStatusFailed,
			newStat:  statusNotAppl,
			expected: StateUpdated,
		},
		{
			name:     "fixed when notReviewed -> passed (notReviewed is failing)",
			oldStat:  statusNotReviewed,
			newStat:  stStatusPassed,
			expected: StateFixed,
		},
		{
			name:     "regressed when passed -> notReviewed",
			oldStat:  stStatusPassed,
			newStat:  statusNotReviewed,
			expected: StateRegressed,
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

func TestComputeEffectiveStatus_MostRecentOverrideGoverns(t *testing.T) {
	// Two non-expired overrides: the most recently applied governs regardless
	// of array order (schema: disposition is "the most recent non-expired
	// override").
	req := stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
		r.StatusOverrides = []hdf.StatusOverride{
			stMakeOverride(struct {
				Type      string
				Status    hdf.ResultStatus
				Reason    string
				AppliedAt time.Time
				ExpiresAt time.Time
			}{
				Status:    hdf.Passed,
				AppliedAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			}),
			stMakeOverride(struct {
				Type      string
				Status    hdf.ResultStatus
				Reason    string
				AppliedAt time.Time
				ExpiresAt time.Time
			}{
				Status:    hdf.NotApplicable,
				AppliedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
			}),
		}
	})
	if got := ComputeEffectiveStatus(req, "2026-01-01T00:00:00Z"); got != stStatusPassed {
		t.Errorf("got %q, want the later-applied override's status %q", got, stStatusPassed)
	}
}

func TestComputeEffectiveStatus_CanonicalOrdering(t *testing.T) {
	// The canonical worst-wins ordering (status-determination.md) ranks
	// notApplicable above notReviewed: a mixed NA+NR result set rolls up to
	// notApplicable.
	req := stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Results = []hdf.RequirementResult{
			stMakeResult(hdf.NotReviewed),
			stMakeResult(hdf.NotApplicable),
		}
	})
	if got := ComputeEffectiveStatus(req, ""); got != statusNotAppl {
		t.Errorf("NA+NR rollup = %q, want %q", got, statusNotAppl)
	}
}

// ---------------------------------------------------------------------------
// Coverage: ComputeEffectiveStatus — bad referenceTimestamp falls back to now
// ---------------------------------------------------------------------------

func TestComputeEffectiveStatus_BadReferenceTimestamp(t *testing.T) {
	req := stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Results = []hdf.RequirementResult{stMakeResult(hdf.Failed)}
		r.StatusOverrides = []hdf.StatusOverride{
			stMakeOverride(struct {
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
	if got != stStatusPassed {
		t.Errorf("ComputeEffectiveStatus with bad timestamp = %q, want %q", got, stStatusPassed)
	}
}

// ---------------------------------------------------------------------------
// Note: TestComputeEffectiveStatus_ResultWithNilStatus removed — canonical
// RequirementResult.Status is a value type (not pointer), so nil is not possible.

// ---------------------------------------------------------------------------
// Coverage: ComputeEffectiveStatus — result with unknown status
// ---------------------------------------------------------------------------

func TestComputeEffectiveStatus_UnknownResultStatus(t *testing.T) {
	unknownStatus := hdf.ResultStatus("customUnknown")
	req := stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Results = []hdf.RequirementResult{
			{Status: unknownStatus, CodeDesc: "unknown", StartTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
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
		stMakeResult(hdf.Failed),
		stMakeResult(hdf.Passed),
		stMakeResult(hdf.Error),
	})
	if len(statuses) != 3 {
		t.Fatalf("expected 3, got %d", len(statuses))
	}
	// Should be sorted
	if statuses[0] != statusError {
		t.Errorf("expected sorted[0]=%q, got %q", statusError, statuses[0])
	}
	if statuses[1] != stStatusFailed {
		t.Errorf("expected sorted[1]=%q, got %q", stStatusFailed, statuses[1])
	}
	if statuses[2] != stStatusPassed {
		t.Errorf("expected sorted[2]=%q, got %q", stStatusPassed, statuses[2])
	}
}

// Note: TestExtractSortedStatuses_NilStatusSkipped removed — canonical
// RequirementResult.Status is a value type (not pointer), so nil is not possible.
