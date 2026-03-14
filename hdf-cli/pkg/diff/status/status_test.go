package status

import (
	"testing"
	"time"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
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
		Status:    status,
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
		Tags:         map[string]interface{}{},
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
			expected: "passed",
		},
		{
			name: "returns failed for a single failing result with no overrides",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
			}),
			expected: "failed",
		},
		{
			name: "returns error for a single error result with no overrides",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Error)}
			}),
			expected: "error",
		},
		{
			name: "returns failed when results contain one passed and one failed (worst wins)",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{
					makeResult(hdf.Passed),
					makeResult(hdf.Failed),
				}
			}),
			expected: "failed",
		},
		{
			name: "returns error when results contain one error and one failed (worst wins)",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{
					makeResult(hdf.Error),
					makeResult(hdf.Failed),
				}
			}),
			expected: "error",
		},
		{
			name: "returns notReviewed for an empty results array",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{}
			}),
			expected: "notReviewed",
		},
		{
			name: "returns notApplicable when impact is 0 and there are no results",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Impact = 0
				r.Results = []hdf.RequirementResult{}
			}),
			expected: "notApplicable",
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
			expected:           "passed",
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
			expected:           "failed",
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
			expected:           "notReviewed",
		},
		{
			name: "uses effectiveStatus field directly when present and no overrides exist",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.EffectiveStatus = ptrResultStatus(hdf.Passed)
			}),
			expected: "passed",
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
			expected: "notApplicable",
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
			expected: "passed",
		},
		{
			name: "uses effectiveStatus when overrides array is empty",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Failed)}
				r.EffectiveStatus = ptrResultStatus(hdf.Passed)
				r.StatusOverrides = []hdf.StatusOverride{}
			}),
			expected: "passed",
		},
		{
			name: "returns notReviewed when results slice is nil",
			req: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = nil
			}),
			expected: "notReviewed",
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
				r.Tags = map[string]interface{}{"cci": []string{"CCI-000001"}}
			}),
			newReq: makeRequirement(func(r *hdf.EvaluatedRequirement) {
				r.Results = []hdf.RequirementResult{makeResult(hdf.Passed)}
				r.Tags = map[string]interface{}{"cci": []string{"CCI-000002"}}
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
			oldStat:  "failed",
			newStat:  "passed",
			expected: types.StateFixed,
		},
		{
			name:     "fixed when error -> passed",
			oldStat:  "error",
			newStat:  "passed",
			expected: types.StateFixed,
		},
		{
			name:     "regressed when passed -> failed",
			oldStat:  "passed",
			newStat:  "failed",
			expected: types.StateRegressed,
		},
		{
			name:     "regressed when passed -> error",
			oldStat:  "passed",
			newStat:  "error",
			expected: types.StateRegressed,
		},
		{
			name:     "unchanged when passed -> passed",
			oldStat:  "passed",
			newStat:  "passed",
			expected: types.StateUnchanged,
		},
		{
			name:     "unchanged when failed -> failed",
			oldStat:  "failed",
			newStat:  "failed",
			expected: types.StateUnchanged,
		},
		{
			name:     "updated when notReviewed -> notApplicable",
			oldStat:  "notReviewed",
			newStat:  "notApplicable",
			expected: types.StateUpdated,
		},
		{
			name:     "updated when failed -> notApplicable",
			oldStat:  "failed",
			newStat:  "notApplicable",
			expected: types.StateUpdated,
		},
		{
			name:     "fixed when notReviewed -> passed (notReviewed is failing)",
			oldStat:  "notReviewed",
			newStat:  "passed",
			expected: types.StateFixed,
		},
		{
			name:     "regressed when passed -> notReviewed",
			oldStat:  "passed",
			newStat:  "notReviewed",
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
