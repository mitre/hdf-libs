package diff

import (
	"encoding/json"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirementStateConstants(t *testing.T) {
	tests := []struct {
		got  RequirementState
		want string
	}{
		{StateNew, "new"},
		{StateAbsent, "absent"},
		{StateUnchanged, "unchanged"},
		{StateUpdated, "updated"},
		{StateFixed, "fixed"},
		{StateRegressed, "regressed"},
		{StateMoved, "moved"},
		{StateSplit, "split"},
		{StateMerged, "merged"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, string(tt.got), "RequirementState constant %q", tt.want)
	}
}

func TestChangeReasonConstants(t *testing.T) {
	tests := []struct {
		got  ChangeReason
		want string
	}{
		{ReasonResultChanged, "resultChanged"},
		{ReasonOverrideAdded, "overrideAdded"},
		{ReasonOverrideExpired, "overrideExpired"},
		{ReasonOverrideRemoved, "overrideRemoved"},
		{ReasonOverrideModified, "overrideModified"},
		{ReasonImpactChanged, "impactChanged"},
		{ReasonBaselineUpgraded, "baselineUpgraded"},
		{ReasonControlMapped, "controlMapped"},
		{ReasonScannerChanged, "scannerChanged"},
		{ReasonTargetChanged, "targetChanged"},
		{ReasonConfigChanged, "configChanged"},
		{ReasonMetadataChanged, "metadataChanged"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, string(tt.got), "ChangeReason constant %q", tt.want)
	}
}

func TestComparisonModeConstants(t *testing.T) {
	tests := []struct {
		got  ComparisonMode
		want string
	}{
		{ModeTemporal, "temporal"},
		{ModeBaseline, "baseline"},
		{ModeFleet, "fleet"},
		{ModeMultiSource, "multiSource"},
		{ModeBaselineEvolution, "baselineEvolution"},
		{ModeSystemDrift, "systemDrift"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, string(tt.got), "ComparisonMode constant %q", tt.want)
	}
}

func TestSourceRoleConstants(t *testing.T) {
	tests := []struct {
		got  SourceRole
		want string
	}{
		{RoleOld, "old"},
		{RoleNew, "new"},
		{RoleGolden, "golden"},
		{RoleReference, "reference"},
		{RoleSystem, "system"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, string(tt.got), "SourceRole constant %q", tt.want)
	}
}

func TestFieldChangeOpConstants(t *testing.T) {
	tests := []struct {
		got  FieldChangeOp
		want string
	}{
		{OpAdd, "add"},
		{OpRemove, "remove"},
		{OpReplace, "replace"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, string(tt.got), "FieldChangeOp constant %q", tt.want)
	}
}

func TestHdfComparisonMarshal(t *testing.T) {
	comparison := HdfComparison{
		FormatVersion:  "1.0.0",
		ComparisonMode: ModeTemporal,
		Timestamp:      "2026-03-14T00:00:00Z",
		Sources: []Source{
			{Role: RoleOld, Label: "scan-2026-01"},
			{Role: RoleNew, Label: "scan-2026-03"},
		},
		Summary: ComparisonSummary{
			Fixed:     1,
			Regressed: 2,
			Total:     10,
		},
		BaselineDiffs:    make([]BaselineDiff, 0),
		RequirementDiffs: make([]RequirementDiff, 0),
	}

	data, err := json.Marshal(comparison)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "1.0.0", parsed["formatVersion"])
	assert.Equal(t, "temporal", parsed["comparisonMode"])
	assert.Equal(t, "2026-03-14T00:00:00Z", parsed["timestamp"])
	assert.Len(t, parsed["sources"], 2)

	summary := parsed["summary"].(map[string]any)
	assert.Equal(t, float64(1), summary["fixed"])
	assert.Equal(t, float64(2), summary["regressed"])
	assert.Equal(t, float64(10), summary["total"])

	// Empty slices must marshal as [] not null
	assert.Equal(t, []any{}, parsed["baselineDiffs"])
	assert.Equal(t, []any{}, parsed["requirementDiffs"])
}

func TestHdfComparisonUnmarshal(t *testing.T) {
	jsonStr := `{
		"formatVersion": "1.0.0",
		"comparisonMode": "baseline",
		"timestamp": "2026-03-14T12:00:00Z",
		"sources": [
			{"role": "golden", "label": "golden-baseline", "uri": "file:///golden.json"},
			{"role": "system", "label": "system-scan"}
		],
		"summary": {
			"fixed": 3,
			"regressed": 1,
			"new": 2,
			"absent": 0,
			"unchanged": 50,
			"updated": 4,
			"total": 60,
			"matchedCount": 55,
			"unmatchedOldCount": 0,
			"unmatchedNewCount": 5
		},
		"baselineDiffs": [
			{"name": "my-baseline", "oldVersion": "1.0", "newVersion": "2.0", "state": "updated"}
		],
		"requirementDiffs": []
	}`

	var comparison HdfComparison
	err := json.Unmarshal([]byte(jsonStr), &comparison)
	require.NoError(t, err)

	assert.Equal(t, "1.0.0", comparison.FormatVersion)
	assert.Equal(t, ModeBaseline, comparison.ComparisonMode)
	assert.Equal(t, "2026-03-14T12:00:00Z", comparison.Timestamp)
	assert.Len(t, comparison.Sources, 2)
	assert.Equal(t, RoleGolden, comparison.Sources[0].Role)
	assert.Equal(t, "golden-baseline", comparison.Sources[0].Label)
	assert.Equal(t, "file:///golden.json", comparison.Sources[0].URI)
	assert.Equal(t, RoleSystem, comparison.Sources[1].Role)

	assert.Equal(t, 3, comparison.Summary.Fixed)
	assert.Equal(t, 1, comparison.Summary.Regressed)
	assert.Equal(t, 2, comparison.Summary.New)
	assert.Equal(t, 0, comparison.Summary.Absent)
	assert.Equal(t, 50, comparison.Summary.Unchanged)
	assert.Equal(t, 4, comparison.Summary.Updated)
	assert.Equal(t, 60, comparison.Summary.Total)
	assert.Equal(t, 55, comparison.Summary.MatchedCount)
	assert.Equal(t, 0, comparison.Summary.UnmatchedOldCount)
	assert.Equal(t, 5, comparison.Summary.UnmatchedNewCount)

	require.Len(t, comparison.BaselineDiffs, 1)
	assert.Equal(t, "my-baseline", comparison.BaselineDiffs[0].Name)
	assert.Equal(t, "1.0", comparison.BaselineDiffs[0].OldVersion)
	assert.Equal(t, "2.0", comparison.BaselineDiffs[0].NewVersion)
	assert.Equal(t, StateUpdated, comparison.BaselineDiffs[0].State)

	assert.Empty(t, comparison.RequirementDiffs)
}

func TestRequirementDiffNilBeforeMarshal(t *testing.T) {
	diff := RequirementDiff{
		ID:            "SV-001",
		State:         StateNew,
		ChangeReasons: make([]ChangeReason, 0),
		Before:        nil,
		After:         &hdf.EvaluatedRequirement{ID: "SV-001", Impact: 0.7},
		FieldChanges:  make([]FieldChange, 0),
	}

	data, err := json.Marshal(diff)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	// "before" must be present as null, not omitted
	_, hasBefore := parsed["before"]
	assert.True(t, hasBefore, "before field must be present in JSON (as null)")
	assert.Nil(t, parsed["before"], "before field must be null")

	// "after" must be present and non-null
	_, hasAfter := parsed["after"]
	assert.True(t, hasAfter, "after field must be present in JSON")
	assert.NotNil(t, parsed["after"], "after field must not be null")

	afterMap := parsed["after"].(map[string]any)
	assert.Equal(t, "SV-001", afterMap["id"])
	assert.Equal(t, 0.7, afterMap["impact"])
}

func TestRequirementDiffWithBeforeMarshal(t *testing.T) {
	oldImpact := 0.5
	newImpact := 0.7

	diff := RequirementDiff{
		ID:                 "SV-002",
		State:              StateUpdated,
		ChangeReasons:      []ChangeReason{ReasonImpactChanged},
		Before:             &hdf.EvaluatedRequirement{ID: "SV-002", Impact: 0.5},
		After:              &hdf.EvaluatedRequirement{ID: "SV-002", Impact: 0.7},
		Title:              "Check file permissions",
		OldEffectiveStatus: "passed",
		NewEffectiveStatus: "passed",
		OldImpact:          &oldImpact,
		NewImpact:          &newImpact,
		FieldChanges: []FieldChange{
			{Op: OpReplace, Path: "impact", OldValue: 0.5, NewValue: 0.7},
		},
		MatchStrategy: "exactId",
	}

	data, err := json.Marshal(diff)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "SV-002", parsed["id"])
	assert.Equal(t, "updated", parsed["state"])
	assert.NotNil(t, parsed["before"])
	assert.NotNil(t, parsed["after"])
	assert.Equal(t, "Check file permissions", parsed["title"])
	assert.Equal(t, "passed", parsed["oldEffectiveStatus"])
	assert.Equal(t, "passed", parsed["newEffectiveStatus"])
	assert.Equal(t, 0.5, parsed["oldImpact"])
	assert.Equal(t, 0.7, parsed["newImpact"])

	reasons := parsed["changeReasons"].([]any)
	assert.Equal(t, "impactChanged", reasons[0])

	changes := parsed["fieldChanges"].([]any)
	require.Len(t, changes, 1)
	change := changes[0].(map[string]any)
	assert.Equal(t, "replace", change["op"])
	assert.Equal(t, "impact", change["path"])
	assert.Equal(t, 0.5, change["oldValue"])
	assert.Equal(t, 0.7, change["newValue"])

	assert.Equal(t, "exactId", parsed["matchStrategy"])
}

func TestFieldChangeMarshal(t *testing.T) {
	tests := []struct {
		name       string
		fc         FieldChange
		wantOp     string
		wantPath   string
		wantOld    any
		wantNew    any
		oldOmitted bool
		newOmitted bool
	}{
		{
			name:       "add omits oldValue",
			fc:         FieldChange{Op: OpAdd, Path: "tags.cci", NewValue: "CCI-001234"},
			wantOp:     "add",
			wantPath:   "tags.cci",
			wantNew:    "CCI-001234",
			oldOmitted: true,
		},
		{
			name:       "remove omits newValue",
			fc:         FieldChange{Op: OpRemove, Path: "tags.legacy", OldValue: "old-tag-value"},
			wantOp:     "remove",
			wantPath:   "tags.legacy",
			wantOld:    "old-tag-value",
			newOmitted: true,
		},
		{
			name:     "replace includes both oldValue and newValue",
			fc:       FieldChange{Op: OpReplace, Path: "title", OldValue: "Old Title", NewValue: "New Title"},
			wantOp:   "replace",
			wantPath: "title",
			wantOld:  "Old Title",
			wantNew:  "New Title",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.fc)
			require.NoError(t, err)

			var parsed map[string]any
			err = json.Unmarshal(data, &parsed)
			require.NoError(t, err)

			assert.Equal(t, tt.wantOp, parsed["op"])
			assert.Equal(t, tt.wantPath, parsed["path"])

			if tt.oldOmitted {
				_, hasOld := parsed["oldValue"]
				assert.False(t, hasOld, "oldValue should be omitted for %s operations", tt.wantOp)
			} else {
				assert.Equal(t, tt.wantOld, parsed["oldValue"])
			}

			if tt.newOmitted {
				_, hasNew := parsed["newValue"]
				assert.False(t, hasNew, "newValue should be omitted for %s operations", tt.wantOp)
			} else {
				assert.Equal(t, tt.wantNew, parsed["newValue"])
			}
		})
	}
}

func TestComparisonSummaryDefaults(t *testing.T) {
	var summary ComparisonSummary

	assert.Equal(t, 0, summary.Fixed)
	assert.Equal(t, 0, summary.Regressed)
	assert.Equal(t, 0, summary.New)
	assert.Equal(t, 0, summary.Absent)
	assert.Equal(t, 0, summary.Unchanged)
	assert.Equal(t, 0, summary.Updated)
	assert.Equal(t, 0, summary.Total)
	assert.Equal(t, 0, summary.MatchedCount)
	assert.Equal(t, 0, summary.UnmatchedOldCount)
	assert.Equal(t, 0, summary.UnmatchedNewCount)
}

func TestHdfComparisonRoundTrip(t *testing.T) {
	oldImpact := 0.7
	confidence := 1.0
	sourceIdx := 0

	original := HdfComparison{
		FormatVersion:  "1.0.0",
		ComparisonMode: ModeFleet,
		Timestamp:      "2026-03-14T00:00:00Z",
		Sources: []Source{
			{
				Role:                RoleOld,
				Label:               "system-a",
				URI:                 "file:///a.json",
				OriginalFormat:      "hdf-results-v2",
				AssessmentTimestamp: "2026-03-13T10:00:00Z",
			},
			{
				Role:  RoleNew,
				Label: "system-b",
			},
		},
		Matching: &MatchingConfig{
			PrimaryStrategy:     "exactId",
			ConfidenceThreshold: 0.8,
		},
		Summary: ComparisonSummary{
			Fixed:             2,
			Regressed:         1,
			New:               3,
			Absent:            0,
			Unchanged:         44,
			Updated:           5,
			Total:             55,
			MatchedCount:      50,
			UnmatchedOldCount: 0,
			UnmatchedNewCount: 5,
		},
		BaselineDiffs: []BaselineDiff{
			{
				Name:       "stig-baseline",
				OldVersion: "v1",
				NewVersion: "v2",
				State:      StateUpdated,
			},
		},
		RequirementDiffs: []RequirementDiff{
			{
				ID:              "SV-100",
				State:           StateFixed,
				ChangeReasons:   []ChangeReason{ReasonResultChanged},
				Before:          &hdf.EvaluatedRequirement{ID: "SV-100", Impact: 0.7},
				After:           &hdf.EvaluatedRequirement{ID: "SV-100", Impact: 0.7},
				OldImpact:       &oldImpact,
				NewImpact:       &oldImpact,
				FieldChanges:    make([]FieldChange, 0),
				MatchStrategy:   "exactId",
				MatchConfidence: &confidence,
				SourceIndex:     &sourceIdx,
			},
		},
		Annotations: map[string]Annotation{
			"SV-100": {
				Label:     "note",
				Text:      "Fixed by deploy #42",
				Timestamp: "2026-03-14T00:00:00Z",
			},
		},
		Extensions: map[string]any{
			"customTool": "myScanner",
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var roundTripped HdfComparison
	err = json.Unmarshal(data, &roundTripped)
	require.NoError(t, err)

	// Verify top-level fields
	assert.Equal(t, original.FormatVersion, roundTripped.FormatVersion)
	assert.Equal(t, original.ComparisonMode, roundTripped.ComparisonMode)
	assert.Equal(t, original.Timestamp, roundTripped.Timestamp)

	// Verify sources
	require.Len(t, roundTripped.Sources, 2)
	assert.Equal(t, original.Sources[0].Role, roundTripped.Sources[0].Role)
	assert.Equal(t, original.Sources[0].Label, roundTripped.Sources[0].Label)
	assert.Equal(t, original.Sources[0].URI, roundTripped.Sources[0].URI)
	assert.Equal(t, original.Sources[0].OriginalFormat, roundTripped.Sources[0].OriginalFormat)
	assert.Equal(t, original.Sources[0].AssessmentTimestamp, roundTripped.Sources[0].AssessmentTimestamp)
	assert.Equal(t, original.Sources[1].Role, roundTripped.Sources[1].Role)
	assert.Equal(t, original.Sources[1].Label, roundTripped.Sources[1].Label)

	// Verify matching
	require.NotNil(t, roundTripped.Matching)
	assert.Equal(t, original.Matching.PrimaryStrategy, roundTripped.Matching.PrimaryStrategy)
	assert.Equal(t, original.Matching.ConfidenceThreshold, roundTripped.Matching.ConfidenceThreshold)

	// Verify summary
	assert.Equal(t, original.Summary, roundTripped.Summary)

	// Verify baseline diffs
	require.Len(t, roundTripped.BaselineDiffs, 1)
	assert.Equal(t, original.BaselineDiffs[0], roundTripped.BaselineDiffs[0])

	// Verify requirement diffs
	require.Len(t, roundTripped.RequirementDiffs, 1)
	rd := roundTripped.RequirementDiffs[0]
	assert.Equal(t, "SV-100", rd.ID)
	assert.Equal(t, StateFixed, rd.State)
	assert.Equal(t, []ChangeReason{ReasonResultChanged}, rd.ChangeReasons)
	require.NotNil(t, rd.Before)
	assert.Equal(t, "SV-100", rd.Before.ID)
	assert.Equal(t, 0.7, rd.Before.Impact)
	require.NotNil(t, rd.After)
	assert.Equal(t, "SV-100", rd.After.ID)
	require.NotNil(t, rd.OldImpact)
	assert.Equal(t, 0.7, *rd.OldImpact)
	require.NotNil(t, rd.NewImpact)
	assert.Equal(t, 0.7, *rd.NewImpact)
	assert.Empty(t, rd.FieldChanges)
	assert.Equal(t, "exactId", rd.MatchStrategy)
	require.NotNil(t, rd.MatchConfidence)
	assert.Equal(t, 1.0, *rd.MatchConfidence)
	require.NotNil(t, rd.SourceIndex)
	assert.Equal(t, 0, *rd.SourceIndex)

	// Verify annotations
	require.Contains(t, roundTripped.Annotations, "SV-100")
	ann := roundTripped.Annotations["SV-100"]
	assert.Equal(t, "note", ann.Label)
	assert.Equal(t, "Fixed by deploy #42", ann.Text)
	assert.Equal(t, "2026-03-14T00:00:00Z", ann.Timestamp)

	// Verify extensions
	require.Contains(t, roundTripped.Extensions, "customTool")
	assert.Equal(t, "myScanner", roundTripped.Extensions["customTool"])
}

func TestEmptySlicesMarshalAsArrayNotNull(t *testing.T) {
	diff := RequirementDiff{
		ID:            "SV-999",
		State:         StateUnchanged,
		ChangeReasons: make([]ChangeReason, 0),
		Before:        &hdf.EvaluatedRequirement{ID: "SV-999"},
		After:         &hdf.EvaluatedRequirement{ID: "SV-999"},
		FieldChanges:  make([]FieldChange, 0),
	}

	data, err := json.Marshal(diff)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	// changeReasons must be [] not null
	reasons, ok := parsed["changeReasons"].([]any)
	assert.True(t, ok, "changeReasons must be a JSON array")
	assert.Empty(t, reasons)

	// fieldChanges must be [] not null
	changes, ok := parsed["fieldChanges"].([]any)
	assert.True(t, ok, "fieldChanges must be a JSON array")
	assert.Empty(t, changes)
}

func TestRequirementDiffNilAfterMarshal(t *testing.T) {
	diff := RequirementDiff{
		ID:            "SV-003",
		State:         StateAbsent,
		ChangeReasons: make([]ChangeReason, 0),
		Before:        &hdf.EvaluatedRequirement{ID: "SV-003", Impact: 0.5},
		After:         nil,
		FieldChanges:  make([]FieldChange, 0),
	}

	data, err := json.Marshal(diff)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	// "after" must be present as null, not omitted
	_, hasAfter := parsed["after"]
	assert.True(t, hasAfter, "after field must be present in JSON (as null)")
	assert.Nil(t, parsed["after"], "after field must be null")

	// "before" must be present and non-null
	_, hasBefore := parsed["before"]
	assert.True(t, hasBefore, "before field must be present in JSON")
	assert.NotNil(t, parsed["before"], "before field must not be null")
}
