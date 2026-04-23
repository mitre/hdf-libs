package render

import (
	"encoding/json"

	diff "github.com/mitre/hdf-libs/hdf-diff/go"
)

// jsonSummary is the shape emitted for DetailSummary.
type jsonSummary struct {
	FormatVersion  string                 `json:"formatVersion"`
	ComparisonMode diff.ComparisonMode    `json:"comparisonMode"`
	Summary        diff.ComparisonSummary `json:"summary"`
}

// strippedRequirementDiff is a RequirementDiff without Before/After snapshots.
type strippedRequirementDiff struct {
	ID                 string                `json:"id"`
	State              diff.RequirementState `json:"state"`
	ChangeReasons      []diff.ChangeReason   `json:"changeReasons"`
	Title              string                `json:"title,omitempty"`
	OldEffectiveStatus string                `json:"oldEffectiveStatus,omitempty"`
	NewEffectiveStatus string                `json:"newEffectiveStatus,omitempty"`
	OldImpact          *float64              `json:"oldImpact,omitempty"`
	NewImpact          *float64              `json:"newImpact,omitempty"`
	FieldChanges       []diff.FieldChange    `json:"fieldChanges"`
	MatchStrategy      string                `json:"matchStrategy,omitempty"`
	MatchConfidence    *float64              `json:"matchConfidence,omitempty"`
	SourceIndex        *int                  `json:"sourceIndex,omitempty"`
}

// strippedComparison mirrors HdfComparison but uses strippedRequirementDiff.
type strippedComparison struct {
	FormatVersion    string                     `json:"formatVersion"`
	ComparisonMode   diff.ComparisonMode        `json:"comparisonMode"`
	Timestamp        string                     `json:"timestamp,omitempty"`
	Sources          []diff.Source              `json:"sources"`
	Matching         *diff.MatchingConfig       `json:"matching,omitempty"`
	Summary          diff.ComparisonSummary     `json:"summary"`
	BaselineDiffs    []diff.BaselineDiff        `json:"baselineDiffs"`
	RequirementDiffs []strippedRequirementDiff  `json:"requirementDiffs"`
	Drift            []diff.RequirementDiff     `json:"drift,omitempty"`
	Annotations      map[string]diff.Annotation `json:"annotations,omitempty"`
	Extensions       map[string]any             `json:"extensions,omitempty"`
}

// stripDiff converts a RequirementDiff to a strippedRequirementDiff (no Before/After).
func stripDiff(d diff.RequirementDiff) strippedRequirementDiff {
	return strippedRequirementDiff{
		ID:                 d.ID,
		State:              d.State,
		ChangeReasons:      d.ChangeReasons,
		Title:              d.Title,
		OldEffectiveStatus: d.OldEffectiveStatus,
		NewEffectiveStatus: d.NewEffectiveStatus,
		OldImpact:          d.OldImpact,
		NewImpact:          d.NewImpact,
		FieldChanges:       d.FieldChanges,
		MatchStrategy:      d.MatchStrategy,
		MatchConfidence:    d.MatchConfidence,
		SourceIndex:        d.SourceIndex,
	}
}

// JSON renders an HdfComparison as a JSON string.
//
//   - DetailSummary: only formatVersion, comparisonMode, summary
//   - DetailControl: full document but Before/After stripped from requirementDiffs
//   - DetailFull: complete JSON with json.MarshalIndent
func JSON(comparison diff.HdfComparison, opts Options) (string, error) {
	detail := opts.effectiveDetail()

	if detail == DetailSummary {
		doc := jsonSummary{
			FormatVersion:  comparison.FormatVersion,
			ComparisonMode: comparison.ComparisonMode,
			Summary:        comparison.Summary,
		}
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	if detail == DetailFull {
		filtered := filterRequirements(comparison.RequirementDiffs, opts)
		if len(filtered) != len(comparison.RequirementDiffs) {
			out := comparison
			out.RequirementDiffs = filtered
			b, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
		b, err := json.MarshalIndent(comparison, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	// detail == DetailControl (default): strip Before/After
	filtered := filterRequirements(comparison.RequirementDiffs, opts)
	stripped := make([]strippedRequirementDiff, len(filtered))
	for i, d := range filtered {
		stripped[i] = stripDiff(d)
	}

	doc := strippedComparison{
		FormatVersion:    comparison.FormatVersion,
		ComparisonMode:   comparison.ComparisonMode,
		Timestamp:        comparison.Timestamp,
		Sources:          comparison.Sources,
		Matching:         comparison.Matching,
		Summary:          comparison.Summary,
		BaselineDiffs:    comparison.BaselineDiffs,
		RequirementDiffs: stripped,
		Drift:            comparison.Drift,
		Annotations:      comparison.Annotations,
		Extensions:       comparison.Extensions,
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
