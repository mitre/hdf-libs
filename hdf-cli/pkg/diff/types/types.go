// Package types defines the comparison-specific types for the HDF diff library.
//
// These types mirror the TypeScript definitions in hdf-diff/src/types.ts and conform
// to the hdf-comparison JSON schema. They are used by the diff engine to represent
// the result of comparing two or more HDF evaluation documents.
package types

import (
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// RequirementState classifies how a requirement changed between evaluations.
// Uses SARIF-inspired vocabulary.
type RequirementState string

// RequirementState values.
const (
	StateNew       RequirementState = "new"
	StateAbsent    RequirementState = "absent"
	StateUnchanged RequirementState = "unchanged"
	StateUpdated   RequirementState = "updated"
	StateFixed     RequirementState = "fixed"
	StateRegressed RequirementState = "regressed"
	StateMoved     RequirementState = "moved"  // reserved v1.1
	StateSplit     RequirementState = "split"  // reserved v1.1
	StateMerged    RequirementState = "merged" // reserved v1.1
)

// ChangeReason describes why a requirement's effective status changed.
type ChangeReason string

// ChangeReason values.
const (
	ReasonResultChanged          ChangeReason = "resultChanged"
	ReasonOverrideAdded          ChangeReason = "overrideAdded"
	ReasonOverrideExpired        ChangeReason = "overrideExpired"
	ReasonOverrideRemoved        ChangeReason = "overrideRemoved"
	ReasonOverrideModified       ChangeReason = "overrideModified"
	ReasonImpactChanged          ChangeReason = "impactChanged"
	ReasonBaselineUpgraded       ChangeReason = "baselineUpgraded"
	ReasonControlMapped          ChangeReason = "controlMapped"
	ReasonScannerChanged         ChangeReason = "scannerChanged"
	ReasonTargetChanged          ChangeReason = "targetChanged"
	ReasonConfigChanged          ChangeReason = "configChanged"
	ReasonMetadataChanged        ChangeReason = "metadataChanged"
	ReasonDispositionChanged     ChangeReason = "dispositionChanged"
	ReasonEffectiveImpactChanged ChangeReason = "effectiveImpactChanged"
)

// ComparisonMode defines how two documents are compared.
type ComparisonMode string

// ComparisonMode values.
const (
	ModeTemporal          ComparisonMode = "temporal"
	ModeBaseline          ComparisonMode = "baseline"
	ModeFleet             ComparisonMode = "fleet"
	ModeMultiSource       ComparisonMode = "multiSource"
	ModeBaselineEvolution ComparisonMode = "baselineEvolution"
	ModeSystemDrift       ComparisonMode = "systemDrift"
)

// SourceRole defines the role of a source document.
type SourceRole string

// SourceRole values.
const (
	RoleOld       SourceRole = "old"
	RoleNew       SourceRole = "new"
	RoleGolden    SourceRole = "golden"
	RoleReference SourceRole = "reference"
	RoleSystem    SourceRole = "system"
)

// FieldChangeOp defines the operation type for a field-level change.
type FieldChangeOp string

// FieldChangeOp values.
const (
	OpAdd     FieldChangeOp = "add"
	OpRemove  FieldChangeOp = "remove"
	OpReplace FieldChangeOp = "replace"
)

// FieldChange represents a field-level difference on a requirement,
// following JSON Patch-like conventions.
type FieldChange struct {
	Op       FieldChangeOp `json:"op"`
	Path     string        `json:"path"`
	OldValue any           `json:"oldValue,omitempty"`
	NewValue any           `json:"newValue,omitempty"`
}

// Source holds metadata about a source document used in the comparison.
type Source struct {
	Role                SourceRole `json:"role"`
	Label               string     `json:"label"`
	URI                 string     `json:"uri,omitempty"`
	OriginalFormat      string     `json:"originalFormat,omitempty"`
	AssessmentTimestamp string     `json:"assessmentTimestamp,omitempty"`
}

// MatchingConfig describes how requirements were matched between evaluations.
type MatchingConfig struct {
	PrimaryStrategy     string  `json:"primaryStrategy"`
	ConfidenceThreshold float64 `json:"confidenceThreshold,omitempty"`
}

// RequirementDiff holds the comparison result for a single requirement.
type RequirementDiff struct {
	ID                 string                    `json:"id"`
	State              RequirementState          `json:"state"`
	ChangeReasons      []ChangeReason            `json:"changeReasons"`
	Before             *hdf.EvaluatedRequirement `json:"before"`
	After              *hdf.EvaluatedRequirement `json:"after"`
	Title              string                    `json:"title,omitempty"`
	Baseline           string                    `json:"baseline,omitempty"`
	OldEffectiveStatus string                    `json:"oldEffectiveStatus,omitempty"`
	NewEffectiveStatus string                    `json:"newEffectiveStatus,omitempty"`
	OldImpact          *float64                  `json:"oldImpact,omitempty"`
	NewImpact          *float64                  `json:"newImpact,omitempty"`
	FieldChanges       []FieldChange             `json:"fieldChanges"`
	MatchStrategy      string                    `json:"matchStrategy,omitempty"`
	MatchConfidence    *float64                  `json:"matchConfidence,omitempty"`
	SourceIndex        *int                      `json:"sourceIndex,omitempty"`
}

// ComponentDiff holds the comparison result for a single component
// between two system documents. Used in systemDrift mode.
type ComponentDiff struct {
	Name         string           `json:"name"`
	State        RequirementState `json:"state"`
	Before       map[string]any   `json:"before"`
	After        map[string]any   `json:"after"`
	FieldChanges []FieldChange    `json:"fieldChanges"`
}

// BaselineDiff holds the comparison result for a single baseline.
type BaselineDiff struct {
	Name       string           `json:"name"`
	OldVersion string           `json:"oldVersion,omitempty"`
	NewVersion string           `json:"newVersion,omitempty"`
	State      RequirementState `json:"state"`
}

// ComparisonSummary holds aggregate counts for the comparison.
type ComparisonSummary struct {
	Fixed             int `json:"fixed"`
	Regressed         int `json:"regressed"`
	New               int `json:"new"`
	Absent            int `json:"absent"`
	Unchanged         int `json:"unchanged"`
	Updated           int `json:"updated"`
	Total             int `json:"total"`
	MatchedCount      int `json:"matchedCount"`
	UnmatchedOldCount int `json:"unmatchedOldCount"`
	UnmatchedNewCount int `json:"unmatchedNewCount"`
}

// Annotation is an explanation attached to a requirement diff.
type Annotation struct {
	Label     string `json:"label"`
	Text      string `json:"text"`
	Timestamp string `json:"timestamp,omitempty"`
}

// HdfComparison is the top-level comparison document.
type HdfComparison struct {
	FormatVersion    string                `json:"formatVersion"`
	ComparisonMode   ComparisonMode        `json:"comparisonMode"`
	Timestamp        string                `json:"timestamp,omitempty"`
	Sources          []Source              `json:"sources"`
	Matching         *MatchingConfig       `json:"matching,omitempty"`
	Summary          ComparisonSummary     `json:"summary"`
	BaselineDiffs    []BaselineDiff        `json:"baselineDiffs"`
	RequirementDiffs []RequirementDiff     `json:"requirementDiffs"`
	ComponentDiffs   []ComponentDiff       `json:"componentDiffs,omitempty"`
	SystemRef        string                `json:"systemRef,omitempty"`
	Drift            []RequirementDiff     `json:"drift,omitempty"`
	Annotations      map[string]Annotation `json:"annotations,omitempty"`
	Extensions       map[string]any        `json:"extensions,omitempty"`
}
