package testhdf

import (
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// DefaultExpiry is a far-future, never-expired override/milestone deadline
// (per the repo's no-time-bomb rule), used by the amendment builders.
var DefaultExpiry = time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)

// ===== HDF Baseline =====

// BaselineReqOption configures a BaselineRequirement built by BaselineReq.
type BaselineReqOption func(*hdf.BaselineRequirement)

// BaselineReq builds a schema-valid BaselineRequirement (a requirement without
// results — the hdf-baseline shape) with defaults: impact 0, empty tags, one
// "default" description.
func BaselineReq(id string, opts ...BaselineReqOption) hdf.BaselineRequirement {
	r := hdf.BaselineRequirement{
		ID:           id,
		Impact:       0,
		Tags:         map[string]any{},
		Descriptions: []hdf.Description{{Label: "default", Data: id}},
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

// BaselineImpact sets the baseline requirement impact.
func BaselineImpact(v float64) BaselineReqOption {
	return func(r *hdf.BaselineRequirement) { r.Impact = v }
}

// BaselineDoc builds a schema-valid HDFBaseline document (requirements without
// results) with the given name.
func BaselineDoc(name string, reqs ...hdf.BaselineRequirement) hdf.HDFBaseline {
	return hdf.HDFBaseline{Name: name, Requirements: reqs}
}

// ===== HDF Amendments =====

// OverrideOption configures a StandaloneOverride built by Override.
type OverrideOption func(*hdf.StandaloneOverride)

// Override builds a schema-valid StandaloneOverride with defaults: applied now,
// expires far-future (never expired), applied by a simple "test" identity.
func Override(overrideType hdf.OverrideType, reqID string, opts ...OverrideOption) hdf.StandaloneOverride {
	o := hdf.StandaloneOverride{
		Type:          overrideType,
		RequirementID: reqID,
		AppliedAt:     DefaultStartTime,
		ExpiresAt:     DefaultExpiry,
		AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "test"},
		Reason:        "test override",
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// OverrideStatus sets the override's effective status.
func OverrideStatus(s hdf.ResultStatus) OverrideOption {
	return func(o *hdf.StandaloneOverride) { o.Status = &s }
}

// OverrideReason sets the override justification.
func OverrideReason(reason string) OverrideOption {
	return func(o *hdf.StandaloneOverride) { o.Reason = reason }
}

// OverrideBy sets who applied the override.
func OverrideBy(idType hdf.IdentityType, identifier string) OverrideOption {
	return func(o *hdf.StandaloneOverride) {
		o.AppliedBy = hdf.Identity{Type: idType, Identifier: identifier}
	}
}

// Amendments builds a schema-valid HDFAmendments document with the given name
// and overrides.
func Amendments(name string, overrides ...hdf.StandaloneOverride) hdf.HDFAmendments {
	return hdf.HDFAmendments{Name: name, Overrides: overrides}
}

// ===== HDF System =====

// ComponentOption configures a Component built by Component.
type ComponentOption func(*hdf.Component)

// Component builds a schema-valid Component with the given name and type.
func Component(name string, targetType hdf.TargetType, opts ...ComponentOption) hdf.Component {
	c := hdf.Component{Name: name, Type: targetType}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// System builds a schema-valid HDFSystem document with the given name and
// components.
func System(name string, components ...hdf.Component) hdf.HDFSystem {
	return hdf.HDFSystem{Name: name, Components: components}
}

// ===== HDF Plan =====

// Assessment builds a schema-valid Assessment referencing a baseline.
func Assessment(baselineRef string) hdf.Assessment {
	return hdf.Assessment{BaselineRef: baselineRef}
}

// Plan builds a schema-valid HDFPlan document with the given name and
// assessments.
func Plan(name string, assessments ...hdf.Assessment) hdf.HDFPlan {
	return hdf.HDFPlan{Name: name, Assessments: assessments}
}

// ===== HDF Evidence Package =====

// Content builds a schema-valid ContentReference (one bundle entry).
func Content(uri string, contentType hdf.ContentType) hdf.ContentReference {
	return hdf.ContentReference{URI: uri, Type: contentType}
}

// EvidencePackage builds a schema-valid HDFEvidencePackage document with the
// given name and content references.
func EvidencePackage(name string, contents ...hdf.ContentReference) hdf.HDFEvidencePackage {
	return hdf.HDFEvidencePackage{Name: name, Contents: contents}
}

// ===== HDF Requirement Change Event =====

// EventOption configures an HDFRequirementChangeEvent built by ChangeEvent.
type EventOption func(*hdf.HDFRequirementChangeEvent)

// ChangeEvent builds a schema-valid HDFRequirementChangeEvent with defaults for
// the many required envelope fields (fixed UUIDs, sequence 1, updated state).
func ChangeEvent(reqID string, opts ...EventOption) hdf.HDFRequirementChangeEvent {
	e := hdf.HDFRequirementChangeEvent{
		RequirementID: reqID,
		EventID:       "00000000-0000-4000-8000-000000000001",
		ComponentID:   "00000000-0000-4000-8000-000000000002",
		SystemRef:     "test-system",
		Source:        "test",
		Sequence:      1,
		Timestamp:     DefaultStartTime,
		// Default to a "new" event: nothing existed before, and after is a full
		// requirement (the shape the schema's per-state oneOf requires).
		State:         hdf.EventRequirementStateNew,
		Before:        nil,
		After:         Req(reqID),
		PriorChecksum: nil,
	}
	for _, o := range opts {
		o(&e)
	}
	return e
}

// EventState sets the change-event lifecycle state.
func EventState(s hdf.EventRequirementState) EventOption {
	return func(e *hdf.HDFRequirementChangeEvent) { e.State = s }
}

// EventBeforeAfter sets the before/after payloads.
func EventBeforeAfter(before, after any) EventOption {
	return func(e *hdf.HDFRequirementChangeEvent) { e.Before = before; e.After = after }
}

// ===== HDF Comparison =====

// Comparison builds a schema-valid HDFComparison document in the given mode
// with two default sources and an empty diff set.
func Comparison(mode hdf.ComparisonMode) hdf.HDFComparison {
	return hdf.HDFComparison{
		ComparisonMode:   mode,
		FormatVersion:    hdf.The100,
		Sources:          []hdf.Source{{Label: "old", Role: hdf.Old}, {Label: "new", Role: hdf.SourceRoleNew}},
		RequirementDiffs: []hdf.RequirementDiff{},
		Summary:          hdf.ComparisonSummary{Total: 0, MatchedCount: 0, UnmatchedNewCount: 0, UnmatchedOldCount: 0},
	}
}
