// Package testhdf builds minimal, schema-valid HDF Results documents for tests
// with sane defaults, so a test expresses its intent in one line instead of a
// nested HDFResults/EvaluatedBaseline/EvaluatedRequirement/RequirementResult
// struct literal. It is a test-support module (never shipped in dist/), so it
// lives beside the generated schema types rather than inside them.
//
// The common case is Results(Req("id", opts...)): a single "test" baseline
// wrapping one requirement with a default description and a notReviewed result.
// Reach for Doc/Baseline directly when a test needs multiple baselines.
package testhdf

import (
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// DefaultStartTime is the fixed, deterministic result start time used by the
// builder so tests never depend on the wall clock.
var DefaultStartTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// ReqOption configures an EvaluatedRequirement built by Req.
type ReqOption func(*hdf.EvaluatedRequirement)

// Req builds a schema-valid EvaluatedRequirement with defaults: impact 0, empty
// tags, a single "default" description (data = id), and one notReviewed result.
func Req(id string, opts ...ReqOption) hdf.EvaluatedRequirement {
	r := hdf.EvaluatedRequirement{
		ID:           id,
		Impact:       0,
		Tags:         map[string]any{},
		Descriptions: []hdf.Description{{Label: "default", Data: id}},
		Results:      []hdf.RequirementResult{defaultResult(id)},
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func defaultResult(id string) hdf.RequirementResult {
	return hdf.RequirementResult{Status: hdf.NotReviewed, CodeDesc: id, StartTime: DefaultStartTime}
}

// Severity sets the requirement severity (e.g. "critical", "high").
func Severity(s string) ReqOption {
	return func(r *hdf.EvaluatedRequirement) { sv := hdf.Severity(s); r.Severity = &sv }
}

// Impact sets the requirement impact score.
func Impact(v float64) ReqOption {
	return func(r *hdf.EvaluatedRequirement) { r.Impact = v }
}

// Status sets the status of the requirement's first result, creating a default
// result when the requirement has none.
func Status(s hdf.ResultStatus) ReqOption {
	return func(r *hdf.EvaluatedRequirement) {
		if len(r.Results) == 0 {
			r.Results = []hdf.RequirementResult{defaultResult(r.ID)}
		}
		r.Results[0].Status = s
	}
}

// Tag sets a single tag key to value.
func Tag(key string, value any) ReqOption {
	return func(r *hdf.EvaluatedRequirement) { r.Tags[key] = value }
}

// Desc sets the data of the requirement's default description.
func Desc(data string) ReqOption {
	return func(r *hdf.EvaluatedRequirement) {
		if len(r.Descriptions) == 0 {
			r.Descriptions = []hdf.Description{{Label: "default", Data: data}}
			return
		}
		r.Descriptions[0].Data = data
	}
}

// AddDesc appends a labeled description. The default description is kept, so the
// schema's "at least one 'default' description" rule still holds.
func AddDesc(label, data string) ReqOption {
	return func(r *hdf.EvaluatedRequirement) {
		r.Descriptions = append(r.Descriptions, hdf.Description{Label: label, Data: data})
	}
}

// Code sets the requirement code (the InSpec check body / rendered rule).
func Code(code string) ReqOption {
	return func(r *hdf.EvaluatedRequirement) { r.Code = &code }
}

// Title sets the requirement title.
func Title(title string) ReqOption {
	return func(r *hdf.EvaluatedRequirement) { r.Title = &title }
}

// CodeDesc sets the codeDesc of the requirement's first result (creating a
// default result when there are none).
func CodeDesc(codeDesc string) ReqOption {
	return func(r *hdf.EvaluatedRequirement) {
		if len(r.Results) == 0 {
			r.Results = []hdf.RequirementResult{defaultResult(r.ID)}
		}
		r.Results[0].CodeDesc = codeDesc
	}
}

// StartTime sets the startTime of the requirement's first result (creating a
// default result when there are none).
func StartTime(t time.Time) ReqOption {
	return func(r *hdf.EvaluatedRequirement) {
		if len(r.Results) == 0 {
			r.Results = []hdf.RequirementResult{defaultResult(r.ID)}
		}
		r.Results[0].StartTime = t
	}
}

// CWE sets the requirement's CWE identifiers.
func CWE(cwes ...string) ReqOption {
	return func(r *hdf.EvaluatedRequirement) { r.Cwe = cwes }
}

// WithResults replaces the requirement's results wholesale (for tests that need
// several results or specific per-result fields).
func WithResults(rs ...hdf.RequirementResult) ReqOption {
	return func(r *hdf.EvaluatedRequirement) { r.Results = rs }
}

// Baseline builds an EvaluatedBaseline with the given name and requirements.
func Baseline(name string, reqs ...hdf.EvaluatedRequirement) hdf.EvaluatedBaseline {
	return hdf.EvaluatedBaseline{Name: name, Requirements: reqs}
}

// Doc builds a schema-valid HDFResults from the given baselines, filling the
// required generator scaffolding.
func Doc(baselines ...hdf.EvaluatedBaseline) hdf.HDFResults {
	return hdf.HDFResults{
		Baselines: baselines,
		Generator: &hdf.Generator{Name: "testhdf", Version: "0.0.0"},
	}
}

// Results is the common shortcut: wraps the requirements in one "test" baseline
// and returns a schema-valid HDFResults.
func Results(reqs ...hdf.EvaluatedRequirement) hdf.HDFResults {
	return Doc(Baseline("test", reqs...))
}
