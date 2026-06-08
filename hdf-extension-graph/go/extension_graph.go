package hdfextension

import (
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ContextualizedBaseline wraps an EvaluatedBaseline with bidirectional
// extension links and contextualized requirements. Use BuildExtensionGraph to
// construct correctly linked instances.
type ContextualizedBaseline struct {
	// Data is the original baseline.
	Data *hdf.EvaluatedBaseline

	// SourcedFrom is the HDFResults this baseline was sourced from.
	SourcedFrom *hdf.HDFResults

	// ExtendsFrom holds parent baselines that this baseline extends.
	ExtendsFrom []*ContextualizedBaseline

	// ExtendedBy holds child baselines that extend this baseline.
	ExtendedBy []*ContextualizedBaseline

	// Requirements are the contextualized wrappers for each requirement in
	// this baseline, in the same order as Data.Requirements.
	Requirements []*ContextualizedRequirement
}

// newContextualizedBaseline wraps a single EvaluatedBaseline and immediately
// creates ContextualizedRequirement wrappers for each of its requirements.
func newContextualizedBaseline(data *hdf.EvaluatedBaseline, sourcedFrom *hdf.HDFResults) *ContextualizedBaseline {
	cb := &ContextualizedBaseline{
		Data:         data,
		SourcedFrom:  sourcedFrom,
		Requirements: make([]*ContextualizedRequirement, 0, len(data.Requirements)),
	}
	for i := range data.Requirements {
		cb.Requirements = append(cb.Requirements, &ContextualizedRequirement{
			Data:        &data.Requirements[i],
			SourcedFrom: cb,
		})
	}
	return cb
}

// ExtensionGraph is a bidirectional extension graph built from an HDF Results
// file. Contains all baselines and requirements with their extension
// relationships wired both ways.
type ExtensionGraph struct {
	// Baselines is every contextualized baseline in the graph.
	Baselines []*ContextualizedBaseline

	// Requirements is every contextualized requirement across all baselines,
	// flattened in baseline-then-requirement order.
	Requirements []*ContextualizedRequirement
}

// FindBaseline returns the first baseline matching the given name, or nil if
// none is found.
func (eg *ExtensionGraph) FindBaseline(name string) *ContextualizedBaseline {
	for _, b := range eg.Baselines {
		if b.Data.Name == name {
			return b
		}
	}
	return nil
}

// FindRequirements returns all requirements with the given id across all
// baselines. The same id may legitimately appear in multiple baselines.
func (eg *ExtensionGraph) FindRequirements(id string) []*ContextualizedRequirement {
	out := []*ContextualizedRequirement{}
	for _, r := range eg.Requirements {
		if r.Data.ID == id {
			out = append(out, r)
		}
	}
	return out
}

// RootBaselines returns the baselines that have no parent (top of extension
// chains). A baseline is considered root if its EvaluatedBaseline.ParentBaseline
// is nil or empty.
func (eg *ExtensionGraph) RootBaselines() []*ContextualizedBaseline {
	out := []*ContextualizedBaseline{}
	for _, b := range eg.Baselines {
		if b.Data.ParentBaseline == nil || *b.Data.ParentBaseline == "" {
			out = append(out, b)
		}
	}
	return out
}

// BuildExtensionGraph constructs a bidirectional extension graph from an HDF
// Results document in four phases:
//
//  1. Wrap each EvaluatedBaseline in a ContextualizedBaseline.
//  2. Link baselines via ParentBaseline name matching (bidirectional).
//     Dangling parent references are silently treated as orphans.
//  3. Collect all requirements into a flat slice.
//  4. Link requirements by ID across parent/child baseline pairs
//     (bidirectional). Requirements in unrelated baselines are not linked
//     even if their IDs match.
//
// Returns a non-nil graph even for empty input.
func BuildExtensionGraph(results *hdf.HDFResults) *ExtensionGraph {
	// Phase 1: wrap baselines and index by name.
	baselineMap := make(map[string]*ContextualizedBaseline, len(results.Baselines))
	baselines := make([]*ContextualizedBaseline, 0, len(results.Baselines))
	for i := range results.Baselines {
		cb := newContextualizedBaseline(&results.Baselines[i], results)
		baselines = append(baselines, cb)
		baselineMap[cb.Data.Name] = cb
	}

	// Phase 2: link baselines via parentBaseline.
	for _, cb := range baselines {
		parentName := cb.Data.ParentBaseline
		if parentName == nil || *parentName == "" {
			continue
		}
		parent, ok := baselineMap[*parentName]
		if !ok {
			continue
		}
		cb.ExtendsFrom = append(cb.ExtendsFrom, parent)
		parent.ExtendedBy = append(parent.ExtendedBy, cb)
	}

	// Phase 3: collect all requirements.
	totalReqs := 0
	for _, cb := range baselines {
		totalReqs += len(cb.Requirements)
	}
	allReqs := make([]*ContextualizedRequirement, 0, totalReqs)
	for _, cb := range baselines {
		allReqs = append(allReqs, cb.Requirements...)
	}

	// Phase 4: link requirements by id across linked baselines.
	for _, cb := range baselines {
		if len(cb.ExtendsFrom) == 0 {
			continue
		}
		for _, childReq := range cb.Requirements {
			for _, parentBaseline := range cb.ExtendsFrom {
				for _, parentReq := range parentBaseline.Requirements {
					if parentReq.Data.ID == childReq.Data.ID {
						childReq.ExtendsFrom = append(childReq.ExtendsFrom, parentReq)
						parentReq.ExtendedBy = append(parentReq.ExtendedBy, childReq)
						break // first match per parent baseline (mirrors TS .find())
					}
				}
			}
		}
	}

	return &ExtensionGraph{
		Baselines:    baselines,
		Requirements: allReqs,
	}
}
