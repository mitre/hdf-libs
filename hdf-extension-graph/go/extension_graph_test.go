package hdfextension

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
)

// makeBaselineData builds an EvaluatedBaseline value (not pointer) suitable
// for placement in HDFResults.Baselines. Optional parentBaseline is set when
// non-empty.
func makeBaselineData(name string, parentBaseline string, reqs []hdf.EvaluatedRequirement) hdf.EvaluatedBaseline {
	b := hdf.EvaluatedBaseline{
		Name:         name,
		Requirements: reqs,
	}
	if parentBaseline != "" {
		b.ParentBaseline = ptr(parentBaseline)
	}
	return b
}

// makeReqData builds an EvaluatedRequirement value with id and optional code.
// Other tracked fields default to zero values, which suffices for graph-shape
// tests (derived-property tests already exercise field changes separately).
func makeReqData(id string, code string) hdf.EvaluatedRequirement {
	r := hdf.EvaluatedRequirement{ID: id}
	if code != "" {
		r.Code = ptr(code)
	}
	return r
}

func makeResults(baselines ...hdf.EvaluatedBaseline) *hdf.HDFResults {
	return &hdf.HDFResults{Baselines: baselines}
}

func TestBuildExtensionGraph_Phase1_BaselineWrapping(t *testing.T) {
	t.Run("wraps all baselines in order", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("alpha", "", nil),
			makeBaselineData("beta", "", nil),
		)

		graph := BuildExtensionGraph(results)

		assert.Len(t, graph.Baselines, 2)
		assert.Equal(t, "alpha", graph.Baselines[0].Data.Name)
		assert.Equal(t, "beta", graph.Baselines[1].Data.Name)
	})

	t.Run("each baseline's SourcedFrom points back to the input results", func(t *testing.T) {
		results := makeResults(makeBaselineData("base", "", nil))

		graph := BuildExtensionGraph(results)

		assert.Same(t, results, graph.Baselines[0].SourcedFrom)
	})

	t.Run("each baseline's Data points back to the underlying EvaluatedBaseline", func(t *testing.T) {
		// Sharing identity matters: callers may rely on equal-by-reference
		// to correlate between the graph and the raw schema document.
		results := makeResults(makeBaselineData("base", "", nil))

		graph := BuildExtensionGraph(results)

		assert.Same(t, &results.Baselines[0], graph.Baselines[0].Data)
	})

	t.Run("returns an empty (but non-nil) graph for empty baselines", func(t *testing.T) {
		results := makeResults()

		graph := BuildExtensionGraph(results)

		assert.NotNil(t, graph)
		assert.Empty(t, graph.Baselines)
		assert.Empty(t, graph.Requirements)
	})
}

func TestBuildExtensionGraph_Phase2_BaselineLinking(t *testing.T) {
	t.Run("links child to parent baseline bidirectionally", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("parent-stig", "", nil),
			makeBaselineData("child-overlay", "parent-stig", nil),
		)

		graph := BuildExtensionGraph(results)
		parent := graph.FindBaseline("parent-stig")
		child := graph.FindBaseline("child-overlay")

		assert.NotNil(t, parent)
		assert.NotNil(t, child)
		assert.Len(t, child.ExtendsFrom, 1)
		assert.Same(t, parent, child.ExtendsFrom[0])
		assert.Len(t, parent.ExtendedBy, 1)
		assert.Same(t, child, parent.ExtendedBy[0])
	})

	t.Run("handles three-layer extension chain", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("base", "", nil),
			makeBaselineData("mid", "base", nil),
			makeBaselineData("top", "mid", nil),
		)

		graph := BuildExtensionGraph(results)
		base := graph.FindBaseline("base")
		mid := graph.FindBaseline("mid")
		top := graph.FindBaseline("top")

		assert.Contains(t, base.ExtendedBy, mid)
		assert.Contains(t, mid.ExtendsFrom, base)
		assert.Contains(t, mid.ExtendedBy, top)
		assert.Contains(t, top.ExtendsFrom, mid)
		assert.Empty(t, base.ExtendsFrom)
		assert.Empty(t, top.ExtendedBy)
	})

	t.Run("leaves extendsFrom empty when parentBaseline names a missing baseline", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("orphan", "nonexistent", nil),
		)

		graph := BuildExtensionGraph(results)

		assert.Empty(t, graph.FindBaseline("orphan").ExtendsFrom)
	})

	t.Run("leaves extendsFrom empty when parentBaseline is an empty string", func(t *testing.T) {
		// Empty-string parent is treated identically to nil — Phase 2 skips
		// the lookup entirely. Test guards the explicit empty-string check
		// added on top of TS semantics (TS only checks falsy, which includes
		// both undefined and "").
		b := makeBaselineData("a", "", nil)
		b.ParentBaseline = ptr("") // explicit empty pointer, not nil
		results := makeResults(b)

		graph := BuildExtensionGraph(results)

		assert.Empty(t, graph.FindBaseline("a").ExtendsFrom)
	})

	t.Run("does not link baselines without parentBaseline", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("a", "", nil),
			makeBaselineData("b", "", nil),
		)

		graph := BuildExtensionGraph(results)

		assert.Empty(t, graph.FindBaseline("a").ExtendsFrom)
		assert.Empty(t, graph.FindBaseline("a").ExtendedBy)
		assert.Empty(t, graph.FindBaseline("b").ExtendsFrom)
		assert.Empty(t, graph.FindBaseline("b").ExtendedBy)
	})
}

func TestBuildExtensionGraph_Phase3_RequirementCollection(t *testing.T) {
	t.Run("collects all requirements from all baselines, in baseline-then-req order", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("a", "", []hdf.EvaluatedRequirement{
				makeReqData("R1", ""),
				makeReqData("R2", ""),
			}),
			makeBaselineData("b", "", []hdf.EvaluatedRequirement{
				makeReqData("R3", ""),
			}),
		)

		graph := BuildExtensionGraph(results)

		assert.Len(t, graph.Requirements, 3)
		assert.Equal(t, "R1", graph.Requirements[0].Data.ID)
		assert.Equal(t, "R2", graph.Requirements[1].Data.ID)
		assert.Equal(t, "R3", graph.Requirements[2].Data.ID)
	})

	t.Run("each requirement's SourcedFrom points to its owning baseline", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("base", "", []hdf.EvaluatedRequirement{
				makeReqData("R1", ""),
			}),
		)

		graph := BuildExtensionGraph(results)

		assert.Equal(t, "base", graph.Requirements[0].SourcedFrom.Data.Name)
		assert.Same(t, graph.Baselines[0], graph.Requirements[0].SourcedFrom)
	})
}

func TestBuildExtensionGraph_Phase4_RequirementLinking(t *testing.T) {
	t.Run("links requirements with matching ids across linked baselines", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("parent", "", []hdf.EvaluatedRequirement{
				makeReqData("SV-001", "original code"),
			}),
			makeBaselineData("child", "parent", []hdf.EvaluatedRequirement{
				makeReqData("SV-001", "overlay code"),
			}),
		)

		graph := BuildExtensionGraph(results)
		parentReq := graph.Baselines[0].Requirements[0]
		childReq := graph.Baselines[1].Requirements[0]

		assert.Len(t, childReq.ExtendsFrom, 1)
		assert.Same(t, parentReq, childReq.ExtendsFrom[0])
		assert.Len(t, parentReq.ExtendedBy, 1)
		assert.Same(t, childReq, parentReq.ExtendedBy[0])
	})

	t.Run("does not link requirements that share id but have no baseline relationship", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("standalone-a", "", []hdf.EvaluatedRequirement{
				makeReqData("SV-001", ""),
			}),
			makeBaselineData("standalone-b", "", []hdf.EvaluatedRequirement{
				makeReqData("SV-001", ""),
			}),
		)

		graph := BuildExtensionGraph(results)

		aReq := graph.Baselines[0].Requirements[0]
		bReq := graph.Baselines[1].Requirements[0]
		assert.Empty(t, aReq.ExtendsFrom)
		assert.Empty(t, aReq.ExtendedBy)
		assert.Empty(t, bReq.ExtendsFrom)
		assert.Empty(t, bReq.ExtendedBy)
	})

	t.Run("links requirements through a three-layer chain", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("base", "", []hdf.EvaluatedRequirement{makeReqData("R1", "base code")}),
			makeBaselineData("mid", "base", []hdf.EvaluatedRequirement{makeReqData("R1", "mid code")}),
			makeBaselineData("top", "mid", []hdf.EvaluatedRequirement{makeReqData("R1", "top code")}),
		)

		graph := BuildExtensionGraph(results)
		baseR1 := graph.Baselines[0].Requirements[0]
		midR1 := graph.Baselines[1].Requirements[0]
		topR1 := graph.Baselines[2].Requirements[0]

		assert.Same(t, baseR1, midR1.ExtendsFrom[0])
		assert.Same(t, midR1, baseR1.ExtendedBy[0])
		assert.Same(t, midR1, topR1.ExtendsFrom[0])
		assert.Same(t, topR1, midR1.ExtendedBy[0])
		assert.Empty(t, baseR1.ExtendsFrom)
		assert.Empty(t, topR1.ExtendedBy)
	})

	t.Run("only links requirements that exist in both parent and child", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("parent", "", []hdf.EvaluatedRequirement{
				makeReqData("R1", ""),
				makeReqData("R2", ""),
			}),
			makeBaselineData("child", "parent", []hdf.EvaluatedRequirement{
				makeReqData("R1", ""),
				makeReqData("R3", ""),
			}),
		)

		graph := BuildExtensionGraph(results)
		parentR1 := graph.Baselines[0].Requirements[0]
		parentR2 := graph.Baselines[0].Requirements[1]
		childR1 := graph.Baselines[1].Requirements[0]
		childR3 := graph.Baselines[1].Requirements[1]

		assert.Same(t, parentR1, childR1.ExtendsFrom[0])
		assert.Empty(t, parentR2.ExtendedBy, "R2 only exists in parent — must not be linked")
		assert.Empty(t, childR3.ExtendsFrom, "R3 only exists in child — must not be linked")
	})

	t.Run("matches only the first parent requirement when a parent baseline has duplicate ids", func(t *testing.T) {
		// Mirrors TS find() semantics: only the first match in the parent
		// baseline is linked. Guards against accidental double-linking when
		// a parent baseline has duplicate ids (rare, but the schema permits
		// it and TS handles it this way).
		results := makeResults(
			makeBaselineData("parent", "", []hdf.EvaluatedRequirement{
				makeReqData("R1", "first"),
				makeReqData("R1", "second"),
			}),
			makeBaselineData("child", "parent", []hdf.EvaluatedRequirement{
				makeReqData("R1", "child"),
			}),
		)

		graph := BuildExtensionGraph(results)
		firstParentR1 := graph.Baselines[0].Requirements[0]
		secondParentR1 := graph.Baselines[0].Requirements[1]
		childR1 := graph.Baselines[1].Requirements[0]

		assert.Len(t, childR1.ExtendsFrom, 1)
		assert.Same(t, firstParentR1, childR1.ExtendsFrom[0])
		assert.Empty(t, secondParentR1.ExtendedBy)
	})
}

func TestContextualizedBaseline_Construction(t *testing.T) {
	t.Run("wraps an EvaluatedBaseline with the original data accessible", func(t *testing.T) {
		results := makeResults(makeBaselineData("test-baseline", "", []hdf.EvaluatedRequirement{
			makeReqData("REQ-1", ""),
		}))

		graph := BuildExtensionGraph(results)
		ctx := graph.Baselines[0]

		assert.Same(t, &results.Baselines[0], ctx.Data)
		assert.Same(t, results, ctx.SourcedFrom)
		assert.Equal(t, "test-baseline", ctx.Data.Name)
	})

	t.Run("initializes a fresh baseline with empty extension link slices", func(t *testing.T) {
		results := makeResults(makeBaselineData("test-baseline", "", []hdf.EvaluatedRequirement{
			makeReqData("REQ-1", ""),
		}))

		graph := BuildExtensionGraph(results)
		ctx := graph.Baselines[0]

		assert.Empty(t, ctx.ExtendsFrom)
		assert.Empty(t, ctx.ExtendedBy)
	})

	t.Run("provides access to wrapped requirements", func(t *testing.T) {
		results := makeResults(makeBaselineData("test-baseline", "", []hdf.EvaluatedRequirement{
			makeReqData("REQ-1", ""),
		}))

		graph := BuildExtensionGraph(results)
		ctx := graph.Baselines[0]

		assert.Len(t, ctx.Requirements, 1)
		assert.Same(t, &results.Baselines[0].Requirements[0], ctx.Requirements[0].Data)
	})
}

func TestContextualizedRequirement_Construction(t *testing.T) {
	t.Run("wraps an EvaluatedRequirement with the original data accessible", func(t *testing.T) {
		results := makeResults(makeBaselineData("base", "", []hdf.EvaluatedRequirement{
			makeReqData("REQ-1", "describe ..."),
		}))

		graph := BuildExtensionGraph(results)
		ctxReq := graph.Baselines[0].Requirements[0]

		assert.Same(t, &results.Baselines[0].Requirements[0], ctxReq.Data)
		assert.Same(t, graph.Baselines[0], ctxReq.SourcedFrom)
		assert.Equal(t, "REQ-1", ctxReq.Data.ID)
	})

	t.Run("initializes with empty extension link slices", func(t *testing.T) {
		results := makeResults(makeBaselineData("base", "", []hdf.EvaluatedRequirement{
			makeReqData("REQ-1", ""),
		}))

		graph := BuildExtensionGraph(results)
		ctxReq := graph.Baselines[0].Requirements[0]

		assert.Empty(t, ctxReq.ExtendsFrom)
		assert.Empty(t, ctxReq.ExtendedBy)
	})
}

func TestExtensionGraph_Queries(t *testing.T) {
	t.Run("FindBaseline locates baselines by name and returns nil for unknown", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("alpha", "", nil),
			makeBaselineData("beta", "", nil),
		)
		graph := BuildExtensionGraph(results)

		assert.NotNil(t, graph.FindBaseline("alpha"))
		assert.Equal(t, "alpha", graph.FindBaseline("alpha").Data.Name)
		assert.NotNil(t, graph.FindBaseline("beta"))
		assert.Nil(t, graph.FindBaseline("gamma"))
	})

	t.Run("FindRequirements returns all reqs with given id across all baselines", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("a", "", []hdf.EvaluatedRequirement{
				makeReqData("SV-001", ""),
				makeReqData("SV-002", ""),
			}),
			makeBaselineData("b", "", []hdf.EvaluatedRequirement{
				makeReqData("SV-001", ""), // duplicate id in unrelated baseline
			}),
		)
		graph := BuildExtensionGraph(results)

		found := graph.FindRequirements("SV-001")
		assert.Len(t, found, 2)

		assert.Equal(t, []*ContextualizedRequirement{}, graph.FindRequirements("SV-999"))
	})

	t.Run("RootBaselines returns baselines with no parent", func(t *testing.T) {
		results := makeResults(
			makeBaselineData("root-baseline", "", nil),
			makeBaselineData("overlay", "root-baseline", nil),
		)
		graph := BuildExtensionGraph(results)

		roots := graph.RootBaselines()
		assert.Len(t, roots, 1)
		assert.Equal(t, "root-baseline", roots[0].Data.Name)
	})

	t.Run("RootBaselines treats empty-string parentBaseline as no parent", func(t *testing.T) {
		// Defends the explicit empty-string check in RootBaselines (TS uses
		// falsy comparison which catches both undefined and "").
		b := makeBaselineData("a", "", nil)
		b.ParentBaseline = ptr("") // explicit empty pointer
		results := makeResults(b)
		graph := BuildExtensionGraph(results)

		roots := graph.RootBaselines()
		assert.Len(t, roots, 1)
		assert.Equal(t, "a", roots[0].Data.Name)
	})

	t.Run("FindRequirements returns empty (non-nil) slice when no matches exist", func(t *testing.T) {
		// Defends downstream callers that range over the result without a
		// nil check — assert the empty-slice semantic explicitly.
		graph := &ExtensionGraph{}
		got := graph.FindRequirements("anything")
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
}
