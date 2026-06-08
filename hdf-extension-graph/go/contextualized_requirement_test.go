package hdfextension

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
)

// ptr is a tiny test helper that returns a pointer to its argument. Avoids
// importing hdfutil just for fixtures, since the production code uses no such
// helper.
func ptr[T any](v T) *T { return &v }

// mkReq builds a minimal valid EvaluatedRequirement for tests, allowing the
// caller to set just the fields under test.
func mkReq(id string) *hdf.EvaluatedRequirement {
	return &hdf.EvaluatedRequirement{ID: id}
}

// linkReqs wires childReq -> parentReq with the bidirectional extension links
// that BuildExtensionGraph would normally set up. Used by derived-property
// tests so they can exercise the methods without spinning up a full graph.
func linkReqs(child, parent *ContextualizedRequirement) {
	child.ExtendsFrom = append(child.ExtendsFrom, parent)
	parent.ExtendedBy = append(parent.ExtendedBy, child)
}

// mkBaseline returns a ContextualizedBaseline named `name` with no underlying
// EvaluatedBaseline.Requirements — useful when tests construct requirements
// directly.
func mkBaseline(name string) *ContextualizedBaseline {
	return &ContextualizedBaseline{
		Data: &hdf.EvaluatedBaseline{Name: name},
	}
}

// mkCtxReq builds a ContextualizedRequirement attached to a fresh baseline
// named `baseline`.
func mkCtxReq(id, baseline string) *ContextualizedRequirement {
	return &ContextualizedRequirement{
		Data:        mkReq(id),
		SourcedFrom: mkBaseline(baseline),
	}
}

func TestRoot(t *testing.T) {
	t.Run("returns self when no parent", func(t *testing.T) {
		r := mkCtxReq("R1", "base")
		assert.Same(t, r, r.Root())
	})

	t.Run("walks single-parent chain to the root", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		child := mkCtxReq("R1", "child")
		linkReqs(child, base)

		assert.Same(t, base, child.Root())
	})

	t.Run("walks multi-layer chain to the deepest root", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		mid := mkCtxReq("R1", "mid")
		top := mkCtxReq("R1", "top")
		linkReqs(mid, base)
		linkReqs(top, mid)

		assert.Same(t, base, top.Root())
		assert.Same(t, base, mid.Root())
	})
}

func TestIsRedundant(t *testing.T) {
	t.Run("root requirements are never redundant, even with nil code", func(t *testing.T) {
		r := mkCtxReq("R1", "base")
		r.Data.Code = nil
		assert.False(t, r.IsRedundant())
	})

	t.Run("overlay with nil code is redundant", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base code")
		child := mkCtxReq("R1", "child")
		child.Data.Code = nil
		linkReqs(child, base)

		assert.True(t, child.IsRedundant())
	})

	t.Run("overlay with empty-string code is redundant", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base code")
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("")
		linkReqs(child, base)

		assert.True(t, child.IsRedundant())
	})

	t.Run("overlay whose code exactly matches root is redundant", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("the code")
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("the code")
		linkReqs(child, base)

		assert.True(t, child.IsRedundant())
	})

	t.Run("overlay with different code is not redundant", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base code")
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("child code")
		linkReqs(child, base)

		assert.False(t, child.IsRedundant())
	})

	t.Run("compares against root code, not immediate-parent code, in three-layer chains", func(t *testing.T) {
		// Mid layer changes the code; top layer reverts to base's code.
		// Per the TS spec, "top" is redundant because it matches root's code
		// even though it differs from its immediate parent (mid).
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base code")
		mid := mkCtxReq("R1", "mid")
		mid.Data.Code = ptr("mid code")
		top := mkCtxReq("R1", "top")
		top.Data.Code = ptr("base code")
		linkReqs(mid, base)
		linkReqs(top, mid)

		assert.True(t, top.IsRedundant())
		assert.False(t, mid.IsRedundant())
	})

	t.Run("returns false when child has code but root has nil code", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Code = nil
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("child code")
		linkReqs(child, base)

		assert.False(t, child.IsRedundant())
	})
}

func TestFullCode(t *testing.T) {
	t.Run("returns empty string when root has no code", func(t *testing.T) {
		r := mkCtxReq("R1", "base")
		r.Data.Code = nil
		assert.Equal(t, "", r.FullCode())
	})

	t.Run("returns header + code for a root with code", func(t *testing.T) {
		r := mkCtxReq("R1", "base")
		r.Data.Code = ptr("describe 'base' do end")
		assert.Equal(t, "# base\ndescribe 'base' do end", r.FullCode())
	})

	t.Run("concatenates child then parent with double-newline separator", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base code")
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("child code")
		linkReqs(child, base)

		assert.Equal(t, "# child\nchild code\n\n# base\nbase code", child.FullCode())
	})

	t.Run("skips redundant overlay layers via parent delegation", func(t *testing.T) {
		// child has identical code to base → child is redundant → fullCode delegates to base.
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base code")
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("base code")
		linkReqs(child, base)

		assert.Equal(t, "# base\nbase code", child.FullCode())
	})

	t.Run("three-layer non-redundant chain stacks deepest-first", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base")
		mid := mkCtxReq("R1", "mid")
		mid.Data.Code = ptr("mid")
		top := mkCtxReq("R1", "top")
		top.Data.Code = ptr("top")
		linkReqs(mid, base)
		linkReqs(top, mid)

		assert.Equal(t, "# top\ntop\n\n# mid\nmid\n\n# base\nbase", top.FullCode())
	})

	t.Run("three-layer with redundant mid skips mid header in output", func(t *testing.T) {
		// mid has nil code → mid is redundant; top's FullCode walks past it.
		// Implementation detail: top is not redundant (its code differs from
		// root). top's parent (mid) is redundant, so mid.FullCode delegates
		// to base. Net result: top's output stacks top + base, no mid header.
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base")
		mid := mkCtxReq("R1", "mid")
		mid.Data.Code = nil
		top := mkCtxReq("R1", "top")
		top.Data.Code = ptr("top")
		linkReqs(mid, base)
		linkReqs(top, mid)

		assert.Equal(t, "# top\ntop\n\n# base\nbase", top.FullCode())
	})

	t.Run("returns parent code alone when child has empty code and parent has code", func(t *testing.T) {
		// child is redundant (empty code) → delegates to parent.
		base := mkCtxReq("R1", "base")
		base.Data.Code = ptr("base code")
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("")
		linkReqs(child, base)

		assert.Equal(t, "# base\nbase code", child.FullCode())
	})

	t.Run("returns child header alone when child has code but parent chain has no code", func(t *testing.T) {
		// Parent's FullCode() returns "" (no code anywhere up the chain).
		// Child is not redundant (its code differs from root's nil code) so
		// it builds its own header, then sees parentCode == "" and returns
		// the header alone — no trailing "\n\n" separator.
		base := mkCtxReq("R1", "base")
		base.Data.Code = nil
		child := mkCtxReq("R1", "child")
		child.Data.Code = ptr("child code")
		linkReqs(child, base)

		assert.Equal(t, "# child\nchild code", child.FullCode())
	})
}

func TestExtensionChain(t *testing.T) {
	t.Run("returns single-element chain for root requirement", func(t *testing.T) {
		r := mkCtxReq("R1", "base")
		chain := r.ExtensionChain()

		assert.Len(t, chain, 1)
		assert.Equal(t, "base", chain[0].Data.Name)
	})

	t.Run("returns root → child for two-layer chain", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		child := mkCtxReq("R1", "child")
		linkReqs(child, base)

		chain := child.ExtensionChain()
		assert.Len(t, chain, 2)
		assert.Equal(t, "base", chain[0].Data.Name)
		assert.Equal(t, "child", chain[1].Data.Name)
	})

	t.Run("returns root → mid → top for three-layer chain", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		mid := mkCtxReq("R1", "mid")
		top := mkCtxReq("R1", "top")
		linkReqs(mid, base)
		linkReqs(top, mid)

		chain := top.ExtensionChain()
		assert.Len(t, chain, 3)
		assert.Equal(t, "base", chain[0].Data.Name)
		assert.Equal(t, "mid", chain[1].Data.Name)
		assert.Equal(t, "top", chain[2].Data.Name)
	})

	t.Run("does not mutate the parent's chain when extended", func(t *testing.T) {
		// Guards against an append-aliasing bug: parentChain may share an
		// underlying array, and naive append could mutate the parent's
		// returned slice across calls.
		base := mkCtxReq("R1", "base")
		mid := mkCtxReq("R1", "mid")
		linkReqs(mid, base)

		// Materialize the parent chain once.
		baseChain := base.ExtensionChain()
		// Then materialize the child chain.
		midChain := mid.ExtensionChain()

		assert.Len(t, baseChain, 1, "base chain should not have grown")
		assert.Len(t, midChain, 2)
	})
}

func TestModifications(t *testing.T) {
	t.Run("root requirements return empty (non-nil) slice", func(t *testing.T) {
		r := mkCtxReq("R1", "base")
		mods := r.Modifications()
		assert.NotNil(t, mods)
		assert.Empty(t, mods)
	})

	t.Run("identical requirements produce no modifications", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Impact = 0.5
		base.Data.Title = ptr("Same")
		child := mkCtxReq("R1", "child")
		child.Data.Impact = 0.5
		child.Data.Title = ptr("Same")
		linkReqs(child, base)

		assert.Empty(t, child.Modifications())
	})

	t.Run("impact change is detected with raw float64 values", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Impact = 0.3
		child := mkCtxReq("R1", "child")
		child.Data.Impact = 0.9
		linkReqs(child, base)

		mods := child.Modifications()
		assert.Len(t, mods, 1)
		assert.Equal(t, "impact", mods[0].Field)
		assert.Equal(t, 0.3, mods[0].OriginalValue)
		assert.Equal(t, 0.9, mods[0].NewValue)
		assert.Equal(t, "child", mods[0].InBaseline)
	})

	t.Run("title change deref'd into string values", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Title = ptr("Original Title")
		child := mkCtxReq("R1", "child")
		child.Data.Title = ptr("Updated Title")
		linkReqs(child, base)

		mods := child.Modifications()
		assert.Len(t, mods, 1)
		assert.Equal(t, "title", mods[0].Field)
		assert.Equal(t, "Original Title", mods[0].OriginalValue)
		assert.Equal(t, "Updated Title", mods[0].NewValue)
	})

	t.Run("nil → set transition is detected with nil originalValue", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Title = nil
		child := mkCtxReq("R1", "child")
		child.Data.Title = ptr("New Title")
		linkReqs(child, base)

		mods := child.Modifications()
		assert.Len(t, mods, 1)
		assert.Equal(t, "title", mods[0].Field)
		assert.Nil(t, mods[0].OriginalValue)
		assert.Equal(t, "New Title", mods[0].NewValue)
	})

	t.Run("set → nil transition is detected with nil newValue", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Title = ptr("Original")
		child := mkCtxReq("R1", "child")
		child.Data.Title = nil
		linkReqs(child, base)

		mods := child.Modifications()
		assert.Len(t, mods, 1)
		assert.Equal(t, "title", mods[0].Field)
		assert.Equal(t, "Original", mods[0].OriginalValue)
		assert.Nil(t, mods[0].NewValue)
	})

	t.Run("severity change captured as the underlying enum value", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Severity = ptr(hdf.SeverityMedium)
		child := mkCtxReq("R1", "child")
		child.Data.Severity = ptr(hdf.SeverityHigh)
		linkReqs(child, base)

		mods := child.Modifications()
		assert.Len(t, mods, 1)
		assert.Equal(t, "severity", mods[0].Field)
		assert.Equal(t, hdf.SeverityMedium, mods[0].OriginalValue)
		assert.Equal(t, hdf.SeverityHigh, mods[0].NewValue)
	})

	t.Run("effectiveImpact pointer change is detected", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.EffectiveImpact = ptr(0.3)
		child := mkCtxReq("R1", "child")
		child.Data.EffectiveImpact = ptr(0.7)
		linkReqs(child, base)

		mods := child.Modifications()
		assert.Len(t, mods, 1)
		assert.Equal(t, "effectiveImpact", mods[0].Field)
		assert.Equal(t, 0.3, mods[0].OriginalValue)
		assert.Equal(t, 0.7, mods[0].NewValue)
	})

	t.Run("disposition change is detected", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Disposition = nil
		child := mkCtxReq("R1", "child")
		child.Data.Disposition = ptr(hdf.OverrideTypeWaiver)
		linkReqs(child, base)

		mods := child.Modifications()
		assert.Len(t, mods, 1)
		assert.Equal(t, "disposition", mods[0].Field)
		assert.Nil(t, mods[0].OriginalValue)
		assert.Equal(t, hdf.OverrideTypeWaiver, mods[0].NewValue)
	})

	t.Run("multi-field changes are returned in TrackedFields order", func(t *testing.T) {
		base := mkCtxReq("R1", "base")
		base.Data.Impact = 0.1
		base.Data.Title = ptr("A")
		base.Data.Severity = ptr(hdf.SeverityLow)
		base.Data.EffectiveImpact = ptr(0.1)
		base.Data.Disposition = nil

		child := mkCtxReq("R1", "child")
		child.Data.Impact = 0.9
		child.Data.Title = ptr("B")
		child.Data.Severity = ptr(hdf.SeverityCritical)
		child.Data.EffectiveImpact = ptr(0.9)
		child.Data.Disposition = ptr(hdf.RiskAdjustment)
		linkReqs(child, base)

		// Pin the emitted field order to the TrackedFields slice directly so
		// a drift between the two lists fails this test.
		mods := child.Modifications()
		assert.Len(t, mods, len(TrackedFields))
		emitted := make([]string, len(mods))
		for i, m := range mods {
			emitted[i] = m.Field
		}
		assert.Equal(t, TrackedFields, emitted)
	})
}
