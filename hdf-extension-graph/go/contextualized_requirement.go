package hdfextension

import (
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ContextualizedRequirement wraps an EvaluatedRequirement with bidirectional
// extension links and lazy derived methods (Root, IsRedundant, FullCode,
// ExtensionChain, Modifications). Use BuildExtensionGraph to construct
// correctly linked instances.
type ContextualizedRequirement struct {
	// Data is the original requirement.
	Data *hdf.EvaluatedRequirement

	// SourcedFrom is the baseline this requirement belongs to.
	SourcedFrom *ContextualizedBaseline

	// ExtendsFrom holds requirements in parent baselines that this
	// requirement extends (overlays). The first element is the primary
	// parent and is the one used for derived computations.
	ExtendsFrom []*ContextualizedRequirement

	// ExtendedBy holds requirements in child baselines that extend this
	// requirement.
	ExtendedBy []*ContextualizedRequirement
}

// Root returns the root (base) requirement at the bottom of the extension
// chain. A requirement with no parent returns itself.
func (cr *ContextualizedRequirement) Root() *ContextualizedRequirement {
	if len(cr.ExtendsFrom) == 0 {
		return cr
	}
	return cr.ExtendsFrom[0].Root()
}

// IsRedundant reports whether this overlay adds no new code: either its code
// is absent/empty, or it matches the root requirement's code exactly. Root
// requirements are never redundant.
func (cr *ContextualizedRequirement) IsRedundant() bool {
	if len(cr.ExtendsFrom) == 0 {
		return false
	}
	code := cr.Data.Code
	if code == nil || *code == "" {
		return true
	}
	rootCode := cr.Root().Data.Code
	if rootCode == nil {
		return false
	}
	return *code == *rootCode
}

// FullCode returns code concatenated from all extension layers, prefixed by
// "# <baseline-name>\n" headers. Redundant overlay layers are skipped. Returns
// an empty string if no code exists anywhere in the chain.
func (cr *ContextualizedRequirement) FullCode() string {
	if cr.IsRedundant() && len(cr.ExtendsFrom) > 0 {
		return cr.ExtendsFrom[0].FullCode()
	}
	code := cr.Data.Code
	if code == nil || *code == "" {
		return ""
	}
	header := "# " + cr.SourcedFrom.Data.Name + "\n" + *code
	if len(cr.ExtendsFrom) == 0 {
		return header
	}
	parentCode := cr.ExtendsFrom[0].FullCode()
	if parentCode == "" {
		return header
	}
	return header + "\n\n" + parentCode
}

// ExtensionChain returns the ordered chain of baselines from root to this
// requirement's baseline (inclusive). A requirement with no parent returns a
// single-element slice containing its own baseline.
func (cr *ContextualizedRequirement) ExtensionChain() []*ContextualizedBaseline {
	if len(cr.ExtendsFrom) == 0 {
		return []*ContextualizedBaseline{cr.SourcedFrom}
	}
	parentChain := cr.ExtendsFrom[0].ExtensionChain()
	return append(parentChain, cr.SourcedFrom)
}

// Modifications returns the TrackedFields that differ between this requirement
// and its immediate parent. Root requirements return an empty (non-nil) slice.
func (cr *ContextualizedRequirement) Modifications() []Modification {
	mods := []Modification{}
	if len(cr.ExtendsFrom) == 0 {
		return mods
	}
	parent := cr.ExtendsFrom[0]
	baseline := cr.SourcedFrom.Data.Name

	if parent.Data.Impact != cr.Data.Impact {
		mods = append(mods, Modification{
			Field:         "impact",
			OriginalValue: parent.Data.Impact,
			NewValue:      cr.Data.Impact,
			InBaseline:    baseline,
		})
	}
	if !equalPtr(parent.Data.Title, cr.Data.Title) {
		mods = append(mods, Modification{
			Field:         "title",
			OriginalValue: derefPtr(parent.Data.Title),
			NewValue:      derefPtr(cr.Data.Title),
			InBaseline:    baseline,
		})
	}
	if !equalPtr(parent.Data.Severity, cr.Data.Severity) {
		mods = append(mods, Modification{
			Field:         "severity",
			OriginalValue: derefPtr(parent.Data.Severity),
			NewValue:      derefPtr(cr.Data.Severity),
			InBaseline:    baseline,
		})
	}
	if !equalPtr(parent.Data.EffectiveImpact, cr.Data.EffectiveImpact) {
		mods = append(mods, Modification{
			Field:         "effectiveImpact",
			OriginalValue: derefPtr(parent.Data.EffectiveImpact),
			NewValue:      derefPtr(cr.Data.EffectiveImpact),
			InBaseline:    baseline,
		})
	}
	if !equalPtr(parent.Data.Disposition, cr.Data.Disposition) {
		mods = append(mods, Modification{
			Field:         "disposition",
			OriginalValue: derefPtr(parent.Data.Disposition),
			NewValue:      derefPtr(cr.Data.Disposition),
			InBaseline:    baseline,
		})
	}
	return mods
}

// equalPtr reports whether two nullable pointer values are equal: both nil
// are equal; one nil and one non-nil are unequal; both non-nil compares the
// pointed-to values directly.
func equalPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// derefPtr returns the pointed-to value as any, or nil if the pointer is nil.
// Used for Modification.OriginalValue and NewValue capture.
func derefPtr[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}
