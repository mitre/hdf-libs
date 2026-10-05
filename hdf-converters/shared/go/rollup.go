package shared

import (
	"encoding/json"
	"maps"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// Requirement roll-up — the single implementation of ADR-0017 §6 ("Requirement
// roll-up: one requirement per id, within one baseline"). Keep in lockstep with
// rollup.ts; the two are compared case for case through
// hdf-converters/shared/rollup-cases.json.
//
// The parameter is ONE baseline's requirement slice, never a document: a
// document-wide merge would collapse findings from different hosts that share an
// id (prisma's golden carries 16 baselines, 94 entries, 53 distinct ids but 92
// distinct (baseline, id) pairs), so the wrong call is deliberately not
// expressible.
//
// ADR-0017 §6, field by field — the table below is the ADR's, in its order, and
// hdf-converters/shared/rollup-field-rules.json pins it so neither language can
// drift from it or from the ADR:
//
//	id                                             the merge key
//	results                                        concatenate, source order
//	affectedPackages                               union, de-duplicated on purl else name+version
//	code                                           first-wins
//	cwe refs externalReferences evidence
//	  statusOverrides poams                        union, de-duplicated on identity
//	tags                                           per key: array-valued union, scalar first-wins
//	impact severity effectiveImpact                worst-wins
//	title descriptions                             first-wins
//	sourceLocation                                 first-wins
//	controlType verificationMethod applicability   first-wins
//	cvss epss kev                                  first-wins
//	effectiveStatus disposition effectiveChecksum  not merged — derived after merging

// RollUpRequirements merges the entries of one baseline's requirement slice that
// share an id, per ADR-0017 §6. The surviving requirement sits at the position of
// its first member and its results are in first-seen order; a slice with no
// repeated id is returned unchanged. Inputs are never mutated.
//
// An entry whose id is empty is passed through untouched and is never a merge
// key: id is schema-required, so an empty one is malformed input, and merging on
// it would fuse unrelated findings.
func RollUpRequirements(reqs []hdf.EvaluatedRequirement) []hdf.EvaluatedRequirement {
	out := make([]hdf.EvaluatedRequirement, 0, len(reqs))
	at := make(map[string]int, len(reqs))
	for _, r := range reqs {
		if r.ID == "" {
			out = append(out, r)
			continue
		}
		if i, seen := at[r.ID]; seen {
			mergeRequirement(&out[i], r)
			continue
		}
		at[r.ID] = len(out)
		out = append(out, r)
	}
	return out
}

// mergeRequirement folds src into dst, which already holds the group's first
// member. Every branch below is one row of the ADR-0017 §6 table, in its order.
func mergeRequirement(dst *hdf.EvaluatedRequirement, src hdf.EvaluatedRequirement) {
	// results: concatenate, in source order.
	dst.Results = concat(dst.Results, src.Results)

	// affectedPackages: union, de-duplicated on purl where present, else name + version.
	dst.AffectedPackages = unionBy(dst.AffectedPackages, src.AffectedPackages, packageIdentity)

	// code: first-wins.

	// cwe, refs, externalReferences, evidence, statusOverrides, poams: union,
	// de-duplicated on identity where the member has one. Only cwe declares an
	// identity (the string itself); for the rest the member's whole value is its
	// identity, which is the only key that cannot discard a distinct member.
	dst.Cwe = unionBy(dst.Cwe, src.Cwe, func(s string) string { return s })
	dst.Refs = unionBy(dst.Refs, src.Refs, canonical[hdf.Reference])
	dst.ExternalReferences = unionBy(dst.ExternalReferences, src.ExternalReferences, canonical[hdf.ExternalReference])
	dst.Evidence = unionBy(dst.Evidence, src.Evidence, canonical[hdf.Evidence])
	dst.StatusOverrides = unionBy(dst.StatusOverrides, src.StatusOverrides, canonical[hdf.StatusOverride])
	dst.Poams = unionBy(dst.Poams, src.Poams, canonical[hdf.PoamElement])

	// tags: per key — array-valued tags union, scalar-valued tags first-wins, a
	// key only a later member carries is added. The unrated-severity marker is
	// the one exception and is handled below.
	dstUnrated := isUnratedMarked(dst.Tags)
	dst.Tags = mergeTags(dst.Tags, src.Tags)

	// The unrated-severity marker is DERIVED, not a scalar tag. It asserts that
	// the severity was defaulted rather than rated, which holds of the merged
	// requirement only if it held of every member — so it survives as an AND and
	// any member lacking it drops it. Merged as an ordinary tag it would be wrong
	// both ways: added from a later member it labels a rated requirement unrated,
	// and kept from the first member it claims no rating beside a genuine
	// worst-wins severity. Unlike the derived fields below, the caller cannot
	// recompute it: once merged, nothing distinguishes a rated severity from a
	// defaulted one.
	// Written as De Morgan's dual of "survives iff both members are unrated".
	if !dstUnrated || !isUnratedMarked(src.Tags) {
		dst.Tags = withoutUnratedMarker(dst.Tags)
	}

	// impact, severity, effectiveImpact: worst-wins.
	dst.Impact = max(dst.Impact, src.Impact)
	dst.Severity = worstSeverity(dst.Severity, src.Severity)
	dst.EffectiveImpact = worstImpact(dst.EffectiveImpact, src.EffectiveImpact)

	// title, descriptions: first-wins.
	// sourceLocation: first-wins.
	// controlType, verificationMethod, applicability: first-wins.
	// cvss, epss, kev: first-wins.

	// effectiveStatus, disposition, effectiveChecksum: not merged — derived after
	// merging, from the merged results and overrides. The first member's values
	// describe only that member, so they are dropped rather than carried.
	dst.EffectiveStatus = nil
	dst.Disposition = nil
	dst.EffectiveChecksum = nil
}

// concat returns a new slice holding a then b, leaving both untouched — appending
// in place could write into the caller's backing array.
func concat[T any](a, b []T) []T {
	out := make([]T, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// unionBy appends the members of b whose key is not already present in a,
// preserving source order. A nil result stays nil so an absent field stays absent.
func unionBy[T any](a, b []T, key func(T) string) []T {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	for _, v := range a {
		seen[key(v)] = true
	}
	add := make([]T, 0, len(b))
	for _, v := range b {
		k := key(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		add = append(add, v)
	}
	if len(add) == 0 {
		return a
	}
	return concat(a, add)
}

// packageIdentity is ADR-0017 §6's de-duplication key for affectedPackages: the
// purl where present, else name + version.
func packageIdentity(p hdf.AffectedPackage) string {
	if p.Purl != nil && *p.Purl != "" {
		return "purl\x00" + *p.Purl
	}
	return "nv\x00" + deref(p.Name) + "\x00" + deref(p.Version)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// canonical is the identity of a member that declares none of its own: its whole
// value, as JSON. Go marshals struct fields in declaration order and map keys
// sorted, so equal members produce equal keys.
func canonical[T any](v T) string {
	b, err := json.Marshal(v)
	if err != nil {
		// A value that cannot be marshalled cannot be compared to any other, so
		// it is its own identity and always survives the union.
		return "\x00unmarshalable"
	}
	return string(b)
}

// mergeTags applies ADR-0017 §6's per-key tag rule: a key both sides carry as an
// array unions (de-duplicated, source order); every other key first-wins. A key
// only the later member carries is added — the rule is stated per key, not over
// the first member's key set.
func mergeTags(dst, src map[string]interface{}) map[string]interface{} {
	if len(src) == 0 {
		return dst
	}
	out := make(map[string]interface{}, len(dst)+len(src))
	maps.Copy(out, dst)
	for k, sv := range src {
		dv, held := out[k]
		if !held {
			out[k] = sv
			continue
		}
		da, dok := dv.([]interface{})
		sa, sok := sv.([]interface{})
		if dok && sok {
			out[k] = unionBy(da, sa, canonical[interface{}])
		}
		// Otherwise first-wins: out[k] already holds the first member's value.
	}
	return out
}

// isUnratedMarked reports whether a tag map carries the shared unrated-severity
// marker. The constant lives in this package (converterutil.go).
func isUnratedMarked(tags map[string]interface{}) bool {
	v, ok := tags[UnratedSeverityTag]
	if !ok {
		return false
	}
	s, isString := v.(string)
	return isString && s == UnratedSeverityValue
}

// withoutUnratedMarker returns tags without the unrated-severity marker,
// allocating only when the marker is actually present. It never mutates its
// argument: mergeTags hands back the caller's own map when the later member has
// no tags, so deleting in place would reach into the input requirement.
// Keyed on the marker's VALUE, not just its name: the key carrying some other
// value is an ordinary scalar tag and first-wins per ADR-0017 §6, so it must
// survive the merge untouched.
func withoutUnratedMarker(tags map[string]interface{}) map[string]interface{} {
	if !isUnratedMarked(tags) {
		return tags
	}
	out := make(map[string]interface{}, len(tags))
	for k, v := range tags {
		if k == UnratedSeverityTag {
			continue
		}
		out[k] = v
	}
	return out
}

// severityRank orders hdf.Severity for the worst-wins rule. A value outside the
// enum is not a rating at all rather than the lowest rating — hdf-utilities'
// IsUnratedSeverity is explicit that an unrecognized token asserts nothing — so
// it loses to every rated value, and two of them fall back to first-wins. An
// unrated SOURCE severity never arrives here as an off-enum value: the converter
// has already defaulted it (medium, 0.5) and marked it with UnratedSeverityTag.
func severityRank(s hdf.Severity) int {
	switch s {
	case hdf.Informational:
		return 0
	case hdf.SeverityLow:
		return 1
	case hdf.SeverityMedium:
		return 2
	case hdf.SeverityHigh:
		return 3
	case hdf.SeverityCritical:
		return 4
	default:
		return -1
	}
}

// worstSeverity is worst-wins over the present values; absent loses to present,
// and two absent values stay absent.
func worstSeverity(a, b *hdf.Severity) *hdf.Severity {
	switch {
	case b == nil:
		return a
	case a == nil:
		return b
	case severityRank(*b) > severityRank(*a):
		return b
	default:
		return a
	}
}

// worstImpact is worst-wins over the present values; absent loses to present.
func worstImpact(a, b *float64) *float64 {
	switch {
	case b == nil:
		return a
	case a == nil:
		return b
	case *b > *a:
		return b
	default:
		return a
	}
}
