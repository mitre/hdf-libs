package evidenceref

import (
	"encoding/json"
	"fmt"
)

// Reference is one reference a package records, in both the spelling it stores
// and the form that spelling means.
type Reference struct {
	// Field is the document member recording it. Reports that identify an entry
	// print this, so an operator can find it.
	Field string
	// Index is the position within that field's array, or -1 for a scalar.
	// Callers re-attach their own per-entry data by (Field, Index) rather than
	// by a flat ordinal, which would pair it with the wrong reference as soon
	// as a field is added or reordered.
	Index int
	// Stored is the recorded spelling. Reports name this, because it is what an
	// operator will find in the document.
	Stored string
	// Decoded is what the reference means, and the only form safe to resolve.
	Decoded Decoded
	// Err is set when Stored is not a valid uri-reference. Field and Stored are
	// still populated, so a report can name the offender; Decoded is empty,
	// because there is no meaning to give it.
	Err error
}

// References is every reference one package records.
type References []Reference

// At returns the reference a field records at an index, or false if the field
// records none there. A consumer that needs its own per-entry fields — a
// content's type, say — iterates its own parse and asks for the reference by
// position, instead of re-reading the uri itself.
//
// The miss is reported rather than returned as a zero Reference, which would
// read as a present-but-empty one.
func (rs References) At(field string, index int) (Reference, bool) {
	for _, r := range rs {
		if r.Field == field && r.Index == index {
			return r, true
		}
	}
	return Reference{}, false
}

// Collect enumerates every reference a package records. Decoding happens here,
// once per reference, so no consumer has to remember to do it.
//
// It is the only place that ENUMERATES them. Resolving is Path, recording is
// Encode, and display-only consumers still read the stored spelling where they
// sit by maintainer decision — so this is not the only code that touches a
// reference, only the one place that decides which fields hold them.
func Collect(pkgData []byte) (References, error) {
	var doc struct {
		SystemRef string `json:"systemRef"`
		PlanRef   string `json:"planRef"`
		Contents  []struct {
			URI string `json:"uri"`
		} `json:"contents"`
		ExternalEvidence []struct {
			URI string `json:"uri"`
		} `json:"externalEvidence"`
		ExternalReferences []struct {
			Href string `json:"href"`
		} `json:"externalReferences"`
		Extensions struct {
			RawSourceArtifacts []struct {
				Href string `json:"href"`
			} `json:"rawSourceArtifacts"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(pkgData, &doc); err != nil {
		return nil, fmt.Errorf("read the package's references: %w", err)
	}

	refs := make(References, 0, len(doc.Contents)+len(doc.ExternalEvidence)+4)
	add := func(field string, index int, stored string) {
		refs = append(refs, Reference{Field: field, Index: index, Stored: stored})
	}
	// A scalar field is recorded even when empty, so a caller reporting on one
	// does not have to tell "absent" apart from "not enumerated".
	add("systemRef", -1, doc.SystemRef)
	add("planRef", -1, doc.PlanRef)
	for i, c := range doc.Contents {
		add("contents", i, c.URI)
	}
	for i, e := range doc.ExternalEvidence {
		add("externalEvidence", i, e.URI)
	}
	for i, r := range doc.ExternalReferences {
		add("externalReferences", i, r.Href)
	}
	for i, r := range doc.Extensions.RawSourceArtifacts {
		add("extensions.rawSourceArtifacts", i, r.Href)
	}

	// One pass over the assembled list rather than a decode at each append: a
	// field added above cannot forget to decode.
	for i := range refs {
		if refs[i].Stored == "" {
			continue
		}
		d, err := Decode(refs[i].Stored)
		if err != nil {
			refs[i].Err = err
			continue
		}
		refs[i].Decoded = d
	}
	return refs, nil
}
