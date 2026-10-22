package evidenceref_test

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
)

// One package carrying every reference-bearing field, each spelled so the raw
// and decoded forms differ. A field missing from this document is a field
// Collect could drop silently.
const everyFieldPkg = `{
  "name": "p",
  "systemRef": "sys%20tem.json",
  "planRef": "pl%20an.json",
  "contents": [
    {"type": "results", "uri": "a%20one.json"},
    {"type": "results", "uri": "b%20two.json"}
  ],
  "externalEvidence": [{"uri": "ext%20ev.json", "format": "pdf"}],
  "externalReferences": [{"href": "ctx%20ref.json"}],
  "extensions": {"rawSourceArtifacts": [{"href": "raw%20src.xml"}]}
}`

func TestCollect_EnumeratesEveryReferenceField(t *testing.T) {
	refs, err := evidenceref.Collect([]byte(everyFieldPkg))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Keyed by field and index, because the caller re-attaches its own per-entry
	// data this way and a flat ordinal would pair it with the wrong reference.
	type key struct {
		field string
		index int
	}
	got := map[key]evidenceref.Reference{}
	for _, r := range refs {
		k := key{r.Field, r.Index}
		if prev, dup := got[k]; dup {
			t.Fatalf("duplicate key %v: %q and %q", k, prev.Stored, r.Stored)
		}
		got[k] = r
	}

	want := map[key][2]string{
		{"systemRef", -1}:                    {"sys%20tem.json", "sys tem.json"},
		{"planRef", -1}:                      {"pl%20an.json", "pl an.json"},
		{"contents", 0}:                      {"a%20one.json", "a one.json"},
		{"contents", 1}:                      {"b%20two.json", "b two.json"},
		{"externalEvidence", 0}:              {"ext%20ev.json", "ext ev.json"},
		{"externalReferences", 0}:            {"ctx%20ref.json", "ctx ref.json"},
		{"extensions.rawSourceArtifacts", 0}: {"raw%20src.xml", "raw src.xml"},
	}
	if len(got) != len(want) {
		t.Errorf("collected %d references, want %d", len(got), len(want))
	}
	for k, w := range want {
		r, ok := got[k]
		if !ok {
			t.Errorf("%v: not collected", k)
			continue
		}
		if r.Stored != w[0] {
			t.Errorf("%v: Stored = %q, want %q", k, r.Stored, w[0])
		}
		if string(r.Decoded) != w[1] {
			t.Errorf("%v: Decoded = %q, want %q", k, r.Decoded, w[1])
		}
		if r.Err != nil {
			t.Errorf("%v: Err = %v, want nil", k, r.Err)
		}
	}
}

// A malformed escape is reported on its own reference, not as a failure of the
// whole enumeration — one bad spelling must not hide the other references.
func TestCollect_ReportsAMalformedEscapePerReference(t *testing.T) {
	const pkg = `{"name":"p","contents":[{"type":"results","uri":"bad%2.json"},{"type":"results","uri":"fine.json"}]}`
	refs, err := evidenceref.Collect([]byte(pkg))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var contents []evidenceref.Reference
	for _, r := range refs {
		if r.Field == "contents" {
			contents = append(contents, r)
		}
		// An absent scalar is still enumerated, so a caller reporting on one
		// never has to tell "absent" apart from "not enumerated". It carries no
		// decode error, because there is nothing to decode.
		if r.Field == "systemRef" || r.Field == "planRef" {
			if r.Stored != "" || r.Decoded != "" || r.Err != nil {
				t.Errorf("%s: absent scalar came back %q/%q/%v", r.Field, r.Stored, r.Decoded, r.Err)
			}
		}
	}
	if len(contents) != 2 {
		t.Fatalf("collected %d contents references, want 2", len(contents))
	}
	if contents[0].Err == nil {
		t.Errorf("%q: Err = nil, want a decode error", contents[0].Stored)
	}
	if contents[1].Err != nil {
		t.Errorf("%q: Err = %v, want nil", contents[1].Stored, contents[1].Err)
	}
	if contents[1].Decoded != "fine.json" {
		t.Errorf("the good reference decoded to %q", contents[1].Decoded)
	}
}

// A consumer that needs its own per-entry fields — a content's type, say —
// iterates its own parse and asks the seam for the reference, rather than
// re-reading the uri itself.
func TestAt_LooksUpByFieldAndIndex(t *testing.T) {
	refs, err := evidenceref.Collect([]byte(everyFieldPkg))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r, ok := refs.At("contents", 1)
	if !ok {
		t.Fatal("contents[1]: not found")
	}
	if r.Stored != "b%20two.json" || string(r.Decoded) != "b two.json" {
		t.Errorf("contents[1] = %q/%q", r.Stored, r.Decoded)
	}

	// A scalar is addressed by -1, the same index Collect records it under.
	if r, ok := refs.At("systemRef", -1); !ok || string(r.Decoded) != "sys tem.json" {
		t.Errorf("systemRef: ok=%v decoded=%q", ok, r.Decoded)
	}

	// A miss must be reported, never a zero Reference that reads as an empty
	// but present one.
	if _, ok := refs.At("contents", 99); ok {
		t.Error("contents[99]: reported found")
	}
	if _, ok := refs.At("noSuchField", 0); ok {
		t.Error("noSuchField: reported found")
	}
}
