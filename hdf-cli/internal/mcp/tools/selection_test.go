package tools

import (
	"slices"
	"strings"
	"testing"
)

func TestResolveToolSelection_DefaultIsEveryTool(t *testing.T) {
	got, err := ResolveToolSelection("")
	if err != nil {
		t.Fatalf("empty spec must not error: %v", err)
	}
	if !slices.Equal(got, canonicalToolOrder) {
		t.Errorf("empty spec must select every tool in canonical order\n got: %v\nwant: %v", got, canonicalToolOrder)
	}
}

func TestResolveToolSelection_AllProfileEqualsDefault(t *testing.T) {
	got, err := ResolveToolSelection("all")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, canonicalToolOrder) {
		t.Errorf("'all' must select every tool\n got: %v\nwant: %v", got, canonicalToolOrder)
	}
}

func TestResolveToolSelection_ReadProfile(t *testing.T) {
	got, err := ResolveToolSelection("read")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hdf_open", "hdf_inspect", "hdf_query", "hdf_compliance", "hdf_aggregate", "hdf_diff", "hdf_validate"}
	if !slices.Equal(got, want) {
		t.Errorf("'read' profile mismatch\n got: %v\nwant: %v", got, want)
	}
	// The read profile must not carry any write/author tool — that is the whole
	// point of advertising a smaller surface to an analysis agent.
	for _, w := range []string{"hdf_convert", "hdf_author", "hdf_apply_amendment"} {
		if slices.Contains(got, w) {
			t.Errorf("read profile must not include the write tool %q", w)
		}
	}
}

func TestResolveToolSelection_ExplicitNamesInCanonicalOrder(t *testing.T) {
	// Input order is deliberately reversed; output must be canonical order so the
	// surface is deterministic regardless of how the operator listed the names.
	got, err := ResolveToolSelection("hdf_query,hdf_open")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hdf_open", "hdf_query"}
	if !slices.Equal(got, want) {
		t.Errorf("explicit names must return in canonical order\n got: %v\nwant: %v", got, want)
	}
}

func TestResolveToolSelection_MixesProfileAndName(t *testing.T) {
	got, err := ResolveToolSelection("read,hdf_convert")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hdf_open", "hdf_inspect", "hdf_query", "hdf_compliance", "hdf_aggregate", "hdf_diff", "hdf_validate", "hdf_convert"}
	if !slices.Equal(got, want) {
		t.Errorf("profile+name mix mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestResolveToolSelection_DedupesAndToleratesWhitespace(t *testing.T) {
	got, err := ResolveToolSelection("  hdf_open , hdf_open ,read ")
	if err != nil {
		t.Fatal(err)
	}
	// read already contains hdf_open; the explicit duplicate must not appear twice.
	if c := slices.Contains(got, "hdf_open"); !c {
		t.Fatal("expected hdf_open present")
	}
	seen := map[string]int{}
	for _, n := range got {
		seen[n]++
	}
	for n, c := range seen {
		if c != 1 {
			t.Errorf("tool %q appears %d times; selection must be deduped", n, c)
		}
	}
}

func TestResolveToolSelection_UnknownTokenErrors(t *testing.T) {
	_, err := ResolveToolSelection("hdf_open,bogus_tool")
	if err == nil {
		t.Fatal("an unknown token must error rather than be silently dropped")
	}
	// The error must name the offending token and list what is valid, so an
	// operator can correct a launch config without reading source.
	msg := err.Error()
	if !strings.Contains(msg, "bogus_tool") {
		t.Errorf("error must name the bad token, got: %q", msg)
	}
	if !strings.Contains(msg, "hdf_query") || !strings.Contains(msg, "read") {
		t.Errorf("error must list valid names and profiles, got: %q", msg)
	}
}

func TestResolveToolSelection_EmptyTokensIgnored(t *testing.T) {
	// A trailing/duplicate comma must not be read as an empty tool name.
	got, err := ResolveToolSelection("hdf_open,,hdf_query,")
	if err != nil {
		t.Fatalf("empty comma fields must be ignored, got error: %v", err)
	}
	want := []string{"hdf_open", "hdf_query"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
