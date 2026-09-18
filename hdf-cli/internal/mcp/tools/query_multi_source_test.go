package tools

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// Three real converter outputs under one HDF_MCP_ROOT: gosec (SARIF, 1 baseline,
// 4 requirements, no CWE), OWASP ZAP (4 baselines, 28, 8 distinct CWEs), grype
// (1 baseline, 26, no CWE). Expected values were computed directly from the
// fixture JSON, not through the tool.
func threeScannerSources(t *testing.T) (gosec, zap, grype string) {
	t.Helper()
	srcs := sourcesUnderRoot(t, "sarif-gosec.json", "zap-webgoat.json", "grype-duplicate-ids.json")
	return srcs[0].Path, srcs[1].Path, srcs[2].Path
}

// allQueryPages follows nextPage until the last page and returns every row, so
// a set-wide assertion is not silently made over one page of a paginated view.
func allQueryPages(t *testing.T, in queryInput) (queryOutput, []map[string]any) {
	t.Helper()
	var rows []map[string]any
	var first queryOutput
	for page := 0; ; {
		in.Page = page
		res, out := callQuery(t, in)
		if res.IsError {
			t.Fatalf("page %d errored: %s", page, payloadText(t, res))
		}
		if page == 0 {
			first = out
		}
		rows = append(rows, out.Requirements...)
		if out.NextPage == 0 {
			return first, rows
		}
		page = out.NextPage
	}
}

// TestQuery_MultiSource_DistinctCWEAcrossTools is the card's first failing test:
// one call over three scanners' documents returns rows from all of them, and the
// opt-in cwe field unions to exactly the CWEs the fixtures carry (only ZAP has
// any: 16, 20, 89, 200, 352, 425, 541, 933).
func TestQuery_MultiSource_DistinctCWEAcrossTools(t *testing.T) {
	gosec, zap, grype := threeScannerSources(t)
	in := queryInput{Sources: pathSources(gosec, zap, grype), Fields: []string{"cwe"}}
	first, rows := allQueryPages(t, in)
	if first.Total != 58 || len(rows) != 58 {
		t.Fatalf("total = %d, rows = %d, want 58 (4 + 28 + 26)", first.Total, len(rows))
	}
	cwes := map[string]bool{}
	for _, r := range rows {
		list, _ := r["cwe"].([]string)
		for _, c := range list {
			if strings.HasSuffix(c, "-1") { // ZAP's "-1" means "no CWE"
				continue
			}
			if n := c[strings.LastIndex(c, "-")+1:]; n != "" {
				cwes[n] = true
			}
		}
	}
	got := make([]string, 0, len(cwes))
	for c := range cwes {
		got = append(got, c)
	}
	sort.Strings(got)
	want := []string{"16", "20", "200", "352", "425", "541", "89", "933"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("distinct CWEs across the set = %v, want %v", got, want)
	}

	// The envelope names the set, not one handle.
	if first.Handle != "" {
		t.Errorf("multi-source output must omit handle, got %q", first.Handle)
	}
	if len(first.Sources) != 3 {
		t.Fatalf("sources = %+v, want three members", first.Sources)
	}
	for i, m := range first.Sources {
		if m.Index != i || m.Handle == "" {
			t.Errorf("sources[%d] = %+v, want index %d and a handle", i, m, i)
		}
	}
	if first.DocType != "results" {
		t.Errorf("docType = %q, want results", first.DocType)
	}
}

// Baselines in the view carry the <tool>/<original> name, so a baseline glob
// selects one scanner's findings across the set and full rows say which
// scanner each row came from.
func TestQuery_MultiSource_BaselineGlobSelectsOneTool(t *testing.T) {
	gosec, zap, grype := threeScannerSources(t)
	set := pathSources(gosec, zap, grype)
	for glob, want := range map[string]int{"gosec/*": 4, "owasp zap/*": 28, "grype/*": 26, "*": 58} {
		_, out := callQuery(t, queryInput{Sources: set, Baseline: glob, Limit: 1})
		if out.Total != want {
			t.Errorf("baseline %q over the set: total = %d, want %d", glob, out.Total, want)
		}
	}
	_, full := callQuery(t, queryInput{Sources: set, Baseline: "gosec/*", Verbosity: "full"})
	if len(full.Requirements) != 4 || full.Requirements[0]["baseline"] != "gosec/gosec" {
		t.Errorf("full rows must carry the renamed baseline gosec/gosec, got %v", full.Requirements)
	}
	_, g := callQuery(t, queryInput{Sources: set, Baseline: "grype/*", Verbosity: "full", Limit: 1})
	if g.Requirements[0]["baseline"] != "grype/tensorflow/tensorflow:latest" {
		t.Errorf("grype baseline name = %v, want grype/tensorflow/tensorflow:latest", g.Requirements[0]["baseline"])
	}
}

// The wire shape of a single-source response is unchanged: handle present,
// no sources key — pinned on the marshalled JSON, which is what clients parse.
func TestQuery_SingleSource_WireShapeUnchanged(t *testing.T) {
	_, zap, _ := threeScannerSources(t)
	_, out := callQuery(t, queryInput{Sources: nil, Source: pathSources(zap)[0], Limit: 1})
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(mustJSON(&out)), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["handle"]; !ok {
		t.Error("single-source response must carry handle")
	}
	if _, ok := m["sources"]; ok {
		t.Error("single-source response must not carry a sources key")
	}
	_, multi := callQuery(t, queryInput{Sources: pathSources(zap, zap), Limit: 1})
	m = nil
	if err := json.Unmarshal([]byte(mustJSON(&multi)), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["handle"]; ok {
		t.Error("multi-source response must omit the handle key")
	}
	if _, ok := m["sources"]; !ok {
		t.Error("multi-source response must carry sources")
	}
}

// TestQuery_DescriptionAdvertisesSources: a model chooses a tool by its
// description, not by reading parameter hints — in the js1nv.11 smoke a 20B
// model used sources[] on hdf_aggregate (whose description says MULTIPLE) and
// made three single-source hdf_query calls for a cross-scanner question. The
// description must say, in a sentence, that sources[] combines several
// documents for the call; the code-blind-spot sentence (uqhe.13) stays.
func TestQuery_DescriptionAdvertisesSources(t *testing.T) {
	d := strings.ToLower(queryToolDescription)
	for _, want := range []string{"sources", "several", "one set"} {
		if !strings.Contains(d, want) {
			t.Errorf("hdf_query description must mention %q, got %q", want, queryToolDescription)
		}
	}
	if !strings.Contains(queryToolDescription, "read the source file for the `code` payload itself") {
		t.Error("the code-blind-spot sentence must be kept verbatim")
	}
}
