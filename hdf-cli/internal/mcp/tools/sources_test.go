package tools

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
)

// The sources[] contract shared by hdf_query and hdf_compliance (ADR-0016 §7,
// card js1nv.10): exactly one of source / sources; a one-element sources is the
// single-source call; every member must be a valid hdf-results document, and a
// bad member refuses the whole set naming its index — never a partial answer.

func TestSources_BothSourceAndSourcesRefused(t *testing.T) {
	srcs := sourcesUnderRoot(t, "sarif-gosec.json", "zap-webgoat.json")
	res, _ := callQuery(t, queryInput{Source: srcs[0], Sources: srcs})
	assertArgError(t, res, "sets both source and sources")
	cres, _ := callCompliance(t, complianceInput{Source: srcs[0], Sources: srcs})
	assertArgError(t, cres, "sets both source and sources")
}

func TestSources_NeitherGivenKeepsTodaysError(t *testing.T) {
	res, _ := callQuery(t, queryInput{})
	assertArgError(t, res, "source sets neither path nor handle")
	cres, _ := callCompliance(t, complianceInput{})
	assertArgError(t, cres, "source sets neither path nor handle")
}

// A handle is as good as a path for a member: the view resolves it, and a
// member that resolves but is the wrong type is still named by its path in
// the refusal — the same label a path member gets.
func TestSources_HandleMembers(t *testing.T) {
	srcs := sourcesUnderRoot(t, "sarif-gosec.json", "zap-webgoat.json", "diff-system-from.json")
	_, opened := callQuery(t, queryInput{Source: srcs[1], Limit: 1})
	zapHandle := handle.Source{Handle: opened.Handle}
	_, out := callQuery(t, queryInput{Sources: []handle.Source{srcs[0], zapHandle}, Limit: 1})
	if out.Total != 32 || len(out.Sources) != 2 || out.Sources[1].Source != srcs[1].Path {
		t.Errorf("path + handle members: total %d, sources %+v; want 32 and the handle's path named at index 1", out.Total, out.Sources)
	}
	// hdf_aggregate names a failing handle member by the path its handle carries.
	_, sys := callInspect(t, inspectInput{Source: srcs[2]})
	_, agg := callAggregate(t, aggregateInput{Sources: []handle.Source{srcs[0], {Handle: sys.Handle}}})
	if len(agg.Failures) != 1 || agg.Failures[0].Index != 1 || agg.Failures[0].Source != "diff-system-from.json" {
		t.Errorf("aggregate failure for a wrong-type handle member = %+v, want index 1 labelled diff-system-from.json", agg.Failures)
	}
	if agg.Aggregate.Total != 4 {
		t.Errorf("the rest still aggregate: total %d, want 4 (gosec)", agg.Aggregate.Total)
	}
}

// A one-element sources is the single-source call, byte for byte: same handle,
// same docType, same rows under their original baseline names — nothing is
// renamed or labelled when there is nothing to combine.
func TestSources_OneElementSourcesIsTheSingleSourceCall(t *testing.T) {
	srcs := sourcesUnderRoot(t, "zap-webgoat.json")
	_, single := callQuery(t, queryInput{Source: srcs[0], Verbosity: "full", Limit: 3})
	_, one := callQuery(t, queryInput{Sources: srcs, Verbosity: "full", Limit: 3})
	if mustJSON(&single) != mustJSON(&one) {
		t.Errorf("sources:[x] must equal source:x\n single: %s\n one:    %s", mustJSON(&single), mustJSON(&one))
	}
	if single.Handle == "" || len(single.Sources) != 0 {
		t.Errorf("single-source output must carry handle and no sources[], got handle %q sources %v", single.Handle, single.Sources)
	}
	if got := single.Requirements[0]["baseline"]; got != "OWASP ZAP Scan: ciscobinary.openh264.org" {
		t.Errorf("one-element sources must not rename baselines, got %v", got)
	}

	_, csingle := callCompliance(t, complianceInput{Source: srcs[0], GroupBy: "baseline"})
	_, cone := callCompliance(t, complianceInput{Sources: srcs, GroupBy: "baseline"})
	if mustJSON(&csingle) != mustJSON(&cone) {
		t.Errorf("compliance sources:[x] must equal source:x\n single: %s\n one:    %s", mustJSON(&csingle), mustJSON(&cone))
	}
}

// A non-results member refuses the set, naming the member and its type, so an
// agent that passed a system document by mistake is told which one — and no
// numbers are returned over the members that did load.
func TestSources_NonResultsMemberRefusesTheSet(t *testing.T) {
	srcs := sourcesUnderRoot(t, "zap-webgoat.json", "diff-system-from.json")
	res, out := callQuery(t, queryInput{Sources: srcs, Limit: 1})
	if !res.IsError {
		t.Fatalf("a system document in sources[] must be refused, got total %d", out.Total)
	}
	text := payloadText(t, res)
	for _, want := range []string{"sources[1]", "system", "WRONG_DOC_TYPE"} {
		if !strings.Contains(text, want) {
			t.Errorf("refusal must contain %q, got %s", want, text)
		}
	}
	if out.Total != 0 || len(out.Requirements) != 0 {
		t.Errorf("a refused set must return no rows, got %+v", out)
	}
	cres, cout := callCompliance(t, complianceInput{Sources: srcs})
	if !cres.IsError || cout.Compliance != 0 {
		t.Errorf("compliance over a refused set must be an error with no score, got %+v", cout)
	}
}

// A baseline document is a requirement-bearing type hdf_query accepts alone, but
// a multi-source view is a results view (statuses, compliance): a baseline
// member is refused too, so the set is never a mix of scored and unscored rows.
func TestSources_BaselineMemberRefusesTheSet(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(readToolsFixture(t, "sarif-gosec.json"), &doc); err != nil {
		t.Fatal(err)
	}
	// Turn the results document into a baseline document: one baseline of
	// requirement definitions, no results. The loader detects it as "baseline".
	b := doc["baselines"].([]any)[0].(map[string]any)
	reqs := b["requirements"].([]any)
	for _, r := range reqs {
		delete(r.(map[string]any), "results")
	}
	baselineDoc := map[string]any{"name": "gosec-rules", "version": "1", "requirements": reqs}
	raw, _ := json.Marshal(baselineDoc)
	writeRootFiles(t, map[string][]byte{"rules.json": raw, "zap.json": readToolsFixture(t, "zap-webgoat.json")})
	_, alone := callQuery(t, queryInput{Source: handle.Source{Path: "rules.json"}, Limit: 1})
	if alone.DocType != "baseline" {
		t.Fatalf("fixture invariant: rules.json must load as a baseline document, got %q", alone.DocType)
	}
	res, _ := callQuery(t, queryInput{Sources: []handle.Source{{Path: "zap.json"}, {Path: "rules.json"}}, Limit: 1})
	if !res.IsError || !strings.Contains(payloadText(t, res), "sources[1]") {
		t.Errorf("a baseline member must refuse the set naming sources[1], got %s", payloadTextOrEmpty(res))
	}
}

// A schema-invalid member refuses the set the same way: the index and the
// reason, no partial view.
func TestSources_InvalidMemberRefusesTheSet(t *testing.T) {
	broken := bytes.Replace(readToolsFixture(t, "sarif-gosec.json"), []byte(`"impact":`), []byte(`"impact":"high","impactWas":`), 1)
	if bytes.Equal(broken, readToolsFixture(t, "sarif-gosec.json")) {
		t.Fatal("fixture invariant: sarif-gosec.json carries an impact field to corrupt")
	}
	writeRootFiles(t, map[string][]byte{"broken.json": broken, "zap.json": readToolsFixture(t, "zap-webgoat.json")})
	res, _ := callQuery(t, queryInput{Sources: []handle.Source{{Path: "broken.json"}, {Path: "zap.json"}}, Limit: 1})
	if !res.IsError {
		t.Fatal("a schema-invalid member must refuse the set")
	}
	text := payloadText(t, res)
	for _, want := range []string{"sources[0]", "SCHEMA_INVALID"} {
		if !strings.Contains(text, want) {
			t.Errorf("refusal must contain %q, got %s", want, text)
		}
	}
}

// Engine merge warnings reach the caller: the same document twice yields two
// same-named baselines, which the view keeps (read tools key on position) and
// the notice reports, so a name-keyed consumer is not surprised later.
func TestSources_MergeWarningsSurfaceInNotice(t *testing.T) {
	srcs := sourcesUnderRoot(t, "sarif-gosec.json")
	_, out := callQuery(t, queryInput{Sources: []handle.Source{srcs[0], srcs[0]}, Limit: 1})
	if out.Total != 8 {
		t.Errorf("the same document twice is 8 requirements, got %d", out.Total)
	}
	for _, want := range []string{"duplicate-baseline-name", "gosec/gosec"} {
		if !strings.Contains(out.Notice, want) {
			t.Errorf("notice must report the merge warning %q, got %q", want, out.Notice)
		}
	}
}

// The member label is the path the caller passed; for a handle member, the
// path inside the handle; for a content-addressed handle (no path), the slot —
// never empty, so a refusal or a member list always names something.
func TestSources_MemberLabel(t *testing.T) {
	for _, c := range []struct{ path, handlePath, slot, want string }{
		{"zap.json", "", "sources[0]", "zap.json"},
		{"", "scans/zap.json", "sources[1]", "scans/zap.json"},
		{"", "", "sources[2]", "sources[2]"},
		{"zap.json", "other.json", "sources[3]", "zap.json"},
	} {
		if got := memberLabel(c.path, c.handlePath, c.slot); got != c.want {
			t.Errorf("memberLabel(%q, %q, %q) = %q, want %q", c.path, c.handlePath, c.slot, got, c.want)
		}
	}
}
