package tools

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callInspect(t *testing.T, in inspectInput) (*sdkmcp.CallToolResult, inspectOutput) {
	t.Helper()
	res, out, err := hdfInspect(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfInspect Go error (should be degraded/taxonomy): %v", err)
	}
	return res, out
}

// structureJSON re-serializes the structure so tests can assert no "requirements"
// array appears anywhere in the response (the bright line).
func structureJSON(t *testing.T, out inspectOutput) string {
	t.Helper()
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// The card's designated first-failing test: hdf_inspect returns structure and
// counts for a results document but NEVER a requirement collection.
func TestHdfInspect_NeverReturnsRequirements(t *testing.T) {
	path := writeRoot(t, "scan.json", fixtures.Results.Minimal)
	errRes, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
	if errRes != nil || !out.Valid || out.DocType != "results" {
		t.Fatalf("results inspect must succeed: err=%v out=%+v", errRes, out)
	}
	// Structure carries baseline structure with a requirement COUNT + status breakdown.
	baselines, ok := out.Structure["baselines"].([]map[string]any)
	if !ok || len(baselines) == 0 {
		t.Fatalf("results structure must list baselines with counts, got %+v", out.Structure["baselines"])
	}
	if _, ok := baselines[0]["requirementCount"]; !ok {
		t.Error("baseline structure must carry requirementCount")
	}
	if _, ok := baselines[0]["statusBreakdown"]; !ok {
		t.Error("baseline structure must carry statusBreakdown")
	}
	// The bright line: no requirement array anywhere in the serialized response.
	raw := structureJSON(t, out)
	if strings.Contains(raw, `"requirements":[`) || strings.Contains(raw, `"requirements": [`) {
		t.Errorf("hdf_inspect must NEVER return a requirements array; response contained one:\n%s", raw)
	}
}

func TestHdfInspect_AllEightTypes(t *testing.T) {
	cases := []struct {
		name     string
		content  []byte
		docType  string
		wantKeys []string
	}{
		{"results", fixtures.Results.Minimal, "results", []string{"baselines", "components", "metadata"}},
		{"baseline", fixtures.Baseline.Win2022Stig, "baseline", []string{"structure", "groups", "metadata"}},
		{"system", readCLIFixture(t, "system.json"), "system", []string{"components", "metadata"}},
		{"plan", readCLIFixture(t, "plan.json"), "plan", []string{"assessments", "metadata"}},
		{"amendments", fixtures.Amendments.UC01Fixed, "amendments", []string{"overrides", "metadata"}},
		{"evidence-package", readCLIFixture(t, "evidence.json"), "evidence-package", []string{"contents", "metadata"}},
		{"comparison", readToolsFixture(t, "comparison.json"), "comparison", []string{"summary", "diffs", "metadata"}},
		{"requirement-change-event", readToolsFixture(t, "change-event.json"), "requirement-change-event", []string{"envelope", "change"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeRoot(t, c.name+".json", c.content)
			errRes, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
			if errRes != nil {
				t.Fatalf("%s must not error: %s", c.name, payloadText(t, errRes))
			}
			if out.DocType != c.docType {
				t.Errorf("docType = %q, want %q", out.DocType, c.docType)
			}
			if !out.Valid {
				t.Fatalf("%s should be valid, got errors: %+v", c.name, out.ValidationErrors)
			}
			for _, k := range c.wantKeys {
				if _, ok := out.Structure[k]; !ok {
					t.Errorf("%s structure missing key %q; got keys %v", c.name, k, keysOf(out.Structure))
				}
			}
			// No requirement array for ANY type.
			if raw := structureJSON(t, out); strings.Contains(raw, `"requirements":[`) || strings.Contains(raw, `"requirements": [`) {
				t.Errorf("%s: hdf_inspect must never return a requirements array:\n%s", c.name, raw)
			}
		})
	}
}

func TestHdfInspect_ChangeEventEnvelopeMetadata(t *testing.T) {
	path := writeRoot(t, "ce.json", readToolsFixture(t, "change-event.json"))
	_, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
	env, ok := out.Structure["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("change-event must surface an envelope, got %+v", out.Structure)
	}
	for _, k := range []string{"eventId", "source", "sequence", "schemaRef"} {
		if _, ok := env[k]; !ok {
			t.Errorf("change-event envelope missing %q", k)
		}
	}
}

func TestHdfInspect_SectionSelects(t *testing.T) {
	path := writeRoot(t, "sys.json", readCLIFixture(t, "system.json"))
	_, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}, Section: "components"})
	if out.Section != "components" {
		t.Errorf("section echo = %q, want components", out.Section)
	}
	if len(out.Structure) != 1 {
		t.Errorf("a selected section must return only that key, got %v", keysOf(out.Structure))
	}
	if _, ok := out.Structure["components"]; !ok {
		t.Error("selected section 'components' missing from structure")
	}
}

func TestHdfInspect_InvalidSectionForType_FullPlusNotice(t *testing.T) {
	// "envelope" is a change-event section, not valid for results.
	path := writeRoot(t, "scan.json", fixtures.Results.Minimal)
	_, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}, Section: "envelope"})
	if out.Section != "" {
		t.Error("an invalid section must not be echoed as selected")
	}
	if out.Notice == "" || !strings.Contains(out.Notice, "not valid for a results document") {
		t.Errorf("invalid section must yield a notice naming valid sections, got %q", out.Notice)
	}
	if _, ok := out.Structure["baselines"]; !ok {
		t.Error("invalid section should fall back to the full structure")
	}
}

func TestHdfInspect_DegradedOnInvalid(t *testing.T) {
	bad := []byte("{\n  \"components\": \"not an array\"\n}") // detects system, invalid
	path := writeRoot(t, "bad.json", bad)
	errRes, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
	if errRes != nil {
		t.Fatalf("invalid doc must degrade, not hard-fail: %s", payloadText(t, errRes))
	}
	if out.Valid || out.DocType != "system" || len(out.ValidationErrors) == 0 {
		t.Errorf("expected degraded system read, got %+v", out)
	}
}

func TestHdfInspect_VerbosityCapTruncates(t *testing.T) {
	// The multilayered results fixture has enough structure to exceed the concise
	// cap at times; assert the cap holds and any truncation carries a notice.
	path := writeRoot(t, "big.json", fixtures.Results.InspecMultilayered)
	_, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}, Verbosity: "concise"})
	if out.Truncated && (out.Notice == "" || out.NextPage == 0) {
		t.Error("a truncated inspect response must carry a notice + nextPage")
	}
	// full verbosity must hold at least as much as concise.
	_, full := callInspect(t, inspectInput{Source: handle.Source{Path: path}, Verbosity: "full"})
	if len(full.Structure) < len(out.Structure) {
		t.Error("full verbosity should return at least as many sections as concise")
	}
}

func TestHdfInspect_Annotations(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterInspect(s, loader.New(0, 0, 0))
	raw := driveToolsListJSON(t, s)
	if !strings.Contains(raw, `"name":"hdf_inspect"`) {
		t.Fatalf("hdf_inspect not listed: %s", raw)
	}
	if !strings.Contains(raw, `"readOnlyHint":true`) || !strings.Contains(raw, `"openWorldHint":false`) {
		t.Errorf("hdf_inspect must be read-only + closed-world: %s", raw)
	}
	// The bright-line clause must appear in the description verbatim.
	if !strings.Contains(raw, "use hdf_query") {
		t.Error("hdf_inspect description must direct requirement listing to hdf_query")
	}
}

// advertisedSections is the section vocabulary hdf_inspect is expected to
// support across all document types — each grounded in a schema $def top-level
// key. The grounding test below pins production's dynamically-derived section
// keys against this contract in both directions.
var advertisedSections = []string{
	"baselines", "components", "statistics", "metadata", // results
	"structure", "groups", // baseline
	"dataflows", "controls", // system
	"assessments", "schedule", // plan
	"overrides",                // amendments
	"contents", "completeness", // evidence-package
	"summary", "diffs", // comparison
	"envelope", "change", // requirement-change-event
}

func TestAllSections_GroundedInStructures(t *testing.T) {
	// Every advertised section must be a real structure key for at least one type,
	// and every real structure key must be advertised — the vocabulary is
	// grounded, not invented.
	advertised := map[string]bool{}
	for _, s := range advertisedSections {
		advertised[s] = true
	}
	seen := map[string]bool{}
	ld := loader.New(0, 0, 0)
	for _, c := range []struct {
		name    string
		content []byte
	}{
		{"results.json", fixtures.Results.Minimal},
		{"baseline.json", fixtures.Baseline.Win2022Stig},
		{"system.json", readCLIFixture(t, "system.json")},
		{"plan.json", readCLIFixture(t, "plan.json")},
		{"amendments.json", fixtures.Amendments.UC01Fixed},
		{"evidence.json", readCLIFixture(t, "evidence.json")},
		{"comparison.json", readToolsFixture(t, "comparison.json")},
		{"change-event.json", readToolsFixture(t, "change-event.json")},
	} {
		res, _ := ld.Load(c.content)
		for k := range buildStructure(res.Engine, c.content) {
			seen[k] = true
			if !advertised[k] {
				t.Errorf("structure key %q (from %s) is not in the advertised section list", k, c.name)
			}
		}
	}
	for s := range advertised {
		if !seen[s] {
			t.Errorf("advertised section %q is not produced by any document type", s)
		}
	}
}

func TestBoundInspectResponse_Truncates(t *testing.T) {
	// A structure well over the concise budget must be truncated with a notice.
	big := map[string]any{}
	for i := 0; i < 40; i++ {
		rows := make([]map[string]any, 0, 30)
		for j := 0; j < 30; j++ {
			rows = append(rows, map[string]any{"id": j, "detail": strings.Repeat("component inventory entry ", 8)})
		}
		big[strings.Repeat("k", 3)+string(rune('a'+i))] = rows
	}
	out := inspectOutput{DocType: "system", Valid: true, Structure: big}
	boundInspectResponse(&out, "concise", 0)
	if !out.Truncated {
		t.Fatal("an over-budget structure must be truncated")
	}
	if out.Notice == "" || out.NextPage != 1 {
		t.Errorf("truncation must carry a notice + nextPage, got notice=%q next=%d", out.Notice, out.NextPage)
	}
	if len(out.Structure) >= len(big) {
		t.Errorf("truncation must drop structure keys, kept %d of %d", len(out.Structure), len(big))
	}
	if !strings.Contains(out.Notice, "concise") {
		t.Errorf("notice should name the verbosity tier, got %q", out.Notice)
	}
}

func TestBoundInspectResponse_FullTierLabel(t *testing.T) {
	big := map[string]any{}
	for i := 0; i < 300; i++ {
		big["key"+string(rune(i))] = strings.Repeat("assessment schedule metadata ", 6)
	}
	out := inspectOutput{DocType: "plan", Valid: true, Structure: big}
	boundInspectResponse(&out, "full", 0)
	if out.Truncated && !strings.Contains(out.Notice, "full") {
		t.Errorf("full-tier truncation notice should say 'full', got %q", out.Notice)
	}
}

func TestBoundInspectResponse_PagingRetrievesDifferentKeys(t *testing.T) {
	// Functional pagination: page 1 must return DIFFERENT structure keys than
	// page 0 — the dropped sections are retrievable by paging, not a dead arg.
	big := map[string]any{}
	for i := 0; i < 40; i++ {
		rows := make([]map[string]any, 0, 30)
		for j := 0; j < 30; j++ {
			rows = append(rows, map[string]any{"id": j, "detail": strings.Repeat("component inventory entry ", 8)})
		}
		big["sec"+string(rune('a'+i))] = rows
	}
	mk := func() inspectOutput {
		s := map[string]any{}
		for k, v := range big {
			s[k] = v
		}
		return inspectOutput{DocType: "system", Valid: true, Structure: s}
	}
	p0 := mk()
	boundInspectResponse(&p0, "concise", 0)
	if !p0.Truncated || p0.NextPage != 1 {
		t.Fatalf("page 0 should truncate with nextPage=1, got truncated=%v next=%d", p0.Truncated, p0.NextPage)
	}
	p1 := mk()
	boundInspectResponse(&p1, "concise", 1)
	// The two pages must not overlap, and together cover more than either alone.
	for k := range p0.Structure {
		if _, dup := p1.Structure[k]; dup {
			t.Errorf("page 1 re-returned key %q from page 0 — paging is not advancing", k)
		}
	}
	if len(p1.Structure) == 0 {
		t.Error("page 1 should return the next set of dropped keys, got none")
	}
}

func TestStructureBuilders_Defensive(t *testing.T) {
	if len(resultsStructure(nil)) != 0 {
		t.Error("resultsStructure(nil) must be empty")
	}
	if len(baselineStructure(nil)) != 0 {
		t.Error("baselineStructure(nil) must be empty")
	}
	if len(genericStructure([]byte("not json"), systemShape)) != 0 {
		t.Error("genericStructure on bad JSON must be empty")
	}
	// An unknown-but-detected type falls to the default minimal metadata.
	if s := buildStructure(&hdfengine.LoadResult{DocType: "mystery"}, nil); s["metadata"] == nil {
		t.Errorf("unknown docType should still return minimal metadata, got %+v", s)
	}
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// readToolsFixture reads a fixture from this package's own testdata dir.
func readToolsFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Skipf("tools fixture %s unavailable: %v", name, err)
	}
	return b
}
