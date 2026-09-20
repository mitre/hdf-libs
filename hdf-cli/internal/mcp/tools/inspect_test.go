package tools

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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
	if (errRes != nil && errRes.IsError) || !out.Valid || out.DocType != "results" {
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
			if errRes != nil && errRes.IsError {
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
	if errRes != nil && errRes.IsError {
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

// TestInspect_ResultsWithoutStatistics guards hdf-libs-l3kf: converters such as
// gosec-to-hdf omit the optional statistics block. hdf_inspect must summarize
// such a document (omitting statistics), not nil-deref *Statistics and crash the
// long-lived MCP session.
func TestInspect_ResultsWithoutStatistics(t *testing.T) {
	doc := []byte(`{"generator":{"name":"gosec-to-hdf","version":"1.0.0"},` +
		`"baselines":[{"name":"gosec Scan","requirements":[{"id":"G101","title":"t",` +
		`"descriptions":[{"label":"default","data":"d"}],"impact":0.5,"tags":{},` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2026-01-01T00:00:00Z"}]}]}],` +
		`"timestamp":"2026-01-01T00:00:00Z"}`)
	path := writeRoot(t, "gosec.hdf.json", doc)
	errRes, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
	if errRes != nil && errRes.IsError {
		t.Fatalf("must not error on a statistics-less Results document: %s", payloadText(t, errRes))
	}
	if _, ok := out.Structure["statistics"]; ok {
		t.Errorf("statistics key must be omitted when the document has none; got %v", out.Structure["statistics"])
	}
	if _, ok := out.Structure["baselines"]; !ok {
		t.Errorf("expected baselines in the structure; got keys %v", keysOf(out.Structure))
	}
}

// TestShapeFunctions_OmittedOptionals covers the generic doc types hdf_inspect
// dispatches on: each must summarize a document that omits its optional blocks
// (an empty map) without panicking. Results/baseline are covered by
// TestInspect_ResultsWithoutStatistics and TestStructureBuilders_Defensive.
func TestShapeFunctions_OmittedOptionals(t *testing.T) {
	shapes := map[string]func(map[string]any) map[string]any{
		"system":                   systemShape,
		"plan":                     planShape,
		"amendments":               amendmentsShape,
		"evidence-package":         evidenceShape,
		"comparison":               comparisonShape,
		"requirement-change-event": changeEventShape,
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			if got := shape(map[string]any{}); got == nil {
				t.Errorf("%s shape must return a non-nil structure for an optionals-omitted document", name)
			}
		})
	}
}

// TestInspect_ResultsSurfacesToolGeneratorAndBaselineLabels is js1nv.6's first
// failing test: a results document's provenance — root tool and generator, and
// each baseline's labels — is visible through hdf_inspect, and a document
// without them gets no synthesized keys (the statistics rule).
func TestInspect_ResultsSurfacesToolGeneratorAndBaselineLabels(t *testing.T) {
	// Real ZAP converter output: tool OWASP ZAP 2.7.0, generator zap-to-hdf 1.0.0,
	// four baselines each labelled with its site as `component`.
	path := writeRoot(t, "zap.hdf.json", readToolsFixture(t, "zap-webgoat.json"))
	errRes, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
	if errRes != nil && errRes.IsError {
		t.Fatalf("inspect must succeed: %s", payloadText(t, errRes))
	}
	meta, ok := out.Structure["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata missing from structure: %v", keysOf(out.Structure))
	}
	if got := meta["tool"]; !reflect.DeepEqual(got, map[string]any{"name": "OWASP ZAP", "version": "2.7.0"}) {
		t.Errorf("metadata.tool = %#v, want {name: OWASP ZAP, version: 2.7.0}", got)
	}
	if got := meta["generator"]; !reflect.DeepEqual(got, map[string]any{"name": "zap-to-hdf", "version": "1.0.0"}) {
		t.Errorf("metadata.generator = %#v, want {name: zap-to-hdf, version: 1.0.0}", got)
	}
	baselines, ok := out.Structure["baselines"].([]map[string]any)
	if !ok || len(baselines) != 4 {
		t.Fatalf("expected 4 baseline entries, got %T %v", out.Structure["baselines"], out.Structure["baselines"])
	}
	if got := baselines[0]["labels"]; !reflect.DeepEqual(got, map[string]string{"component": "ciscobinary.openh264.org"}) {
		t.Errorf("baselines[0].labels = %#v, want {component: ciscobinary.openh264.org}", got)
	}
	if out.Truncated {
		t.Errorf("a 4-baseline document with labels must fit the concise budget; got truncated with notice %q", out.Notice)
	}

	// A document with no tool, no generator and no baseline labels: the keys are
	// absent, never synthesized as empty.
	bare := writeRoot(t, "bare.json", readToolsFixture(t, "query-results.json"))
	_, out = callInspect(t, inspectInput{Source: handle.Source{Path: bare}})
	meta = out.Structure["metadata"].(map[string]any)
	for _, k := range []string{"tool", "generator"} {
		if _, present := meta[k]; present {
			t.Errorf("metadata.%s must be absent when the document has none; got %#v", k, meta[k])
		}
	}
	for i, b := range out.Structure["baselines"].([]map[string]any) {
		if _, present := b["labels"]; present {
			t.Errorf("baselines[%d].labels must be absent when the baseline has none", i)
		}
	}
}

// TestInspect_ToolMetadataShapes pins the tool projection across the shapes real
// converter output takes: name only (Prisma has no tool.version), name +
// version + format (SARIF converter output records the named source format),
// and — derived from a real document, as TestInspect_ResultsWithoutStatistics
// does — an empty tool object, which must project to no key at all.
func TestInspect_ToolMetadataShapes(t *testing.T) {
	cases := []struct {
		name    string
		fixture []byte
		want    any // nil means the key must be absent
	}{
		{"name only (Prisma)", readToolsFixture(t, "duplicate-baselines.json"), map[string]any{"name": "Prisma Cloud"}},
		{"name, version and format (SARIF)", readToolsFixture(t, "sarif-gosec.json"), map[string]any{"name": "gosec", "version": "2.18.2", "format": "SARIF"}},
		{"empty tool object", withEmptyTool(t, readToolsFixture(t, "sarif-gosec.json")), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRoot(t, "doc.json", tc.fixture)
			errRes, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
			if errRes != nil && errRes.IsError {
				t.Fatalf("inspect must succeed: %s", payloadText(t, errRes))
			}
			meta := out.Structure["metadata"].(map[string]any)
			got, present := meta["tool"]
			if tc.want == nil {
				if present {
					t.Fatalf("metadata.tool must be absent for an empty tool object; got %#v", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("metadata.tool = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// withEmptyTool replaces a real document's root tool with {} — schema-legal,
// since every Tool field is optional.
func withEmptyTool(t *testing.T, doc []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatalf("parse: %v", err)
	}
	m["tool"] = map[string]any{}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// TestInspect_MergedDocumentShowsPerBaselineProvenance is the reason for this
// card: on a document produced by the engine's Merge (ADR-0016), every baseline
// entry names its scanner through the provenance labels, so an agent can
// attribute a finding without opening the file. Built in-test from two real
// fixtures with the real engine; the largest tools fixture is also confirmed to
// fit the concise budget.
func TestInspect_MergedDocumentShowsPerBaselineProvenance(t *testing.T) {
	var zap, prisma hdf.HDFResults
	if err := json.Unmarshal(readToolsFixture(t, "zap-webgoat.json"), &zap); err != nil {
		t.Fatalf("parse zap: %v", err)
	}
	if err := json.Unmarshal(readToolsFixture(t, "duplicate-baselines.json"), &prisma); err != nil {
		t.Fatalf("parse prisma: %v", err)
	}
	merged, _, err := hdfengine.Merge([]hdfengine.MergeSource{
		{Name: "zap-webgoat.json", Doc: zap},
		{Name: "duplicate-baselines.json", Doc: prisma},
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	doc, err := json.Marshal(merged)
	if err != nil {
		t.Fatalf("marshal merged: %v", err)
	}
	path := writeRoot(t, "merged.json", doc)
	errRes, out := callInspect(t, inspectInput{Source: handle.Source{Path: path}})
	if errRes != nil && errRes.IsError {
		t.Fatalf("inspect must succeed on a merged document: %s", payloadText(t, errRes))
	}
	meta := out.Structure["metadata"].(map[string]any)
	if got := meta["generator"]; !reflect.DeepEqual(got, map[string]any{"name": "hdf-merge", "version": hdfengine.Version()}) {
		t.Errorf("metadata.generator = %#v, want hdf-merge @ %s", got, hdfengine.Version())
	}
	if _, present := meta["tool"]; present {
		t.Errorf("a merged root carries no tool; got %#v", meta["tool"])
	}
	baselines := out.Structure["baselines"].([]map[string]any)
	if len(baselines) != 4+16 {
		t.Fatalf("expected 20 baseline entries (4 ZAP + 16 Prisma), got %d", len(baselines))
	}
	if got := baselines[0]["labels"]; !reflect.DeepEqual(got, map[string]string{
		"component": "ciscobinary.openh264.org", "tool": "owasp zap", "toolVersion": "2.7.0", "sourceDocument": "zap-webgoat.json",
	}) {
		t.Errorf("baselines[0].labels = %#v", got)
	}
	if got := baselines[4]["labels"]; !reflect.DeepEqual(got, map[string]string{"tool": "prisma cloud", "sourceDocument": "duplicate-baselines.json"}) {
		t.Errorf("baselines[4].labels = %#v (Prisma has no tool.version, so no toolVersion label)", got)
	}
	if out.Truncated {
		t.Errorf("a 20-baseline merged document must fit the concise budget; notice %q", out.Notice)
	}

	// The largest committed tools fixture on its own also fits the concise budget.
	big := writeRoot(t, "big.json", readToolsFixture(t, "duplicate-baselines.json"))
	_, out = callInspect(t, inspectInput{Source: handle.Source{Path: big}})
	if out.Truncated {
		t.Errorf("duplicate-baselines.json (16 baselines) must fit the concise budget; notice %q", out.Notice)
	}
}
