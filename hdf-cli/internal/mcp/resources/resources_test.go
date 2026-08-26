package resources

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// readReq builds a resource read request for a direct handler call.
func readReq(uri string) *sdkmcp.ReadResourceRequest {
	return &sdkmcp.ReadResourceRequest{Params: &sdkmcp.ReadResourceParams{URI: uri}}
}

// TestHandlers_ErrorBranches exercises the handler not-found and shape-guard
// paths directly (unknown doc type, unknown def, examples-not-found, unknown
// enum, and malformed segment counts).
func TestHandlers_ErrorBranches(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		handler func(context.Context, *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error)
		uri     string
	}{
		{"slice-unknown-doctype", handleSchemaSlice, "hdf://schema/hdf-nope/Override_Type"},
		{"slice-unknown-def", handleSchemaSlice, "hdf://schema/hdf-amendments/NoSuchDef"},
		{"slice-examples-unknown-def", handleSchemaSlice, "hdf://schema/hdf-amendments/NoSuchDef?view=examples"},
		{"slice-wrong-segments", handleSchemaSlice, "hdf://schema/only-one"},
		{"whole-unknown-doctype", handleWholeSchema, "hdf://schema/hdf-nope"},
		{"whole-wrong-segments", handleWholeSchema, "hdf://schema/a/b"},
		{"enum-unknown", handleEnum, "hdf://enum/Not_An_Enum"},
		{"enum-wrong-segments", handleEnum, "hdf://enum/a/b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := c.handler(ctx, readReq(c.uri))
			if err == nil {
				t.Fatalf("expected error, got result %v", res)
			}
		})
	}
}

// TestHandlers_SuccessBranches exercises the handler success paths directly.
func TestHandlers_SuccessBranches(t *testing.T) {
	ctx := context.Background()
	res, err := handleSchemaSlice(ctx, readReq("hdf://schema/hdf-amendments/Override_Type"))
	if err != nil || len(res.Contents) == 0 {
		t.Fatalf("slice: err=%v res=%v", err, res)
	}
	res, err = handleSchemaSlice(ctx, readReq("hdf://schema/hdf-amendments/Identity?view=examples"))
	if err != nil || len(res.Contents) == 0 {
		t.Fatalf("examples: err=%v res=%v", err, res)
	}
	res, err = handleWholeSchema(ctx, readReq("hdf://schema/hdf-plan"))
	if err != nil || len(res.Contents) == 0 {
		t.Fatalf("whole: err=%v res=%v", err, res)
	}
	res, err = handleEnum(ctx, readReq("hdf://enum/Result_Status"))
	if err != nil || len(res.Contents) == 0 {
		t.Fatalf("enum: err=%v res=%v", err, res)
	}
	res, err = handleCatalog(ctx, readReq("hdf://catalog/converters"))
	if err != nil || len(res.Contents) == 0 {
		t.Fatalf("catalog: err=%v res=%v", err, res)
	}
}

// TestParseErrors covers the schema-parse error propagation in the helpers.
func TestParseErrors(t *testing.T) {
	bad := []byte("not valid json")
	if _, err := namedDefs(bad); err == nil {
		t.Fatal("namedDefs should error on malformed schema")
	}
	if _, err := defNames(bad); err == nil {
		t.Fatal("defNames should error on malformed schema")
	}
	if _, _, err := sliceForDef(bad, "X"); err == nil {
		t.Fatal("sliceForDef should error on malformed schema")
	}
	if _, _, err := examplesForDef(bad, "X"); err == nil {
		t.Fatal("examplesForDef should error on malformed schema")
	}
}

func TestPathSegments_Empty(t *testing.T) {
	if segs := pathSegments(&url.URL{Path: "/"}); segs != nil {
		t.Fatalf("expected nil for empty path, got %v", segs)
	}
}

func TestEnumDescription_Fallback(t *testing.T) {
	if got := enumDescription(enumEntry{Values: []string{"a", "b"}}); got != "Allowed values: a, b" {
		t.Fatalf("fallback description = %q", got)
	}
	if got := enumDescription(enumEntry{Description: "real"}); got != "real" {
		t.Fatalf("described enum = %q", got)
	}
}

// wholeSchemaBytes reads the bundled schema for a doc type, for size comparisons.
func wholeSchemaBytes(t *testing.T, docType string) []byte {
	t.Helper()
	st, ok := schemaTypeFor(docType)
	if !ok {
		t.Fatalf("unknown doc type %q", docType)
	}
	b, err := validators.SchemaBytes(st)
	if err != nil {
		t.Fatalf("SchemaBytes(%s): %v", docType, err)
	}
	return b
}

// TestSchemaSlice_SingleDef_UnderBudget is the founding-constraint (§9) test:
// one $defs type is served as a self-contained slice that is an order of
// magnitude smaller than the whole schema.
func TestSchemaSlice_SingleDef_UnderBudget(t *testing.T) {
	whole := wholeSchemaBytes(t, "hdf-amendments")
	payload, found, err := sliceForDef(whole, "Override_Type")
	if err != nil {
		t.Fatalf("sliceForDef: %v", err)
	}
	if !found {
		t.Fatal("Override_Type not found in hdf-amendments")
	}

	defs, ok := payload["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("payload $defs is not an object: %T", payload["$defs"])
	}
	if _, ok := defs["Override_Type"]; !ok {
		t.Fatalf("slice does not contain the requested def; got defs %v", keys(defs))
	}
	if ref, _ := payload["$ref"].(string); ref != "#/$defs/Override_Type" {
		t.Fatalf("slice $ref = %q, want #/$defs/Override_Type", ref)
	}

	sliceJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal slice: %v", err)
	}
	// Order-of-magnitude cheaper than the whole schema.
	if len(sliceJSON)*10 > len(whole) {
		t.Fatalf("slice not an order of magnitude smaller: slice=%dB whole=%dB", len(sliceJSON), len(whole))
	}
}

// collectRefStrings walks a decoded JSON value and returns every literal $ref
// string value it finds — the actual on-the-wire refs, not name captures.
func collectRefStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "$ref" {
				if s, ok := val.(string); ok {
					out = append(out, s)
				}
				continue
			}
			out = append(out, collectRefStrings(val)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, collectRefStrings(e)...)
		}
	}
	return out
}

// TestSchemaSlice_SelfContained proves every interior $ref STRING resolves
// within the slice's own $defs. It uses Evaluated_Requirement — a deeply
// cross-bundle type whose closure spans several primitive bundles — because a
// single-bundle type (e.g. Requirement_Core) cannot exercise the URL-qualified
// ref case, and it checks the literal ref strings, not name captures, so a
// dangling `<bundle-url>#/$defs/Name` ref fails rather than passing on the name.
func TestSchemaSlice_SelfContained(t *testing.T) {
	whole := wholeSchemaBytes(t, "hdf-results")
	payload, found, err := sliceForDef(whole, "Evaluated_Requirement")
	if err != nil || !found {
		t.Fatalf("sliceForDef: found=%v err=%v", found, err)
	}
	defs := payload["$defs"].(map[string]any)
	if len(defs) < 10 {
		t.Fatalf("Evaluated_Requirement should pull in a large cross-bundle closure, got %d", len(defs))
	}
	refs := collectRefStrings(payload)
	if len(refs) == 0 {
		t.Fatal("expected interior refs to exercise resolution")
	}
	for _, ref := range refs {
		if strings.Contains(ref, "://") {
			t.Fatalf("slice carries a URL-qualified ref %q — will not resolve within the slice (not self-contained)", ref)
		}
		name := strings.TrimPrefix(ref, "#/$defs/")
		if name == ref {
			t.Fatalf("ref %q is not in bare #/$defs/<Name> form", ref)
		}
		if _, ok := defs[name]; !ok {
			t.Fatalf("slice references #/$defs/%s which is not included — not self-contained", name)
		}
	}
}

// TestSchemaSlice_AllEightDocTypes verifies a slice can be produced for every
// one of the eight document types.
func TestSchemaSlice_AllEightDocTypes(t *testing.T) {
	if len(docTypes) != 8 {
		t.Fatalf("expected 8 doc types, got %d: %v", len(docTypes), docTypes)
	}
	for _, dt := range docTypes {
		whole := wholeSchemaBytes(t, dt)
		names, err := defNames(whole)
		if err != nil {
			t.Fatalf("%s: defNames: %v", dt, err)
		}
		if len(names) == 0 {
			t.Fatalf("%s: no named defs", dt)
		}
		payload, found, err := sliceForDef(whole, names[0])
		if err != nil || !found {
			t.Fatalf("%s/%s: found=%v err=%v", dt, names[0], found, err)
		}
		if _, ok := payload["$defs"].(map[string]any)[names[0]]; !ok {
			t.Fatalf("%s: slice missing requested def %s", dt, names[0])
		}
	}
}

// TestSchemaSlice_UnknownDef_NotFound: an unknown def returns not-found, never a
// whole-schema fallback.
func TestSchemaSlice_UnknownDef_NotFound(t *testing.T) {
	whole := wholeSchemaBytes(t, "hdf-amendments")
	payload, found, err := sliceForDef(whole, "NoSuchDefinition")
	if err != nil {
		t.Fatalf("sliceForDef: %v", err)
	}
	if found {
		t.Fatalf("unknown def reported as found; payload=%v", payload)
	}
	if payload != nil {
		t.Fatalf("unknown def returned a payload (whole-schema fallback?): %v", payload)
	}
}

// TestExamplesView_ReturnsOnlyExamples: ?view=examples returns only the examples
// array (plus identity), nothing from the constraint body.
func TestExamplesView_ReturnsOnlyExamples(t *testing.T) {
	whole := wholeSchemaBytes(t, "hdf-amendments")
	payload, found, err := examplesForDef(whole, "Identity")
	if err != nil || !found {
		t.Fatalf("examplesForDef(Identity): found=%v err=%v", found, err)
	}
	ex, ok := payload["examples"].([]any)
	if !ok || len(ex) == 0 {
		t.Fatalf("Identity should carry examples, got %v", payload["examples"])
	}
	for _, forbidden := range []string{"type", "properties", "enum", "description", "required"} {
		if _, present := payload[forbidden]; present {
			t.Fatalf("examples view leaked constraint field %q: %v", forbidden, payload)
		}
	}
}

// TestExamplesView_NoExamples_Explicit: a def with no examples returns an
// explicit empty result, not the constraint text.
func TestExamplesView_NoExamples_Explicit(t *testing.T) {
	whole := wholeSchemaBytes(t, "hdf-amendments")
	payload, found, err := examplesForDef(whole, "Override_Type")
	if err != nil || !found {
		t.Fatalf("examplesForDef(Override_Type): found=%v err=%v", found, err)
	}
	ex, ok := payload["examples"].([]any)
	if !ok {
		t.Fatalf("examples must be an array even when empty, got %T", payload["examples"])
	}
	if len(ex) != 0 {
		t.Fatalf("Override_Type declares no examples, got %d", len(ex))
	}
	if _, leaked := payload["enum"]; leaked {
		t.Fatalf("no-examples result leaked the enum constraint: %v", payload)
	}
}

// TestExamplesView_UnknownDef_NotFound.
func TestExamplesView_UnknownDef_NotFound(t *testing.T) {
	whole := wholeSchemaBytes(t, "hdf-amendments")
	_, found, err := examplesForDef(whole, "Nope")
	if err != nil {
		t.Fatalf("examplesForDef: %v", err)
	}
	if found {
		t.Fatal("unknown def reported as found")
	}
}

// TestConverterCatalog_FromRegistry: the catalog is built from the importable
// registry and lists real converters.
func TestConverterCatalog_FromRegistry(t *testing.T) {
	cat := converterCatalog()
	if len(cat) == 0 {
		t.Fatal("converter catalog is empty — registry not populated")
	}
	var haveNessus, haveIngest bool
	for _, e := range cat {
		if e.ID == "" || e.Direction == "" {
			t.Fatalf("catalog entry missing id/direction: %+v", e)
		}
		if e.ID == "nessus-to-hdf" {
			haveNessus = true
		}
		if e.Direction == "ingest" {
			haveIngest = true
		}
	}
	if !haveNessus {
		t.Fatal("catalog missing nessus-to-hdf")
	}
	if !haveIngest {
		t.Fatal("catalog has no ingest converters")
	}
	// Deterministic ordering: sorted by ID.
	for i := 1; i < len(cat); i++ {
		if cat[i-1].ID > cat[i].ID {
			t.Fatalf("catalog not sorted by ID at %d: %q > %q", i, cat[i-1].ID, cat[i].ID)
		}
	}
}

// TestEnumIndex_KnownEnum: enums are collected across all schemas and served
// whole with their values.
func TestEnumIndex_KnownEnum(t *testing.T) {
	idx, err := collectEnums()
	if err != nil {
		t.Fatalf("collectEnums: %v", err)
	}
	e, ok := idx["Result_Status"]
	if !ok {
		t.Fatalf("Result_Status enum not collected; have %v", keys(anyMap(idx)))
	}
	want := map[string]bool{"passed": true, "failed": true, "notApplicable": true, "notReviewed": true, "error": true}
	for _, v := range e.Values {
		delete(want, v)
	}
	if len(want) != 0 {
		t.Fatalf("Result_Status missing values %v; got %v", keys2(want), e.Values)
	}
}

// TestServeEnum_Unknown_NotFound.
func TestServeEnum_Unknown_NotFound(t *testing.T) {
	_, found, err := serveEnum("Not_An_Enum")
	if err != nil {
		t.Fatalf("serveEnum: %v", err)
	}
	if found {
		t.Fatal("unknown enum reported as found")
	}
}

// --- SDK round-trip tests ---

func connect(t *testing.T) *sdkmcp.ClientSession {
	t.Helper()
	server := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterAll(server)
	clientT, serverT := sdkmcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func readResource(t *testing.T, cs *sdkmcp.ClientSession, uri string) *sdkmcp.ReadResourceResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cs.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatalf("ReadResource(%s): %v", uri, err)
	}
	return res
}

func firstText(t *testing.T, res *sdkmcp.ReadResourceResult) string {
	t.Helper()
	if len(res.Contents) == 0 {
		t.Fatal("resource returned no contents")
	}
	return res.Contents[0].Text
}

func TestRoundTrip_SchemaSlice(t *testing.T) {
	cs := connect(t)
	res := readResource(t, cs, "hdf://schema/hdf-amendments/Override_Type")
	var payload map[string]any
	if err := json.Unmarshal([]byte(firstText(t, res)), &payload); err != nil {
		t.Fatalf("unmarshal slice: %v", err)
	}
	if _, ok := payload["$defs"].(map[string]any)["Override_Type"]; !ok {
		t.Fatalf("round-trip slice missing Override_Type: %v", payload)
	}
}

func TestRoundTrip_ExamplesView(t *testing.T) {
	cs := connect(t)
	res := readResource(t, cs, "hdf://schema/hdf-amendments/Identity?view=examples")
	var payload map[string]any
	if err := json.Unmarshal([]byte(firstText(t, res)), &payload); err != nil {
		t.Fatalf("unmarshal examples: %v", err)
	}
	if _, ok := payload["examples"].([]any); !ok {
		t.Fatalf("examples view did not return an examples array: %v", payload)
	}
	if _, leaked := payload["properties"]; leaked {
		t.Fatalf("examples view leaked constraint body: %v", payload)
	}
}

func TestRoundTrip_WholeSchema_Expensive(t *testing.T) {
	cs := connect(t)
	// The whole schema is served (retained for tooling)...
	res := readResource(t, cs, "hdf://schema/hdf-comparison")
	if len(firstText(t, res)) < 50_000 {
		t.Fatal("whole schema should be large")
	}
	// ...but the template that offers it documents it as expensive.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tmpls, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	var wholeDesc string
	for _, rt := range tmpls.ResourceTemplates {
		if rt.URITemplate == "hdf://schema/{docType}" {
			wholeDesc = rt.Description
		}
	}
	if wholeDesc == "" {
		t.Fatal("whole-schema template not listed")
	}
	if !strings.Contains(strings.ToLower(wholeDesc), "expensive") {
		t.Fatalf("whole-schema template must be documented as expensive; got %q", wholeDesc)
	}
}

func TestRoundTrip_Catalog(t *testing.T) {
	cs := connect(t)
	res := readResource(t, cs, "hdf://catalog/converters")
	var cat []catalogEntry
	if err := json.Unmarshal([]byte(firstText(t, res)), &cat); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}
	if len(cat) == 0 {
		t.Fatal("round-trip catalog empty")
	}
	// It is listed as a concrete resource for discovery.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	var found bool
	for _, r := range list.Resources {
		if r.URI == "hdf://catalog/converters" {
			found = true
		}
	}
	if !found {
		t.Fatal("catalog resource not listed")
	}
}

func TestRoundTrip_Enum(t *testing.T) {
	cs := connect(t)
	res := readResource(t, cs, "hdf://enum/Result_Status")
	var payload enumEntry
	if err := json.Unmarshal([]byte(firstText(t, res)), &payload); err != nil {
		t.Fatalf("unmarshal enum: %v", err)
	}
	if len(payload.Values) == 0 {
		t.Fatal("enum returned no values")
	}
}

func TestRoundTrip_UnknownDef_Error(t *testing.T) {
	cs := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cs.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: "hdf://schema/hdf-amendments/NoSuchDef"})
	if err == nil {
		t.Fatal("unknown def should return an error, not a fallback")
	}
	if !strings.Contains(err.Error(), "NoSuchDef") && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Fatalf("error should identify the missing def: %v", err)
	}
}

func TestRoundTrip_UnknownDocType_Error(t *testing.T) {
	cs := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cs.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: "hdf://schema/hdf-bogus/Foo"})
	if err == nil {
		t.Fatal("unknown doc type should return an error")
	}
}

// --- small test helpers ---

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keys2(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func anyMap(m map[string]enumEntry) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
