package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"testing"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/contract"
)

// toolsListSchemas drives a real initialize + tools/list over the transport and returns
// each tool's advertised inputSchema. Asserting on the live response rather than on the Go
// struct is the point: the vocabulary has to reach a client, and the SDK renders a
// `jsonschema` struct tag as a description only.
func toolsListSchemas(t *testing.T, s *sdkmcp.Server) map[string]map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10e9)
	defer cancel()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() { _ = s.Run(ctx, &sdkmcp.IOTransport{Reader: reqR, Writer: respW}); _ = respW.Close() }()
	go func() {
		_, _ = reqW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"))
	}()
	dec := json.NewDecoder(respR)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("no tools/list response: %v", err)
		}
		if m["id"] != float64(2) {
			continue
		}
		res, ok := m["result"].(map[string]any)
		if !ok {
			t.Fatalf("tools/list returned no result: %v", m)
		}
		list, _ := res["tools"].([]any)
		if len(list) == 0 {
			t.Fatal("tools/list advertised no tools")
		}
		out := map[string]map[string]any{}
		for _, raw := range list {
			tool, _ := raw.(map[string]any)
			name, _ := tool["name"].(string)
			schema, _ := tool["inputSchema"].(map[string]any)
			out[name] = schema
		}
		return out
	}
}

// propertyEnum returns the enum advertised for one property of one tool.
func propertyEnum(t *testing.T, schemas map[string]map[string]any, tool, property string) []string {
	t.Helper()
	schema, ok := schemas[tool]
	if !ok {
		t.Fatalf("tools/list did not advertise %s", tool)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("%s advertised no properties", tool)
	}
	p, ok := props[property].(map[string]any)
	if !ok {
		// Not the guard against a renamed field — mustEnumSchema panics in RegisterAll long
		// before this, which is asserted by TestMustEnumSchema_RefusesAnUnknownProperty.
		// This only reports a property that exists in the vocabulary table but not on the
		// tool, i.e. a mistake in the test's own expectations.
		t.Fatalf("%s advertises no %q property; check this test's expectation table", tool, property)
	}
	// A repeated field's vocabulary constrains each item, so that is where to read it.
	//
	// Detected by the presence of `items`, NOT by type == "array": a Go slice reflects to
	// the union `"type":["null","array"]`, so a type check never matches and this guard
	// would be dead — which is exactly how a misplaced enum first shipped. An enum on the
	// array itself rejects every valid call, so it must fail here rather than read as a
	// correctly-advertised vocabulary.
	holder := p
	if items, repeated := p["items"].(map[string]any); repeated {
		if _, misplaced := p["enum"]; misplaced {
			t.Fatalf("%s.%s carries an enum on the array instead of on its items, so a call passing a valid value is rejected", tool, property)
		}
		holder = items
	}
	raw, ok := holder["enum"].([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		values = append(values, s)
	}
	return values
}

// Every field that must advertise a closed vocabulary, with the source the advertised
// enum has to equal. Asserting equality with the SOURCE rather than with a literal is what
// makes this a contract test: a literal here would be the second copy the card forbids.
func enumExpectations() []struct {
	tool     string
	property string
	source   []string
} {
	return []struct {
		tool     string
		property string
		source   []string
	}{
		{"hdf_query", "status", schemaEnum("Result_Status")},
		{"hdf_query", "severity", schemaEnum("Severity")},
		{"hdf_query", "verbosity", vocabValues(verbosityVocabulary)},
		{"hdf_inspect", "verbosity", vocabValues(verbosityVocabulary)},
		{"hdf_diff", "verbosity", vocabValues(verbosityVocabulary)},
		{"hdf_diff", "mode", vocabValues(diffModeVocabulary)},
		{"hdf_validate", "mode", vocabValues(validateModeVocabulary)},
		{"hdf_compliance", "groupBy", vocabValues(complianceGroupByVocabulary)},
		{"hdf_author", "docType", authorableDocTypes()},
		// hdf_aggregate carries the same two vocabularies as hdf_query. The card's file
		// list omitted it; leaving it as prose would have the contract say two different
		// things about the same field across two tools.
		{"hdf_aggregate", "status", schemaEnum("Result_Status")},
		{"hdf_aggregate", "severity", schemaEnum("Severity")},
		// Sourced from the projector map the handler already validates against, so the
		// advertised set and the accepted set cannot diverge.
		{"hdf_query", "fields", correlationFields()},
	}
}

func TestToolsList_EveryClosedVocabularyIsAdvertised(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "1"}, nil)
	RegisterAll(s)
	schemas := toolsListSchemas(t, s)

	for _, want := range enumExpectations() {
		t.Run(want.tool+"."+want.property, func(t *testing.T) {
			if len(want.source) == 0 {
				t.Fatalf("the source vocabulary for %s.%s is empty, so this assertion could not fail",
					want.tool, want.property)
			}
			got := propertyEnum(t, schemas, want.tool, want.property)
			if len(got) == 0 {
				t.Fatalf("%s.%s advertises no enum", want.tool, want.property)
			}
			if !slices.Equal(got, want.source) {
				t.Errorf("%s.%s advertises %v, its source says %v", want.tool, want.property, got, want.source)
			}
		})
	}
}

// The vocabulary must not also sit in the PROPERTY description, where it would be a second
// copy free to disagree with the enum.
//
// Scoped to the property deliberately. A tool-level description may still name members when
// it says something the enum cannot — hdf_author's maps each docType to the content key it
// needs ("system (components), plan (assessments)") — and stripping that would cost real
// guidance to remove nothing.
func TestToolsList_DescriptionsDoNotRepeatTheVocabulary(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "1"}, nil)
	RegisterAll(s)
	schemas := toolsListSchemas(t, s)

	for _, want := range enumExpectations() {
		props, _ := schemas[want.tool]["properties"].(map[string]any)
		p, _ := props[want.property].(map[string]any)
		desc, _ := p["description"].(string)
		for _, v := range want.source {
			if strings.Contains(desc, v) {
				t.Errorf("%s.%s description still names %q from its own vocabulary: %q",
					want.tool, want.property, v, desc)
			}
		}
	}
}

// hdf_convert.from deliberately carries no enum. The registry's source-format list is by
// far the largest vocabulary here and churns with every new converter, it did not fit the
// tools/list budget, and it is already served by the hdf://catalog/converters resource — so
// an inline enum would be a third copy paid for in every agent turn. Phase 2 derives the
// parameter enum from the contract golden instead. The measured figures behind that
// decision are in the card (hdf-libs-lx1oj.2), where they can be dated rather than rotting
// here. Pinned so the decision cannot be silently reversed, and so a reader finds the
// reason here rather than wondering at the omission.
func TestToolsList_ConvertFromCarriesNoEnumByDecision(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "1"}, nil)
	RegisterAll(s)

	if got := propertyEnum(t, toolsListSchemas(t, s), "hdf_convert", "from"); len(got) != 0 {
		t.Errorf("hdf_convert.from advertises %d enum values; the recorded decision is that it carries none", len(got))
	}
}

func TestToolsList_QueryStatusCarriesEnum(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "1"}, nil)
	RegisterAll(s)

	got := propertyEnum(t, toolsListSchemas(t, s), "hdf_query", "status")
	if len(got) == 0 {
		t.Fatal("hdf_query.status advertises no enum; the vocabulary is only in the description, " +
			"so a generator cannot derive the parameter's allowed values")
	}
}

// A vocabulary with a dispatch table is only single-sourced if the table covers it. The
// equality test above cannot see a gap, because for these two the vocabulary slice and the
// advertised enum both come from the same declaration — so assert the TABLE's key set,
// which is written independently of the slice.
//
// This is the assertion that catches a member added to the vocabulary with no behaviour
// behind it: the tool would advertise it, the SDK would accept it, and the handler would
// answer "unknown ...".
func TestDispatchTablesCoverTheirVocabulary(t *testing.T) {
	t.Run("hdf_validate.mode", func(t *testing.T) {
		got := make([]string, 0, len(validateChecks))
		for mode := range validateChecks {
			got = append(got, string(mode))
		}
		sort.Strings(got)
		want := vocabValues(validateModeVocabulary)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("validateChecks covers %v, the advertised vocabulary is %v", got, want)
		}
	})

	t.Run("hdf_compliance.groupBy", func(t *testing.T) {
		got := make([]string, 0, len(groupPartitioners))
		for dim := range groupPartitioners {
			got = append(got, string(dim))
		}
		sort.Strings(got)
		want := vocabValues(complianceGroupByVocabulary)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("groupPartitioners covers %v, the advertised vocabulary is %v", got, want)
		}
	})

	// verbosity has no table and needs none: every value is accepted and anything that is
	// not "full" renders concise, so there is no acceptance set to drift from. Recorded
	// rather than left as an apparent omission.
	t.Run("verbosity accepts anything by design", func(t *testing.T) {
		if IsFull("not-a-verbosity") {
			t.Error("an unrecognised verbosity must render concise, not full")
		}
		if !IsFull(string(VerbosityFull)) {
			t.Error("the full member must select the full projection")
		}
	})
}

// Every value a tool ADVERTISES must be one the handler actually accepts. Called end to
// end, because that is the contract an agent relies on: it reads the enum and sends a
// member, and an "unknown ..." reply would make the advertised schema a lie.
func TestEveryAdvertisedMemberIsAccepted(t *testing.T) {
	for _, c := range []struct {
		tool     string
		property string
		members  []string
		args     func(source map[string]any, member string) map[string]any
	}{
		{"hdf_compliance", "groupBy", vocabValues(complianceGroupByVocabulary),
			func(src map[string]any, m string) map[string]any {
				return map[string]any{"source": src, "groupBy": m}
			}},
		{"hdf_validate", "mode", vocabValues(validateModeVocabulary),
			func(src map[string]any, m string) map[string]any {
				return map[string]any{"source": src, "mode": m}
			}},
		{"hdf_query", "verbosity", vocabValues(verbosityVocabulary),
			func(src map[string]any, m string) map[string]any {
				return map[string]any{"source": src, "verbosity": m}
			}},
	} {
		for _, member := range c.members {
			t.Run(c.tool+"."+c.property+"="+member, func(t *testing.T) {
				writeRoot(t, "scan.json", fixtures.Results.Minimal)
				s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "1"}, nil)
				RegisterAll(s)

				m := driveToolCall(t, s, c.tool, c.args(map[string]any{"path": "scan.json"}, member))
				if e, ok := m["error"]; ok {
					t.Fatalf("advertised %s=%q was rejected at the protocol level: %v", c.property, member, e)
				}
				res, _ := m["result"].(map[string]any)
				content, _ := res["content"].([]any)
				text := ""
				if len(content) > 0 {
					text, _ = content[0].(map[string]any)["text"].(string)
				}
				// The handler's own rejection message for an out-of-vocabulary value. Seeing
				// it for an ADVERTISED member means the schema and the handler disagree.
				if strings.Contains(text, "unknown "+c.property) {
					t.Errorf("%s advertises %s=%q but the handler rejects it: %s", c.tool, c.property, member, text)
				}
			})
		}
	}
}

// mustEnumSchema's panics are the mechanism that stops a wrong contract being served, so
// they need testing rather than asserting in a comment. Registration is deterministic, so
// a panic here is a build-time-shaped failure, not a request-time one.
func TestMustEnumSchema_RefusesAnUnknownProperty(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("attaching an enum to a property that does not exist must panic; otherwise a " +
				"renamed field silently stops advertising its vocabulary while still accepting values")
		}
		if !strings.Contains(fmt.Sprint(r), "no \"nosuchproperty\" property") {
			t.Errorf("the panic must name the missing property, got: %v", r)
		}
	}()
	mustEnumSchema[queryInput](map[string]closedVocabulary{
		"nosuchproperty": {values: []string{"a"}},
	})
}

func TestMustEnumSchema_RefusesADefaultOutsideItsVocabulary(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a default outside its own vocabulary must panic; the SDK applies defaults to " +
				"arguments, so it would inject a value the same schema then rejects")
		}
		if !strings.Contains(fmt.Sprint(r), "not in its own vocabulary") {
			t.Errorf("the panic must say the default is not a member, got: %v", r)
		}
	}()
	mustEnumSchema[queryInput](map[string]closedVocabulary{
		"verbosity": {values: vocabValues(verbosityVocabulary), defaultValue: "neither"},
	})
}

// Every HDF document type is either summarised by hdf_open or recorded as summaryless with
// a reason. Without this, a new document type gets a silent nil summary and the contract
// simply does not mention it — indistinguishable from an oversight.
func TestOpenSummaries_EveryDocTypeAccountedFor(t *testing.T) {
	summarised := map[string]bool{}
	for _, name := range contract.Names() {
		if strings.HasPrefix(name, "open.summary.") {
			summarised[strings.TrimPrefix(name, "open.summary.")] = true
		}
	}
	if len(summarised) == 0 {
		t.Fatal("no open summary shapes are registered, so this test could not fail")
	}

	// hdf-engine owns the document-type list; using it means a ninth type reaches this
	// test the moment the engine knows about it.
	for _, dt := range hdfengine.KnownTypes() {
		reason, listed := summarylessDocTypes[dt]
		switch {
		case summarised[dt] && listed:
			t.Errorf("%s is both summarised and listed as summaryless", dt)
		case !summarised[dt] && !listed:
			t.Errorf("%s has no open summary and no recorded reason; either register a shape "+
				"for it or add it to summarylessDocTypes", dt)
		case listed && reason == "":
			t.Errorf("%s is listed as summaryless with no reason", dt)
		}
	}
}
