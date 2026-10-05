package evals

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/tools"
)

// TestToolErrorPaths_DeliverTaxonomyCode drives the hdf_query, hdf_diff, and
// hdf_validate error paths END-TO-END through the SDK (not the handlers
// directly) and asserts each returns a proper isError tool result carrying its
// taxonomy code and nextCall — AND that the structured output's required
// collection field serializes as an empty array, never JSON null.
//
// Guards the output-schema-validation masking class (the lj0g.10 hdf_compliance
// defect). The SDK validates a tool's structured output even on an isError
// result; a required field that serializes as JSON null against a non-nullable
// schema fails that validation and replaces the whole result with a generic
// "validating tool output" protocol error, discarding the taxonomy code. Rather
// than rely on jsonschema-go happening to make Go slice fields nullable (type
// ["null","array"]), each tool returns an empty (non-nil) collection on its
// error paths, so the structured output is [] not null and validates against any
// schema. Handler-direct unit tests bypass the SDK and cannot see any of this.
func TestToolErrorPaths_DeliverTaxonomyCode(t *testing.T) {
	cases := []struct {
		call       call
		wantInText []string // taxonomy code / argError message + nextCall
		collection string   // the required collection field that must be [] not null
	}{
		{
			call: call{Tool: "hdf_query", Args: map[string]any{
				"source": map[string]any{"path": "nonexistent-4908-2-query.json"}}},
			wantInText: []string{`"code":"DOCUMENT_NOT_FOUND"`, `"nextCall":`},
			collection: "requirements",
		},
		{
			call: call{Tool: "hdf_diff", Args: map[string]any{
				"from": map[string]any{"path": "nonexistent-4908-2-from.json"},
				"to":   map[string]any{"path": "nonexistent-4908-2-to.json"}}},
			wantInText: []string{`"code":"DOCUMENT_NOT_FOUND"`, `"nextCall":`},
			collection: "changes",
		},
		{
			// A SEMANTIC error, which is what this test is about: it reaches the handler, so
			// the taxonomy code, the nextCall hint and the non-nil errors[] all have to
			// survive the SDK's output validation. The mode is valid on purpose — an
			// out-of-vocabulary mode is now rejected before the handler runs and produces
			// no structured output at all, so it cannot exercise this at all. That
			// behaviour is pinned by TestEnumRejection_HappensBeforeTheHandler below.
			call: call{Tool: "hdf_validate", Args: map[string]any{
				"source": map[string]any{"path": "nonexistent-4908-2-validate.json"},
				"mode":   "schema"}},
			wantInText: []string{`"code":"DOCUMENT_NOT_FOUND"`, `"nextCall":`},
			collection: "errors",
		},
	}

	calls := make([]call, len(cases))
	for i, c := range cases {
		calls[i] = c.call
	}
	frames := driveCalls(t, calls)

	for i, c := range cases {
		text, structured := assertToolIsError(t, c.call.Tool, frames[i])
		for _, w := range c.wantInText {
			if !strings.Contains(text, w) {
				t.Errorf("%s error result missing %q; got content: %s", c.call.Tool, w, text)
			}
		}
		v, present := structured[c.collection]
		if !present {
			t.Errorf("%s: structured output missing required collection %q", c.call.Tool, c.collection)
			continue
		}
		if _, isArray := v.([]any); !isArray {
			t.Errorf("%s: required collection %q must be an empty array on error, got %#v (null?)",
				c.call.Tool, c.collection, v)
		}
	}
}

// assertToolIsError parses a tools/call response frame, fails if it is a
// JSON-RPC protocol error (the output-validation-masking failure mode) rather
// than a proper isError tool result, and returns the result's content text and
// its structured output.
func assertToolIsError(t *testing.T, tool, frame string) (string, map[string]any) {
	t.Helper()
	var m struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Result *struct {
			IsError           bool           `json:"isError"`
			StructuredContent map[string]any `json:"structuredContent"`
			Content           []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(frame), &m); err != nil {
		t.Fatalf("%s: parse frame: %v\n%s", tool, err, frame)
	}
	if m.Error != nil {
		t.Fatalf("%s: got a JSON-RPC protocol error instead of an isError tool result "+
			"(taxonomy code masked by output-schema validation): %s", tool, m.Error.Message)
	}
	if m.Result == nil {
		t.Fatalf("%s: response had neither result nor error: %s", tool, frame)
	}
	if !m.Result.IsError {
		t.Fatalf("%s: expected an isError result, got a success result: %s", tool, frame)
	}
	if len(m.Result.Content) == 0 {
		t.Fatalf("%s: isError result carried no content: %s", tool, frame)
	}
	return m.Result.Content[0].Text, m.Result.StructuredContent
}

// An out-of-vocabulary enum value is rejected by the SDK's argument validation before the
// handler runs, so it carries no taxonomy code, no nextCall and no structured output.
//
// Accepted deliberately (owner decision 2026-10-05) when the closed vocabularies became
// advertised enums: the SDK validates arguments against the input schema with no opt-out
// and no hook to own the message, the rejection still names the property, the offending
// value and the allowed values, and an agent that reads the schema cannot produce this
// error at all. The alternative was a middleware regex-parsing a dependency's error prose
// to rebuild a message we used to own — fragile in a way that degrades silently.
//
// Pinned so the trade is visible rather than looking like a lost taxonomy, and so a future
// SDK that lets a server own this error fails here and prompts restoring the richer form.
func TestEnumRejection_HappensBeforeTheHandler(t *testing.T) {
	frames := driveCalls(t, []call{{Tool: "hdf_validate", Args: map[string]any{
		"source": map[string]any{"path": "nonexistent-4908-2-validate.json"},
		"mode":   "bogus-mode",
	}}})

	text, structured := assertToolIsError(t, "hdf_validate", frames[0])
	// Built from the exported vocabulary, not typed out: a fourth hand-written copy of
	// validate's modes is exactly what the declared vocabulary exists to prevent.
	wantMembers := fmt.Sprintf("%s %s %s",
		tools.ValidateModeSchema, tools.ValidateModeChecksums, tools.ValidateModeCompleteness)
	for _, want := range []string{"/properties/mode", "bogus-mode", wantMembers} {
		if !strings.Contains(text, want) {
			t.Errorf("the rejection must still name %q, so a caller can fix the call; got: %s", want, text)
		}
	}
	// The absences are the point: asserting them keeps this test honest about what was
	// given up, instead of only checking what remains.
	if strings.Contains(text, `"nextCall":`) {
		t.Errorf("a nextCall hint reappeared — the SDK may now let a server own this error, "+
			"so restore the handler's taxonomy message and delete this test: %s", text)
	}
	if _, present := structured["errors"]; present {
		t.Errorf("structured output reappeared for a schema-rejected call: %#v", structured)
	}
}
