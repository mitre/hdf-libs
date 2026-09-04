package tools

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// compactContent asserts a success result carries exactly one short TextContent
// block (the middle-way: a compact gist in content, the full payload only in
// structuredContent) and returns its text.
func compactContent(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	if res == nil {
		t.Fatal("success result must be non-nil so content is a compact summary, not the SDK's full-payload auto-fill")
	}
	if len(res.Content) != 1 {
		t.Fatalf("expected exactly one content block, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("content[0] must be *TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

// TestReadTools_ReturnCompactContent is 6i1a's guard: every read tool returns a
// compact content summary on success rather than letting the SDK re-serialize the
// full structured payload into content (which doubled every response on the wire).
// A compact summary is short; the full payloads here are multiple KB, so a tight
// character bound proves the content is a gist, not the payload.
func TestReadTools_ReturnCompactContent(t *testing.T) {
	const maxSummaryChars = 400
	p := writeRoot(t, "r.json", readToolsFixture(t, "query-results.json"))
	src := handle.Source{Path: p}

	checks := []struct {
		name string
		run  func() *sdkmcp.CallToolResult
	}{
		{"hdf_open", func() *sdkmcp.CallToolResult { res, _ := callOpen(t, openInput{Source: src}); return res }},
		{"hdf_inspect", func() *sdkmcp.CallToolResult { res, _ := callInspect(t, inspectInput{Source: src}); return res }},
		{"hdf_query", func() *sdkmcp.CallToolResult {
			res, _ := callQuery(t, queryInput{Source: src, Verbosity: "full"})
			return res
		}},
		{"hdf_compliance", func() *sdkmcp.CallToolResult { res, _ := callCompliance(t, complianceInput{Source: src}); return res }},
		{"hdf_aggregate", func() *sdkmcp.CallToolResult {
			res, _ := callAggregate(t, aggregateInput{Sources: []handle.Source{src}})
			return res
		}},
		{"hdf_diff", func() *sdkmcp.CallToolResult { res, _ := callDiff(t, diffInput{From: src, To: src}); return res }},
		{"hdf_validate", func() *sdkmcp.CallToolResult {
			res, _ := callValidate(t, validateInput{Source: &src, Mode: "schema"})
			return res
		}},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			txt := compactContent(t, c.run())
			if txt == "" {
				t.Errorf("%s: compact content must not be empty", c.name)
			}
			if len(txt) > maxSummaryChars {
				t.Errorf("%s: content is %d chars — not a compact summary (should be < %d); the full payload belongs only in structuredContent", c.name, len(txt), maxSummaryChars)
			}
		})
	}
}
