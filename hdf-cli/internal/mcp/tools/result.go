package tools

import (
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// textResult wraps a compact, model-readable summary as the tool result's single
// content block. Returning it (instead of a nil result) on the success path stops
// the go-sdk from auto-filling content with a full re-serialization of the typed
// output — which otherwise ships every response's payload twice (once as
// structuredContent, once as content text), doubling its on-wire and in-context
// cost and re-compounding on every turn. The full typed payload still travels in
// structuredContent (the SDK sets it from the output value); content carries only
// this gist, so a host that reads content text gets the headline rather than an
// empty result or a duplicate. Our outputs marshal as JSON objects, so the SDK
// does not append the full JSON alongside a content block that is already set.
func textResult(summary string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: summary}},
	}
}
