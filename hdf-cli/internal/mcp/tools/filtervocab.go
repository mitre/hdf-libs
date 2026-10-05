package tools

import (
	"fmt"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// canonicalFilters resolves the status and severity filters a read tool accepts
// to the engine's schema spellings, or returns the refusal for the first
// unrecognized value. An unvalidated typo matches nothing, which an agent cannot
// tell apart from "asked and found none" — so every tool taking these filters
// rejects at the boundary instead, and they all reject identically.
func canonicalFilters(status, severity []string) (canonStatus, canonSeverity []string, refusal *sdkmcp.CallToolResult) {
	canonStatus, refusal = canonicalFilterList(status, "status", hdfengine.CanonicalStatusFilter, hdfengine.StatusFilterValues())
	if refusal != nil {
		return nil, nil, refusal
	}
	canonSeverity, refusal = canonicalFilterList(severity, "severity", hdfengine.CanonicalSeverityFilter, hdfengine.SeverityFilterValues())
	if refusal != nil {
		return nil, nil, refusal
	}
	return canonStatus, canonSeverity, nil
}

func canonicalFilterList(values []string, field string, canonical func(string) (string, bool), legal []string) ([]string, *sdkmcp.CallToolResult) {
	if len(values) == 0 {
		return values, nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		c, ok := canonical(v)
		if !ok {
			return nil, argError(fmt.Sprintf("unknown %s %q", field, v),
				fmt.Sprintf("use %s %s", field, orList(legal)))
		}
		out = append(out, c)
	}
	return out, nil
}

// orList renders a closed vocabulary the way the other argument refusals do
// ("system, plan, evidence, or amendments").
func orList(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	}
	return strings.Join(values[:len(values)-1], ", ") + ", or " + values[len(values)-1]
}
