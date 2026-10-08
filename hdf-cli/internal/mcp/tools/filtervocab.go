package tools

import (
	"fmt"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// refuseUnknownStatusSeverity returns the refusal for the first status or
// severity value outside its closed vocabulary, or nil when every value is
// understood. A value the vocabulary does not hold matches nothing and reports a
// clean run, which reads to an agent as "asked and found none" rather than as
// the mistake it is.
//
// hdf_query and hdf_aggregate share it so the same typo draws the same refusal
// from either tool: the two advertise the same two filters, and a reader
// comparing their answers has no way to tell a strict tool from a lenient one.
func refuseUnknownStatusSeverity(status, severity []string) *sdkmcp.CallToolResult {
	for _, c := range []struct {
		field  string
		values []string
		valid  func(string) bool
		legal  []string
	}{
		{"status", status, hdfengine.ValidStatus, hdfengine.StatusValues},
		{"severity", severity, hdfengine.ValidSeverity, hdfengine.SeverityValues},
	} {
		for _, v := range c.values {
			if !c.valid(v) {
				return argError(fmt.Sprintf("unknown %s %q", c.field, v),
					fmt.Sprintf("%s accepts only: %s", c.field, strings.Join(c.legal, ", ")))
			}
		}
	}
	return nil
}
