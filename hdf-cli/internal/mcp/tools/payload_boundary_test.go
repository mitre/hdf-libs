package tools

import (
	"strings"
	"testing"
)

// TestReadToolsStateThePayloadBoundary pins a deliberate product decision
// (hdf-libs-uqhe.13): conversion RETAINS the original scanner finding verbatim in
// each requirement's `code`, but no read tool projects it, and that boundary is
// permanent until revisited.
//
// The boundary is cheap to state and expensive to discover. Measured on a real
// grype scan: one `code` blob is ~1,607 tokens (median) against a ~295-token
// bounded query response, and all 89 blobs total ~149,735 tokens — within 4% of
// the entire raw file. Projecting them would erase the token-bounding guarantee
// that is the whole point of this surface.
//
// So an agent must be TOLD, in the tool descriptions it already reads, that a
// tool-specific field means falling back to the source file. Discovering it by
// getting an incomplete answer is the failure this test exists to prevent.
func TestReadToolsStateThePayloadBoundary(t *testing.T) {
	for _, tc := range []struct {
		tool string
		desc string
	}{
		{"hdf_query", queryToolDescription},
		{"hdf_inspect", inspectToolDescription},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			low := strings.ToLower(tc.desc)
			// It must name the field an agent would otherwise hunt for...
			if !strings.Contains(low, "code") {
				t.Errorf("%s description must name the retained `code` payload: %q", tc.tool, tc.desc)
			}
			// ...and say what to do instead, rather than only that it is absent.
			if !strings.Contains(low, "source file") && !strings.Contains(low, "raw") {
				t.Errorf("%s description must tell the agent to fall back to the source file: %q", tc.tool, tc.desc)
			}
		})
	}
}
