package tools

import (
	"strings"
	"testing"
)

// TestReadToolsStateThePayloadBoundary pins a deliberate product decision:
// conversion RETAINS the original scanner finding verbatim in each requirement's
// `code`, and no read tool projects `code` at any verbosity.
//
// The per-response token budgets are structural (the response paginates to fit
// regardless of field size), so projecting `code` would not breach a bound — it
// would cost page yield: one `code` blob is ~1,607 tokens (median) against a
// ~295-token bounded query response, so a payload-per-row page fits ~6
// requirements instead of ~24, and all 89 blobs total ~149,735 tokens (within 4%
// of the entire raw file). The boundary is specific to `code`; full verbosity
// still projects descriptions[] verbatim.
//
// So an agent must be TOLD, in the tool descriptions it already reads, that the
// `code` payload lives only in the source file. Discovering it by getting an
// incomplete answer is the failure this test exists to prevent.
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
