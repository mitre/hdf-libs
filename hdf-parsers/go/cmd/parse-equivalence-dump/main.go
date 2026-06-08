// Command parse-equivalence-dump emits a canonical JSON description of
// hdfparsers.ParseResults output for cross-language equivalence checking
// against the TypeScript implementation. See
// ../../../typescript/parse-equivalence-dump.ts for the matching producer
// and ../../../typescript/parse-equivalence.test.ts for the test that
// spawns this binary and deep-equals the outputs.
//
// Usage: parse-equivalence-dump <hdf-results.json>
//
// Shape is intentionally narrow (success + error + baseline/requirement
// counts) — Go's struct serialization and TS's object serialization differ
// in field-ordering and optional-property handling, so a byte-equal
// "compare the full parsed shape" test would chase those harmless
// differences forever. Both parsers go through the same schema + JSON
// unmarshal; if both succeed and surface the same baseline/requirement
// counts, they parsed the same data.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
)

// Error strings intentionally absent — see parse-equivalence-dump.ts for
// rationale (ajv-formats vs gojsonschema format the same violation
// differently; success+counts captures the signal we care about).
type dump struct {
	Success          bool `json:"success"`
	BaselineCount    int  `json:"baselineCount"`
	RequirementCount int  `json:"requirementCount"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: parse-equivalence-dump <hdf-results.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1]) //nolint:gosec // path supplied by developer, not user input
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	r := hdfparsers.ParseResults(data)
	out := dump{Success: r.Success}
	if r.Success && r.Data != nil {
		out.BaselineCount = len(r.Data.Baselines)
		for _, b := range r.Data.Baselines {
			out.RequirementCount += len(b.Requirements)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}
