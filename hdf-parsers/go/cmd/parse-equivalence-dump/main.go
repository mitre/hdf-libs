// Command parse-equivalence-dump emits a canonical JSON description of
// hdfparsers.ParseResults / ParseBaseline output for cross-language
// equivalence checking against the TypeScript implementation. See
// ../../../typescript/parse-equivalence-dump.ts for the matching producer
// and ../../../typescript/parse-equivalence.test.ts for the test that
// spawns this binary and deep-equals the outputs.
//
// Usage: parse-equivalence-dump <kind> <hdf-doc.json>
//
//	kind: "results" | "baseline" — picks which parser is exercised. Without
//	this dispatch a baseline fixture would always be tested against
//	ParseResults and the baseline-parse parity case would go uncovered.
//
// Shape is intentionally narrow (success + baseline/requirement counts) —
// Go's struct serialization and TS's object serialization differ in field
// ordering and optional-property handling, so a byte-equal "compare the
// full parsed shape" test would chase those harmless differences forever.
// Both parsers go through the same schema + JSON unmarshal; if both succeed
// and surface the same baseline/requirement counts, they parsed the same
// data.
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
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: parse-equivalence-dump <kind:results|baseline> <hdf-doc.json>")
		os.Exit(2)
	}
	kind := os.Args[1]
	data, err := os.ReadFile(os.Args[2]) //nolint:gosec // path supplied by developer, not user input
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	var out dump
	switch kind {
	case "results":
		r := hdfparsers.ParseResults(data)
		out.Success = r.Success
		if r.Success && r.Data != nil {
			out.BaselineCount = len(r.Data.Baselines)
			for _, b := range r.Data.Baselines {
				out.RequirementCount += len(b.Requirements)
			}
		}
	case "baseline":
		r := hdfparsers.ParseBaseline(data)
		out.Success = r.Success
		if r.Success && r.Data != nil {
			// HDF Baseline is one doc with a flat requirements[] — model
			// it as baselineCount=1 so the counts are still meaningful.
			out.BaselineCount = 1
			out.RequirementCount = len(r.Data.Requirements)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown kind:", kind)
		os.Exit(2)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}
