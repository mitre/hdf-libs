package hdfengine

import (
	"encoding/json"
	"strings"

	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// InputFormat classifies the wire encoding of loader input.
type InputFormat string

const (
	// FormatJSON is a single JSON document (the normal HDF encoding).
	FormatJSON InputFormat = "json"
	// FormatNDJSON is newline-delimited JSON — multiple JSON values, one per
	// line. HDF documents are single objects, so NDJSON input is surfaced (a
	// caller can reject it or handle the first record) rather than mis-parsed.
	FormatNDJSON InputFormat = "ndjson"
)

// LoadResult is the pure engine-core outcome of loading an HDF document: the
// detected wire format, the detected document type (see Detect), and — for the
// results/baseline types this core parses — the typed document or a parse-error
// message. It carries no cache and no degraded envelope; those are MCP concerns
// layered on top in hdf-cli/internal/mcp/loader.
type LoadResult struct {
	Format   InputFormat
	DocType  string
	Results  *hdf.HDFResults
	Baseline *hdf.HDFBaseline
	// ParseError is non-empty when the document was detected as results/baseline
	// but failed to parse/validate. Valid reports the inverse.
	ParseError string
	Valid      bool
}

// Load is the schema-typed loader core. It runs, in order:
//  1. ValidateInputSize (the FIRST operation, before any parse) — maxSize <= 0
//     uses hdfutil.DefaultMaxInputSize.
//  2. wire-format detection (JSON vs NDJSON).
//  3. document-type detection (Detect).
//  4. parse for the results and baseline types (via the canonical hdf-parsers).
//
// It is pure and dependency-light: no cache, no cobra, no I/O policy beyond
// reading the bytes it is given. Other document types are detected but not
// parsed here (their typed parse belongs to their own tools).
func Load(data []byte, maxSize int) (*LoadResult, error) {
	if err := hdfutil.ValidateInputSize(data, maxSize); err != nil {
		return nil, err
	}

	res := &LoadResult{
		Format:  detectFormat(data),
		DocType: Detect(data),
	}

	switch res.DocType {
	case string(validators.TypeResults):
		r := hdfparsers.ParseResults(data)
		if r.Success {
			res.Results = r.Data
			res.Valid = true
		} else {
			res.ParseError = r.Error
		}
	case string(validators.TypeBaseline):
		r := hdfparsers.ParseBaseline(data)
		if r.Success {
			res.Baseline = r.Data
			res.Valid = true
		} else {
			res.ParseError = r.Error
		}
	default:
		// Detected (or unknown) non-results/baseline type: the core reports the
		// type without a typed parse. Validity is left false — the caller's
		// tool decides how to handle it.
	}

	return res, nil
}

// detectFormat classifies input as a single JSON document or newline-delimited
// JSON (NDJSON), consistent with the repo's converter NDJSON handling: NDJSON is
// two or more non-blank lines that each parse as an independent JSON value. A
// single JSON object that happens to be pretty-printed across many lines is
// still FormatJSON (its first line is not itself valid JSON).
func detectFormat(data []byte) InputFormat {
	lines := nonBlankLines(data)
	if len(lines) < 2 {
		return FormatJSON
	}
	// If the first two non-blank lines each independently parse as JSON, treat
	// the stream as NDJSON. A pretty-printed single object fails this (line 1 is
	// "{" — not a complete JSON value).
	if isCompleteJSON(lines[0]) && isCompleteJSON(lines[1]) {
		return FormatNDJSON
	}
	return FormatJSON
}

func nonBlankLines(data []byte) []string {
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// isCompleteJSON reports whether s is a single complete JSON value with no
// trailing garbage — the test the NDJSON classifier applies per line.
func isCompleteJSON(s string) bool {
	dec := json.NewDecoder(strings.NewReader(s))
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	return !dec.More()
}
