package cmd

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// jsonPathLineMap scans JSON data and builds a mapping from dotted JSON paths
// (e.g. "baselines.0.name") to the line number where that key or value starts.
// This enables annotating schema validation errors with source line numbers.
//
// Returns an empty map if the data is not valid JSON.
func jsonPathLineMap(data []byte) map[string]int {
	lineMap := make(map[string]int)

	// Quick validity check — don't attempt to walk invalid JSON
	if !json.Valid(data) {
		return lineMap
	}

	lineOffsets := buildLineOffsets(data)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var path []string
	walkJSON(dec, &path, lineOffsets, lineMap)

	return lineMap
}

// walkJSON recursively processes JSON tokens, tracking the current path and
// recording line numbers for each path.
func walkJSON(
	dec *json.Decoder,
	path *[]string,
	lineOffsets []int,
	lineMap map[string]int,
) {
	tok, err := dec.Token()
	if err != nil {
		return
	}

	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			recordPath(*path, dec.InputOffset(), lineOffsets, lineMap)
			for dec.More() {
				// Read key
				keyTok, err := dec.Token()
				if err != nil {
					return
				}
				key, ok := keyTok.(string)
				if !ok {
					return
				}
				*path = append(*path, key)
				offset := dec.InputOffset()
				recordPath(*path, offset, lineOffsets, lineMap)

				// Read value
				walkJSON(dec, path, lineOffsets, lineMap)

				*path = (*path)[:len(*path)-1]
			}
			// consume closing '}'
			dec.Token() //nolint:errcheck // closing delimiter
		case '[':
			recordPath(*path, dec.InputOffset(), lineOffsets, lineMap)
			idx := 0
			for dec.More() {
				*path = append(*path, strconv.Itoa(idx))
				offset := dec.InputOffset()
				recordPath(*path, offset, lineOffsets, lineMap)

				walkJSON(dec, path, lineOffsets, lineMap)

				*path = (*path)[:len(*path)-1]
				idx++
			}
			// consume closing ']'
			dec.Token() //nolint:errcheck // closing delimiter
		}
	default:
		// Scalar value — path already recorded by caller
		_ = v
	}
}

// recordPath stores the line number for the given path.
func recordPath(path []string, byteOffset int64, lineOffsets []int, lineMap map[string]int) {
	if len(path) == 0 {
		return
	}
	key := strings.Join(path, ".")
	if _, exists := lineMap[key]; !exists {
		lineMap[key] = offsetToLine(lineOffsets, int(byteOffset))
	}
}

// buildLineOffsets returns a slice where lineOffsets[i] is the byte offset
// where line i+1 starts (0-indexed: lineOffsets[0] = 0 for line 1).
func buildLineOffsets(data []byte) []int {
	offsets := []int{0}
	for i, b := range data {
		if b == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// offsetToLine converts a byte offset to a 1-based line number.
func offsetToLine(lineOffsets []int, offset int) int {
	// Binary search for the largest lineOffset <= offset
	lo, hi := 0, len(lineOffsets)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if lineOffsets[mid] <= offset {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return lo // 1-based: lo is the count of lines whose start offset <= offset
}

// Special field values from gojsonschema that don't map to real JSON paths.
const (
	fieldRoot  = "(root)"
	fieldParse = "(parse)"
)

// lookupLineNumber finds the best line number for a validation error field path.
// Tries exact match first, then progressively shorter prefixes.
func lookupLineNumber(lineMap map[string]int, field string) int {
	if field == "" || field == fieldRoot || field == fieldParse {
		return 0
	}

	// Exact match
	if line, ok := lineMap[field]; ok {
		return line
	}

	// Try progressively shorter prefixes
	parts := strings.Split(field, ".")
	for i := len(parts) - 1; i > 0; i-- {
		prefix := strings.Join(parts[:i], ".")
		if line, ok := lineMap[prefix]; ok {
			return line
		}
	}

	return 0
}
