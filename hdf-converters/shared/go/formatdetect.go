package testing

import (
	"encoding/json"
)

// InputFormat represents a detected input file format.
type InputFormat string

const (
	// FormatSARIF indicates SARIF 2.1.0 JSON input.
	FormatSARIF InputFormat = "sarif"
	// FormatUnknown indicates the format could not be determined.
	FormatUnknown InputFormat = "unknown"
)

// DetectFormat examines raw input bytes and returns the detected format.
// Uses structural fingerprinting — checks for characteristic top-level fields.
//
// SARIF fingerprint: JSON object with "version" string and "runs" array.
func DetectFormat(input []byte) InputFormat {
	if len(input) == 0 {
		return FormatUnknown
	}

	// Quick byte-level pre-check: must start with '{' (JSON object)
	for _, b := range input {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			goto parseJSON
		default:
			return FormatUnknown
		}
	}
	return FormatUnknown

parseJSON:
	var probe struct {
		Schema  string          `json:"$schema"`
		Version json.RawMessage `json:"version"`
		Runs    json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(input, &probe); err != nil {
		return FormatUnknown
	}

	if isSARIF(probe.Version, probe.Runs, probe.Schema) {
		return FormatSARIF
	}

	return FormatUnknown
}

// isSARIF checks whether the probed fields match SARIF structure:
// - "version" is a string (e.g. "2.1.0")
// - "runs" is an array
// - optionally "$schema" contains "sarif"
func isSARIF(version, runs json.RawMessage, schema string) bool {
	// Must have both "version" and "runs"
	if len(version) == 0 || len(runs) == 0 {
		return false
	}

	// "version" must be a JSON string
	var versionStr string
	if err := json.Unmarshal(version, &versionStr); err != nil {
		return false
	}

	// "runs" must be a JSON array
	if len(runs) == 0 || runs[0] != '[' {
		return false
	}

	return true
}
