package testing

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
)

// InputFormat represents a detected input file format.
type InputFormat string

const (
	// FormatSARIF indicates SARIF 2.1.0 JSON input.
	FormatSARIF InputFormat = "sarif"
	// FormatJUnit indicates JUnit XML input.
	FormatJUnit InputFormat = "junit"
	// FormatXCCDF indicates XCCDF 1.2 XML input.
	FormatXCCDF InputFormat = "xccdf"
	// FormatARF indicates ARF 1.1 XML input (wraps XCCDF).
	FormatARF InputFormat = "arf"
	// FormatUnknown indicates the format could not be determined.
	FormatUnknown InputFormat = "unknown"
)

// DetectFormat examines raw input bytes and returns the detected format.
// Uses structural fingerprinting — checks for characteristic top-level fields.
//
// SARIF fingerprint: JSON object with "version" string and "runs" array.
// JUnit fingerprint: XML with <testsuites> or <testsuite> root element.
func DetectFormat(input []byte) InputFormat {
	if len(input) == 0 {
		return FormatUnknown
	}

	// Find the first non-whitespace byte to determine format family
	for _, b := range input {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return detectJSON(input)
		case '<':
			return detectXML(input)
		default:
			return FormatUnknown
		}
	}
	return FormatUnknown
}

// detectJSON probes JSON input for known formats.
func detectJSON(input []byte) InputFormat {
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

// detectXML probes XML input for known formats by reading the root element name.
func detectXML(input []byte) InputFormat {
	decoder := xml.NewDecoder(bytes.NewReader(input))
	for {
		tok, err := decoder.Token()
		if err != nil {
			return FormatUnknown
		}
		if se, ok := tok.(xml.StartElement); ok {
			switch se.Name.Local {
			case "testsuites", "testsuite":
				return FormatJUnit
			case "Benchmark":
				return FormatXCCDF
			case "asset-report-collection":
				return FormatARF
			default:
				return FormatUnknown
			}
		}
	}
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
