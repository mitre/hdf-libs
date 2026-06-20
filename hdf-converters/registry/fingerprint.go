package registry

import (
	"bytes"
	"encoding/json"
	"sort"
)

// DetectionResult holds a matched fingerprint and its confidence score.
type DetectionResult struct {
	Fingerprint ConverterFingerprint
	Confidence  float64
	// Version is the detected format version (e.g. "2.1.0" for SARIF).
	// Empty when the fingerprint does not implement DetectVersion.
	Version string
}

// DetectConverter returns the highest-confidence ingest converter match,
// or nil if no match is found.
// minConfidence is the minimum confidence to accept an auto-detection result.
// Below this threshold, the user should specify the format explicitly.
const minConfidence = 0.8

func DetectConverter(input []byte) *DetectionResult {
	results := DetectConverterAll(input)
	if len(results) == 0 {
		return nil
	}
	best := results[0]
	// Refuse to guess if confidence is too low
	if best.Confidence < minConfidence {
		return nil
	}
	// Refuse to guess if there's an ambiguous tie at the top
	if len(results) > 1 && results[1].Confidence == best.Confidence {
		return nil
	}
	return &best
}

// maxDetectSize is the maximum input size for fingerprint detection (100 MB).
// Fingerprinting only needs top-level structure; full parsing of larger files
// is wasteful and a DoS risk.
const maxDetectSize = 100 * 1024 * 1024

// maxXMLPreamble is the maximum bytes scanned for XML root element detection.
// XML fingerprints only need the preamble (declarations, DOCTYPE, root tag).
const maxXMLPreamble = 8 * 1024

// DetectConverterAll returns all matching ingest converters sorted by
// confidence descending.
func DetectConverterAll(input []byte) []DetectionResult {
	if len(input) > maxDetectSize {
		return nil
	}

	// Strip a leading UTF-8 BOM so direct library callers (e.g. heimdall passing
	// raw input) detect BOM-prefixed JSON/XML; the CLI strips it earlier too.
	input = bytes.TrimPrefix(input, utf8BOM)

	family := DetectFamily(input)
	if family == "" {
		return nil
	}

	var parsed any
	if family == FamilyJSON {
		if err := json.Unmarshal(input, &parsed); err != nil {
			// Tools like `trufflehog --json` emit NDJSON (one object per line),
			// which fails a whole-input Unmarshal. Fingerprint the first line.
			first, ok := firstJSONLine(input)
			if !ok {
				return nil
			}
			parsed = first
		}
	} else {
		// For XML/text, only pass the preamble to fingerprints
		preamble := input
		if len(preamble) > maxXMLPreamble {
			preamble = preamble[:maxXMLPreamble]
		}
		parsed = string(preamble)
	}

	candidates := GetIngestFingerprints()
	var results []DetectionResult
	for _, fp := range candidates {
		if fp.InputFamily != family {
			continue
		}
		confidence := safeFingerprint(fp.Fingerprint, parsed)
		if confidence > 0 {
			ver := ""
			if fp.DetectVersion != nil {
				ver = safeDetectVersion(fp.DetectVersion, parsed)
			}
			results = append(results, DetectionResult{
				Fingerprint: fp,
				Confidence:  confidence,
				Version:     ver,
			})
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Confidence != results[j].Confidence {
			return results[i].Confidence > results[j].Confidence
		}
		return results[i].Fingerprint.ID < results[j].Fingerprint.ID
	})
	return results
}

// firstJSONLine parses the first non-blank line of NDJSON input as a single
// JSON value. Only the first line is scanned — detection needs one
// representative object, not the whole stream. Returns ok=false if that line is
// not valid JSON (i.e. the input is genuinely malformed, not NDJSON).
func firstJSONLine(input []byte) (any, bool) {
	for len(input) > 0 {
		var line []byte
		if nl := bytes.IndexByte(input, '\n'); nl >= 0 {
			line, input = input[:nl], input[nl+1:]
		} else {
			line, input = input, nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var obj any
		if err := json.Unmarshal(line, &obj); err != nil {
			return nil, false
		}
		return obj, true
	}
	return nil, false
}

// safeFingerprint calls a fingerprint function, recovering from panics.
// A buggy fingerprint should return 0, not crash the process.
func safeFingerprint(fn func(any) float64, input any) (confidence float64) {
	defer func() {
		if r := recover(); r != nil {
			confidence = 0
		}
	}()
	return fn(input)
}

// safeDetectVersion calls a DetectVersion function, recovering from panics.
func safeDetectVersion(fn func(any) string, input any) (ver string) {
	defer func() {
		if r := recover(); r != nil {
			ver = ""
		}
	}()
	return fn(input)
}

// utf8BOM is the byte sequence for a UTF-8 Byte Order Mark.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// DetectFamily determines the input family from raw bytes.
func DetectFamily(input []byte) InputFamily {
	if len(input) == 0 {
		return ""
	}

	// Strip UTF-8 BOM — common on Windows-generated files
	trimmed := bytes.TrimPrefix(input, utf8BOM)
	trimmed = bytes.TrimSpace(trimmed)
	if len(trimmed) == 0 {
		return ""
	}

	switch trimmed[0] {
	case '{', '[':
		return FamilyJSON
	case '<':
		return FamilyXML
	default:
		return FamilyText
	}
}
