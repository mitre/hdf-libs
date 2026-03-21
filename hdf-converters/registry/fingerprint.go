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
}

// DetectConverter returns the highest-confidence ingest converter match,
// or nil if no match is found.
func DetectConverter(input []byte) *DetectionResult {
	results := DetectConverterAll(input)
	if len(results) == 0 {
		return nil
	}
	return &results[0]
}

// DetectConverterAll returns all matching ingest converters sorted by
// confidence descending.
func DetectConverterAll(input []byte) []DetectionResult {
	family := DetectFamily(input)
	if family == "" {
		return nil
	}

	var parsed any
	if family == FamilyJSON {
		if err := json.Unmarshal(input, &parsed); err != nil {
			return nil
		}
	} else {
		parsed = string(input)
	}

	candidates := GetIngestFingerprints()
	var results []DetectionResult
	for _, fp := range candidates {
		if fp.InputFamily != family {
			continue
		}
		confidence := fp.Fingerprint(parsed)
		if confidence > 0 {
			results = append(results, DetectionResult{
				Fingerprint: fp,
				Confidence:  confidence,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})
	return results
}

// DetectFamily determines the input family from raw bytes.
func DetectFamily(input []byte) InputFamily {
	if len(input) == 0 {
		return ""
	}

	trimmed := bytes.TrimSpace(input)
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
