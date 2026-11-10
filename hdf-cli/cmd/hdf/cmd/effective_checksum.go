package cmd

import (
	"encoding/json"
	"fmt"

	diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
)

// stampConvertOutput sets effectiveChecksum on every requirement of an
// HDF-results conversion output so consumers can seed per-control change
// detection directly from converted documents. Operates on the decoded map to
// preserve unknown/extension fields; override expiry is anchored to the
// document's own timestamp for determinism. Non-results shapes (e.g. legacy
// v2 output and baseline definitions) pass through unchanged.
func stampConvertOutput(data []byte) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse output for checksum stamping: %w", err)
	}
	if _, isResults := doc["baselines"].([]interface{}); !isResults {
		return data, nil
	}

	docTimestamp, _ := doc["timestamp"].(string)
	if err := diff.StampEffectiveChecksums(doc, docTimestamp); err != nil {
		return nil, fmt.Errorf("failed to stamp effective checksums: %w", err)
	}

	return json.MarshalIndent(doc, "", "  ")
}
