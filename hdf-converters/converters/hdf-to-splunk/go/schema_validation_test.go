package hdftosplunk

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
)

// NO PUBLISHED SCHEMA. Searched 2026-09-11: Splunk documents the HTTP Event
// Collector event envelope (event, time, host, source, sourcetype, index) in
// prose and publishes no JSON Schema for it; the payload under `event` is
// explicitly free-form, so there is nothing a document schema could constrain.
//
// What remains checkable is that every emitted line is a JSON object, which is
// what HEC requires and what a malformed serializer would break. A no-op
// validator would make every MustConvert contract pass vacuously.
type splunkNDJSONValidator struct{}

func (splunkNDJSONValidator) Validate(doc []byte) error {
	if len(doc) == 0 {
		return nil
	}
	for i, line := range strings.Split(strings.TrimSpace(string(doc)), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			return fmt.Errorf("line %d is not a JSON object: %w", i+1, err)
		}
	}
	return nil
}

// TestConvertHDFToSplunk_AdversarialCorpus holds this converter to the shared
// corpus contracts, with NDJSON well-formedness standing in for a schema.
func TestConvertHDFToSplunk_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, splunkNDJSONValidator{}, corpus.ResultsCorpus(),
		func(in []byte) ([]byte, error) { return ConvertHDFToSplunk(in, "1.0.0") })
}
