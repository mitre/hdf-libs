package hdftoecs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
)

// NO DOCUMENT SCHEMA EXISTS, confirmed independently 2026-09-11 rather than
// taken from the audit: elastic/ecs publishes its generated artifacts as
// ecs_flat.yml and ecs_nested.yml (field definitions), Elasticsearch composable
// and legacy index templates (mappings), fields.csv, and Beats fields.ecs.yml.
// None is a JSON Schema. ECS is a field dictionary whose conformance is enforced
// by Elasticsearch mappings at index time, so there is no document-level schema
// to validate an exported event against.
//
// What remains checkable is that every emitted line is a JSON object, which is
// what the NDJSON contract requires. A no-op validator would make every
// MustConvert contract pass vacuously.
type ecsNDJSONValidator struct{}

func (ecsNDJSONValidator) Validate(doc []byte) error {
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
		// Unmarshalling the literal null into a map SUCCEEDS and leaves obj nil,
		// so without this a null line passes here while the TypeScript peer
		// rejects it — the two would disagree about the same output.
		if obj == nil {
			return fmt.Errorf("line %d is null, not a JSON object", i+1)
		}
	}
	return nil
}

// TestConvertHDFToECS_AdversarialCorpus holds this converter to the shared
// corpus contracts, with NDJSON well-formedness standing in for a schema.
func TestConvertHDFToECS_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, ecsNDJSONValidator{}, corpus.ResultsCorpus(),
		func(in []byte) ([]byte, error) { return ConvertHDFToECS(in, "1.0.0") })
}
