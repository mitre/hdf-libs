package hdfvalidators

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// results[].rawSourceRecord is closed, and the two shipped validators must
// enforce that identically — the Go one is a draft-07 engine that silently
// ignores `unevaluatedProperties`, so a closure written that way would hold in
// TypeScript alone. Both languages read
// testdata/shipped-raw-source-record-cases.json.
type shippedRawSourceRecordCase struct {
	Name   string `json:"name"`
	Record any    `json:"record"`
	Valid  bool   `json:"valid"`
	Why    string `json:"why"`
}

func resultsWithRawSourceRecord(t *testing.T, record any) []byte {
	t.Helper()
	raw, err := json.Marshal(record)
	require.NoError(t, err)
	return []byte(`{
		"baselines": [{
			"name": "Test Baseline",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "REQ-001",
				"descriptions": [{ "label": "default", "data": "d" }],
				"impact": 0.5,
				"tags": {},
				"results": [{
					"status": "passed",
					"codeDesc": "ok",
					"startTime": "2025-01-01T00:00:00Z",
					"rawSourceRecord": ` + string(raw) + `
				}]
			}]
		}],
		"components": [],
		"statistics": {}
	}`)
}

func TestValidateResults_RawSourceRecordIsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "shipped-raw-source-record-cases.json"))
	require.NoError(t, err, "read the shared raw-source-record table")
	var table struct {
		Cases []shippedRawSourceRecordCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			result := ValidateResults(resultsWithRawSourceRecord(t, tc.Record))
			assert.Equal(t, tc.Valid, result.Valid, "%s\ngot: %s", tc.Why, result.Error())
		})
	}
}

// A result carrying no record at all stays valid: the field is optional, and a
// tool that emits HDF natively has no source record to carry.
func TestValidateResults_RawSourceRecordIsOptional(t *testing.T) {
	doc := []byte(`{
		"baselines": [{
			"name": "B",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "REQ-001",
				"descriptions": [{ "label": "default", "data": "d" }],
				"impact": 0.5,
				"tags": {},
				"results": [{ "status": "passed", "codeDesc": "ok", "startTime": "2025-01-01T00:00:00Z" }]
			}]
		}],
		"components": [],
		"statistics": {}
	}`)
	assert.True(t, ValidateResults(doc).Valid)
}
