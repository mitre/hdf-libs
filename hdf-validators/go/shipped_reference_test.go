package hdfvalidators

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Reference primitive is closed, and the two shipped validators must enforce
// that identically. Both languages read testdata/shipped-reference-cases.json.
type shippedReferenceCase struct {
	Name      string `json:"name"`
	Reference any    `json:"reference"`
	Valid     bool   `json:"valid"`
	Why       string `json:"why"`
}

func resultsWithReference(t *testing.T, reference any) []byte {
	t.Helper()
	raw, err := json.Marshal(reference)
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
				"refs": [` + string(raw) + `],
				"results": [{ "status": "passed", "codeDesc": "ok", "startTime": "2025-01-01T00:00:00Z" }]
			}]
		}],
		"components": [],
		"statistics": {}
	}`)
}

func TestValidateResults_ReferenceIsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "shipped-reference-cases.json"))
	require.NoError(t, err, "read the shared reference table")
	var table struct {
		Cases []shippedReferenceCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			result := ValidateResults(resultsWithReference(t, tc.Reference))
			assert.Equal(t, tc.Valid, result.Valid, "%s\ngot: %s", tc.Why, result.Error())
		})
	}
}
