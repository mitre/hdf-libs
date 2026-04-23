package hdftocsv

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertHDFToCSV_Minimal(t *testing.T) {
	// Load minimal fixture
	inputPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-csv", "fixtures", "input", "minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.json fixture")

	// Convert
	result, err := ConvertHDFToCSV(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, result, "Result should not be empty")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(string(result)))
	records, err := reader.ReadAll()
	require.NoError(t, err, "Should parse CSV")

	// Verify structure
	require.Len(t, records, 3, "Should have header + 2 data rows")

	// Verify header
	header := records[0]
	assert.Contains(t, header, "Baseline ID")
	assert.Contains(t, header, "Requirement ID")
	assert.Contains(t, header, "Status")

	// Verify first data row
	row1 := records[1]
	assert.Equal(t, "Example STIG Baseline", row1[0]) // Baseline ID
	assert.Equal(t, "SV-123456", row1[5])             // Requirement ID
	assert.Equal(t, "passed", row1[10])               // Status
	assert.Contains(t, row1[11], "IA-5 (1)")          // NIST Controls
	assert.Contains(t, row1[12], "CCI-000192")        // CCI Controls

	// Verify second data row
	row2 := records[2]
	assert.Equal(t, "SV-123457", row2[5])                        // Requirement ID
	assert.Equal(t, "failed", row2[10])                          // Status
	assert.Equal(t, "Audit logging is not configured", row2[13]) // Message
}

func TestConvertHDFToCSV_EmptyBaselines(t *testing.T) {
	input := `{
		"baselines": [],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")
	assert.Empty(t, result, "Result should be empty for no data")
}

func TestConvertHDFToCSV_NoRequirements(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Empty Baseline",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": []
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")
	assert.Empty(t, result, "Result should be empty for no requirements")
}

func TestConvertHDFToCSV_MultipleBaselines(t *testing.T) {
	input := `{
		"baselines": [
			{
				"name": "Baseline 1",
				"version": "1.0.0",
				"title": "First Baseline",
				"maintainer": "Test",
				"supports": [],
				"inputs": [],
				"groups": [],
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": [{
					"id": "REQ-001",
					"title": "Test Requirement",
					"descriptions": [{ "label": "default", "data": "Test description" }],
					"impact": 0.5,
					"tags": { "severity": "medium" },
					"sourceLocation": { "ref": "REQ-001", "line": 1 },
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
				}]
			},
			{
				"name": "Baseline 2",
				"version": "2.0.0",
				"title": "Second Baseline",
				"maintainer": "Test",
				"supports": [],
				"inputs": [],
				"groups": [],
				"checksum": { "algorithm": "sha256", "value": "def" },
				"requirements": [{
					"id": "REQ-002",
					"title": "Another Requirement",
					"descriptions": [{ "label": "default", "data": "Another description" }],
					"impact": 0.7,
					"tags": { "severity": "high" },
					"sourceLocation": { "ref": "REQ-002", "line": 1 },
					"results": [{ "status": "failed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
				}]
			}
		],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(string(result)))
	records, err := reader.ReadAll()
	require.NoError(t, err, "Should parse CSV")

	// Should have header + 2 data rows
	require.Len(t, records, 3)

	// Verify both baselines present
	assert.Equal(t, "Baseline 1", records[1][0])
	assert.Equal(t, "Baseline 2", records[2][0])
}

func TestConvertHDFToCSV_MultipleComponents(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Test Baseline",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test Requirement",
				"descriptions": [{ "label": "default", "data": "Test description" }],
				"impact": 0.5,
				"tags": { "severity": "medium" },
				"sourceLocation": { "ref": "REQ-001", "line": 1 },
				"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
			}]
		}],
		"components": [
			{ "name": "target1", "type": "host" },
			{ "name": "target2", "type": "container" }
		],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")

	resultStr := string(result)
	assert.Contains(t, resultStr, "target1,host")
	assert.Contains(t, resultStr, "target2,container")
}

func TestConvertHDFToCSV_FieldExtraction(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Test",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test",
				"descriptions": [{ "label": "default", "data": "Test" }],
				"impact": 0.5,
				"tags": {
					"nist": ["AC-2", "AC-3", "IA-5 (1)"],
					"cci": ["CCI-000001", "CCI-000002"],
					"severity": "medium"
				},
				"sourceLocation": { "ref": "REQ-001", "line": 1 },
				"results": [{
					"status": "failed",
					"codeDesc": "Test",
					"message": "Security control not implemented",
					"startTime": "2026-01-29T18:00:00.000Z"
				}]
			}]
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")

	resultStr := string(result)
	assert.Contains(t, resultStr, "AC-2; AC-3; IA-5 (1)")
	assert.Contains(t, resultStr, "CCI-000001; CCI-000002")
	assert.Contains(t, resultStr, "Security control not implemented")
}

func TestConvertHDFToCSV_CSVInjection(t *testing.T) {
	input := `{
		"baselines": [{
			"name": "Test",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [
				{
					"id": "REQ-001",
					"title": "=1+1",
					"descriptions": [{ "label": "default", "data": "=SUM(A1:A10)" }],
					"impact": 0.5,
					"tags": { "severity": "medium" },
					"sourceLocation": { "ref": "REQ-001", "line": 1 },
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
				},
				{
					"id": "REQ-002",
					"title": "+dangerous",
					"descriptions": [{ "label": "default", "data": "test" }],
					"impact": 0.5,
					"tags": { "severity": "medium" },
					"sourceLocation": { "ref": "REQ-002", "line": 1 },
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
				},
				{
					"id": "REQ-003",
					"title": "-dangerous",
					"descriptions": [{ "label": "default", "data": "test" }],
					"impact": 0.5,
					"tags": { "severity": "medium" },
					"sourceLocation": { "ref": "REQ-003", "line": 1 },
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
				},
				{
					"id": "REQ-004",
					"title": "@dangerous",
					"descriptions": [{ "label": "default", "data": "test" }],
					"impact": 0.5,
					"tags": { "severity": "medium" },
					"sourceLocation": { "ref": "REQ-004", "line": 1 },
					"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
				}
			]
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`

	result, err := ConvertHDFToCSV([]byte(input))
	require.NoError(t, err, "Conversion should succeed")

	resultStr := string(result)
	assert.Contains(t, resultStr, "'=1+1")
	assert.Contains(t, resultStr, "'=SUM(A1:A10)")
	assert.Contains(t, resultStr, "'+dangerous")
	assert.Contains(t, resultStr, "'-dangerous")
	assert.Contains(t, resultStr, "'@dangerous")
}

func TestGetSeverity_ArrayPath(t *testing.T) {
	t.Run("severity tag as []interface{} slice returns first element", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{
			Impact: 0.5,
			Tags: map[string]interface{}{
				"severity": []interface{}{"high", "critical"},
			},
		}
		result := getSeverity(req)
		assert.Equal(t, "high", result)
	})

	t.Run("impact exactly 0.7 returns high", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.7}
		assert.Equal(t, "high", getSeverity(req))
	})

	t.Run("impact exactly 0.4 returns medium", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.4}
		assert.Equal(t, "medium", getSeverity(req))
	})

	t.Run("impact 0.39 returns low", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.39}
		assert.Equal(t, "low", getSeverity(req))
	})

	t.Run("impact 0.0 returns low (below medium threshold)", func(t *testing.T) {
		req := &hdf.EvaluatedRequirement{Impact: 0.0}
		assert.Equal(t, "low", getSeverity(req))
	})
}

func TestConvertHDFToCSV_InvalidJSON(t *testing.T) {
	_, err := ConvertHDFToCSV([]byte("not valid json"))
	assert.Error(t, err)
}

func TestConvertHDFToCSV_MissingBaselines(t *testing.T) {
	_, err := ConvertHDFToCSV([]byte("{}"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing baselines")
}

func TestConvertHDFToCSV_InvalidStructure(t *testing.T) {
	_, err := ConvertHDFToCSV([]byte(`{ "baselines": "not an array" }`))
	assert.Error(t, err)
}
