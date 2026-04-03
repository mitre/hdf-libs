package hdfparsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseResults_Valid(t *testing.T) {
	t.Run("should parse minimal valid HDF results", func(t *testing.T) {
		validJSON := []byte(`{
			"baselines": [{
				"name": "Test Baseline",
				"integrity": { "algorithm": "sha256", "checksum": "abc123" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test description" }],
					"impact": 0.5,
					"tags": {},
					"results": [{
						"status": "passed",
						"codeDesc": "Test",
						"startTime": "2025-01-01T00:00:00Z"
					}]
				}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(validJSON)

		assert.True(t, result.Success)
		assert.Empty(t, result.Error)
		assert.NotNil(t, result.Data)
		assert.Equal(t, 1, len(result.Data.Baselines))
		assert.Equal(t, "Test Baseline", result.Data.Baselines[0].Name)
	})

	t.Run("should parse complex HDF results with multiple baselines", func(t *testing.T) {
		complexJSON := []byte(`{
			"baselines": [
				{
					"name": "Baseline 1",
					"integrity": { "algorithm": "sha256", "checksum": "hash1" },
					"requirements": [{
						"id": "REQ-001",
						"descriptions": [{ "label": "default", "data": "Desc 1" }],
						"impact": 0.7,
						"tags": { "nist": ["AC-1"] },
						"results": [{
							"status": "failed",
							"codeDesc": "Check 1",
							"startTime": "2025-01-01T00:00:00Z",
							"message": "Failed check"
						}]
					}]
				},
				{
					"name": "Baseline 2",
					"integrity": { "algorithm": "sha512", "checksum": "hash2" },
					"requirements": [{
						"id": "REQ-002",
						"descriptions": [{ "label": "default", "data": "Desc 2" }],
						"impact": 0.3,
						"tags": {},
						"results": [{
							"status": "passed",
							"codeDesc": "Check 2",
							"startTime": "2025-01-02T00:00:00Z"
						}]
					}]
				}
			],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(complexJSON)

		assert.True(t, result.Success)
		assert.NotNil(t, result.Data)
		assert.Equal(t, 2, len(result.Data.Baselines))
	})
}

func TestParseResults_Invalid(t *testing.T) {
	t.Run("should reject invalid JSON syntax", func(t *testing.T) {
		invalidJSON := []byte(`{ "baselines": [invalid json }`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
		assert.Regexp(t, "(?i)(JSON|invalid|character)", result.Error)
		assert.Nil(t, result.Data)
	})

	t.Run("should reject results missing baselines field", func(t *testing.T) {
		invalidJSON := []byte(`{
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "baselines")
	})

	t.Run("should reject results with invalid baseline structure", func(t *testing.T) {
		invalidJSON := []byte(`{
			"baselines": [{
				"integrity": { "algorithm": "sha256", "checksum": "test" },
				"requirements": []
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject results with invalid requirement", func(t *testing.T) {
		invalidJSON := []byte(`{
			"baselines": [{
				"name": "Test",
				"integrity": { "algorithm": "sha256", "checksum": "test" },
				"requirements": [{
					"id": "REQ-001",
					"impact": 0.5,
					"tags": {},
					"results": []
				}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject empty input", func(t *testing.T) {
		result := ParseResults([]byte(""))

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject whitespace-only input", func(t *testing.T) {
		result := ParseResults([]byte("   \n\t  "))

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})
}

func TestParseBaseline_Valid(t *testing.T) {
	t.Run("should parse minimal valid HDF baseline", func(t *testing.T) {
		validJSON := []byte(`{
			"name": "Security Baseline",
			"title": "Test Baseline",
			"version": "1.0.0",
			"integrity": { "algorithm": "sha256", "checksum": "def456" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Access Control",
				"descriptions": [{ "label": "default", "data": "Requirement description" }],
				"impact": 0.7,
				"tags": { "nist": ["AC-1", "AC-2"] }
			}]
		}`)

		result := ParseBaseline(validJSON)

		assert.True(t, result.Success)
		assert.NotNil(t, result.Data)
		assert.Equal(t, "Security Baseline", result.Data.Name)
		assert.Equal(t, 1, len(result.Data.Requirements))
	})

	t.Run("should parse baseline with multiple requirements", func(t *testing.T) {
		validJSON := []byte(`{
			"name": "Multi-Req Baseline",
			"version": "2.0.0",
			"integrity": { "algorithm": "sha512", "checksum": "hash" },
			"requirements": [
				{
					"id": "REQ-001",
					"title": "Requirement 1",
					"descriptions": [{ "label": "default", "data": "Desc 1" }],
					"impact": 0.5,
					"tags": {}
				},
				{
					"id": "REQ-002",
					"title": "Requirement 2",
					"descriptions": [{ "label": "default", "data": "Desc 2" }],
					"impact": 0.8,
					"tags": { "nist": ["AU-1"] }
				}
			]
		}`)

		result := ParseBaseline(validJSON)

		assert.True(t, result.Success)
		assert.Equal(t, 2, len(result.Data.Requirements))
	})
}

func TestParseBaseline_Invalid(t *testing.T) {
	t.Run("should reject baseline missing name", func(t *testing.T) {
		invalidJSON := []byte(`{
			"version": "1.0.0",
			"integrity": { "algorithm": "sha256", "checksum": "test" },
			"requirements": []
		}`)

		result := ParseBaseline(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should reject baseline with empty requirements array", func(t *testing.T) {
		invalidJSON := []byte(`{
			"name": "Test Baseline",
			"integrity": { "algorithm": "sha256", "checksum": "test" },
			"requirements": []
		}`)

		result := ParseBaseline(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})
}

func TestParse_AutoDetection(t *testing.T) {
	t.Run("should auto-detect and parse HDF Results", func(t *testing.T) {
		resultsJSON := []byte(`{
			"baselines": [{
				"name": "Test",
				"integrity": { "algorithm": "sha256", "checksum": "test" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test" }],
					"impact": 0.5,
					"tags": {},
					"results": [{ "status": "passed", "codeDesc": "OK", "startTime": "2025-01-01T00:00:00Z" }]
				}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := Parse(resultsJSON)

		assert.True(t, result.Success)
		assert.Equal(t, "results", result.Type)
		assert.NotNil(t, result.Data)
	})

	t.Run("should auto-detect and parse HDF Baseline", func(t *testing.T) {
		baselineJSON := []byte(`{
			"name": "Test Baseline",
			"version": "1.0.0",
			"integrity": { "algorithm": "sha256", "checksum": "test" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test",
				"descriptions": [{ "label": "default", "data": "Test" }],
				"impact": 0.5,
				"tags": {}
			}]
		}`)

		result := Parse(baselineJSON)

		assert.True(t, result.Success)
		assert.Equal(t, "baseline", result.Type)
		assert.NotNil(t, result.Data)
	})

	t.Run("should return error for ambiguous document", func(t *testing.T) {
		ambiguousJSON := []byte(`{
			"unknown": "field"
		}`)

		result := Parse(ambiguousJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should return error for invalid document", func(t *testing.T) {
		invalidJSON := []byte(`{ invalid }`)

		result := Parse(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})
}

func TestErrorMessages(t *testing.T) {
	t.Run("should provide helpful error message for schema validation failure", func(t *testing.T) {
		invalidJSON := []byte(`{
			"baselines": [{
				"name": "Test"
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ParseResults(invalidJSON)

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("should provide helpful error for JSON parse failure", func(t *testing.T) {
		result := ParseResults([]byte(`{ not valid json`))

		assert.False(t, result.Success)
		assert.NotEmpty(t, result.Error)
		assert.Regexp(t, "(?i)(JSON|parse|syntax|invalid|character)", result.Error)
	})
}
