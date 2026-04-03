package hdfvalidators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateResults_ValidDocuments(t *testing.T) {
	t.Run("should validate minimal valid HDF results", func(t *testing.T) {
		validResults := []byte(`{
			"baselines": [{
				"name": "Test Baseline",
				"checksum": { "algorithm": "sha256", "value": "abc123" },
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

		result := ValidateResults(validResults)
		assert.True(t, result.Valid, "Should be valid")
		assert.Empty(t, result.Errors)
	})

	t.Run("should validate results with components and statistics", func(t *testing.T) {
		validResults := []byte(`{
			"baselines": [{
				"name": "Test Baseline",
				"checksum": { "algorithm": "sha256", "value": "abc123" },
				"requirements": [{
					"id": "REQ-001",
					"descriptions": [{ "label": "default", "data": "Test" }],
					"impact": 0.5,
					"tags": {},
					"results": [{ "status": "passed", "codeDesc": "OK", "startTime": "2025-01-01T00:00:00Z" }]
				}]
			}],
			"components": [{
				"name": "web-server-01",
				"type": "host"
			}],
			"statistics": {
				"duration": 45.5
			}
		}`)

		result := ValidateResults(validResults)
		if !result.Valid {
			t.Logf("Validation errors: %s", result.Error())
		}
		assert.True(t, result.Valid)
	})
}

func TestValidateResults_InvalidDocuments(t *testing.T) {
	t.Run("should reject results missing baselines field", func(t *testing.T) {
		invalid := []byte(`{
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
		assert.Contains(t, result.Error(), "baselines")
	})

	t.Run("should reject results with invalid baselines type", func(t *testing.T) {
		invalid := []byte(`{
			"baselines": "not an array",
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "baselines")
	})

	t.Run("should reject baseline missing required name field", func(t *testing.T) {
		invalid := []byte(`{
			"baselines": [{
				"checksum": { "algorithm": "sha256", "value": "abc123" },
				"requirements": []
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "name")
	})

	t.Run("should reject invalid JSON", func(t *testing.T) {
		invalid := []byte(`not valid json`)

		result := ValidateResults(invalid)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})
}

func TestValidateBaseline_ValidDocuments(t *testing.T) {
	t.Run("should validate minimal valid baseline", func(t *testing.T) {
		validBaseline := []byte(`{
			"name": "Test Baseline",
			"title": "Test Baseline Title",
			"version": "1.0.0",
			"checksum": {
				"algorithm": "sha256",
				"value": "abc123"
			},
			"requirements": [{
				"id": "REQ-001",
				"title": "Test Requirement",
				"descriptions": [{ "label": "default", "data": "Description" }],
				"impact": 0.7,
				"tags": {}
			}]
		}`)

		result := ValidateBaseline(validBaseline)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("should validate baseline with requirements", func(t *testing.T) {
		validBaseline := []byte(`{
			"name": "Test Baseline",
			"title": "Test Title",
			"version": "1.0.0",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "REQ-001",
				"title": "Test Requirement",
				"descriptions": [{ "label": "default", "data": "Description" }],
				"impact": 0.7,
				"tags": { "nist": ["AC-1"] }
			}]
		}`)

		result := ValidateBaseline(validBaseline)
		assert.True(t, result.Valid)
	})
}

func TestValidateBaseline_InvalidDocuments(t *testing.T) {
	t.Run("should reject baseline missing name", func(t *testing.T) {
		invalid := []byte(`{
			"title": "Test",
			"version": "1.0.0",
			"checksum": { "algorithm": "sha256", "value": "abc123" },
			"requirements": [{
				"id": "REQ-001",
				"descriptions": [{ "label": "default", "data": "Test" }],
				"impact": 0.5,
				"tags": {}
			}]
		}`)

		result := ValidateBaseline(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "name")
	})

	t.Run("should reject baseline missing requirements", func(t *testing.T) {
		invalid := []byte(`{
			"name": "Test",
			"title": "Test",
			"version": "1.0.0"
		}`)

		result := ValidateBaseline(invalid)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Error(), "requirements")
	})
}

func TestValidationResult_ErrorMessage(t *testing.T) {
	t.Run("should format error messages correctly", func(t *testing.T) {
		result := ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{Field: "baselines", Description: "is required"},
				{Field: "baselines[0].name", Description: "must be a string"},
			},
		}

		msg := result.Error()
		assert.Contains(t, msg, "baselines")
		assert.Contains(t, msg, "name")
	})

	t.Run("should return empty string for valid results", func(t *testing.T) {
		result := ValidationResult{
			Valid:  true,
			Errors: []ValidationError{},
		}

		assert.Empty(t, result.Error())
	})
}

func TestSetSchemaDir(t *testing.T) {
	t.Run("should allow loading schemas from custom directory", func(t *testing.T) {
		// Store original
		originalDir := GetSchemaDir()
		defer SetSchemaDir(originalDir)

		// Set custom directory
		customDir := "../../hdf-schema/dist/schemas"
		SetSchemaDir(customDir)

		assert.Equal(t, customDir, GetSchemaDir())

		// Should still validate correctly
		validResults := []byte(`{
			"baselines": [{
				"name": "Test",
				"checksum": { "algorithm": "sha256", "value": "abc" },
				"requirements": [{"id": "SV-1", "impact": 0.5, "tags": {}, "descriptions": [{"label": "default", "data": "Test"}], "results": [{"status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z"}]}]
			}],
			"components": [],
			"statistics": {}
		}`)

		result := ValidateResults(validResults)
		assert.True(t, result.Valid)
	})
}
