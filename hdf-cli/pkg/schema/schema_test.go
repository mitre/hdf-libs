package schema

import (
	"testing"
)

func TestValidateResults_ValidMinimal(t *testing.T) {
	// Minimal valid HDF v2.0 results
	data := []byte(`{
		"baselines": [],
		"statistics": {}
	}`)

	result := ValidateResults(data)
	if !result.Valid {
		t.Errorf("expected valid, got errors: %s", result.Error())
	}
}

func TestValidateResults_MissingRequired(t *testing.T) {
	// Missing required 'baselines' field
	data := []byte(`{
		"statistics": {}
	}`)

	result := ValidateResults(data)
	if result.Valid {
		t.Error("expected invalid for missing required field")
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one error")
	}
}

func TestValidateResults_InvalidJSON(t *testing.T) {
	data := []byte(`not valid json`)

	result := ValidateResults(data)
	if result.Valid {
		t.Error("expected invalid for malformed JSON")
	}
}

func TestValidateResults_WrongType(t *testing.T) {
	// Version should be string, not number
	data := []byte(`{
		"version": 123,
		"platform": {"name": "test", "release": "1.0"},
		"profiles": [],
		"statistics": {}
	}`)

	result := ValidateResults(data)
	if result.Valid {
		t.Error("expected invalid for wrong type")
	}
}

func TestValidateBaseline_ValidMinimal(t *testing.T) {
	// Minimal valid HDF baseline (v2.0 requires name, supports, requirements, groups, depends, and checksum)
	data := []byte(`{
		"name": "test-baseline",
		"checksum": {
			"algorithm": "sha256",
			"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		},
		"supports": [],
		"requirements": [{
			"id": "test-1",
			"descriptions": [{"label": "default", "data": "test"}],
			"impact": 0.5,
			"refs": [],
			"tags": {},
			"sourceLocation": {"ref": "test.rb", "line": 1}
		}],
		"groups": [{"id": "test", "requirements": ["test-1"]}],
		"depends": []
	}`)

	result := ValidateBaseline(data)
	if !result.Valid {
		t.Errorf("expected valid, got errors: %s", result.Error())
	}
}

func TestValidateBaseline_MissingRequired(t *testing.T) {
	// Missing required fields (name, sha256/sha512, etc.)
	data := []byte(`{
		"supports": []
	}`)

	result := ValidateBaseline(data)
	if result.Valid {
		t.Error("expected invalid for missing required field")
	}
}

func TestResult_Error(t *testing.T) {
	// Test error formatting
	result := Result{
		Valid: false,
		Errors: []ValidationError{
			{Field: "version", Description: "is required"},
			{Field: "platform.name", Description: "is required"},
		},
	}

	errStr := result.Error()
	if errStr == "" {
		t.Error("expected non-empty error string")
	}
	if errStr != "version: is required; platform.name: is required" {
		t.Errorf("unexpected error format: %s", errStr)
	}
}

func TestResult_ErrorEmpty(t *testing.T) {
	result := Result{Valid: true}
	if result.Error() != "" {
		t.Error("expected empty error string for valid result")
	}
}

func TestType_Invalid(t *testing.T) {
	result := Validate([]byte(`{}`), Type("invalid"))
	if result.Valid {
		t.Error("expected invalid for unknown schema type")
	}
}
