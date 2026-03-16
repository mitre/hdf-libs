// Package hdfparsers provides functions for parsing HDF documents with validation.
package hdfparsers

import (
	"encoding/json"
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-schema"
	validators "github.com/mitre/hdf-validators/go"
)

// ParseResult represents the result of a parse operation
type ParseResult struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Type    string      `json:"type,omitempty"` // "results" or "baseline"
}

// ResultsParseResult is a specialized parse result for HDF Results
type ResultsParseResult struct {
	Success bool            `json:"success"`
	Data    *hdf.HDFResults `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// BaselineParseResult is a specialized parse result for HDF Baseline
type BaselineParseResult struct {
	Success bool             `json:"success"`
	Data    *hdf.HDFBaseline `json:"data,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// ParseResults parses HDF Results document from JSON bytes
func ParseResults(input []byte) ResultsParseResult {
	// Check for empty input
	trimmed := strings.TrimSpace(string(input))
	if len(trimmed) == 0 {
		return ResultsParseResult{
			Success: false,
			Error:   "Input is empty",
		}
	}

	// Validate against schema first
	validationResult := validators.ValidateResults(input)
	if !validationResult.Valid {
		return ResultsParseResult{
			Success: false,
			Error:   fmt.Sprintf("Schema validation failed: %s", validationResult.Error()),
		}
	}

	// Parse JSON into struct
	var data hdf.HDFResults
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	if err := decoder.Decode(&data); err != nil {
		return ResultsParseResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON: %s", err.Error()),
		}
	}

	// Check for trailing garbage
	if decoder.More() {
		return ResultsParseResult{
			Success: false,
			Error:   "Invalid JSON: unexpected trailing data after end of object",
		}
	}

	return ResultsParseResult{
		Success: true,
		Data:    &data,
	}
}

// ParseBaseline parses HDF Baseline document from JSON bytes
func ParseBaseline(input []byte) BaselineParseResult {
	// Check for empty input
	trimmed := strings.TrimSpace(string(input))
	if len(trimmed) == 0 {
		return BaselineParseResult{
			Success: false,
			Error:   "Input is empty",
		}
	}

	// Validate against schema first
	validationResult := validators.ValidateBaseline(input)
	if !validationResult.Valid {
		return BaselineParseResult{
			Success: false,
			Error:   fmt.Sprintf("Schema validation failed: %s", validationResult.Error()),
		}
	}

	// Parse JSON into struct
	var data hdf.HDFBaseline
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	if err := decoder.Decode(&data); err != nil {
		return BaselineParseResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON: %s", err.Error()),
		}
	}

	// Check for trailing garbage
	if decoder.More() {
		return BaselineParseResult{
			Success: false,
			Error:   "Invalid JSON: unexpected trailing data after end of object",
		}
	}

	return BaselineParseResult{
		Success: true,
		Data:    &data,
	}
}

// Parse parses an HDF document with auto-detection of type
func Parse(input []byte) ParseResult {
	// Check for empty input
	trimmed := strings.TrimSpace(string(input))
	if len(trimmed) == 0 {
		return ParseResult{
			Success: false,
			Error:   "Input is empty",
		}
	}

	// First, parse as generic JSON to detect structure
	var generic map[string]interface{}
	if err := json.Unmarshal(input, &generic); err != nil {
		return ParseResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON: %s", err.Error()),
		}
	}

	// Determine type based on structure
	// HDF Results has 'baselines' array at root
	if _, hasBaselines := generic["baselines"]; hasBaselines {
		result := ParseResults(input)
		if !result.Success {
			return ParseResult{
				Success: false,
				Error:   result.Error,
			}
		}
		return ParseResult{
			Success: true,
			Data:    result.Data,
			Type:    "results",
		}
	}

	// HDF Baseline has 'name' and 'requirements' at root
	if _, hasName := generic["name"]; hasName {
		if _, hasRequirements := generic["requirements"]; hasRequirements {
			result := ParseBaseline(input)
			if !result.Success {
				return ParseResult{
					Success: false,
					Error:   result.Error,
				}
			}
			return ParseResult{
				Success: true,
				Data:    result.Data,
				Type:    "baseline",
			}
		}
	}

	return ParseResult{
		Success: false,
		Error:   "Unable to determine HDF document type",
	}
}
