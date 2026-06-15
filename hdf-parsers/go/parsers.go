// Package hdfparsers provides functions for parsing HDF documents with validation.
package hdfparsers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// JSON-quoted ISO 8601 timestamp with no trailing timezone — InSpec emits these.
var noTzTimestamp = regexp.MustCompile(`"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)"`)

// NormalizeTimestamps appends Z (treats as UTC) to bare ISO timestamps in a
// JSON byte slice so they pass schema validation. Exported so other workspace
// packages can use the same regex instead of re-implementing it. Mirrors
// hdf-parsers/typescript/index.ts normalizeTimestamps.
func NormalizeTimestamps(input []byte) []byte {
	return noTzTimestamp.ReplaceAll(input, []byte(`"${1}Z"`))
}

// ParseResult represents the result of a parse operation
type ParseResult struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Type    string      `json:"type,omitempty"` // "results", "baseline", "system", "plan", "evidencePackage", "comparison"
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

// SystemParseResult is a specialized parse result for HDF System
type SystemParseResult struct {
	Success bool           `json:"success"`
	Data    *hdf.HDFSystem `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// PlanParseResult is a specialized parse result for HDF Plan
type PlanParseResult struct {
	Success bool         `json:"success"`
	Data    *hdf.HDFPlan `json:"data,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// EvidencePackageParseResult is a specialized parse result for HDF Evidence Package
type EvidencePackageParseResult struct {
	Success bool                    `json:"success"`
	Data    *hdf.HDFEvidencePackage `json:"data,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// ComparisonParseResult is a specialized parse result for HDF Comparison
type ComparisonParseResult struct {
	Success bool               `json:"success"`
	Data    *hdf.HDFComparison `json:"data,omitempty"`
	Error   string             `json:"error,omitempty"`
}

// ParseResults parses HDF Results document from JSON bytes
func ParseResults(input []byte) ResultsParseResult {
	input = NormalizeTimestamps(input)
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
	input = NormalizeTimestamps(input)
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

// ParseSystem parses HDF System document from JSON bytes
func ParseSystem(input []byte) SystemParseResult {
	trimmed := strings.TrimSpace(string(input))
	if len(trimmed) == 0 {
		return SystemParseResult{Success: false, Error: "Input is empty"}
	}

	validationResult := validators.ValidateSystem(input)
	if !validationResult.Valid {
		return SystemParseResult{
			Success: false,
			Error:   fmt.Sprintf("Schema validation failed: %s", validationResult.Error()),
		}
	}

	var data hdf.HDFSystem
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	if err := decoder.Decode(&data); err != nil {
		return SystemParseResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON: %s", err.Error()),
		}
	}
	if decoder.More() {
		return SystemParseResult{
			Success: false,
			Error:   "Invalid JSON: unexpected trailing data after end of object",
		}
	}
	return SystemParseResult{Success: true, Data: &data}
}

// ParsePlan parses HDF Plan document from JSON bytes
func ParsePlan(input []byte) PlanParseResult {
	trimmed := strings.TrimSpace(string(input))
	if len(trimmed) == 0 {
		return PlanParseResult{Success: false, Error: "Input is empty"}
	}

	validationResult := validators.ValidatePlan(input)
	if !validationResult.Valid {
		return PlanParseResult{
			Success: false,
			Error:   fmt.Sprintf("Schema validation failed: %s", validationResult.Error()),
		}
	}

	var data hdf.HDFPlan
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	if err := decoder.Decode(&data); err != nil {
		return PlanParseResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON: %s", err.Error()),
		}
	}
	if decoder.More() {
		return PlanParseResult{
			Success: false,
			Error:   "Invalid JSON: unexpected trailing data after end of object",
		}
	}
	return PlanParseResult{Success: true, Data: &data}
}

// ParseEvidencePackage parses HDF Evidence Package document from JSON bytes
func ParseEvidencePackage(input []byte) EvidencePackageParseResult {
	trimmed := strings.TrimSpace(string(input))
	if len(trimmed) == 0 {
		return EvidencePackageParseResult{Success: false, Error: "Input is empty"}
	}

	validationResult := validators.ValidateEvidencePackage(input)
	if !validationResult.Valid {
		return EvidencePackageParseResult{
			Success: false,
			Error:   fmt.Sprintf("Schema validation failed: %s", validationResult.Error()),
		}
	}

	var data hdf.HDFEvidencePackage
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	if err := decoder.Decode(&data); err != nil {
		return EvidencePackageParseResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON: %s", err.Error()),
		}
	}
	if decoder.More() {
		return EvidencePackageParseResult{
			Success: false,
			Error:   "Invalid JSON: unexpected trailing data after end of object",
		}
	}
	return EvidencePackageParseResult{Success: true, Data: &data}
}

// ParseComparison parses HDF Comparison document from JSON bytes
func ParseComparison(input []byte) ComparisonParseResult {
	trimmed := strings.TrimSpace(string(input))
	if len(trimmed) == 0 {
		return ComparisonParseResult{Success: false, Error: "Input is empty"}
	}

	validationResult := validators.ValidateComparison(input)
	if !validationResult.Valid {
		return ComparisonParseResult{
			Success: false,
			Error:   fmt.Sprintf("Schema validation failed: %s", validationResult.Error()),
		}
	}

	var data hdf.HDFComparison
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	if err := decoder.Decode(&data); err != nil {
		return ComparisonParseResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid JSON: %s", err.Error()),
		}
	}
	if decoder.More() {
		return ComparisonParseResult{
			Success: false,
			Error:   "Invalid JSON: unexpected trailing data after end of object",
		}
	}
	return ComparisonParseResult{Success: true, Data: &data}
}

// Parse parses an HDF document with auto-detection of type. Detection uses
// each schema's uniquely-named second required key (e.g. components→system,
// assessments→plan, requirementDiffs→comparison) so a doc with a shared `name`
// root key doesn't ambiguously land on baseline.
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

	// HDF Comparison has 'requirementDiffs' (most distinctive — check first)
	if _, has := generic["requirementDiffs"]; has {
		result := ParseComparison(input)
		if !result.Success {
			return ParseResult{Success: false, Error: result.Error}
		}
		return ParseResult{Success: true, Data: result.Data, Type: "comparison"}
	}

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

	// Remaining doc types share `name` — disambiguate by the second required key.
	if _, hasName := generic["name"]; hasName {
		if _, has := generic["requirements"]; has {
			result := ParseBaseline(input)
			if !result.Success {
				return ParseResult{Success: false, Error: result.Error}
			}
			return ParseResult{Success: true, Data: result.Data, Type: "baseline"}
		}
		if _, has := generic["components"]; has {
			result := ParseSystem(input)
			if !result.Success {
				return ParseResult{Success: false, Error: result.Error}
			}
			return ParseResult{Success: true, Data: result.Data, Type: "system"}
		}
		if _, has := generic["assessments"]; has {
			result := ParsePlan(input)
			if !result.Success {
				return ParseResult{Success: false, Error: result.Error}
			}
			return ParseResult{Success: true, Data: result.Data, Type: "plan"}
		}
		if _, has := generic["contents"]; has {
			result := ParseEvidencePackage(input)
			if !result.Success {
				return ParseResult{Success: false, Error: result.Error}
			}
			return ParseResult{Success: true, Data: result.Data, Type: "evidencePackage"}
		}
	}

	return ParseResult{
		Success: false,
		Error:   "Unable to determine HDF document type",
	}
}
