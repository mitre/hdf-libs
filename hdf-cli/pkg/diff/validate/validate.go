// Package validate provides JSON Schema 2020-12 validation for HDF comparison documents.
//
// It loads schemas from the sibling hdf-schema package and validates HdfComparison
// documents produced by the diff engine against the hdf-comparison schema.
package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ValidationResult holds the result of validating a document.
type ValidationResult struct {
	Valid  bool
	Errors []string
}

// comparisonSchemaID is the $id of the hdf-comparison schema.
const comparisonSchemaID = "https://mitre.github.io/hdf-libs/schemas/hdf-comparison/v1.0.0"

// Cached compiled schema (initialized once).
var (
	cachedSchema *jsonschema.Schema
	compileOnce  sync.Once
	errCompile   error
)

// schemasDir returns the absolute path to the hdf-schema package's schemas directory.
// From pkg/diff/validate/ up to hdf-cli root, then to sibling hdf-schema/src/schemas/.
func schemasDir() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	// From hdf-cli/pkg/diff/validate/ -> hdf-libs root -> hdf-schema/src/schemas.
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "hdf-schema", "src", "schemas")
	return filepath.Abs(dir)
}

// loadSchemaFile reads a JSON schema file from the schemas directory.
func loadSchemaFile(baseDir, relativePath string) (any, error) {
	fullPath := filepath.Join(baseDir, relativePath)
	data, err := os.ReadFile(fullPath) // #nosec G304 -- path from known schema directory
	if err != nil {
		return nil, fmt.Errorf("failed to read schema %s: %w", relativePath, err)
	}
	var schema any
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("failed to parse schema %s: %w", relativePath, err)
	}
	return schema, nil
}

// buildSchema loads all schemas and compiles the comparison schema.
//
// Schema loading order (mirrors TypeScript):
//  1. All primitive schemas (common, platform, target, runner, statistics, result, extensions, component, data-flow, system, comparison).
//  2. hdf-results schema (defines Evaluated_Requirement referenced by comparison).
//  3. hdf-comparison schema (top-level validation target).
func buildSchema() (*jsonschema.Schema, error) {
	dir, err := schemasDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find schemas directory: %w", err)
	}

	// Schema files to load in dependency order.
	// Each entry is {relative path, expected $id}.
	type schemaEntry struct {
		path string
		id   string
	}

	entries := []schemaEntry{
		{"primitives/common.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/common/v2.0.0"},
		{"primitives/platform.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/platform/v2.0.0"},
		{"primitives/target.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/target/v2.0.0"},
		{"primitives/runner.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/runner/v2.0.0"},
		{"primitives/statistics.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/statistics/v2.0.0"},
		{"primitives/result.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/result/v2.0.0"},
		{"primitives/amendments.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/amendments/v2.0.0"},
		{"primitives/extensions.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/extensions/v2.0.0"},
		{"primitives/parameter.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/parameter/v2.0.0"},
		{"primitives/component.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/component/v2.0.0"},
		{"primitives/data-flow.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/data-flow/v2.0.0"},
		{"primitives/system.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/system/v2.0.0"},
		{"primitives/comparison.schema.json", "https://mitre.github.io/hdf-libs/schemas/primitives/comparison/v1.0.0"},
		{"hdf-results.schema.json", "https://mitre.github.io/hdf-libs/schemas/hdf-results/v2.0.0"},
		{"hdf-comparison.schema.json", comparisonSchemaID},
	}

	c := jsonschema.NewCompiler()

	for _, entry := range entries {
		doc, loadErr := loadSchemaFile(dir, entry.path)
		if loadErr != nil {
			return nil, loadErr
		}
		if addErr := c.AddResource(entry.id, doc); addErr != nil {
			return nil, fmt.Errorf("failed to add schema %s (id=%s): %w", entry.path, entry.id, addErr)
		}
	}

	compiled, err := c.Compile(comparisonSchemaID)
	if err != nil {
		return nil, fmt.Errorf("failed to compile comparison schema: %w", err)
	}

	return compiled, nil
}

// getSchema returns the cached compiled comparison schema, building it on first call.
func getSchema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		cachedSchema, errCompile = buildSchema()
	})
	return cachedSchema, errCompile
}

// formatValidationErrors extracts human-readable error messages from a validation error.
func formatValidationErrors(err error) []string {
	valErr, ok := err.(*jsonschema.ValidationError) //nolint:errorlint // need concrete type for Causes
	if !ok {
		return []string{err.Error()}
	}
	return collectErrors(valErr)
}

// collectErrors recursively collects leaf error messages from a ValidationError tree.
// Branch nodes (those with Causes) are not included directly; only leaf errors
// with actual validation messages are collected.
func collectErrors(ve *jsonschema.ValidationError) []string {
	if len(ve.Causes) == 0 {
		// Leaf node: use the built-in Error() which includes instance location and message.
		return []string{ve.Error()}
	}
	var errors []string
	for _, cause := range ve.Causes {
		errors = append(errors, collectErrors(cause)...)
	}
	return errors
}

// NormalizeForSchema recursively normalizes a Go-serialized JSON document
// to be schema-valid by fixing the Go nil-slice → JSON null mismatch.
//
// Go's encoding/json serializes nil slices as JSON null, but JSON Schema
// 2020-12 with "unevaluatedProperties: false" rejects null for optional
// fields that aren't explicitly nullable. In contrast, TypeScript/JavaScript
// simply omits undefined fields from serialized JSON.
//
// This function applies three rules:
//   - Nullable fields (before, after) preserve null values
//   - Required array fields (fieldChanges, changeReasons) convert null → []
//   - All other null values are omitted (matching JS undefined behavior)
//
// Call this on any Go-produced HdfComparison before schema validation.
// This is a known Go serialization limitation tracked for deeper resolution
// in the quicktype code generator (see beads memory: go-nil-slice-null).
func NormalizeForSchema(v any) any {
	switch val := v.(type) {
	case map[string]any:
		cleaned := make(map[string]any, len(val))
		for key, value := range val {
			if value == nil {
				if nullableFields[key] {
					cleaned[key] = nil // preserve explicit nulls (before/after)
				} else if requiredArrayFields[key] {
					cleaned[key] = []any{} // convert null arrays to empty
				}
				// else: omit non-nullable null values (matches JS undefined)
				continue
			}
			cleaned[key] = NormalizeForSchema(value)
		}
		return cleaned
	case []any:
		cleaned := make([]any, 0, len(val))
		for _, item := range val {
			cleaned = append(cleaned, NormalizeForSchema(item))
		}
		return cleaned
	default:
		return v
	}
}

// nullableFields are fields explicitly declared as oneOf [type, null] in the schema.
// These MUST preserve null rather than being stripped.
var nullableFields = map[string]bool{
	"before": true,
	"after":  true,
}

// requiredArrayFields are required array fields that must be [] not null.
var requiredArrayFields = map[string]bool{
	"fieldChanges":     true,
	"changeReasons":    true,
	"requirementDiffs": true,
	"baselineDiffs":    true,
	"sources":          true,
}

// ValidateComparison validates an HdfComparison document against the schema.
//
// The doc parameter should be the document as a Go value (typically a map[string]any
// obtained by json.Unmarshal into an any). The document is validated against the
// hdf-comparison JSON Schema 2020-12.
//
// The document is automatically normalized via NormalizeForSchema to handle
// Go's nil-slice → null serialization before validation.
//
//nolint:revive // Name matches the TypeScript API and is used by external callers.
func ValidateComparison(doc any) ValidationResult {
	schema, err := getSchema()
	if err != nil {
		return ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("schema compilation error: %v", err)},
		}
	}

	// Normalize to handle Go nil-slice → null serialization mismatch.
	normalized := NormalizeForSchema(doc)

	if err := schema.Validate(normalized); err != nil {
		return ValidationResult{
			Valid:  false,
			Errors: formatValidationErrors(err),
		}
	}

	return ValidationResult{Valid: true}
}
