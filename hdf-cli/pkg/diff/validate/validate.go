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

// extractSchemaID reads the $id field from a parsed JSON schema document.
func extractSchemaID(doc any) (string, error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return "", fmt.Errorf("schema is not a JSON object")
	}
	id, ok := m["$id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("schema has no $id field")
	}
	return id, nil
}

// buildSchema loads all schemas and compiles the comparison schema.
//
// Each schema's $id is read from the file at runtime so that version
// changes in the schema files propagate automatically without updating
// constants in this code.
//
// Schema loading order:
//  1. All primitive schemas (dependency order for $ref resolution).
//  2. hdf-results schema (defines Evaluated_Requirement referenced by comparison).
//  3. hdf-comparison schema (top-level validation target).
func buildSchema() (*jsonschema.Schema, error) {
	dir, err := schemasDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find schemas directory: %w", err)
	}

	// Schema files to load in dependency order.
	schemaFiles := []string{
		"primitives/common.schema.json",
		"primitives/platform.schema.json",
		"primitives/target.schema.json",
		"primitives/runner.schema.json",
		"primitives/statistics.schema.json",
		"primitives/result.schema.json",
		"primitives/amendments.schema.json",
		"primitives/extensions.schema.json",
		"primitives/parameter.schema.json",
		"primitives/component.schema.json",
		"primitives/data-flow.schema.json",
		"primitives/system.schema.json",
		"primitives/comparison.schema.json",
		"hdf-results.schema.json",
		"hdf-comparison.schema.json",
	}

	c := jsonschema.NewCompiler()
	var comparisonSchemaID string

	for _, file := range schemaFiles {
		doc, loadErr := loadSchemaFile(dir, file)
		if loadErr != nil {
			return nil, loadErr
		}
		id, idErr := extractSchemaID(doc)
		if idErr != nil {
			return nil, fmt.Errorf("schema %s: %w", file, idErr)
		}
		if addErr := c.AddResource(id, doc); addErr != nil {
			return nil, fmt.Errorf("failed to add schema %s (id=%s): %w", file, id, addErr)
		}
		// Remember the last schema's $id — that's hdf-comparison, the validation target
		comparisonSchemaID = id
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
