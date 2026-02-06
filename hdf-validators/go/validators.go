// Package hdfvalidators provides JSON Schema validation for HDF files.
package hdfvalidators

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schemas/*.schema.json
var schemaFS embed.FS

// schemaDir is an optional directory to load schemas from instead of embedded.
// When set, schemas are loaded from disk for development/testing workflows.
var schemaDir string

// SetSchemaDir configures the package to load schemas from the specified
// directory instead of using embedded schemas. Pass empty string to revert
// to embedded schemas. This also clears any cached schemas.
func SetSchemaDir(dir string) {
	schemaDir = dir
	// Clear cached schemas so they reload from new source
	resultsSchema = nil
	baselineSchema = nil
}

// GetSchemaDir returns the current schema directory, or empty if using embedded.
func GetSchemaDir() string {
	return schemaDir
}

// SchemaType represents the type of HDF schema.
type SchemaType string

const (
	// TypeResults is the HDF results schema.
	TypeResults SchemaType = "results"
	// TypeBaseline is the HDF baseline schema.
	TypeBaseline SchemaType = "baseline"
)

// ValidationError represents a single validation error.
type ValidationError struct {
	Field       string `json:"field"`
	Description string `json:"description"`
	Value       any    `json:"value,omitempty"`
}

// ValidationResult contains the result of schema validation.
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// Error returns a formatted error string.
func (r ValidationResult) Error() string {
	if r.Valid {
		return ""
	}
	var msgs []string
	for _, e := range r.Errors {
		if e.Field != "" && e.Field != "(root)" {
			msgs = append(msgs, fmt.Sprintf("%s: %s", e.Field, e.Description))
		} else {
			msgs = append(msgs, e.Description)
		}
	}
	return strings.Join(msgs, "; ")
}

var (
	resultsSchema  *gojsonschema.Schema
	baselineSchema *gojsonschema.Schema
)

// loadSchema loads and compiles a schema from either the filesystem (if schemaDir
// is set) or from embedded schemas.
func loadSchema(filename string) (*gojsonschema.Schema, error) {
	var data []byte
	var err error
	var source string

	if schemaDir != "" {
		// Load from filesystem
		path := filepath.Join(schemaDir, filename)
		data, err = os.ReadFile(path) // #nosec G304 -- intentional for dev workflow
		if err != nil {
			return nil, fmt.Errorf("failed to read schema from %s: %w", path, err)
		}
		source = path
	} else {
		// Load from embedded filesystem
		data, err = schemaFS.ReadFile("schemas/" + filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded schema %s: %w", filename, err)
		}
		source = "embedded:" + filename
	}

	loader := gojsonschema.NewBytesLoader(data)
	schema, err := gojsonschema.NewSchema(loader)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema %s: %w", source, err)
	}

	return schema, nil
}

// getSchema returns the compiled schema for the given type.
func getSchema(schemaType SchemaType) (*gojsonschema.Schema, error) {
	switch schemaType {
	case TypeResults:
		if resultsSchema == nil {
			var err error
			resultsSchema, err = loadSchema("hdf-results.schema.json")
			if err != nil {
				return nil, err
			}
		}
		return resultsSchema, nil

	case TypeBaseline:
		if baselineSchema == nil {
			var err error
			baselineSchema, err = loadSchema("hdf-baseline.schema.json")
			if err != nil {
				return nil, err
			}
		}
		return baselineSchema, nil

	default:
		return nil, fmt.Errorf("unknown schema type: %s", schemaType)
	}
}

// Validate validates JSON data against the specified HDF schema.
func Validate(data []byte, schemaType SchemaType) ValidationResult {
	s, err := getSchema(schemaType)
	if err != nil {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{Description: err.Error()},
			},
		}
	}

	documentLoader := gojsonschema.NewBytesLoader(data)
	result, err := s.Validate(documentLoader)
	if err != nil {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{Description: fmt.Sprintf("validation error: %v", err)},
			},
		}
	}

	if result.Valid() {
		return ValidationResult{Valid: true}
	}

	// Convert errors to our format
	var errors []ValidationError
	for _, desc := range result.Errors() {
		errors = append(errors, ValidationError{
			Field:       desc.Field(),
			Description: desc.Description(),
			Value:       desc.Value(),
		})
	}

	return ValidationResult{
		Valid:  false,
		Errors: errors,
	}
}

// ValidateResults validates JSON data against the HDF results schema.
func ValidateResults(data []byte) ValidationResult {
	return Validate(data, TypeResults)
}

// ValidateBaseline validates JSON data against the HDF baseline schema.
func ValidateBaseline(data []byte) ValidationResult {
	return Validate(data, TypeBaseline)
}
