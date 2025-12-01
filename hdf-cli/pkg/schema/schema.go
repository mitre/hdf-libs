// Package schema provides JSON Schema validation for HDF files.
package schema

import (
	"embed"
	"fmt"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schemas/*.schema.json
var schemaFS embed.FS

// Type represents the type of HDF schema.
type Type string

const (
	// TypeResults is the HDF results schema.
	TypeResults Type = "results"
	// TypeBaseline is the HDF baseline schema.
	TypeBaseline Type = "baseline"
)

// ValidationError represents a single validation error.
type ValidationError struct {
	Field       string `json:"field"`
	Description string `json:"description"`
	Value       any    `json:"value,omitempty"`
}

// Result contains the result of schema validation.
// It implements the error interface for convenience but is not strictly an error type.
//
//nolint:errname // Result is not an error type, it contains validation results
type Result struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// Error returns a formatted error string.
func (r Result) Error() string {
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

// loadSchema loads and compiles a schema from the embedded filesystem.
func loadSchema(filename string) (*gojsonschema.Schema, error) {
	data, err := schemaFS.ReadFile("schemas/" + filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded schema %s: %w", filename, err)
	}

	loader := gojsonschema.NewBytesLoader(data)
	schema, err := gojsonschema.NewSchema(loader)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema %s: %w", filename, err)
	}

	return schema, nil
}

// getSchema returns the compiled schema for the given type.
func getSchema(schemaType Type) (*gojsonschema.Schema, error) {
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
func Validate(data []byte, schemaType Type) Result {
	s, err := getSchema(schemaType)
	if err != nil {
		return Result{
			Valid: false,
			Errors: []ValidationError{
				{Description: err.Error()},
			},
		}
	}

	documentLoader := gojsonschema.NewBytesLoader(data)
	result, err := s.Validate(documentLoader)
	if err != nil {
		return Result{
			Valid: false,
			Errors: []ValidationError{
				{Description: fmt.Sprintf("validation error: %v", err)},
			},
		}
	}

	if result.Valid() {
		return Result{Valid: true}
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

	return Result{
		Valid:  false,
		Errors: errors,
	}
}

// ValidateResults validates JSON data against the HDF results schema.
func ValidateResults(data []byte) Result {
	return Validate(data, TypeResults)
}

// ValidateBaseline validates JSON data against the HDF baseline schema.
func ValidateBaseline(data []byte) Result {
	return Validate(data, TypeBaseline)
}
