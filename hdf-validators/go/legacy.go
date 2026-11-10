package hdfvalidators

import (
	_ "embed"
	"fmt"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

// legacyV2SchemaBytes is the pinned HDF v2 (Heimdall/InSpec exec-json) schema.
// Sourced from heimdall2 libs/inspecjs/schemas/exec-json.json; see
// legacy/PROVENANCE.md. Kept out of the build:schemas-synced schemas/ dir so it
// is never clobbered, and out of hdf-schema/src/schemas / the docs site.
//
//go:embed legacy/exec-json.schema.json
var legacyV2SchemaBytes []byte

var (
	legacyV2Once   sync.Once
	legacyV2Schema *gojsonschema.Schema
	errLegacyV2    error
)

func legacyV2Compiled() (*gojsonschema.Schema, error) {
	legacyV2Once.Do(func() {
		legacyV2Schema, errLegacyV2 = gojsonschema.NewSchema(gojsonschema.NewBytesLoader(legacyV2SchemaBytes))
	})
	return legacyV2Schema, errLegacyV2
}

// LegacyV2SchemaBytes returns the raw pinned v2 schema JSON.
func LegacyV2SchemaBytes() []byte {
	return legacyV2SchemaBytes
}

// ValidateLegacyV2 validates a legacy HDF v2 document — the Heimdall/InSpec
// exec-json shape (profiles[] + platform) that SAF converters emit — against the
// pinned exec-json schema, retaining gojsonschema and field-level error mapping.
// The schema's permissiveness is Heimdall's, not tightened here.
func ValidateLegacyV2(data []byte) ValidationResult {
	schema, err := legacyV2Compiled()
	if err != nil {
		return ValidationResult{Valid: false, Errors: []ValidationError{{Description: err.Error()}}}
	}

	result, err := schema.Validate(gojsonschema.NewBytesLoader(data))
	if err != nil {
		return ValidationResult{Valid: false, Errors: []ValidationError{{Description: fmt.Sprintf("validation error: %v", err)}}}
	}
	if result.Valid() {
		return ValidationResult{Valid: true}
	}

	errors := make([]ValidationError, 0, len(result.Errors()))
	for _, desc := range result.Errors() {
		errors = append(errors, ValidationError{
			Field:       desc.Field(),
			Description: desc.Description(),
			Keyword:     desc.Type(),
			Format:      formatName(desc),
			Value:       desc.Value(),
		})
	}
	return ValidationResult{Valid: false, Errors: errors}
}

// formatName reports the expected format for a failed "format" assertion, and
// empty for every other violation. gojsonschema carries it in the error details
// rather than on the error type.
func formatName(desc gojsonschema.ResultError) string {
	if desc.Type() != "format" {
		return ""
	}
	if f, ok := desc.Details()["format"]; ok {
		return fmt.Sprintf("%v", f)
	}
	return ""
}
