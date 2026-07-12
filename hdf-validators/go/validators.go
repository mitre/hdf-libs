// Package hdfvalidators provides JSON Schema validation for HDF files.
package hdfvalidators

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schemas/*.schema.json
var schemaFS embed.FS

// schemaMu protects schemaDir and the cached schema pointers from concurrent access.
var schemaMu sync.RWMutex

// schemaDir is an optional directory to load schemas from instead of embedded.
// When set, schemas are loaded from disk for development/testing workflows.
var schemaDir string

// SetSchemaDir configures the package to load schemas from the specified
// directory instead of using embedded schemas. Pass empty string to revert
// to embedded schemas. This also clears any cached schemas.
func SetSchemaDir(dir string) {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	schemaDir = dir
	// Reset sync.Once instances so schemas reload from new source
	schemaOnce = map[SchemaType]*sync.Once{
		TypeResults:         new(sync.Once),
		TypeBaseline:        new(sync.Once),
		TypeComparison:      new(sync.Once),
		TypeSystem:          new(sync.Once),
		TypePlan:            new(sync.Once),
		TypeAmendments:      new(sync.Once),
		TypeEvidencePackage: new(sync.Once),
	}
	schemaCache = make(map[SchemaType]*gojsonschema.Schema)
	schemaErrors = make(map[SchemaType]error)
}

// GetSchemaDir returns the current schema directory, or empty if using embedded.
func GetSchemaDir() string {
	schemaMu.RLock()
	defer schemaMu.RUnlock()
	return schemaDir
}

// SchemaBytes returns the raw JSON of the embedded (or --schema-dir override)
// schema for the given type. Exposed so callers can derive constraints from the
// single source of truth (e.g. an enum) instead of duplicating them.
func SchemaBytes(schemaType SchemaType) ([]byte, error) {
	filename, ok := schemaFiles[schemaType]
	if !ok {
		return nil, fmt.Errorf("unknown schema type %q", schemaType)
	}
	data, _, err := readSchemaData(filename)
	return data, err
}

// SchemaType represents the type of HDF schema.
type SchemaType string

const (
	// TypeResults is the HDF results schema.
	TypeResults SchemaType = "results"
	// TypeBaseline is the HDF baseline schema.
	TypeBaseline SchemaType = "baseline"
	// TypeComparison is the HDF comparison schema.
	TypeComparison SchemaType = "comparison"
	// TypeSystem is the HDF system schema.
	TypeSystem SchemaType = "system"
	// TypePlan is the HDF plan schema.
	TypePlan SchemaType = "plan"
	// TypeAmendments is the HDF amendments schema.
	TypeAmendments SchemaType = "amendments"
	// TypeEvidencePackage is the HDF evidence-package schema.
	TypeEvidencePackage SchemaType = "evidence-package"
)

// ValidationError represents a single validation error.
type ValidationError struct {
	Field       string `json:"field"`
	Description string `json:"description"`
	Value       any    `json:"value,omitempty"`
}

// ValidationResult contains the result of schema validation. It implements
// the error interface for convenience but is semantically a "result" (may
// represent a successful validation), not an error — hence the naming.
//
//nolint:errname // result type, not an error type
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

// schemaOnce ensures each schema is loaded exactly once (per SetSchemaDir cycle).
var schemaOnce = map[SchemaType]*sync.Once{
	TypeResults:         {},
	TypeBaseline:        {},
	TypeComparison:      {},
	TypeSystem:          {},
	TypePlan:            {},
	TypeAmendments:      {},
	TypeEvidencePackage: {},
}

// schemaCache stores compiled schemas keyed by type.
var schemaCache = make(map[SchemaType]*gojsonschema.Schema)

// schemaErrors stores load errors keyed by type, so subsequent callers
// see the original error instead of a generic "not loaded" message.
var schemaErrors = make(map[SchemaType]error)

// schemaFiles maps schema types to their filenames.
var schemaFiles = map[SchemaType]string{
	TypeResults:         "hdf-results.schema.json",
	TypeBaseline:        "hdf-baseline.schema.json",
	TypeComparison:      "hdf-comparison.schema.json",
	TypeSystem:          "hdf-system.schema.json",
	TypePlan:            "hdf-plan.schema.json",
	TypeAmendments:      "hdf-amendments.schema.json",
	TypeEvidencePackage: "hdf-evidence-package.schema.json",
}

// readSchemaData reads schema bytes from either the filesystem (if schemaDir
// is set) or from embedded schemas.
func readSchemaData(filename string) ([]byte, string, error) {
	schemaMu.RLock()
	dir := schemaDir
	schemaMu.RUnlock()

	if dir != "" {
		path := filepath.Join(dir, filename)
		data, err := os.ReadFile(path) // #nosec G304 -- intentional for dev workflow
		if err != nil {
			return nil, "", fmt.Errorf("failed to read schema from %s: %w", path, err)
		}
		return data, path, nil
	}
	data, err := schemaFS.ReadFile("schemas/" + filename)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read embedded schema %s: %w", filename, err)
	}
	return data, "embedded:" + filename, nil
}

// loadSchema loads and compiles a schema. Bundled schemas use JSON Schema
// 2020-12 bundling (external schemas embedded under their $id), but
// gojsonschema doesn't support this. We extract the embedded schemas and
// pre-register them so $ref URIs resolve locally.
func loadSchema(filename string) (*gojsonschema.Schema, error) {
	data, source, err := readSchemaData(filename)
	if err != nil {
		return nil, err
	}

	sl := gojsonschema.NewSchemaLoader()
	sl.Validate = false

	// Extract and register embedded schemas from the bundled document.
	// Bundled schemas appear either as top-level keys or as $defs entries,
	// keyed by their $id URI (e.g., "https://mitre.github.io/hdf-libs/schemas/primitives/...").
	var doc map[string]interface{}
	if jsonErr := json.Unmarshal(data, &doc); jsonErr == nil {
		registerEmbeddedSchemas(sl, doc)
		// Also check $defs for bundled sub-schemas
		if defs, ok := doc["$defs"].(map[string]interface{}); ok {
			registerEmbeddedSchemas(sl, defs)
		}
	}

	schema, err := sl.Compile(gojsonschema.NewBytesLoader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema %s: %w", source, err)
	}

	return schema, nil
}

// registerEmbeddedSchemas scans a map for URI-keyed sub-schemas and registers them
// with the schema loader so $ref can resolve them.
func registerEmbeddedSchemas(sl *gojsonschema.SchemaLoader, entries map[string]interface{}) {
	for key, val := range entries {
		if !strings.HasPrefix(key, "https://") {
			continue
		}
		subSchema, ok := val.(map[string]interface{})
		if !ok {
			continue
		}
		subBytes, marshalErr := json.Marshal(subSchema)
		if marshalErr != nil {
			continue
		}
		_ = sl.AddSchemas(gojsonschema.NewBytesLoader(subBytes))
	}
}

// getSchema returns the compiled schema for the given type.
// Thread-safe: uses sync.Once per schema type to ensure single initialization.
func getSchema(schemaType SchemaType) (*gojsonschema.Schema, error) {
	schemaMu.RLock()
	once, ok := schemaOnce[schemaType]
	schemaMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown schema type: %s", schemaType)
	}

	once.Do(func() {
		filename, exists := schemaFiles[schemaType]
		if !exists {
			schemaMu.Lock()
			schemaErrors[schemaType] = fmt.Errorf("no filename for schema type: %s", schemaType)
			schemaMu.Unlock()
			return
		}
		schema, err := loadSchema(filename)
		if err != nil {
			schemaMu.Lock()
			schemaErrors[schemaType] = err
			schemaMu.Unlock()
			return
		}
		schemaMu.Lock()
		schemaCache[schemaType] = schema
		schemaMu.Unlock()
	})

	schemaMu.RLock()
	s := schemaCache[schemaType]
	e := schemaErrors[schemaType]
	schemaMu.RUnlock()

	if e != nil {
		return nil, e
	}
	if s == nil {
		return nil, fmt.Errorf("schema %s not loaded", schemaType)
	}

	return s, nil
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

// ValidateComparison validates JSON data against the HDF comparison schema.
func ValidateComparison(data []byte) ValidationResult {
	return Validate(data, TypeComparison)
}

// ValidateSystem validates JSON data against the HDF system schema.
func ValidateSystem(data []byte) ValidationResult {
	return Validate(data, TypeSystem)
}

// ValidatePlan validates JSON data against the HDF plan schema.
func ValidatePlan(data []byte) ValidationResult {
	return Validate(data, TypePlan)
}

// ValidateAmendments validates JSON data against the HDF amendments schema.
func ValidateAmendments(data []byte) ValidationResult {
	return Validate(data, TypeAmendments)
}

// ValidateEvidencePackage validates JSON data against the HDF evidence-package schema.
func ValidateEvidencePackage(data []byte) ValidationResult {
	return Validate(data, TypeEvidencePackage)
}
