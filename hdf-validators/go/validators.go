// Package hdfvalidators provides JSON Schema validation for HDF files.
package hdfvalidators

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
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
	schemaCache = make(map[SchemaType]*cachedSchema)
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
	data, _, err := readSchemaData(filename, GetSchemaDir())
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
	// TypeRequirementChangeEvent is the HDF requirement-change-event schema.
	TypeRequirementChangeEvent SchemaType = "requirement-change-event"
)

// ValidationError represents a single validation error.
type ValidationError struct {
	Field       string `json:"field"`
	Description string `json:"description"`
	Value       any    `json:"value,omitempty"`
	// Keyword names the kind of violation ("invalid_type", "required",
	// "format", ...). Surfaced so a caller can act on the KIND: the converters
	// reject a wrongly-typed field without rejecting a merely sparse document.
	Keyword string `json:"keyword,omitempty"`
	// Format is the expected format when Keyword is "format".
	Format string `json:"format,omitempty"`
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

// Each cache entry belongs to one SetSchemaDir generation. In-flight callers
// retain their entry after a reset and cannot publish into the new generation.
type cachedSchema struct {
	once   sync.Once
	schema *jsonschema.Schema
	err    error
}

var schemaCache = make(map[SchemaType]*cachedSchema)

// schemaFiles maps schema types to their filenames.
var schemaFiles = map[SchemaType]string{
	TypeResults:                "hdf-results.schema.json",
	TypeBaseline:               "hdf-baseline.schema.json",
	TypeComparison:             "hdf-comparison.schema.json",
	TypeSystem:                 "hdf-system.schema.json",
	TypePlan:                   "hdf-plan.schema.json",
	TypeAmendments:             "hdf-amendments.schema.json",
	TypeEvidencePackage:        "hdf-evidence-package.schema.json",
	TypeRequirementChangeEvent: "hdf-requirement-change-event.schema.json",
}

// readSchemaData reads schema bytes from either the filesystem (if schemaDir
// is set) or from embedded schemas.
func readSchemaData(filename, dir string) ([]byte, string, error) {
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

type offlineSchemaLoader struct{}

func (offlineSchemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("schema reference %q is not bundled; external loading is disabled", url)
}

func loadSchema(filename, dir string) (*jsonschema.Schema, error) {
	data, source, err := readSchemaData(filename, dir)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse schema %s: %w", source, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(offlineSchemaLoader{})
	compiler.AssertFormat()
	registerModernFormats(compiler)
	resource := "https://hdf.invalid/" + filename
	if err := compiler.AddResource(resource, doc); err != nil {
		return nil, fmt.Errorf("failed to register schema %s: %w", source, err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema %s: %w", source, err)
	}
	return schema, nil
}

// getSchema compiles lazily, once per type and schema-directory generation.
func getSchema(schemaType SchemaType) (*jsonschema.Schema, error) {
	filename, ok := schemaFiles[schemaType]
	if !ok {
		return nil, fmt.Errorf("unknown schema type: %s", schemaType)
	}
	schemaMu.Lock()
	dir := schemaDir
	entry := schemaCache[schemaType]
	if entry == nil {
		entry = &cachedSchema{}
		schemaCache[schemaType] = entry
	}
	schemaMu.Unlock()
	entry.once.Do(func() {
		entry.schema, entry.err = loadSchema(filename, dir)
	})
	return entry.schema, entry.err
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

	document, err := decodeDocument(data)
	if err != nil {
		return ValidationResult{Errors: []ValidationError{{Description: fmt.Sprintf("validation error: %v", err)}}}
	}
	err = s.Validate(document)
	if err == nil {
		return ValidationResult{Valid: true}
	}
	var failure *jsonschema.ValidationError
	if !errors.As(err, &failure) {
		return ValidationResult{Errors: []ValidationError{{Description: fmt.Sprintf("validation error: %v", err)}}}
	}
	return ValidationResult{Errors: modernValidationErrors(failure, document)}
}

// Keep JSON syntax diagnostics stable across schema-engine changes, without
// losing numeric precision or accepting bytes after the first JSON value.
func decodeDocument(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("unexpected trailing data after end of JSON value")
	}
	return document, nil
}

func modernValidationErrors(failure *jsonschema.ValidationError, document any) []ValidationError {
	var result []ValidationError
	if len(failure.Causes) != 0 {
		for _, cause := range failure.Causes {
			result = append(result, modernValidationErrors(cause, document)...)
		}
		return result
	}
	field := strings.Join(failure.InstanceLocation, ".")
	if field == "" {
		field = "(root)"
	}
	item := ValidationError{
		Field:       field,
		Description: failure.ErrorKind.LocalizedString(message.NewPrinter(language.English)),
		Value:       instanceValue(document, failure.InstanceLocation),
	}
	path := failure.ErrorKind.KeywordPath()
	if len(path) != 0 {
		item.Keyword = path[0]
	}
	switch k := failure.ErrorKind.(type) {
	case *kind.Required:
		for _, property := range k.Missing {
			missing := item
			missing.Description = property + " is required"
			result = append(result, missing)
		}
		return result
	case *kind.Type:
		item.Keyword = "invalid_type"
	case *kind.Format:
		item.Format = k.Want
	case *kind.FalseSchema:
		item.Keyword = "false"
		if strings.HasSuffix(failure.SchemaURL, "/unevaluatedProperties") {
			item.Keyword = "unevaluatedProperties"
			item.Description = "is not allowed"
		}
	}
	return append(result, item)
}

func instanceValue(document any, path []string) any {
	value := document
	for _, token := range path {
		switch current := value.(type) {
		case map[string]any:
			value = current[token]
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(current) {
				return nil
			}
			value = current[index]
		default:
			return nil
		}
	}
	return value
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

// ValidateRequirementChangeEvent validates JSON data against the HDF
// requirement-change-event schema (one continuous-monitoring wire event).
func ValidateRequirementChangeEvent(data []byte) ValidationResult {
	return Validate(data, TypeRequirementChangeEvent)
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
