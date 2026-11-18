// Package hdfvalidators provides JSON Schema validation for HDF files.
package hdfvalidators

import (
	"bytes"
	"cmp"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
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

// modernValidationErrors flattens a tekuri error tree into one entry per
// violation, deduplicated and sorted so repeated runs report the same list.
func modernValidationErrors(failure *jsonschema.ValidationError, document any) []ValidationError {
	result := dedupeErrors(flattenErrors(failure, document))
	slices.SortFunc(result, compareErrors)
	return result
}

func flattenErrors(failure *jsonschema.ValidationError, document any) []ValidationError {
	var result []ValidationError
	if len(failure.Causes) != 0 {
		switch failure.ErrorKind.(type) {
		case *kind.AnyOf, *kind.OneOf:
			result = matchedBranchErrors(failure, document)
		case *kind.Contains:
			result = causeErrors(failure, document)
		default:
			return causeErrors(failure, document)
		}
	}
	field := strings.Join(failure.InstanceLocation, ".")
	if field == "" {
		field = "(root)"
	}
	item := ValidationError{
		Field:       field,
		Keyword:     keywordFor(failure.ErrorKind),
		Description: describe(failure.ErrorKind),
		Value:       instanceValue(document, failure.InstanceLocation),
	}
	switch k := failure.ErrorKind.(type) {
	case *kind.AdditionalProperties:
		hint := ""
		if strings.HasSuffix(failure.SchemaURL, "/$defs/Extensions") {
			hint = ". Move producer-specific data under extensions.passthrough, namespaced by tool name."
		}
		for _, property := range k.Properties {
			extra := item
			extra.Field = childField(field, property)
			extra.Description = "is not allowed" + hint
			result = append(result, extra)
		}
		return result
	case *kind.Required:
		for _, property := range k.Missing {
			missing := item
			missing.Description = property + " is required"
			result = append(result, missing)
		}
		return result
	case *kind.Format:
		item.Format = k.Want
	case *kind.FalseSchema:
		if strings.HasSuffix(failure.SchemaURL, "/unevaluatedProperties") {
			item.Keyword = "unevaluatedProperties"
			item.Description = "is not allowed"
		}
	}
	return append(result, item)
}

func causeErrors(failure *jsonschema.ValidationError, document any) []ValidationError {
	var result []ValidationError
	for _, cause := range failure.Causes {
		result = append(result, flattenErrors(cause, document)...)
	}
	return result
}

// matchedBranchErrors drops the branches of a oneOf/anyOf that failed a const
// on a direct child of the instance (a discriminator such as components[].type)
// when another branch got past that check; with no such branch, every one stays.
func matchedBranchErrors(failure *jsonschema.ValidationError, document any) []ValidationError {
	var matched, missed []ValidationError
	for _, cause := range failure.Causes {
		branch := flattenErrors(cause, document)
		if missesDiscriminator(cause, len(failure.InstanceLocation)+1) {
			missed = append(missed, branch...)
		} else {
			matched = append(matched, branch...)
		}
	}
	if len(matched) == 0 {
		return missed
	}
	return matched
}

func missesDiscriminator(failure *jsonschema.ValidationError, depth int) bool {
	if _, ok := failure.ErrorKind.(*kind.Const); ok && len(failure.InstanceLocation) == depth {
		return true
	}
	for _, cause := range failure.Causes {
		if missesDiscriminator(cause, depth) {
			return true
		}
	}
	return false
}

func childField(parent, property string) string {
	if parent == "(root)" {
		return property
	}
	return parent + "." + property
}

func dedupeErrors(errs []ValidationError) []ValidationError {
	type identity struct{ field, keyword, description string }
	seen := make(map[identity]bool, len(errs))
	kept := errs[:0]
	for _, e := range errs {
		id := identity{e.Field, e.Keyword, e.Description}
		if seen[id] {
			continue
		}
		seen[id] = true
		kept = append(kept, e)
	}
	return kept
}

// compareErrors orders by instance path (array indexes numerically, a parent
// before its children), then keyword, then description.
func compareErrors(a, b ValidationError) int {
	as, bs := pathSegments(a.Field), pathSegments(b.Field)
	for i := range min(len(as), len(bs)) {
		if c := compareSegments(as[i], bs[i]); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(len(as), len(bs)); c != 0 {
		return c
	}
	if c := strings.Compare(a.Keyword, b.Keyword); c != 0 {
		return c
	}
	return strings.Compare(a.Description, b.Description)
}

func pathSegments(field string) []string {
	if field == "(root)" {
		return nil
	}
	return strings.Split(field, ".")
}

func compareSegments(a, b string) int {
	ai, aErr := strconv.Atoi(a)
	bi, bErr := strconv.Atoi(b)
	if aErr == nil && bErr == nil {
		return cmp.Compare(ai, bi)
	}
	return strings.Compare(a, b)
}

// describe formats the counting kinds with fmt, so their numbers are not
// digit-grouped the way the x/text printer renders them ("got 70,000").
func describe(k jsonschema.ErrorKind) string {
	switch k := k.(type) {
	case *kind.MinLength:
		return limit("minLength", k.Got, k.Want)
	case *kind.MaxLength:
		return limit("maxLength", k.Got, k.Want)
	case *kind.MinItems:
		return limit("minItems", k.Got, k.Want)
	case *kind.MaxItems:
		return limit("maxItems", k.Got, k.Want)
	case *kind.MinProperties:
		return limit("minProperties", k.Got, k.Want)
	case *kind.MaxProperties:
		return limit("maxProperties", k.Got, k.Want)
	case *kind.Minimum:
		return bound("minimum", k.Got, k.Want)
	case *kind.Maximum:
		return bound("maximum", k.Got, k.Want)
	case *kind.ExclusiveMinimum:
		return bound("exclusiveMinimum", k.Got, k.Want)
	case *kind.ExclusiveMaximum:
		return bound("exclusiveMaximum", k.Got, k.Want)
	case *kind.MultipleOf:
		return bound("multipleOf", k.Got, k.Want)
	case *kind.AdditionalItems:
		return fmt.Sprintf("last %d additionalItem(s) not allowed", k.Count)
	case *kind.UniqueItems:
		return fmt.Sprintf("items at %d and %d are equal", k.Duplicates[0], k.Duplicates[1])
	case *kind.MinContains:
		if len(k.Got) == 0 {
			return fmt.Sprintf("min %d items required to match contains schema, but none matched", k.Want)
		}
		return fmt.Sprintf("min %d items required to match contains schema, but matched %d items at %s",
			k.Want, len(k.Got), indexList(k.Got))
	case *kind.MaxContains:
		return fmt.Sprintf("max %d items required to match contains schema, but matched %d items at %s",
			k.Want, len(k.Got), indexList(k.Got))
	}
	return k.LocalizedString(message.NewPrinter(language.English))
}

func limit(name string, got, want int) string {
	return fmt.Sprintf("%s: got %d, want %d", name, got, want)
}

func bound(name string, got, want *big.Rat) string {
	gotFloat, _ := got.Float64()
	wantFloat, _ := want.Float64()
	return fmt.Sprintf("%s: got %v, want %v", name, gotFloat, wantFloat)
}

func indexList(indexes []int) string {
	return strings.Trim(fmt.Sprint(indexes), "[]")
}

// keywordFor names the kinds whose KeywordPath is nil, and renames Type to the
// "invalid_type" the converters already act on.
func keywordFor(k jsonschema.ErrorKind) string {
	switch k.(type) {
	case *kind.Type, *kind.InvalidJsonValue:
		return "invalid_type"
	case *kind.FalseSchema:
		return "false"
	case *kind.Not:
		return "not"
	case *kind.Group:
		return "group"
	case *kind.Schema:
		return "schema"
	case *kind.RefCycle:
		return "$ref"
	}
	if path := k.KeywordPath(); len(path) != 0 {
		return path[0]
	}
	return ""
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
