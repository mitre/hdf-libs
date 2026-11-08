package hdfvalidators

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type conformanceCase struct {
	Name       string         `json:"name"`
	Type       SchemaType     `json:"type"`
	Document   string         `json:"document"`
	Path       []any          `json:"path"`
	Properties map[string]any `json:"properties"`
	Valid      bool           `json:"valid"`
	Keyword    string         `json:"keyword"`
	Field      string         `json:"field"`
}

func TestModernErrorContract(t *testing.T) {
	for _, tc := range []struct {
		name, property, keyword, format string
		value                           any
	}{
		{"wrong type", "impact", "invalid_type", "", "high"},
		{"null type", "impact", "invalid_type", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := documentWithProperties(t, resultsWith(""), []any{"baselines", float64(0), "requirements", float64(0)}, map[string]any{tc.property: tc.value})
			result := ValidateResults(data)
			require.False(t, result.Valid)
			var found bool
			for _, e := range result.Errors {
				if e.Field == "baselines.0.requirements.0."+tc.property && e.Keyword == tc.keyword {
					found = true
					assert.Equal(t, tc.value, e.Value)
					assert.Equal(t, tc.format, e.Format)
				}
			}
			assert.True(t, found, "%+v", result.Errors)
		})
	}
	data := formatCaseDocument(t, shippedFormatCase{Field: "startTime", Value: "not-a-time"})
	result := ValidateResults(data)
	require.False(t, result.Valid)
	require.Len(t, result.Errors, 1)
	assert.Equal(t, "baselines.0.requirements.0.results.0.startTime", result.Errors[0].Field)
	assert.Equal(t, "format", result.Errors[0].Keyword)
	assert.Equal(t, "date-time", result.Errors[0].Format)
	assert.Equal(t, "not-a-time", result.Errors[0].Value)
	result = ValidateResults(formatCaseDocument(t, shippedFormatCase{Field: "componentId", Value: "not-a-uuid"}))
	require.False(t, result.Valid)
	var found bool
	for _, e := range result.Errors {
		if e.Field == "components.0.componentId" && e.Keyword == "format" {
			found = true
			assert.Equal(t, "uuid", e.Format)
			assert.Equal(t, "not-a-uuid", e.Value)
		}
	}
	assert.True(t, found, "%+v", result.Errors)
}

func TestDateTimeBoundaryValidation(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"2024-02-29T00:00:00Z", true},
		{"2025-02-29T00:00:00Z", false},
		{"2025-00-01T00:00:00Z", false},
		{"2025-01-00T00:00:00Z", false},
		{"2025-1-01T00:00:00Z", false},
		{"2025-01-01T24:00:00Z", false},
		{"2025-01-01T00:00:61Z", false},
		{"2016-12-31T18:59:60-05:00", true},
		{"2017-01-01T00:29:60+00:30", true},
		{"2025-01-01T00:00:00+24:00", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			result := ValidateResults(formatCaseDocument(t, shippedFormatCase{Field: "startTime", Value: tc.value}))
			assert.Equal(t, tc.valid, result.Valid, "%s", result.Error())
		})
	}
}

func TestLegacyValidationRemainsIndependent(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "legacy", "testdata", "inspec-exec-json-valid.json"))
	require.NoError(t, err)
	SetSchemaDir(t.TempDir())
	t.Cleanup(func() { SetSchemaDir("") })
	assert.True(t, ValidateLegacyV2(data).Valid, "modern schema overrides must not affect legacy validation")
	assert.False(t, ValidateLegacyV2([]byte(`{`)).Valid)
	var schema map[string]any
	require.NoError(t, json.Unmarshal(LegacyV2SchemaBytes(), &schema))
	assert.Contains(t, schema, "properties")
}

func TestSchemaLoadErrorsAndReset(t *testing.T) {
	dir := t.TempDir()
	SetSchemaDir(dir)
	t.Cleanup(func() { SetSchemaDir("") })
	filename := filepath.Join(dir, "hdf-results.schema.json")
	missing := ValidateResults([]byte(`{}`))
	require.False(t, missing.Valid)
	assert.Contains(t, missing.Error(), "failed to read schema")
	require.NoError(t, os.WriteFile(filename, []byte(`true`), 0600))
	assert.Equal(t, missing, ValidateResults([]byte(`{}`)), "load errors are cached until reset")
	SetSchemaDir(dir)
	assert.True(t, ValidateResults([]byte(`{}`)).Valid)
	for _, tc := range []struct{ name, schema, message string }{
		{"malformed", `{`, "failed to parse schema"},
		{"invalid schema", `{"type":123}`, "failed to compile schema"},
		{"remote reference", `{"$ref":"https://example.invalid/schema.json"}`, "external loading is disabled"},
		{"local reference", `{"$ref":"file:///nonexistent/schema.json"}`, "external loading is disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(filename, []byte(tc.schema), 0600))
			SetSchemaDir(dir)
			result := ValidateResults([]byte(`{}`))
			require.False(t, result.Valid)
			assert.Contains(t, result.Error(), tc.message)
			assert.Equal(t, result, ValidateResults([]byte(`{}`)))
		})
	}
	SetSchemaDir("")
	assert.True(t, ValidateResults(resultsWith(`"impact":0.5`)).Valid)
}

func TestMalformedInputAndUnknownSchema(t *testing.T) {
	for _, input := range []string{"", "{", "{} {}", "null", "[]"} {
		t.Run(input, func(t *testing.T) {
			result := ValidateResults([]byte(input))
			assert.False(t, result.Valid)
			assert.NotEmpty(t, result.Error())
		})
	}
	result := Validate([]byte(`{}`), SchemaType("unknown"))
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "unknown schema type")
}

func TestSchemaBytesSources(t *testing.T) {
	for schemaType := range schemaFiles {
		data, err := SchemaBytes(schemaType)
		require.NoError(t, err)
		assert.True(t, json.Valid(data))
	}
	_, err := SchemaBytes(SchemaType("unknown"))
	require.ErrorContains(t, err, "unknown schema type")
	dir := t.TempDir()
	SetSchemaDir(dir)
	t.Cleanup(func() { SetSchemaDir("") })
	_, err = SchemaBytes(TypeResults)
	require.ErrorContains(t, err, "failed to read schema")
	custom := []byte(`{"type":"object"}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hdf-results.schema.json"), custom, 0600))
	got, err := SchemaBytes(TypeResults)
	require.NoError(t, err)
	assert.Equal(t, custom, got)
}

func TestConcurrentSchemaReset(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hdf-results.schema.json"), []byte(`true`), 0600))
	SetSchemaDir(dir)
	t.Cleanup(func() { SetSchemaDir("") })
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				SetSchemaDir(dir)
				result := ValidateResults([]byte(`{}`))
				if !result.Valid {
					t.Errorf("concurrent reset lost a valid schema: %s", result.Error())
					return
				}
			}
		})
	}
	workers.Wait()
}

func TestShippedSchemaConformance(t *testing.T) {
	t.Run("embedded", runShippedSchemaConformance)
	t.Run("directory override", func(t *testing.T) {
		_, file, _, ok := runtime.Caller(0)
		require.True(t, ok)
		SetSchemaDir(filepath.Join(filepath.Dir(file), "..", "..", "hdf-schema", "dist", "schemas"))
		t.Cleanup(func() { SetSchemaDir("") })
		runShippedSchemaConformance(t)
	})
}

func runShippedSchemaConformance(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "testdata", "shipped-schema-conformance-cases.json"))
	require.NoError(t, err)
	var table struct {
		Documents map[string]json.RawMessage `json:"documents"`
		Cases     []conformanceCase          `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)
	validators := map[SchemaType]func([]byte) ValidationResult{
		TypeResults: ValidateResults, TypeBaseline: ValidateBaseline,
		TypeSystem: ValidateSystem, TypePlan: ValidatePlan,
		TypeAmendments: ValidateAmendments, TypeComparison: ValidateComparison,
		TypeEvidencePackage:        ValidateEvidencePackage,
		TypeRequirementChangeEvent: ValidateRequirementChangeEvent,
	}
	covered := map[SchemaType]bool{}
	for _, tc := range table.Cases {
		covered[tc.Type] = true
		t.Run(tc.Name, func(t *testing.T) {
			source, exists := table.Documents[tc.Document]
			require.True(t, exists)
			data := documentWithProperties(t, source, tc.Path, tc.Properties)
			before := append([]byte(nil), data...)
			validate, exists := validators[tc.Type]
			require.True(t, exists)
			result := validate(data)
			require.Equal(t, tc.Valid, result.Valid, "%s", result.Error())
			assert.Equal(t, before, data)
			if !tc.Valid {
				found := false
				for _, e := range result.Errors {
					if e.Field == tc.Field && e.Keyword == tc.Keyword {
						found = true
					}
				}
				assert.True(t, found, "expected %s at %s, got %+v", tc.Keyword, tc.Field, result.Errors)
				assert.Contains(t, result.Error(), tc.Field)
			}
		})
	}
	require.Len(t, covered, len(validators))
}

func documentWithProperties(t *testing.T, source []byte, path []any, properties map[string]any) []byte {
	t.Helper()
	var doc any
	require.NoError(t, json.Unmarshal(source, &doc))
	target := doc
	for _, key := range path {
		switch k := key.(type) {
		case string:
			obj, isObject := target.(map[string]any)
			require.True(t, isObject)
			target = obj[k]
		case float64:
			items, isArray := target.([]any)
			require.True(t, isArray)
			require.Greater(t, len(items), int(k))
			target = items[int(k)]
		default:
			t.Fatalf("unsupported path token %v", key)
		}
	}
	obj, isObject := target.(map[string]any)
	require.True(t, isObject)
	for key, value := range properties {
		obj[key] = value
	}
	data, marshalErr := json.Marshal(doc)
	require.NoError(t, marshalErr)
	return data
}
