package hdfvalidators

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resultsWithComponent(t *testing.T, component map[string]any) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(resultsWith(""), &doc))
	doc["components"] = []any{component}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	return data
}

func fieldsOf(errs []ValidationError) []string {
	fields := make([]string, 0, len(errs))
	for _, e := range errs {
		fields = append(fields, e.Field)
	}
	return fields
}

func TestValidateResults_ErrorOrderIsStable(t *testing.T) {
	doc := []byte(`{"baselines":1,"components":"x","statistics":[]}`)
	want := []string{"baselines", "components", "statistics"}
	for range 30 {
		result := ValidateResults(doc)
		require.False(t, result.Valid)
		require.Equal(t, want, fieldsOf(result.Errors))
		assert.Equal(t, "invalid_type", result.Errors[0].Keyword)
	}
}

func TestCompareErrorsOrdersPathsNumerically(t *testing.T) {
	ordered := []ValidationError{
		{Field: "(root)", Keyword: "required"},
		{Field: "components.2.name", Keyword: "invalid_type"},
		{Field: "components.10", Keyword: "oneOf"},
		{Field: "components.10.type", Keyword: "const", Description: "value must be 'host'"},
		{Field: "components.10.type", Keyword: "const", Description: "value must be 'network'"},
		{Field: "components.10.type", Keyword: "enum"},
	}
	for i := 1; i < len(ordered); i++ {
		assert.Negative(t, compareErrors(ordered[i-1], ordered[i]), "%d", i)
		assert.Positive(t, compareErrors(ordered[i], ordered[i-1]), "%d", i)
	}
	assert.Zero(t, compareErrors(ordered[0], ordered[0]))
}

func TestValidateResults_OneOfReportsOnlyTheMatchingBranch(t *testing.T) {
	t.Run("host with a malformed componentId", func(t *testing.T) {
		result := ValidateResults(resultsWithComponent(t, map[string]any{"name": "n", "type": "host", "componentId": "not-a-uuid"}))
		require.False(t, result.Valid)
		assert.Equal(t, []ValidationError{
			{Field: "components.0", Keyword: "oneOf", Description: "'oneOf' failed, none matched", Value: map[string]any{"name": "n", "type": "host", "componentId": "not-a-uuid"}},
			{Field: "components.0.componentId", Keyword: "format", Format: "uuid", Description: "'not-a-uuid' is not valid uuid: invalid uuid", Value: "not-a-uuid"},
		}, result.Errors)
	})
	t.Run("database port above the maximum", func(t *testing.T) {
		result := ValidateResults(resultsWithComponent(t, map[string]any{"name": "n", "type": "database", "port": 70000}))
		require.False(t, result.Valid)
		require.Len(t, result.Errors, 2)
		assert.Equal(t, "components.0.port", result.Errors[1].Field)
		assert.Equal(t, "maximum", result.Errors[1].Keyword)
		assert.Equal(t, "maximum: got 70000, want 65535", result.Errors[1].Description)
	})
	t.Run("unknown type keeps every branch once", func(t *testing.T) {
		result := ValidateResults(resultsWithComponent(t, map[string]any{"name": "n", "type": "spaceship"}))
		require.False(t, result.Valid)
		seen := map[ValidationError]int{}
		enums := 0
		for _, e := range result.Errors {
			e.Value = nil
			seen[e]++
			if e.Keyword == "enum" {
				enums++
			}
		}
		assert.Equal(t, 1, enums)
		for e, n := range seen {
			assert.Equal(t, 1, n, "%+v", e)
		}
		assert.Len(t, result.Errors, 15)
	})
}

func TestValidateResults_ClosedObjectsReportEachUndeclaredKey(t *testing.T) {
	t.Run("raw source record", func(t *testing.T) {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(resultsWith(""), &doc))
		baseline := doc["baselines"].([]any)[0].(map[string]any)
		requirement := baseline["requirements"].([]any)[0].(map[string]any)
		resultDoc := requirement["results"].([]any)[0].(map[string]any)
		record := map[string]any{"content": "{}", "encoding": "utf-8", "mediaType": "application/json", "system_context": map[string]any{}, "alpha": true}
		resultDoc["rawSourceRecord"] = record
		data, err := json.Marshal(doc)
		require.NoError(t, err)
		result := ValidateResults(data)
		require.False(t, result.Valid)
		const parent = "baselines.0.requirements.0.results.0.rawSourceRecord."
		assert.Equal(t, []ValidationError{
			{Field: parent + "alpha", Keyword: "additionalProperties", Description: "is not allowed", Value: record},
			{Field: parent + "system_context", Keyword: "additionalProperties", Description: "is not allowed", Value: record},
		}, result.Errors)
	})
	t.Run("bom", func(t *testing.T) {
		bom := map[string]any{"bomType": "sbom", "format": "cyclonedx", "ref": "sbom.cdx.json", "vendorTag": true}
		result := ValidateResults(resultsWithComponent(t, map[string]any{"name": "n", "type": "host", "boms": []any{bom}}))
		require.False(t, result.Valid)
		assert.Equal(t, []ValidationError{
			{Field: "components.0", Keyword: "oneOf", Description: "'oneOf' failed, none matched", Value: map[string]any{"name": "n", "type": "host", "boms": []any{bom}}},
			{Field: "components.0.boms.0.vendorTag", Keyword: "additionalProperties", Description: "is not allowed", Value: bom},
		}, result.Errors)
	})
}

func TestDescribeFormatsCountsWithoutGrouping(t *testing.T) {
	rat := func(n int64) *big.Rat { return big.NewRat(n, 1) }
	for _, tc := range []struct {
		kind jsonschema.ErrorKind
		want string
	}{
		{&kind.MaxLength{Got: 70000, Want: 65536}, "maxLength: got 70000, want 65536"},
		{&kind.MinLength{Got: 1000, Want: 2000}, "minLength: got 1000, want 2000"},
		{&kind.MinItems{Got: 1000, Want: 2000}, "minItems: got 1000, want 2000"},
		{&kind.MaxItems{Got: 2000, Want: 1000}, "maxItems: got 2000, want 1000"},
		{&kind.MinProperties{Got: 1000, Want: 2000}, "minProperties: got 1000, want 2000"},
		{&kind.MaxProperties{Got: 2000, Want: 1000}, "maxProperties: got 2000, want 1000"},
		{&kind.Minimum{Got: rat(1000), Want: rat(2000)}, "minimum: got 1000, want 2000"},
		{&kind.Maximum{Got: rat(70000), Want: rat(65535)}, "maximum: got 70000, want 65535"},
		{&kind.ExclusiveMinimum{Got: rat(1000), Want: rat(2000)}, "exclusiveMinimum: got 1000, want 2000"},
		{&kind.ExclusiveMaximum{Got: rat(2000), Want: rat(1000)}, "exclusiveMaximum: got 2000, want 1000"},
		{&kind.MultipleOf{Got: rat(1001), Want: rat(1000)}, "multipleOf: got 1001, want 1000"},
		{&kind.AdditionalItems{Count: 1000}, "last 1000 additionalItem(s) not allowed"},
		{&kind.UniqueItems{Duplicates: [2]int{1000, 2000}}, "items at 1000 and 2000 are equal"},
		{&kind.MinContains{Got: nil, Want: 1000}, "min 1000 items required to match contains schema, but none matched"},
		{&kind.MinContains{Got: []int{1000, 2000}, Want: 3000}, "min 3000 items required to match contains schema, but matched 2 items at 1000 2000"},
		{&kind.MaxContains{Got: []int{1000, 2000}, Want: 1}, "max 1 items required to match contains schema, but matched 2 items at 1000 2000"},
		{&kind.Not{}, "'not' failed"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, describe(tc.kind))
		})
	}
}

func TestKeywordForNamesEveryKind(t *testing.T) {
	for _, tc := range []struct {
		kind jsonschema.ErrorKind
		want string
	}{
		{&kind.Not{}, "not"},
		{&kind.Group{}, "group"},
		{&kind.Schema{Location: "x"}, "schema"},
		{&kind.RefCycle{}, "$ref"},
		{&kind.Type{}, "invalid_type"},
		{&kind.FalseSchema{}, "false"},
		{&kind.Format{Want: "uuid"}, "format"},
		{&kind.Reference{Keyword: "$ref"}, "$ref"},
		{&kind.AdditionalProperties{}, "additionalProperties"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, keywordFor(tc.kind))
		})
	}
}

func TestValidateResults_NotFailureCarriesItsKeyword(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal(resultsWith(""), &doc))
	artifact := map[string]any{"sourceName": "grype", "document": map[string]any{}}
	doc["extensions"] = map[string]any{"rawSourceArtifacts": []any{artifact}}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	result := ValidateResults(data)
	require.False(t, result.Valid)
	assert.Equal(t, []ValidationError{
		{Field: "extensions.rawSourceArtifacts.0", Keyword: "not", Description: "'not' failed", Value: artifact},
	}, result.Errors)
}
