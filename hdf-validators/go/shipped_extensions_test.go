package hdfvalidators

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both languages consume the same closure and migration cases.
type shippedExtensionsCase struct {
	Name           string         `json:"name"`
	Extensions     map[string]any `json:"extensions"`
	Valid          bool           `json:"valid"`
	Why            string         `json:"why"`
	UndeclaredKeys []string       `json:"undeclaredKeys"`
}

func extensionsCaseDocument(t *testing.T, ext map[string]any, atBaseline bool) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(resultsWith(""), &doc))
	if atBaseline {
		doc["baselines"].([]any)[0].(map[string]any)["extensions"] = ext
	} else {
		doc["extensions"] = ext
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

func TestValidateResults_ExtensionsIsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "shipped-extensions-cases.json"))
	require.NoError(t, err, "read the shared extensions table")
	var table struct {
		Cases []shippedExtensionsCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)

	for _, tc := range table.Cases {
		for _, site := range []struct {
			label      string
			atBaseline bool
		}{{"root", false}, {"baseline", true}} {
			t.Run(tc.Name+"/"+site.label, func(t *testing.T) {
				result := ValidateResults(extensionsCaseDocument(t, tc.Extensions, site.atBaseline))
				assert.Equal(t, tc.Valid, result.Valid, "%s\ngot: %s", tc.Why, result.Error())
			})
		}
	}
}

func TestValidateResults_ExtensionsMigrationHint(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "shipped-extensions-cases.json"))
	require.NoError(t, err)
	var table struct {
		MigrationMessage string                  `json:"migrationMessage"`
		Cases            []shippedExtensionsCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.MigrationMessage)
	matched := 0
	for _, tc := range table.Cases {
		if len(tc.UndeclaredKeys) == 0 {
			continue
		}
		matched++
		for _, atBaseline := range []bool{false, true} {
			prefix := "extensions."
			if atBaseline {
				prefix = "baselines.0.extensions."
			}
			t.Run(tc.Name+"/"+prefix, func(t *testing.T) {
				result := ValidateResults(extensionsCaseDocument(t, tc.Extensions, atBaseline))
				require.False(t, result.Valid)
				require.NotEmpty(t, result.Errors)
				// Check the missing guidance before the intentionally changed Go field path.
				assert.Equal(t, table.MigrationMessage, result.Errors[0].Description)
				var want []ValidationError
				for _, key := range tc.UndeclaredKeys {
					want = append(want, ValidationError{Field: prefix + key, Description: table.MigrationMessage, Keyword: "additionalProperties", Value: tc.Extensions})
				}
				assert.ElementsMatch(t, want, result.Errors)
			})
		}
	}
	require.Equal(t, 2, matched)
}

func TestValidateResults_ExtensionsHintDoesNotLeak(t *testing.T) {
	for _, atBaseline := range []bool{false, true} {
		t.Run(fmt.Sprint(atBaseline), func(t *testing.T) {
			data := extensionsCaseDocument(t, map[string]any{}, atBaseline)
			var doc map[string]any
			require.NoError(t, json.Unmarshal(data, &doc))
			target := doc
			if atBaseline {
				target = doc["baselines"].([]any)[0].(map[string]any)
			}
			target["extensions"] = "wrong type"
			data, err := json.Marshal(doc)
			require.NoError(t, err)
			result := ValidateResults(data)
			require.False(t, result.Valid)
			require.NotEmpty(t, result.Errors)
			for _, item := range result.Errors {
				assert.NotContains(t, item.Description, "Move producer-specific data")
			}
		})
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(resultsWith(""), &doc))
	baseline := doc["baselines"].([]any)[0].(map[string]any)
	requirement := baseline["requirements"].([]any)[0].(map[string]any)
	resultDoc := requirement["results"].([]any)[0].(map[string]any)
	resultDoc["rawSourceRecord"] = map[string]any{"content": "{}", "encoding": "utf-8", "mediaType": "application/json", "system_context": map[string]any{}}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	result := ValidateResults(data)
	require.False(t, result.Valid)
	require.Len(t, result.Errors, 1)
	assert.Equal(t, "additionalProperties", result.Errors[0].Keyword)
	assert.Equal(t, "additional properties 'system_context' not allowed", result.Errors[0].Description)
}
