package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "test-version"

func fixturePath(filename string) string {
	return filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "input", filename)
}

// --- Backward compatibility tests (updated for enriched behavior) ---

func TestConvertSarifToHDF_SarifInput(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("sarif_input.sarif"))
	require.NoError(t, err, "Failed to read sarif_input.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "sarif-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)

	// Verify structure — sarif_input.sarif has rules[], baseline name = tool name
	require.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Flawfinder", baseline.Name)
	assert.Equal(t, "2.1.0", *baseline.Version)
	assert.Len(t, baseline.Requirements, 21, "Should have 21 requirements (one per rule)")

	// Verify first requirement (FF1014 - buffer/gets, error level)
	var ff1014 *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "FF1014" {
			ff1014 = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, ff1014, "Expected FF1014 requirement")
	assert.Equal(t, "buffer/gets", *ff1014.Title)
	assert.Contains(t, ff1014.Descriptions[0].Data, "Does not check for buffer overflows")
	assert.Equal(t, 0.7, ff1014.Impact)
	assert.Equal(t, "error", ff1014.Tags["severity"])
	cwe1, ok := ff1014.Tags["cwe"].([]string)
	require.True(t, ok, "CWE should be string slice")
	assert.Contains(t, cwe1, "CWE-120")
	assert.Contains(t, cwe1, "CWE-20")
	require.NotEmpty(t, ff1014.Results)
	assert.Equal(t, hdf.Failed, ff1014.Results[0].Status)
	assert.Contains(t, ff1014.Results[0].CodeDesc, "test/test-patched.c")
}

func TestConvertSarifToHDF_DataSource(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("sarif_input.sarif"))
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.DataSource)
	require.NotNil(t, result.DataSource.Format)
	assert.Equal(t, "SARIF", *result.DataSource.Format)
	require.NotNil(t, result.DataSource.Name)
	assert.Equal(t, "Flawfinder", *result.DataSource.Name)
	require.NotNil(t, result.DataSource.Version)
	assert.Equal(t, "2.0.15", *result.DataSource.Version)
}

func TestConvertSarifToHDF_EmptyResults(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "TestTool", "version": "1.0.0" } },
			"results": []
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err, "Should succeed with empty results")
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 0)
}

func TestConvertSarifToHDF_MissingLocations(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "TestTool", "version": "1.0.0" } },
			"results": [{
				"ruleId": "TEST-001",
				"level": "error",
				"message": { "text": "test/issue: Test issue description (CWE-79)." },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.SourceLocation, "Should have no source location when locations array is empty")
	require.Len(t, req.Results, 1, "Should create a location-less result")
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
	assert.Equal(t, "No source location", req.Results[0].CodeDesc)
}

func TestMultipleLocations(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "TEST",
				"level": "error",
				"message": { "text": "test: description (CWE-120)." },
				"locations": [
					{
						"physicalLocation": {
							"artifactLocation": { "uri": "file1.c" },
							"region": { "startLine": 10, "startColumn": 5 }
						}
					},
					{
						"physicalLocation": {
							"artifactLocation": { "uri": "file2.c" },
							"region": { "startLine": 20, "startColumn": 3 }
						}
					}
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	req := result.Baselines[0].Requirements[0]

	require.NotNil(t, req.SourceLocation, "SourceLocation should not be nil")
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "file1.c", *req.SourceLocation.Ref)
	require.NotNil(t, req.SourceLocation.Line)
	assert.Equal(t, float64(10), *req.SourceLocation.Line)

	require.Len(t, req.Results, 2)
	assert.Contains(t, req.Results[0].CodeDesc, "file1.c")
	assert.Contains(t, req.Results[0].CodeDesc, "LINE : 10")
	assert.Contains(t, req.Results[1].CodeDesc, "file2.c")
	assert.Contains(t, req.Results[1].CodeDesc, "LINE : 20")
}

func TestInvalidJSON(t *testing.T) {
	_, err := ConvertSarifToHDF([]byte("not valid json"), testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SARIF JSON")
}

func TestMissingRuns(t *testing.T) {
	input := `{ "version": "2.1.0" }`
	_, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or empty runs field")
}

// --- Level resolution tests ---

func TestImpactMapping(t *testing.T) {
	tests := []struct {
		name           string
		level          string
		expectedImpact float64
	}{
		{"error level", "error", 0.7},
		{"warning level", "warning", 0.5},
		{"note level", "note", 0.3},
		// Missing level now falls back to SARIF spec default "warning" = 0.5
		{"missing level defaults to warning", "", 0.5},
		{"unknown level", "unknown", 0.1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]interface{}{
				"version": "2.1.0",
				"runs": []map[string]interface{}{
					{
						"tool": map[string]interface{}{
							"driver": map[string]string{"name": "Test", "version": "1.0"},
						},
						"results": []map[string]interface{}{
							{
								"ruleId":    "TEST",
								"level":     tt.level,
								"message":   map[string]string{"text": "test: description"},
								"locations": []interface{}{},
							},
						},
					},
				},
			}

			inputBytes, _ := json.Marshal(input)
			result, err := ConvertSarifToHDF(inputBytes, testConverterVersion)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedImpact, result.Baselines[0].Requirements[0].Impact)
		})
	}
}

func TestLevelFallbackToRuleDefault(t *testing.T) {
	// Result has no level; rule has defaultConfiguration.level=warning
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Test", "version": "1.0",
					"rules": [{
						"id": "R1",
						"name": "TestRule",
						"defaultConfiguration": { "level": "error" }
					}]
				}
			},
			"results": [{
				"ruleId": "R1",
				"ruleIndex": 0,
				"message": { "text": "Something bad happened" },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, 0.7, req.Impact, "Should use rule default level 'error' → 0.7")
	assert.Equal(t, "error", req.Tags["severity"])
}

// --- CWE extraction tests ---

func TestCweExtraction(t *testing.T) {
	tests := []struct {
		name        string
		messageText string
		expectedCWE []string
	}{
		{
			"comma separated",
			"test: description (CWE-79, CWE-89).",
			[]string{"CWE-79", "CWE-89"},
		},
		{
			"exclamation slash separated",
			"test: description (CWE-119!/CWE-120).",
			[]string{"CWE-119", "CWE-120"},
		},
		{
			"no CWE",
			"test: description without CWE.",
			[]string{},
		},
		{
			"single CWE",
			"test: description (CWE-120).",
			[]string{"CWE-120"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cweIds := extractCweIds(tt.messageText)
			assert.Equal(t, tt.expectedCWE, cweIds)
		})
	}
}

func TestCweExtractionPriority_Relationships(t *testing.T) {
	rule := &ReportingDescriptor{
		ID: "R1",
		Relationships: []ReportingDescriptorRelation{
			{
				Target: DescriptorReference{
					ID:            "89",
					ToolComponent: &ToolComponentReference{Name: "CWE"},
				},
			},
		},
		Properties: map[string]interface{}{
			"tags": []interface{}{"CWE-999"},
		},
	}

	// Relationships should be preferred over properties.tags
	cweIds := extractCweFromRule(rule)
	assert.Equal(t, []string{"CWE-89"}, cweIds)
}

func TestCweExtractionPriority_PropertiesTags(t *testing.T) {
	rule := &ReportingDescriptor{
		ID: "R1",
		// No relationships
		Properties: map[string]interface{}{
			"tags": []interface{}{"security", "CWE-798", "credentials"},
		},
	}

	cweIds := extractCweFromRule(rule)
	assert.Equal(t, []string{"CWE-798"}, cweIds)
}

func TestCweExtractionPriority_FallbackToMessage(t *testing.T) {
	// Rule with no CWE info → extractCweFromRule returns nil
	rule := &ReportingDescriptor{ID: "R1"}

	cweIds := extractCweFromRule(rule)
	assert.Nil(t, cweIds, "Should return nil when no CWE in rule")

	// Caller then falls back to message
	messageCwe := extractCweIds("Something about (CWE-120).")
	assert.Equal(t, []string{"CWE-120"}, messageCwe)
}

func TestCweExtractionPriority_NilRule(t *testing.T) {
	cweIds := extractCweFromRule(nil)
	assert.Nil(t, cweIds)
}

func TestCweExtractionPriority_NoCweAnywhere(t *testing.T) {
	// No CWE from rule, no CWE from message → default NIST tags
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Test", "version": "1.0",
					"rules": [{"id": "R1", "name": "NoRelationships"}]
				}
			},
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "No CWE reference here" },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	nist := req.Tags["nist"].([]string)
	assert.Contains(t, nist, "SA-11", "Should fall back to default NIST tags")
	assert.Contains(t, nist, "RA-5")
}

// --- Message parsing tests ---

func TestMessageParsing(t *testing.T) {
	tests := []struct {
		name          string
		messageText   string
		expectedTitle string
		expectedDesc  string
	}{
		{
			"with colon",
			"buffer/strcpy: Does not check for buffer overflows (CWE-120).",
			"buffer/strcpy",
			"Does not check for buffer overflows (CWE-120).",
		},
		{
			"without colon",
			"Simple message without colon",
			"Simple message without colon",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, desc := parseMessage(tt.messageText)
			assert.Equal(t, tt.expectedTitle, title)
			assert.Equal(t, tt.expectedDesc, desc)
		})
	}
}

// --- Kind → status mapping tests ---

func TestMapKindToStatus(t *testing.T) {
	tests := []struct {
		kind     string
		expected hdf.ResultStatus
	}{
		{"pass", hdf.Passed},
		{"fail", hdf.Failed},
		{"", hdf.Failed}, // default
		{"open", hdf.Failed},
		{"review", hdf.NotReviewed},
		{"informational", hdf.NotApplicable},
		{"notApplicable", hdf.NotApplicable},
	}

	for _, tt := range tests {
		name := tt.kind
		if name == "" {
			name = "empty (default)"
		}
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapKindToStatus(tt.kind))
		})
	}
}

func TestKindMappingIntegration(t *testing.T) {
	// Test kind values produce correct HDF status through full conversion
	tests := []struct {
		kind           string
		expectedStatus hdf.ResultStatus
		expectedImpact float64
	}{
		// Impact is now determined at rule level, not per-result kind.
		// Without a rule definition, resolveRuleLevel falls back to first fail-kind
		// result's level or "warning". Non-fail-only results get "warning" → 0.5.
		{"pass", hdf.Passed, 0.5},
		{"fail", hdf.Failed, 0.7},
		{"", hdf.Failed, 0.7},       // default kind=fail, level=error → 0.7
		{"open", hdf.Failed, 0.5},
		{"review", hdf.NotReviewed, 0.5},
		{"informational", hdf.NotApplicable, 0.5},
		{"notApplicable", hdf.NotApplicable, 0.5},
	}

	for _, tt := range tests {
		name := tt.kind
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			input := map[string]interface{}{
				"version": "2.1.0",
				"runs": []map[string]interface{}{
					{
						"tool": map[string]interface{}{
							"driver": map[string]string{"name": "Test", "version": "1.0"},
						},
						"results": []map[string]interface{}{
							{
								"ruleId":  "TEST",
								"kind":    tt.kind,
								"level":   "error",
								"message": map[string]string{"text": "test message"},
								"locations": []map[string]interface{}{
									{
										"physicalLocation": map[string]interface{}{
											"artifactLocation": map[string]string{"uri": "file.go"},
											"region":           map[string]int{"startLine": 1, "startColumn": 1},
										},
									},
								},
							},
						},
					},
				},
			}

			inputBytes, _ := json.Marshal(input)
			result, err := ConvertSarifToHDF(inputBytes, testConverterVersion)
			require.NoError(t, err)

			req := result.Baselines[0].Requirements[0]
			assert.Equal(t, tt.expectedImpact, req.Impact)
			require.Len(t, req.Results, 1)
			assert.Equal(t, tt.expectedStatus, req.Results[0].Status)
		})
	}
}

// --- Suppression tests ---

func TestApplySuppression(t *testing.T) {
	tests := []struct {
		name                 string
		suppressions         []Suppression
		expectSuppressed     bool
		expectJustification  string
	}{
		{
			"no suppressions",
			nil,
			false, "",
		},
		{
			"accepted suppression",
			[]Suppression{{Kind: "inSource", Status: "accepted", Justification: "test key"}},
			true, "test key",
		},
		{
			"rejected suppression",
			[]Suppression{{Kind: "external", Status: "rejected"}},
			false, "",
		},
		{
			"underReview suppression",
			[]Suppression{{Kind: "inSource", Status: "underReview", Justification: "reviewing"}},
			true, "reviewing",
		},
		{
			"multiple suppressions combine justifications",
			[]Suppression{
				{Kind: "inSource", Status: "underReview", Justification: "reason A"},
				{Kind: "external", Status: "accepted", Justification: "reason B"},
			},
			true, "reason A; reason B",
		},
		{
			"mixed rejected and accepted",
			[]Suppression{
				{Kind: "external", Status: "rejected"},
				{Kind: "inSource", Status: "accepted", Justification: "valid"},
			},
			true, "valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suppressed, justification := applySuppression(tt.suppressions)
			assert.Equal(t, tt.expectSuppressed, suppressed)
			assert.Equal(t, tt.expectJustification, justification)
		})
	}
}

func TestSuppressionIntegration_AcceptedOverridesStatus(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "TEST",
				"level": "error",
				"message": { "text": "test: suppressed finding" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "file.go" },
						"region": { "startLine": 1, "startColumn": 1 }
					}
				}],
				"suppressions": [
					{ "kind": "inSource", "status": "accepted", "justification": "false positive" }
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "false positive")
}

func TestSuppressionIntegration_RejectedKeepsStatus(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "TEST",
				"level": "error",
				"message": { "text": "test: not suppressed" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "file.go" },
						"region": { "startLine": 1, "startColumn": 1 }
					}
				}],
				"suppressions": [
					{ "kind": "external", "status": "rejected" }
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestSuppressionInTags(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "TEST",
				"level": "error",
				"message": { "text": "test finding" },
				"locations": [],
				"suppressions": [
					{ "kind": "inSource", "status": "accepted", "justification": "test" },
					{ "kind": "external", "status": "rejected" }
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	supps, ok := req.Tags["suppressions"].([]map[string]string)
	require.True(t, ok, "suppressions should be in tags")
	assert.Len(t, supps, 2)
	assert.Equal(t, "inSource", supps[0]["kind"])
	assert.Equal(t, "accepted", supps[0]["status"])
	assert.Equal(t, "external", supps[1]["kind"])
	assert.Equal(t, "rejected", supps[1]["status"])
}

// --- Rule metadata tests ---

func TestRuleMetadata_TitleFromRuleName(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Test", "version": "1.0",
					"rules": [{
						"id": "R1",
						"name": "SqlInjection",
						"shortDescription": { "text": "SQL Injection vulnerability" },
						"fullDescription": { "text": "Full description of the SQL injection issue." },
						"helpUri": "https://example.com/rules/R1",
						"help": { "text": "Use parameterized queries." }
					}]
				}
			},
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "User input used in SQL query." },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]

	// Title should come from rule.name
	assert.Equal(t, "SqlInjection", *req.Title)

	// Default description should be the message text (since rule name is the title)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Equal(t, "User input used in SQL query.", req.Descriptions[0].Data)

	// fullDescription → rationale
	found := false
	for _, d := range req.Descriptions {
		if d.Label == "rationale" {
			assert.Equal(t, "Full description of the SQL injection issue.", d.Data)
			found = true
		}
	}
	assert.True(t, found, "Should have rationale description from fullDescription")

	// help → check
	found = false
	for _, d := range req.Descriptions {
		if d.Label == "check" {
			assert.Equal(t, "Use parameterized queries.", d.Data)
			found = true
		}
	}
	assert.True(t, found, "Should have check description from help")

	// helpUri in tags
	assert.Equal(t, "https://example.com/rules/R1", req.Tags["helpUri"])
}

func TestRuleMetadata_NoRuleName_FallsBackToMessageParsing(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Test", "version": "1.0",
					"rules": [{"id": "R1"}]
				}
			},
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "category/name: Description here." },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "category/name", *req.Title)
	assert.Equal(t, "Description here.", req.Descriptions[0].Data)
}

func TestBaselineNameFromToolDriver(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "gosec", "version": "2.18.2" } },
			"results": []
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "gosec", result.Baselines[0].Name)
}

func TestBaselineNameFallsBackToSARIF(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "", "version": "1.0" } },
			"results": []
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "SARIF", result.Baselines[0].Name)
}

// --- Fix tests ---

func TestFixDescription(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "test finding" },
				"locations": [],
				"fixes": [
					{ "description": { "text": "Replace with safe alternative." } }
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	found := false
	for _, d := range req.Descriptions {
		if d.Label == "fix" {
			assert.Equal(t, "Replace with safe alternative.", d.Data)
			found = true
		}
	}
	assert.True(t, found, "Should have fix description")
}

func TestNoFixDescription(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "test finding" },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	for _, d := range req.Descriptions {
		assert.NotEqual(t, "fix", d.Label, "Should not have fix description")
	}
}

// --- Code flow / backtrace tests ---

func TestCodeFlowBacktrace(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "data flow issue" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "sink.go" },
						"region": { "startLine": 50, "startColumn": 1 }
					}
				}],
				"codeFlows": [{
					"threadFlows": [{
						"locations": [
							{
								"location": {
									"physicalLocation": {
										"artifactLocation": { "uri": "source.go" },
										"region": { "startLine": 10, "startColumn": 1 }
									},
									"message": { "text": "User input received" }
								},
								"importance": "essential"
							},
							{
								"location": {
									"physicalLocation": {
										"artifactLocation": { "uri": "sink.go" },
										"region": { "startLine": 50, "startColumn": 1 }
									},
									"message": { "text": "Unsanitized use" }
								},
								"importance": "essential"
							}
						]
					}]
				}]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	bt := req.Results[0].Backtrace
	require.Len(t, bt, 2)
	assert.Equal(t, "source.go:10 - User input received", bt[0])
	assert.Equal(t, "sink.go:50 - Unsanitized use", bt[1])
}

func TestEmptyCodeFlows(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "no code flow" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "file.go" },
						"region": { "startLine": 1, "startColumn": 1 }
					}
				}]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Empty(t, req.Results[0].Backtrace)
}

// --- Snippet tests ---

func TestSnippetInCodeDesc(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "test finding" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "file.go" },
						"region": {
							"startLine": 42,
							"startColumn": 5,
							"snippet": { "text": "db.Query(sql + input)" }
						}
					}
				}]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Contains(t, req.Results[0].CodeDesc, "URL : file.go LINE : 42 COLUMN : 5")
	assert.Contains(t, req.Results[0].CodeDesc, "db.Query(sql + input)")
}

func TestNoSnippetInCodeDesc(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "test finding" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "file.go" },
						"region": { "startLine": 42, "startColumn": 5 }
					}
				}]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Equal(t, "URL : file.go LINE : 42 COLUMN : 5", req.Results[0].CodeDesc)
}

// --- Fingerprint tests ---

func TestFingerprintsInTags(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "test finding" },
				"locations": [],
				"fingerprints": { "primaryLocationHash": "abc123" },
				"partialFingerprints": { "lineHash": "def456" }
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	fp, ok := req.Tags["fingerprints"].(map[string]interface{})
	require.True(t, ok, "Should have fingerprints in tags")

	fingerprints, ok := fp["fingerprints"].(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "abc123", fingerprints["primaryLocationHash"])

	partial, ok := fp["partialFingerprints"].(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "def456", partial["lineHash"])
}

func TestNoFingerprintsInTags(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "R1",
				"level": "error",
				"message": { "text": "test finding" },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	_, ok := req.Tags["fingerprints"]
	assert.False(t, ok, "Should not have fingerprints when not present")
}

// --- Integration tests with fixtures ---

func TestConvertSarifToHDF_RichFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("rich.sarif"))
	require.NoError(t, err, "Failed to read rich.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Baseline should use tool name
	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]
	assert.Equal(t, "SecurityScanner", baseline.Name)
	assert.Equal(t, "2.1.0", *baseline.Version)
	require.Len(t, baseline.Requirements, 5, "rich.sarif has 5 distinct rules")

	// SEC-001: SqlInjection — 3 SARIF results (fail, informational, open)
	sec001 := baseline.Requirements[0]
	assert.Equal(t, "SEC-001", sec001.ID)
	assert.Equal(t, "SqlInjection", *sec001.Title)
	assert.Equal(t, 0.7, sec001.Impact) // error → 0.7 (rule-level)
	cweIds := sec001.Tags["cwe"].([]string)
	assert.Contains(t, cweIds, "CWE-89")
	assert.Equal(t, "https://example.com/rules/SEC-001", sec001.Tags["helpUri"])
	// Fix description from first result
	hasFix := false
	for _, d := range sec001.Descriptions {
		if d.Label == "fix" {
			assert.Contains(t, d.Data, "parameterized query")
			hasFix = true
		}
	}
	assert.True(t, hasFix)
	// 3 results: fail (with backtrace+snippet), informational, open
	require.Len(t, sec001.Results, 3)
	assert.Equal(t, hdf.Failed, sec001.Results[0].Status)
	assert.Contains(t, sec001.Results[0].CodeDesc, "db.Query")
	require.Len(t, sec001.Results[0].Backtrace, 3)
	assert.Contains(t, sec001.Results[0].Backtrace[0], "src/handlers/user.go:22")
	assert.Equal(t, hdf.NotApplicable, sec001.Results[1].Status) // informational
	assert.Equal(t, hdf.Failed, sec001.Results[2].Status)        // open

	// SEC-002: WeakCrypto — 1 result, rule default level "warning"
	sec002 := baseline.Requirements[1]
	assert.Equal(t, "SEC-002", sec002.ID)
	assert.Equal(t, "WeakCrypto", *sec002.Title)
	assert.Equal(t, 0.5, sec002.Impact)
	assert.Equal(t, "warning", sec002.Tags["severity"])
	require.Len(t, sec002.Results, 1)
	assert.Equal(t, hdf.Failed, sec002.Results[0].Status)

	// SEC-003: HardcodedCredential — 3 results (accepted suppression, rejected, multiple supps)
	sec003 := baseline.Requirements[2]
	assert.Equal(t, "SEC-003", sec003.ID)
	assert.Equal(t, 0.7, sec003.Impact) // error
	require.Len(t, sec003.Results, 3)
	// First result: accepted suppression → NotReviewed
	assert.Equal(t, hdf.NotReviewed, sec003.Results[0].Status)
	require.NotNil(t, sec003.Results[0].Message)
	assert.Contains(t, *sec003.Results[0].Message, "test API key")
	// Second result: rejected suppression → Failed
	assert.Equal(t, hdf.Failed, sec003.Results[1].Status)
	// Third result: multiple suppressions (underReview + accepted) → NotReviewed
	assert.Equal(t, hdf.NotReviewed, sec003.Results[2].Status)

	// SEC-004: InfoDisclosure — 2 results (pass, review)
	sec004 := baseline.Requirements[3]
	assert.Equal(t, "SEC-004", sec004.ID)
	assert.Equal(t, 0.3, sec004.Impact) // note
	require.Len(t, sec004.Results, 2)
	assert.Equal(t, hdf.Passed, sec004.Results[0].Status)
	assert.Equal(t, hdf.NotReviewed, sec004.Results[1].Status)

	// SEC-005: DeprecatedAPI — 1 result (notApplicable)
	sec005 := baseline.Requirements[4]
	assert.Equal(t, "SEC-005", sec005.ID)
	assert.Equal(t, 0.3, sec005.Impact) // note
	require.Len(t, sec005.Results, 1)
	assert.Equal(t, hdf.NotApplicable, sec005.Results[0].Status)
}

// --- Multi-tool fixture tests (DefectDojo-sourced, schema-validated) ---

func TestConvertSarifToHDF_CodeQLFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("codeQL-output.sarif"))
	require.NoError(t, err, "Failed to read codeQL-output.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	baseline := result.Baselines[0]
	assert.Equal(t, "CodeQL", baseline.Name)
	assert.Equal(t, "2.1.0", *baseline.Version)
	require.Len(t, baseline.Requirements, 13, "72 results should group into 13 distinct rules")

	// py/sql-injection — has codeFlows (data flow traces from real CodeQL)
	var sqlInj *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "py/sql-injection" {
			sqlInj = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, sqlInj, "Expected py/sql-injection requirement")
	require.Len(t, sqlInj.Results, 2)
	// CodeQL produces codeFlows for taint-tracking queries
	assert.NotEmpty(t, sqlInj.Results[0].Backtrace, "SQL injection result should have backtrace from codeFlows")

	// py/unused-import — heaviest grouping: 40 results → 1 requirement
	var unusedImport *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "py/unused-import" {
			unusedImport = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, unusedImport, "Expected py/unused-import requirement")
	assert.Len(t, unusedImport.Results, 40, "All 40 unused-import results should be under one requirement")

	// All CodeQL results have no explicit level → resolveRuleLevel should use
	// rule.defaultConfiguration.level where available
	// py/sql-injection has defaultConfiguration.level = "error"
	assert.Equal(t, 0.7, sqlInj.Impact, "py/sql-injection should have error-level impact")

	// Fingerprints — CodeQL puts partialFingerprints on results
	fp, ok := sqlInj.Tags["fingerprints"].(map[string]interface{})
	assert.True(t, ok, "Should have fingerprints from CodeQL output")
	if ok {
		_, hasPFP := fp["partialFingerprints"]
		assert.True(t, hasPFP, "Should have partialFingerprints")
	}
}

func TestConvertSarifToHDF_GitleaksFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("gitleaks_7.5.0.sarif"))
	require.NoError(t, err, "Failed to read gitleaks_7.5.0.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	baseline := result.Baselines[0]
	assert.Equal(t, "Gitleaks", baseline.Name)

	// All 8 results lack ruleId. They should group by message text:
	// 6x "AWS Access Key secret detected" → 1 requirement
	// 2x "Asymmetric Private Key secret detected" → 1 requirement
	require.Len(t, baseline.Requirements, 2, "Should group by message text when ruleId is absent")

	var awsReq, asymReq *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "AWS Access Key secret detected" {
			awsReq = &baseline.Requirements[i]
		}
		if baseline.Requirements[i].ID == "Asymmetric Private Key secret detected" {
			asymReq = &baseline.Requirements[i]
		}
	}
	require.NotNil(t, awsReq, "Expected requirement for AWS Access Key findings")
	assert.Len(t, awsReq.Results, 6)
	require.NotNil(t, asymReq, "Expected requirement for Asymmetric Private Key findings")
	assert.Len(t, asymReq.Results, 2)

	// Results should have snippets from the SARIF locations
	for _, r := range awsReq.Results {
		assert.Contains(t, r.CodeDesc, "URL :")
		assert.Contains(t, r.CodeDesc, "LINE :")
	}
}

func TestConvertSarifToHDF_SpotBugsFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("spotbugs.sarif"))
	require.NoError(t, err, "Failed to read spotbugs.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	baseline := result.Baselines[0]
	assert.Equal(t, "SpotBugs", baseline.Name)
	require.Len(t, baseline.Requirements, 9, "56 results should group into 9 rules")

	// All SpotBugs results are "note" level → 0.3 impact
	for _, req := range baseline.Requirements {
		assert.Equal(t, 0.3, req.Impact, "SpotBugs rule %s should have note-level impact", req.ID)
		assert.Equal(t, "note", req.Tags["severity"])
	}

	// NM_METHOD_NAMING_CONVENTION — heaviest grouping: 33 results
	var nmMethod *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "NM_METHOD_NAMING_CONVENTION" {
			nmMethod = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, nmMethod, "Expected NM_METHOD_NAMING_CONVENTION requirement")
	assert.Len(t, nmMethod.Results, 33)

	// SpotBugs rules have shortDescription and helpUri
	assert.NotNil(t, nmMethod.Title)
	helpUri, ok := nmMethod.Tags["helpUri"]
	assert.True(t, ok, "SpotBugs rules should have helpUri")
	assert.NotEmpty(t, helpUri)

	// SpotBugs uses message.id + arguments instead of message.text.
	// The converter should resolve messageStrings templates.
	var dmiRule *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "DMI_HARDCODED_ABSOLUTE_FILENAME" {
			dmiRule = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, dmiRule, "Expected DMI_HARDCODED_ABSOLUTE_FILENAME requirement")
	// messageStrings.default.text = "Hard coded reference to an absolute pathname in {0}."
	// arguments = ["Boot.main(String[])"]
	// → resolved: "Hard coded reference to an absolute pathname in Boot.main(String[])."
	require.NotEmpty(t, dmiRule.Descriptions)
	assert.Contains(t, dmiRule.Descriptions[0].Data, "Boot.main(String[])",
		"Should resolve message.id template with arguments")
}

func TestConvertSarifToHDF_DockleFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("dockle_0_3_15.sarif"))
	require.NoError(t, err, "Failed to read dockle_0_3_15.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	baseline := result.Baselines[0]
	assert.Equal(t, "Dockle", baseline.Name)
	require.Len(t, baseline.Requirements, 4, "4 rules with 4 results")

	// All Dockle results have 0 locations (container-level findings).
	// Each should still produce 1 RequirementResult with a generic codeDesc.
	for _, req := range baseline.Requirements {
		require.Len(t, req.Results, 1, "Dockle rule %s should have 1 result even without locations", req.ID)
		assert.Equal(t, hdf.Failed, req.Results[0].Status)
	}

	// CIS-DI-0010 is error level, the rest are note
	var cis0010 *hdf.EvaluatedRequirement
	var cis0005 *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		switch baseline.Requirements[i].ID {
		case "CIS-DI-0010":
			cis0010 = &baseline.Requirements[i]
		case "CIS-DI-0005":
			cis0005 = &baseline.Requirements[i]
		}
	}
	require.NotNil(t, cis0010)
	assert.Equal(t, 0.7, cis0010.Impact, "CIS-DI-0010 is error level")
	require.NotNil(t, cis0005)
	assert.Equal(t, 0.3, cis0005.Impact, "CIS-DI-0005 is note level")

	// Dockle rules have help text → should produce "check" description
	hasCheck := false
	for _, d := range cis0010.Descriptions {
		if d.Label == "check" {
			hasCheck = true
			assert.Contains(t, d.Data, "CHECKPOINT")
		}
	}
	assert.True(t, hasCheck, "Dockle rules with help should have check description")
}

func TestConvertSarifToHDF_GosecFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("gosec.sarif"))
	require.NoError(t, err, "Failed to read gosec.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	baseline := result.Baselines[0]
	assert.Equal(t, "gosec", baseline.Name)
	require.Len(t, baseline.Requirements, 4)

	// G201 — CWE from relationships
	r0 := baseline.Requirements[0]
	assert.Equal(t, "G201", r0.ID)
	cweIds := r0.Tags["cwe"].([]string)
	assert.Contains(t, cweIds, "CWE-89")
	assert.Equal(t, 0.7, r0.Impact) // error level
	// Should have snippet
	require.Len(t, r0.Results, 1)
	assert.Contains(t, r0.Results[0].CodeDesc, "fmt.Sprintf")

	// G304 — suppressed (nosec annotation)
	r1 := baseline.Requirements[1]
	assert.Equal(t, "G304", r1.ID)
	require.Len(t, r1.Results, 1)
	assert.Equal(t, hdf.NotReviewed, r1.Results[0].Status)
	cweIds1 := r1.Tags["cwe"].([]string)
	assert.Contains(t, cweIds1, "CWE-22")

	// G401 — CWE from relationships
	r2 := baseline.Requirements[2]
	assert.Equal(t, "G401", r2.ID)
	cweIds2 := r2.Tags["cwe"].([]string)
	assert.Contains(t, cweIds2, "CWE-326")

	// G101 — CWE from properties.tags (no relationships, has CWE-798 in tags)
	r3 := baseline.Requirements[3]
	assert.Equal(t, "G101", r3.ID)
	cweIds3 := r3.Tags["cwe"].([]string)
	assert.Contains(t, cweIds3, "CWE-798")
}
