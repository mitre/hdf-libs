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

func TestConvertSarifToHDF_Minimal(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("minimal.sarif"))
	require.NoError(t, err, "Failed to read minimal.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "sarif-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)

	// Verify structure — minimal.sarif has no rules[], so baseline name falls back to tool name
	require.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Flawfinder", baseline.Name)
	assert.Equal(t, "2.1.0", *baseline.Version)
	require.Len(t, baseline.Requirements, 2, "Should have 2 requirements")

	// Verify first requirement — no rule metadata so falls back to message parsing
	req1 := baseline.Requirements[0]
	assert.Equal(t, "RULE-001", req1.ID)
	assert.Equal(t, "buffer/strcpy", *req1.Title)
	assert.Contains(t, req1.Descriptions[0].Data, "Does not check for buffer overflows")
	assert.Equal(t, 0.7, req1.Impact)
	assert.Equal(t, "error", req1.Tags["severity"])
	cwe1, ok := req1.Tags["cwe"].([]string)
	require.True(t, ok, "CWE should be string slice")
	assert.Len(t, cwe1, 2)
	require.NotNil(t, req1.SourceLocation, "SourceLocation should not be nil")
	require.NotNil(t, req1.SourceLocation.Ref)
	assert.Equal(t, "src/main.c", *req1.SourceLocation.Ref)
	require.NotNil(t, req1.SourceLocation.Line)
	assert.Equal(t, float64(42), *req1.SourceLocation.Line)
	require.Len(t, req1.Results, 1)
	assert.Equal(t, hdf.Failed, req1.Results[0].Status)
	assert.Contains(t, req1.Results[0].CodeDesc, "src/main.c")

	// Verify second requirement
	req2 := baseline.Requirements[1]
	assert.Equal(t, "RULE-002", req2.ID)
	assert.Equal(t, "format/printf", *req2.Title)
	assert.Equal(t, 0.5, req2.Impact)
	assert.Equal(t, "warning", req2.Tags["severity"])
}

func TestConvertSarifToHDF_DataSource(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("minimal.sarif"))
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
	assert.Len(t, req.Results, 0, "Should have no results")
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

func TestResolveLevel(t *testing.T) {
	tests := []struct {
		name     string
		result   SarifResult
		rule     *ReportingDescriptor
		expected string
	}{
		{
			"result.level present",
			SarifResult{Level: "error"},
			nil,
			"error",
		},
		{
			"result.level absent, rule default present",
			SarifResult{},
			&ReportingDescriptor{
				DefaultConfiguration: &ReportingConfiguration{Level: "note"},
			},
			"note",
		},
		{
			"both absent, defaults to warning",
			SarifResult{},
			nil,
			"warning",
		},
		{
			"non-fail kind always returns none",
			SarifResult{Kind: "pass", Level: "error"},
			nil,
			"none",
		},
		{
			"kind=fail uses result level",
			SarifResult{Kind: "fail", Level: "error"},
			nil,
			"error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveLevel(tt.result, tt.rule))
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
		{"pass", hdf.Passed, 0.0},
		{"fail", hdf.Failed, 0.7},
		{"", hdf.Failed, 0.7},       // default kind=fail
		{"open", hdf.Failed, 0.0},
		{"review", hdf.NotReviewed, 0.0},
		{"informational", hdf.NotApplicable, 0.0},
		{"notApplicable", hdf.NotApplicable, 0.0},
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
	require.Len(t, baseline.Requirements, 10, "rich.sarif has 10 results")

	// Result 0: SEC-001 fail with full metadata
	r0 := baseline.Requirements[0]
	assert.Equal(t, "SEC-001", r0.ID)
	assert.Equal(t, "SqlInjection", *r0.Title) // from rule name
	assert.Equal(t, 0.7, r0.Impact)            // error → 0.7
	require.Len(t, r0.Results, 1)
	assert.Equal(t, hdf.Failed, r0.Results[0].Status)
	// Should have snippet in codeDesc
	assert.Contains(t, r0.Results[0].CodeDesc, "db.Query")
	// Should have backtrace from codeFlows
	require.Len(t, r0.Results[0].Backtrace, 3)
	assert.Contains(t, r0.Results[0].Backtrace[0], "src/handlers/user.go:22")
	// Should have CWE from relationships
	cweIds := r0.Tags["cwe"].([]string)
	assert.Contains(t, cweIds, "CWE-89")
	// Should have helpUri
	assert.Equal(t, "https://example.com/rules/SEC-001", r0.Tags["helpUri"])
	// Should have fix description
	hasFix := false
	for _, d := range r0.Descriptions {
		if d.Label == "fix" {
			assert.Contains(t, d.Data, "parameterized query")
			hasFix = true
		}
	}
	assert.True(t, hasFix)
	// Should have fingerprints
	_, hasFP := r0.Tags["fingerprints"]
	assert.True(t, hasFP)

	// Result 1: SEC-002 with no explicit level → falls back to rule default "warning"
	r1 := baseline.Requirements[1]
	assert.Equal(t, "SEC-002", r1.ID)
	assert.Equal(t, "WeakCrypto", *r1.Title)
	assert.Equal(t, 0.5, r1.Impact)      // warning → 0.5
	assert.Equal(t, "warning", r1.Tags["severity"])

	// Result 2: SEC-003 with accepted suppression → NotReviewed
	r2 := baseline.Requirements[2]
	assert.Equal(t, "SEC-003", r2.ID)
	require.Len(t, r2.Results, 1)
	assert.Equal(t, hdf.NotReviewed, r2.Results[0].Status)
	require.NotNil(t, r2.Results[0].Message)
	assert.Contains(t, *r2.Results[0].Message, "test API key")

	// Result 3: SEC-003 with rejected suppression → still Failed
	r3 := baseline.Requirements[3]
	assert.Equal(t, "SEC-003", r3.ID)
	require.Len(t, r3.Results, 1)
	assert.Equal(t, hdf.Failed, r3.Results[0].Status)

	// Result 4: SEC-004 kind=pass → Passed
	r4 := baseline.Requirements[4]
	assert.Equal(t, "SEC-004", r4.ID)
	require.Len(t, r4.Results, 1)
	assert.Equal(t, hdf.Passed, r4.Results[0].Status)
	assert.Equal(t, 0.0, r4.Impact) // non-fail kind → 0 impact

	// Result 5: SEC-005 kind=notApplicable → NotApplicable
	r5 := baseline.Requirements[5]
	assert.Equal(t, "SEC-005", r5.ID)
	require.Len(t, r5.Results, 1)
	assert.Equal(t, hdf.NotApplicable, r5.Results[0].Status)
	assert.Equal(t, 0.0, r5.Impact)

	// Result 6: SEC-004 kind=review → NotReviewed
	r6 := baseline.Requirements[6]
	require.Len(t, r6.Results, 1)
	assert.Equal(t, hdf.NotReviewed, r6.Results[0].Status)

	// Result 7: SEC-001 kind=informational → NotApplicable
	r7 := baseline.Requirements[7]
	require.Len(t, r7.Results, 1)
	assert.Equal(t, hdf.NotApplicable, r7.Results[0].Status)

	// Result 8: SEC-001 kind=open → Failed
	r8 := baseline.Requirements[8]
	require.Len(t, r8.Results, 1)
	assert.Equal(t, hdf.Failed, r8.Results[0].Status)

	// Result 9: SEC-003 with multiple suppressions (underReview + accepted) → NotReviewed
	r9 := baseline.Requirements[9]
	require.Len(t, r9.Results, 1)
	assert.Equal(t, hdf.NotReviewed, r9.Results[0].Status)
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
