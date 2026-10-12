package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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
	assert.Equal(t, "error", ff1014.Tags["sarif-level"])
	cwe1, ok := ff1014.Tags["cwe"].([]string)
	require.True(t, ok, "CWE should be string slice")
	assert.Contains(t, cwe1, "CWE-120")
	assert.Contains(t, cwe1, "CWE-20")
	require.NotEmpty(t, ff1014.Results)
	assert.Equal(t, hdf.Failed, ff1014.Results[0].Status)
	assert.Contains(t, ff1014.Results[0].CodeDesc, "test/test-patched.c")
}

func TestConvertSarifToHDF_Tool(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("sarif_input.sarif"))
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "SARIF", *result.Tool.Format)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Flawfinder", *result.Tool.Name)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "2.0.15", *result.Tool.Version)
}

func TestConvertSarifToHDF_EmptyResultsSynthesizesPlaceholder(t *testing.T) {
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

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1,
		"empty SARIF run must synthesize one placeholder requirement (HDF requires requirements.minItems=1)")

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "TestTool-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "TestTool")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
	require.NotNil(t, result.Timestamp)
	assert.Equal(t, *result.Timestamp, req.Results[0].StartTime,
		"synthesized startTime should equal the doc-level Timestamp so downstream tools can reuse it")
}

func TestConvertSarifToHDF_EmptyResultsFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("empty-results.sarif"))
	require.NoError(t, err, "Failed to read empty-results.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "ExampleAnalyzer-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "ExampleAnalyzer")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

// The fixture can only carry the absent form, since a literal null fails the
// vendored schema. Pin literal null against the fixture's own output so the
// golden covers both spellings rather than only one.
func TestConvertSarifToHDF_ResultsNullMatchesAbsentFixture(t *testing.T) {
	absentData, err := os.ReadFile(fixturePath("results-absent.sarif"))
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(absentData, &doc))
	runs := doc["runs"].([]interface{})
	runs[0].(map[string]interface{})["results"] = nil
	nullData, err := json.Marshal(doc)
	require.NoError(t, err)

	fromAbsent, err := ConvertSarifToHDF(absentData, testConverterVersion)
	require.NoError(t, err)
	fromNull, err := ConvertSarifToHDF(nullData, testConverterVersion)
	require.NoError(t, err)

	a := fromAbsent.Baselines[0].Requirements[0]
	n := fromNull.Baselines[0].Requirements[0]
	assert.Equal(t, a.ID, n.ID)
	assert.Equal(t, a.Title, n.Title)
	assert.Equal(t, a.Impact, n.Impact)
	require.Len(t, n.Results, 1)
	assert.Equal(t, a.Results[0].Status, n.Results[0].Status)
	assert.Equal(t, a.Results[0].CodeDesc, n.Results[0].CodeDesc)
}

func TestConvertSarifToHDF_ResultsAbsentFixture(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("results-absent.sarif"))
	require.NoError(t, err, "Failed to read results-absent.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "ExampleAnalyzer-not-analyzed", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status,
		"a run that reported no result set analyzed nothing; passed would assert a clean scan")
	assert.NotContains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertSarifToHDF_EmptyResultsFallbackTarget(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "", "version": "1.0" } },
			"results": []
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "sarif-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "SARIF analyzer")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertSarifToHDF_EmptyResultsPerRunBaseline(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [
			{
				"tool": { "driver": { "name": "ToolA", "version": "1.0" } },
				"results": []
			},
			{
				"tool": { "driver": { "name": "ToolB", "version": "2.0" } },
				"results": []
			}
		]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 2)

	require.Len(t, result.Baselines[0].Requirements, 1)
	assert.Equal(t, "ToolA-no-findings", result.Baselines[0].Requirements[0].ID)

	require.Len(t, result.Baselines[1].Requirements, 1)
	assert.Equal(t, "ToolB-no-findings", result.Baselines[1].Requirements[0].ID)
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

// An ABSENT runs field is an error; an EMPTY one is conformant (§3.13.4) and converts.
func TestMissingRuns(t *testing.T) {
	input := `{ "version": "2.1.0" }`
	_, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing runs field")
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
	assert.Equal(t, "error", req.Tags["sarif-level"])
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
		{"", hdf.Failed, 0.7}, // default kind=fail, level=error → 0.7
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

func TestAcceptedSuppressionReason(t *testing.T) {
	tests := []struct {
		name         string
		suppressions []Suppression
		expect       string
	}{
		{"no suppressions", nil, ""},
		{
			"accepted with justification",
			[]Suppression{{Kind: "inSource", Status: "accepted", Justification: "test key"}},
			"test key",
		},
		{
			"accepted without justification falls back",
			[]Suppression{{Kind: "inSource", Status: "accepted"}},
			defaultSuppressionReason,
		},
		{
			"rejected is not accepted",
			[]Suppression{{Kind: "external", Status: "rejected", Justification: "no"}},
			"",
		},
		{
			"underReview is not accepted",
			[]Suppression{{Kind: "inSource", Status: "underReview", Justification: "reviewing"}},
			"",
		},
		{
			"only accepted justifications combine",
			[]Suppression{
				{Kind: "inSource", Status: "underReview", Justification: "reason A"},
				{Kind: "external", Status: "accepted", Justification: "reason B"},
				{Kind: "external", Status: "rejected", Justification: "reason C"},
			},
			"reason B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, acceptedSuppressionReason(tt.suppressions))
		})
	}
}

func TestJustificationIndicatesFalsePositive(t *testing.T) {
	assert.True(t, justificationIndicatesFalsePositive("Marked as false positive by security team"))
	assert.True(t, justificationIndicatesFalsePositive("known FALSE-POSITIVE"))
	assert.False(t, justificationIndicatesFalsePositive("validated against allowlist"))
	assert.False(t, justificationIndicatesFalsePositive(""))
}

// An accepted suppression whose justification does NOT read as a false positive
// becomes a waiver override: raw status stays failed, effectiveStatus → passed,
// disposition → waiver. The full attributed, expiring override is present.
func TestSuppressionIntegration_AcceptedWaiverOverride(t *testing.T) {
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
					{ "kind": "inSource", "status": "accepted", "justification": "validated against allowlist" }
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	// De-laundering: raw result status stays the tool's failed.
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "validated against allowlist")

	require.Len(t, req.StatusOverrides, 1)
	ov := req.StatusOverrides[0]
	assert.Equal(t, hdf.OverrideTypeWaiver, ov.Type)
	require.NotNil(t, ov.Status)
	assert.Equal(t, hdf.Passed, *ov.Status)
	assert.Equal(t, "validated against allowlist", ov.Reason)
	assert.Equal(t, "sarif suppression", ov.AppliedBy.Identifier)
	assert.Equal(t, hdf.IdentityTypeOther, ov.AppliedBy.Type)
	assert.False(t, ov.AppliedAt.IsZero())
	assert.Equal(t, shared.DefaultOverrideExpiry(ov.AppliedAt), ov.ExpiresAt)

	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.Passed, *req.EffectiveStatus)
	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.OverrideTypeWaiver, *req.Disposition)
}

// An accepted suppression whose justification reads as a false positive becomes a
// falsePositive override → effectiveStatus notApplicable, disposition falsePositive.
func TestSuppressionIntegration_AcceptedFalsePositiveOverride(t *testing.T) {
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
					{ "kind": "external", "status": "accepted", "justification": "Confirmed false positive" }
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)

	require.Len(t, req.StatusOverrides, 1)
	ov := req.StatusOverrides[0]
	assert.Equal(t, hdf.FalsePositive, ov.Type)
	require.NotNil(t, ov.Status)
	assert.Equal(t, hdf.NotApplicable, *ov.Status)

	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.NotApplicable, *req.EffectiveStatus)
	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.FalsePositive, *req.Disposition)
}

// A suppression with NO status property is in force per the SARIF 2.1.0 default
// (producers like CodeQL and semgrep emit only {"kind": ...}) and becomes a
// waiver override exactly like an explicit "accepted" one.
func TestSuppressionIntegration_AbsentStatusIsAccepted(t *testing.T) {
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
				"suppressions": [ { "kind": "inSource" } ]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)

	require.Len(t, req.StatusOverrides, 1)
	ov := req.StatusOverrides[0]
	assert.Equal(t, hdf.OverrideTypeWaiver, ov.Type)
	assert.Equal(t, defaultSuppressionReason, ov.Reason)

	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.Passed, *req.EffectiveStatus)
}

// The requirement-level rollup follows the canonical worst-wins ordering
// (error worse than failed): a group mixing error and failed rolls to error.
func TestRollupStatus_CanonicalOrdering(t *testing.T) {
	assert.Equal(t, hdf.Error, rollupStatus([]hdf.ResultStatus{hdf.Failed, hdf.Error}))
	assert.Equal(t, hdf.Passed, rollupStatus([]hdf.ResultStatus{hdf.NotReviewed, hdf.Passed}))
	assert.Equal(t, hdf.NotApplicable, rollupStatus([]hdf.ResultStatus{hdf.NotReviewed, hdf.NotApplicable}))
}

// underReview and unsuppressed findings get NO override and keep their raw status.
func TestSuppressionIntegration_UnderReviewNoOverride(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [
				{
					"ruleId": "UR",
					"level": "error",
					"message": { "text": "under review" },
					"locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a.go" }, "region": { "startLine": 1 } } }],
					"suppressions": [ { "kind": "inSource", "status": "underReview", "justification": "reviewing" } ]
				},
				{
					"ruleId": "PLAIN",
					"level": "error",
					"message": { "text": "no suppression" },
					"locations": [{ "physicalLocation": { "artifactLocation": { "uri": "b.go" }, "region": { "startLine": 1 } } }]
				}
			]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Empty(t, req.StatusOverrides, "requirement %s should carry no override", req.ID)
		assert.Nil(t, req.EffectiveStatus, "requirement %s should carry no effectiveStatus", req.ID)
		assert.Nil(t, req.Disposition, "requirement %s should carry no disposition", req.ID)
		require.Len(t, req.Results, 1)
		assert.Equal(t, hdf.Failed, req.Results[0].Status)
		assert.Nil(t, req.Results[0].Message, "requirement %s should carry no suppression message", req.ID)
	}
}

// A result carrying BOTH an accepted and an underReview suppression keeps BOTH in
// the suppressions tag (lossless — no source data dropped) while emitting exactly
// one override from the accepted one.
func TestSuppressionIntegration_MixedResultPreservesAllInTag(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "TEST",
				"level": "error",
				"message": { "text": "test: mixed suppressions" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "file.go" },
						"region": { "startLine": 1, "startColumn": 1 }
					}
				}],
				"suppressions": [
					{ "kind": "inSource", "status": "underReview", "justification": "Reviewing whether this token is still active" },
					{ "kind": "external", "status": "accepted", "justification": "Marked as false positive by security team" }
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]

	// Exactly one override — from the accepted suppression only.
	require.Len(t, req.StatusOverrides, 1)
	assert.Equal(t, hdf.FalsePositive, req.StatusOverrides[0].Type)

	// BOTH suppressions preserved losslessly in the tag.
	supps, ok := req.Tags["suppressions"].([]map[string]string)
	require.True(t, ok, "suppressions should be in tags")
	require.Len(t, supps, 2)
	assert.Equal(t, "underReview", supps[0]["status"])
	assert.Equal(t, "Reviewing whether this token is still active", supps[0]["justification"])
	assert.Equal(t, "accepted", supps[1]["status"])
	assert.Equal(t, "Marked as false positive by security team", supps[1]["justification"])
}

// A requirement with an accepted suppression AND an unsuppressed sibling failure
// records the override but does NOT flip effectiveStatus (the sibling still fails).
func TestSuppressionIntegration_MixedGroupKeepsFailed(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [
				{
					"ruleId": "SEC",
					"level": "error",
					"message": { "text": "accepted one" },
					"locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a.go" }, "region": { "startLine": 1 } } }],
					"suppressions": [ { "kind": "inSource", "status": "accepted", "justification": "test key in dev" } ]
				},
				{
					"ruleId": "SEC",
					"level": "error",
					"message": { "text": "unsuppressed sibling" },
					"locations": [{ "physicalLocation": { "artifactLocation": { "uri": "b.go" }, "region": { "startLine": 2 } } }]
				}
			]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.StatusOverrides, 1)
	assert.Equal(t, hdf.OverrideTypeWaiver, req.StatusOverrides[0].Type)
	assert.Nil(t, req.EffectiveStatus, "unsuppressed sibling failure keeps the requirement effectively failed")
	assert.Nil(t, req.Disposition)
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
	assert.Equal(t, "warning", sec002.Tags["sarif-level"])
	require.Len(t, sec002.Results, 1)
	assert.Equal(t, hdf.Failed, sec002.Results[0].Status)

	// SEC-003: HardcodedCredential — 3 results (accepted suppression, rejected, multiple supps).
	// De-laundering: raw statuses all stay Failed; accepted suppressions become
	// structured overrides. The unsuppressed rejected sibling keeps the requirement
	// effectively failed, so no effectiveStatus/disposition is set.
	sec003 := baseline.Requirements[2]
	assert.Equal(t, "SEC-003", sec003.ID)
	assert.Equal(t, 0.7, sec003.Impact) // error
	require.Len(t, sec003.Results, 3)
	// First result: accepted suppression → Failed raw + waiver override.
	assert.Equal(t, hdf.Failed, sec003.Results[0].Status)
	require.NotNil(t, sec003.Results[0].Message)
	assert.Contains(t, *sec003.Results[0].Message, "test API key")
	// Second result: rejected suppression → Failed, no override.
	assert.Equal(t, hdf.Failed, sec003.Results[1].Status)
	// Third result: underReview + accepted → Failed raw + falsePositive override.
	assert.Equal(t, hdf.Failed, sec003.Results[2].Status)
	// Two accepted suppressions (results 0 and 2) → two overrides; sibling failure
	// keeps effectiveStatus/disposition unset.
	require.Len(t, sec003.StatusOverrides, 2)
	assert.Equal(t, hdf.OverrideTypeWaiver, sec003.StatusOverrides[0].Type)
	assert.Equal(t, hdf.FalsePositive, sec003.StatusOverrides[1].Type)
	assert.Nil(t, sec003.EffectiveStatus)
	assert.Nil(t, sec003.Disposition)

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
		assert.Equal(t, "note", req.Tags["sarif-level"])
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

// --- Ground-truth anchor (input-derived count; see shared/go/anchor.go) ---
// Golden parity proves Go and TS AGREE, not that either is CORRECT. This anchor
// asserts the converter emits exactly the requirement count predicted by a
// source-derived count computed INDEPENDENTLY of the converter's own parser and
// types. sarif emits one requirement per DISTINCT rule referenced by results:
// the set of result.ruleId (falling back to result.rule.id when ruleId is
// absent) across every runs[].results[]. If the converter silently drops or
// merges rules, this fails even when the Go and TS goldens match.

// countDistinctSarifRules unmarshals raw SARIF into a minimal local struct —
// deliberately NOT the converter's structs — and returns the number of distinct
// rule identifiers among all results.
func countDistinctSarifRules(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Rule   struct {
					ID string `json:"id"`
				} `json:"rule"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "failed to parse SARIF for anchor count")

	distinct := make(map[string]struct{})
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			id := r.RuleID
			if id == "" {
				id = r.Rule.ID
			}
			distinct[id] = struct{}{}
		}
	}
	return len(distinct)
}

func TestConvertSarifToHDF_SpotBugsAnchor(t *testing.T) {
	input, err := os.ReadFile(fixturePath("spotbugs.sarif"))
	require.NoError(t, err, "Failed to read spotbugs.sarif fixture")

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)

	want := countDistinctSarifRules(t, input)
	shared.AssertRequirementCount(t, result, want,
		"spotbugs.sarif: one requirement per distinct result ruleId (fallback rule.id)")
}

// WHAT THIS GUARANTEE DOES NOT COVER. A golden-based parity test can only discriminate
// shapes the corpus actually contains, so it is silent on every conformant construct no
// fixture carries. Four Go/TypeScript divergences were found by reading the two
// implementations against the spec, not by this test, and it stayed green through all of
// them: an empty runs array, a SARIF 2.0 resources.rules block, an artifactLocation with
// no uri, and a host-zone timestamp. Two of them now have fixtures; the 2.0 shape
// cannot have one, because the only vendored schema admits 2.1.0 alone, so it is
// covered by inline documents in both languages instead. The conformance
// surface is much larger than the corpus (SARIF defines 30 result properties alone), so a
// divergence in an uncovered construct will not be caught here. Add a fixture when a
// conformant shape matters, rather than trusting this to find it.
func TestSnapshots(t *testing.T) {
	// SARIF fixtures carry no run start time; conversion-time fallback. Suppression
	// overrides likewise carry no owner/date, so appliedAt/expiresAt are conversion-
	// time — masked alongside startTime.
	shared.RunSnapshotTestsMasking(t, "sarif-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSarifToHDF(input, "1.0.0")
	}, []string{"appliedAt", "expiresAt"}, "*")
}

func TestConvertSarifToHDF_ControlType(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("gosec.sarif"))
	require.NoError(t, err, "Failed to read gosec.sarif fixture")

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// At least one requirement should have a derived controlType once NIST
	// tags are present via CWE→NIST mapping (gosec rules carry CWE relationships).
	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			// Sanity check: must be one of the known classification values.
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one gosec requirement should have a derived controlType")
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

	// G304 — accepted #nosec suppression → waiver override. Raw stays failed,
	// effectiveStatus passed, disposition waiver (single-result group).
	r1 := baseline.Requirements[1]
	assert.Equal(t, "G304", r1.ID)
	require.Len(t, r1.Results, 1)
	assert.Equal(t, hdf.Failed, r1.Results[0].Status)
	require.Len(t, r1.StatusOverrides, 1)
	assert.Equal(t, hdf.OverrideTypeWaiver, r1.StatusOverrides[0].Type)
	assert.Equal(t, "sarif suppression", r1.StatusOverrides[0].AppliedBy.Identifier)
	require.NotNil(t, r1.EffectiveStatus)
	assert.Equal(t, hdf.Passed, *r1.EffectiveStatus)
	require.NotNil(t, r1.Disposition)
	assert.Equal(t, hdf.OverrideTypeWaiver, *r1.Disposition)
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

// --- Version handling tests ---

func TestConvertSarifToHDF_ExplicitVersion(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("sarif_input.sarif"))
	require.NoError(t, err)

	// Explicit version "2.1.0" should produce same result as no version
	resultDefault, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)

	resultExplicit, err := ConvertSarifToHDF(inputData, testConverterVersion, "2.1.0")
	require.NoError(t, err)

	// Both should produce the same number of baselines and requirements
	require.Len(t, resultExplicit.Baselines, len(resultDefault.Baselines))
	for i := range resultDefault.Baselines {
		assert.Equal(t, len(resultDefault.Baselines[i].Requirements),
			len(resultExplicit.Baselines[i].Requirements),
			"baseline %d requirement count should match", i)
	}
}

// SCA-shaped SARIF carries package identity in result.properties; SAST results
// leave properties empty. These tests synthesize minimal SARIF documents to
// exercise the new affectedPackages path independent of any specific tool fixture.
func TestSCASarif_AffectedPackagesFromProperties(t *testing.T) {
	t.Parallel()
	convertWith := func(props map[string]any) hdf.EvaluatedRequirement {
		doc := map[string]any{
			"version": "2.1.0",
			"runs": []map[string]any{{
				"tool": map[string]any{"driver": map[string]any{"name": "TestSCA", "version": "1.0"}},
				"results": []map[string]any{{
					"ruleId":     "CVE-2026-1234",
					"level":      "error",
					"message":    map[string]any{"text": "vulnerable package"},
					"locations":  []any{},
					"properties": props,
				}},
			}},
		}
		b, err := json.Marshal(doc)
		require.NoError(t, err)
		result, err := ConvertSarifToHDF(b, testConverterVersion)
		require.NoError(t, err)
		require.NotEmpty(t, result.Baselines)
		require.NotEmpty(t, result.Baselines[0].Requirements)
		return result.Baselines[0].Requirements[0]
	}

	t.Run("purl decomposes to ecosystem", func(t *testing.T) {
		req := convertWith(map[string]any{"purl": "pkg:npm/lodash@4.17.20"})
		require.Len(t, req.AffectedPackages, 1)
		require.NotNil(t, req.AffectedPackages[0].Purl)
		assert.Equal(t, "pkg:npm/lodash@4.17.20", *req.AffectedPackages[0].Purl)
		require.NotNil(t, req.AffectedPackages[0].Ecosystem)
		assert.Equal(t, hdf.Npm, *req.AffectedPackages[0].Ecosystem)
	})

	t.Run("packageName + packageVersion → generic ecosystem", func(t *testing.T) {
		req := convertWith(map[string]any{"packageName": "openssl", "packageVersion": "1.1.1k"})
		require.Len(t, req.AffectedPackages, 1)
		pkg := req.AffectedPackages[0]
		require.NotNil(t, pkg.Name)
		require.NotNil(t, pkg.Version)
		require.NotNil(t, pkg.Ecosystem)
		assert.Equal(t, "openssl", *pkg.Name)
		assert.Equal(t, "1.1.1k", *pkg.Version)
		assert.Equal(t, hdf.Generic, *pkg.Ecosystem)
	})

	t.Run("cpe-only is preserved as cpe-only", func(t *testing.T) {
		req := convertWith(map[string]any{"cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"})
		require.Len(t, req.AffectedPackages, 1)
		pkg := req.AffectedPackages[0]
		assert.Nil(t, pkg.Name)
		assert.Nil(t, pkg.Purl)
		require.NotNil(t, pkg.Cpe)
		assert.Equal(t, "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", *pkg.Cpe)
	})

	t.Run("fixedInVersion lands in the structured field", func(t *testing.T) {
		req := convertWith(map[string]any{
			"purl":           "pkg:npm/lodash@4.17.20",
			"fixedInVersion": "4.17.21",
		})
		require.Len(t, req.AffectedPackages, 1)
		require.NotNil(t, req.AffectedPackages[0].FixedInVersion)
		assert.Equal(t, "4.17.21", *req.AffectedPackages[0].FixedInVersion)
	})

	t.Run("empty properties → no affectedPackages (SAST result)", func(t *testing.T) {
		req := convertWith(map[string]any{})
		assert.Empty(t, req.AffectedPackages)
	})
}

func TestConvertSarifToHDF_VerificationMethod(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("sarif_input.sarif"))
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}

// findReq locates a requirement by ID across all baselines.
func findReq(t *testing.T, result *hdf.HDFResults, id string) *hdf.EvaluatedRequirement {
	t.Helper()
	for bi := range result.Baselines {
		for ri := range result.Baselines[bi].Requirements {
			if result.Baselines[bi].Requirements[ri].ID == id {
				return &result.Baselines[bi].Requirements[ri]
			}
		}
	}
	return nil
}

// requirement.code carries the raw source snippet from the primary location so
// Heimdall's CODE tab is populated (region.snippet.text — literal source).
func TestConvertSarifToHDF_RequirementCodeFromSnippet(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("rich.sarif"))
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)

	req := findReq(t, result, "SEC-001")
	require.NotNil(t, req, "expected SEC-001 requirement")
	require.NotNil(t, req.Code, "requirement.code should be set from region.snippet.text")
	assert.Equal(t, `db.Query("SELECT * FROM users WHERE name = '" + userInput + "'")`, *req.Code)
}

// Fixtures whose primary locations carry no region.snippet.text must leave
// requirement.code unset — no fabrication (NOT-IN-SOURCE).
func TestConvertSarifToHDF_RequirementCodeNilWhenNoSnippet(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("spotbugs.sarif"))
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	for bi := range result.Baselines {
		for ri := range result.Baselines[bi].Requirements {
			assert.Nil(t, result.Baselines[bi].Requirements[ri].Code,
				"requirement %q must have nil code when no snippet present",
				result.Baselines[bi].Requirements[ri].ID)
		}
	}
}

// --- security-severity (CVSS) impact + severity ---

// sarifWithSecuritySeverity builds a one-rule, one-result SARIF where the rule
// carries the given security-severity property and the result carries the given
// level, so precedence between the two can be asserted directly.
// A nil securitySeverity omits the property entirely; any other value is set as
// given, so "present but blank" and "absent" are distinguishable.
func sarifWithSecuritySeverity(t *testing.T, level string, securitySeverity interface{}) []byte {
	t.Helper()
	props := map[string]interface{}{}
	if securitySeverity != nil {
		props["security-severity"] = securitySeverity
	}
	input := map[string]interface{}{
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":    "Test",
					"version": "1.0",
					"rules": []map[string]interface{}{{
						"id":         "TEST",
						"properties": props,
					}},
				},
			},
			"results": []map[string]interface{}{{
				"ruleId":    "TEST",
				"level":     level,
				"message":   map[string]string{"text": "test: description"},
				"locations": []interface{}{},
			}},
		}},
	}
	b, err := json.Marshal(input)
	require.NoError(t, err)
	return b
}

// fixtures/input/grype.sarif is real grype 0.91.2 output over a public container
// image, taken verbatim from chainguard-demo/auto-deploy-demo (MIT) at commit
// cb4f28125158db261775b139b184f283539d7c42, path grype-results.sarif. Every result
// is level "warning" while the rules carry distinct CVSS scores — the exact shape
// that collapses to one impact when only level is read.
func TestConvertSarifToHDF_SecuritySeverityDrivesImpact(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("grype.sarif"))
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	want := map[string]float64{
		"CVE-2025-12781-python-3.12": 0.63,
		"CVE-2025-15366-python-3.12": 0.59,
		"CVE-2025-15367-python-3.12": 0.59,
		"CVE-2026-2297-python-3.12":  0.57,
	}
	seen := map[string]bool{}
	for _, req := range result.Baselines[0].Requirements {
		expected, ok := want[req.ID]
		if !ok {
			continue
		}
		seen[req.ID] = true
		assert.Equal(t, expected, req.Impact, "%s: impact must come from the rule's CVSS, not its level", req.ID)
		require.NotNil(t, req.Severity, "%s: severity must be published, not left for consumers to re-derive", req.ID)
		assert.Equal(t, hdf.SeverityMedium, *req.Severity, "%s", req.ID)
	}
	assert.Len(t, seen, len(want), "every CVE rule in the fixture should be asserted")
}

// severity is a schema field consumers read directly, so level-only SARIF gets one
// too — the converter records the band rather than leaving consumers to re-derive it.
func TestConvertSarifToHDF_SeverityPopulatedForLevelOnlySarif(t *testing.T) {
	for _, tt := range []struct {
		level  string
		impact float64
		want   hdf.Severity
	}{
		{"error", 0.7, hdf.SeverityHigh},
		{"warning", 0.5, hdf.SeverityMedium},
		{"note", 0.3, hdf.SeverityLow},
	} {
		t.Run(tt.level, func(t *testing.T) {
			result, err := ConvertSarifToHDF(sarifWithSecuritySeverity(t, tt.level, nil), testConverterVersion)
			require.NoError(t, err)
			req := result.Baselines[0].Requirements[0]
			assert.Equal(t, tt.impact, req.Impact)
			require.NotNil(t, req.Severity)
			assert.Equal(t, tt.want, *req.Severity)
		})
	}
}

// An unusable security-severity must not produce a nonsense impact — it falls
// back to the level mapping it would have used had the property been absent.
func TestConvertSarifToHDF_MalformedSecuritySeverityFallsBackToLevel(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value interface{}
	}{
		{"non-numeric", "abc"},
		{"present but empty", ""},
		{"present but whitespace", "   "},
		{"negative", "-1"},
		{"above the CVSS ceiling", "10.1"},
		{"not a number", "NaN"},
		{"infinity", "Inf"},
		// Neither language may accept a literal the other rejects: Go's
		// strconv.ParseFloat takes hex floats, JavaScript's Number() takes hex and
		// binary integers. None is a CVSS score, so both reject all three.
		{"hex integer literal", "0x8"},
		{"binary integer literal", "0b101"},
		{"hex float literal", "0x1p3"},
		// Passes the decimal shape but overflows to infinity when parsed.
		{"exponent overflow", "1e999"},
		{"wrong JSON type", map[string]interface{}{"score": 7}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ConvertSarifToHDF(sarifWithSecuritySeverity(t, "error", tt.value), testConverterVersion)
			require.NoError(t, err)
			req := result.Baselines[0].Requirements[0]
			assert.Equal(t, 0.7, req.Impact, "should fall back to level 'error'")
			require.NotNil(t, req.Severity)
			assert.Equal(t, hdf.SeverityHigh, *req.Severity)
		})
	}
}

// security-severity is GitHub's property, so GitHub's reading of it governs, and it
// documents that "a value of 0.0 or any other value outside the given range is
// regarded as having no security severity" — not as a severity of none. So 0.0 is an
// absent rating and the level mapping applies. This replaces an earlier reading that
// treated 0.0 as a CVSS "none" rating which won and was then floored to 0.1; falling
// back to the level serves that reading's own concern better, since the finding lands
// on its real severity instead of the floor.
func TestConvertSarifToHDF_ZeroSecuritySeverityFallsBackToLevel(t *testing.T) {
	result, err := ConvertSarifToHDF(sarifWithSecuritySeverity(t, "error", "0.0"), testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, 0.7, req.Impact, "0.0 carries no security severity, so level error applies")
	require.NotNil(t, req.Severity)
	assert.Equal(t, hdf.SeverityHigh, *req.Severity)
}

// Producers conventionally emit the score as a string, but a JSON number is
// valid too — the TS counterpart accepts both, so this side must as well.
func TestConvertSarifToHDF_SecuritySeverityAcceptsJSONNumber(t *testing.T) {
	input := map[string]interface{}{
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":    "Test",
					"version": "1.0",
					"rules": []map[string]interface{}{{
						"id":         "TEST",
						"properties": map[string]interface{}{"security-severity": 9.1},
					}},
				},
			},
			"results": []map[string]interface{}{{
				"ruleId":    "TEST",
				"level":     "warning",
				"message":   map[string]string{"text": "test: description"},
				"locations": []interface{}{},
			}},
		}},
	}
	inputBytes, err := json.Marshal(input)
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputBytes, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, 0.91, req.Impact)
	require.NotNil(t, req.Severity)
	assert.Equal(t, hdf.SeverityCritical, *req.Severity)
}

// --- rules defined on tool.extensions ---

func descriptionByLabel(t *testing.T, req hdf.EvaluatedRequirement, label string) string {
	t.Helper()
	for _, d := range req.Descriptions {
		if d.Label == label {
			return d.Data
		}
	}
	t.Fatalf("requirement %s has no %q description", req.ID, label)
	return ""
}

// fixtures/input/codeql-extensions.sarif is real CodeQL 2.17.4 output taken verbatim
// from SecureCodeWarrior/github-action-add-sarif-contextual-training (MIT) at commit
// 5b832744d3228f5fdea93c403514c2457e3485c4, path fixtures/codeql-extension-rules.sarif.
// Its tool.driver.rules is EMPTY and both rules live on tool.extensions[0].rules —
// the shape modern CodeQL emits, in which a driver-only rule map resolves nothing.
func TestConvertSarifToHDF_ResolvesRulesFromExtensions(t *testing.T) {
	inputData, err := os.ReadFile(fixturePath("codeql-extensions.sarif"))
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputData, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	byID := map[string]hdf.EvaluatedRequirement{}
	for _, req := range result.Baselines[0].Requirements {
		byID[req.ID] = req
	}

	// Resolving the rule is not the point — what the rule CARRIES is. Assert the
	// metadata that only an extension-defined rule can supply.
	pathInj, ok := byID["py/path-injection"]
	require.True(t, ok, "requirement for py/path-injection should exist")
	// The rationale description is the rule's fullDescription — nothing but a
	// resolved rule can supply it, so it proves resolution rather than merely
	// echoing the result. (Title is a weak witness here: deriveMetadata prefers
	// rule.Name, and CodeQL sets name equal to the rule id.)
	rationale := descriptionByLabel(t, pathInj, "rationale")
	assert.Equal(t, "Accessing paths influenced by users can allow an attacker to access unexpected resources.", rationale,
		"rationale must come from the extension rule's fullDescription")
	assert.Equal(t, 0.75, pathInj.Impact, "security-severity 7.5 on the extension rule")
	require.NotNil(t, pathInj.Severity)
	assert.Equal(t, hdf.SeverityHigh, *pathInj.Severity)
	assert.Contains(t, pathInj.Tags["cwe"], "CWE-022", "CWE must be extracted from the extension rule's tags")
	assert.Equal(t, []string{"SI-10"}, pathInj.Tags["nist"], "NIST controls derive from those CWEs")

	cmdInj, ok := byID["py/command-line-injection"]
	require.True(t, ok, "requirement for py/command-line-injection should exist")
	assert.Equal(t, 0.98, cmdInj.Impact, "security-severity 9.8 on the extension rule")
	require.NotNil(t, cmdInj.Severity)
	assert.Equal(t, hdf.SeverityCritical, *cmdInj.Severity)
	assert.Contains(t, cmdInj.Tags["cwe"], "CWE-078")
}

// SARIF permits the same rule id on the driver and on an extension. The driver is
// the primary tool component, so it wins; an extension must never silently shadow
// the tool's own definition. Pinned so map-iteration order can never decide it.
func TestConvertSarifToHDF_DriverRuleWinsOverExtensionRule(t *testing.T) {
	input := map[string]interface{}{
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":    "Test",
					"version": "1.0",
					"rules": []map[string]interface{}{{
						"id":               "DUP",
						"shortDescription": map[string]string{"text": "from the driver"},
					}},
				},
				"extensions": []map[string]interface{}{{
					"name": "ext",
					"rules": []map[string]interface{}{{
						"id":               "DUP",
						"shortDescription": map[string]string{"text": "from the extension"},
					}},
				}},
			},
			"results": []map[string]interface{}{{
				"ruleId":    "DUP",
				"level":     "warning",
				"message":   map[string]string{"text": "dup: description"},
				"locations": []interface{}{},
			}},
		}},
	}
	inputBytes, err := json.Marshal(input)
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputBytes, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	require.NotNil(t, req.Title)
	assert.Equal(t, "from the driver", *req.Title)
}

// The real CodeQL fixture's rules carry no helpUri, so the tag that only a
// resolved rule can populate is pinned synthetically instead of left unproven.
func TestConvertSarifToHDF_ExtensionRuleSuppliesHelpURI(t *testing.T) {
	input := map[string]interface{}{
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{"name": "Test", "version": "1.0"},
				"extensions": []map[string]interface{}{{
					"name": "ext",
					"rules": []map[string]interface{}{{
						"id":               "EXT-1",
						"shortDescription": map[string]string{"text": "defined only by the extension"},
						"helpUri":          "https://example.invalid/rules/EXT-1",
					}},
				}},
			},
			"results": []map[string]interface{}{{
				"ruleId":    "EXT-1",
				"level":     "warning",
				"message":   map[string]string{"text": "ext: description"},
				"locations": []interface{}{},
			}},
		}},
	}
	inputBytes, err := json.Marshal(input)
	require.NoError(t, err)

	result, err := ConvertSarifToHDF(inputBytes, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "https://example.invalid/rules/EXT-1", req.Tags["helpUri"],
		"helpUri must populate from a rule defined only on an extension")
	require.NotNil(t, req.Title)
	assert.Equal(t, "defined only by the extension", *req.Title)
}

// §3.14.23 makes null the default for an absent results array, and Appendix I gives
// that null a meaning: the tool "either failed to start or failed to begin its
// analysis". An empty array is the opposite — the tool ran and found nothing. Go
// decoded both to a nil slice, so a failed scan reported as a clean pass.
func TestConvertSarifToHDF_ResultsNullIsNotAPass(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "TestTool", "version": "1.0.0" } },
			"invocations": [ { "executionSuccessful": false } ],
			"results": null
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input), testConverterVersion)
	require.NoError(t, err, "a run that did not analyze is still a convertible document")
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status,
		"a tool that failed to start reviewed nothing; passed would assert a clean scan that never happened")
	assert.NotContains(t, req.Results[0].CodeDesc, "zero findings",
		"the text must not claim the tool reported anything")
}

// Absent and null are the same case per §3.14.23, so they must convert the same way.
func TestConvertSarifToHDF_ResultsAbsentMatchesResultsNull(t *testing.T) {
	absent := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"TestTool"}}}]}`
	null := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"TestTool"}},"results":null}]}`

	a, err := ConvertSarifToHDF([]byte(absent), testConverterVersion)
	require.NoError(t, err)
	n, err := ConvertSarifToHDF([]byte(null), testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, n.Baselines[0].Requirements[0].Results[0].Status,
		a.Baselines[0].Requirements[0].Results[0].Status,
		"§3.14.23: an absent results array defaults to null, so the two inputs are one case")
	assert.Equal(t, hdf.NotReviewed, a.Baselines[0].Requirements[0].Results[0].Status)
}

// The contrast is the point of the fix: these two inputs differ only in null versus
// empty, and they must not produce the same status.
func TestConvertSarifToHDF_NullAndEmptyResultsAreDistinguished(t *testing.T) {
	tool := `"tool": { "driver": { "name": "TestTool" } }`
	ranClean := `{"version":"2.1.0","runs":[{` + tool + `,"results":[]}]}`
	neverRan := `{"version":"2.1.0","runs":[{` + tool + `,"results":null}]}`

	clean, err := ConvertSarifToHDF([]byte(ranClean), testConverterVersion)
	require.NoError(t, err)
	never, err := ConvertSarifToHDF([]byte(neverRan), testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, hdf.Passed, clean.Baselines[0].Requirements[0].Results[0].Status,
		"an empty results array means the tool ran and found nothing")
	assert.Equal(t, hdf.NotReviewed, never.Baselines[0].Requirements[0].Results[0].Status)
	assert.NotEqual(t,
		clean.Baselines[0].Requirements[0].Results[0].Status,
		never.Baselines[0].Requirements[0].Results[0].Status,
		"if these match, the two SARIF states are indistinguishable after conversion")
}

// --- Severity resolution (§3.27.9, §3.27.10, §3.50.3) ---

// §3.27.10: a rule's defaultConfiguration.level applies only to a result "which
// does not itself specify a level property". The rule default previously won
// outright, so a rule's note beat a result's explicit error.
func TestConvertSarifToHDF_ResultLevelOutranksRuleDefault(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"note"}}]}},
		"results":[{"ruleId":"R1","level":"error","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.InDelta(t, 0.7, req.Impact, 0.0001,
		"the result's own error level must outrank the rule's note default")
	assert.Equal(t, "error", req.Tags["sarif-level"])
}

// GitHub documents that a security-severity of 0.0, and any value outside
// 0.0-10.0, is treated as having no security severity — so the level mapping
// applies. The impact floor masked this: it produced 0.1 while the level said error.
func TestConvertSarifToHDF_SecuritySeverityZeroFallsBackToLevel(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1",
			"defaultConfiguration":{"level":"error"},"properties":{"security-severity":"0.0"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.InDelta(t, 0.7, req.Impact, 0.0001,
		"security-severity 0.0 carries no severity, so the error level applies")
}

// §3.27.10: level "none" means "the concept of severity does not apply". It
// previously resolved to warning/0.5, inventing a middling severity for a finding
// explicitly marked as having none.
func TestConvertSarifToHDF_LevelNoneMeansSeverityDoesNotApply(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[{"ruleId":"R1","level":"none","kind":"informational","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Zero(t, req.Impact, "level none means severity does not apply, so impact is 0")
	assert.Equal(t, "none", req.Tags["sarif-level"])
}

// tags.severity held the SARIF level string while impact could derive from
// GitHub's security-severity, so one name carried two contradictory values.
func TestConvertSarifToHDF_SarifLevelTagReplacesSeverity(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"note"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	tags := result.Baselines[0].Requirements[0].Tags
	assert.Equal(t, "note", tags["sarif-level"])
	assert.NotContains(t, tags, "severity",
		"severity must mean the impact-derived band only; the SARIF level is sarif-level")
}

// A consumer cannot otherwise tell whether an impact came from GitHub's
// security-severity, a result's level, the rule default, or the fallback.
func TestConvertSarifToHDF_SeverityProvenanceIsRecoverable(t *testing.T) {
	cases := []struct{ name, rules, result, want string }{
		{"security-severity", `{"id":"R1","properties":{"security-severity":"8.6"}}`, `"kind":"fail"`, "security-severity"},
		{"result level", `{"id":"R1"}`, `"level":"error","kind":"fail"`, "result-level"},
		{"rule default", `{"id":"R1","defaultConfiguration":{"level":"note"}}`, `"kind":"fail"`, "rule-default"},
		{"fallback", `{"id":"R1"}`, `"kind":"fail"`, "fallback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(`{"version":"2.1.0","runs":[{
				"tool":{"driver":{"name":"T","rules":[` + tc.rules + `]}},
				"results":[{"ruleId":"R1",` + tc.result + `,"message":{"text":"m"},
					"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)
			result, err := ConvertSarifToHDF(input, testConverterVersion)
			require.NoError(t, err)
			assert.Equal(t, tc.want, result.Baselines[0].Requirements[0].Tags["sarif-severity-source"])
		})
	}
}

// A rule group mixing levels took the FIRST fail-kind result's level, so an error
// reported after a note was presented as a note. The worst level in the group is
// the only safe requirement-level summary while HDF has no per-result severity field.
func TestConvertSarifToHDF_MixedLevelGroupTakesTheWorst(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[
			{"ruleId":"R1","level":"note","kind":"fail","message":{"text":"low"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]},
			{"ruleId":"R1","level":"error","kind":"fail","message":{"text":"high"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":2}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.InDelta(t, 0.7, req.Impact, 0.0001,
		"a note listed before an error must not hide the error")
	assert.Equal(t, "error", req.Tags["sarif-level"])
}

// §3.27.10 forces level "none" on any non-failing result, so a none carried by a
// passing result is spec compliance rather than a severity statement and must not
// discard the rule's own declared level.
func TestConvertSarifToHDF_RuleDefaultBeatsNoneOnAPassingResult(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"note"}}]}},
		"results":[{"ruleId":"R1","level":"none","kind":"pass","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.InDelta(t, 0.3, req.Impact, 0.0001, "the rule's declared note must survive")
	assert.Equal(t, "note", req.Tags["sarif-level"])
}

// §3.27.10 defines "none" as severity not applying BECAUSE kind is not "fail", so a
// "none" on a failing result contradicts the definition and must not be honoured.
// Honouring it would put a reported failure at impact 0, which the effective-status
// ladder reads as notApplicable — dropping a real finding out of the denominator.
func TestConvertSarifToHDF_NoneOnAFailingResultIsNotHonoured(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","level":"none","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.InDelta(t, 0.7, req.Impact, 0.0001, "the rule's error default applies; impact must not be 0")
	assert.NotZero(t, req.Impact, "a reported failure must never land at impact 0")
	assert.Equal(t, "error", req.Tags["sarif-level"])
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

// The companion to the test above, and the one that actually guards the hazard: with
// NO rule default to fall back on, honouring a failing result's "none" would resolve
// the group to none and put a reported failure at impact 0. The rule-default branch
// masks that, so a case without one is required to pin it.
func TestConvertSarifToHDF_NoneOnAFailingResultWithNoRuleDefault(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[{"ruleId":"R1","level":"none","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.NotZero(t, req.Impact, "a reported failure must never land at impact 0")
	assert.InDelta(t, 0.5, req.Impact, 0.0001, "falls through to the SARIF default level")
	assert.Equal(t, "warning", req.Tags["sarif-level"])
	assert.Equal(t, "fallback", req.Tags["sarif-severity-source"])
}

// --- Per-result carriage (§3.27.2, §3.27.12, §3.27.16) ---

// Results sharing a ruleId become one requirement, and everything past the first was
// dropped. Fingerprints are the identity mechanism cross-run correlation depends on,
// so losing them is the loss most destructive to trend analysis over SARIF input.
func TestConvertSarifToHDF_EveryResultsFingerprintsSurvive(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[
			{"ruleId":"R1","kind":"fail","level":"error","message":{"text":"a"},
			 "partialFingerprints":{"h":"first"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]},
			{"ruleId":"R1","kind":"fail","level":"error","message":{"text":"b"},
			 "partialFingerprints":{"h":"second"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":2}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 2)

	per, ok := req.Tags["sarif-results"].([]map[string]interface{})
	require.True(t, ok, "sarif-results must carry one entry per HDF result")
	require.Len(t, per, 2)

	got := make([]string, 0, 2)
	for _, entry := range per {
		fp, ok := entry["partialFingerprints"].(map[string]string)
		require.True(t, ok, "entry must carry partialFingerprints")
		got = append(got, fp["h"])
	}
	assert.ElementsMatch(t, []string{"first", "second"}, got,
		"the second result's fingerprint must not be discarded")
}

// A group whose results disagree on kind previously reported only the first one's,
// claiming a single kind the group does not have.
func TestConvertSarifToHDF_MixedKindGroupDoesNotClaimOneKind(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[
			{"ruleId":"R1","kind":"pass","message":{"text":"a"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]},
			{"ruleId":"R1","kind":"fail","message":{"text":"b"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":2}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]

	assert.NotContains(t, req.Tags, "kind",
		"a mixed group must not publish one kind; the per-result entries carry them")

	per := req.Tags["sarif-results"].([]map[string]interface{})
	require.Len(t, per, 2)
	kinds := make([]string, 0, 2)
	for _, e := range per {
		k, ok := e["kind"].(string)
		require.True(t, ok, "each entry must carry a kind")
		kinds = append(kinds, k)
	}
	assert.ElementsMatch(t, []string{"pass", "fail"}, kinds)
}

// A uniform group keeps the aggregate, because it is accurate there.
func TestConvertSarifToHDF_UniformKindGroupKeepsTheAggregate(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[
			{"ruleId":"R1","kind":"fail","level":"error","message":{"text":"a"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]},
			{"ruleId":"R1","kind":"fail","level":"error","message":{"text":"b"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":2}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.Equal(t, "fail", result.Baselines[0].Requirements[0].Tags["kind"])
}

// ADR-0017 scoped rawSourceRecord to the result precisely because records merged onto
// a requirement collide and one has to be discarded — which is this defect.
func TestConvertSarifToHDF_EachResultCarriesItsRawSourceRecord(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[
			{"ruleId":"R1","kind":"fail","level":"error","message":{"text":"alpha"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]},
			{"ruleId":"R1","kind":"fail","level":"error","message":{"text":"beta"},
			 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":2}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 2)

	for i, want := range []string{"alpha", "beta"} {
		rec := req.Results[i].RawSourceRecord
		require.NotNil(t, rec, "result %d must carry its own native record", i)
		assert.Equal(t, "application/json", rec.MediaType)
		assert.Contains(t, rec.Content, want, "the record must be THIS result, verbatim")
		// It must round-trip as JSON, not be a lossy rendering.
		var back map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(rec.Content), &back))
		assert.Equal(t, "R1", back["ruleId"])
		require.NotNil(t, rec.Pointer)
		assert.Equal(t, "/runs/0/results/"+strconv.Itoa(i), *rec.Pointer)
	}
}

// §3.27.12: "The locations array SHALL NOT be used to specify distinct occurrences of
// the same result." The importer expands one result per location anyway, so the
// original result count has to be recoverable or cardinality is lost.
func TestConvertSarifToHDF_SourceResultCountIsRecoverable(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[{"ruleId":"R1","kind":"fail","level":"error","message":{"text":"a"},
			"locations":[
				{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}},
				{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":2}}},
				{"physicalLocation":{"artifactLocation":{"uri":"c.c"},"region":{"startLine":3}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Len(t, req.Results, 3, "one HDF result per location, as today")
	assert.EqualValues(t, 1, req.Tags["sarif-source-result-count"],
		"one SARIF result produced those three, and that must stay recoverable")
}

// tags["kind"] carries what the tool WROTE, like tags["sarif-level"]. §3.27.9 defaults
// an absent kind to "fail", but publishing that derived value under the same key would
// silently change the tag's meaning from "the tool said this" to "the spec implies
// this" — and the effective value is already in the per-result entries.
func TestConvertSarifToHDF_AbsentKindIsNotPublishedAsAnAggregate(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]

	assert.NotContains(t, req.Tags, "kind",
		"the tool stated no kind, so no aggregate kind may be published")

	per, ok := req.Tags["sarif-results"].([]map[string]interface{})
	require.True(t, ok)
	require.Len(t, per, 1)
	assert.Equal(t, "fail", per[0]["kind"],
		"the per-result entry is where the §3.27.9 default belongs")
}

// A record re-marshalled from the typed struct would silently drop every SARIF
// property the struct does not declare — 17 of the 30 the spec defines, including the
// cross-run correlation fields this carriage exists to preserve. No fixture carries
// them, so only a named test pins it.
func TestConvertSarifToHDF_RawSourceRecordKeepsUnmodeledProperties(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"guid":"11111111-2222-3333-4444-555555555555",
			"correlationGuid":"66666666-7777-8888-9999-000000000000",
			"baselineState":"unchanged","rank":42.5,
			"hostedViewerUri":"https://example.test/v/1",
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	rec := result.Baselines[0].Requirements[0].Results[0].RawSourceRecord
	require.NotNil(t, rec)
	assert.Equal(t, hdf.UTF8, rec.Encoding)

	var back map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rec.Content), &back))
	for _, k := range []string{"guid", "correlationGuid", "baselineState", "rank", "hostedViewerUri"} {
		assert.Contains(t, back, k, "SarifResult does not declare %q, so only an untyped record keeps it", k)
	}
	assert.Equal(t, "unchanged", back["baselineState"])
}

// Go HTML-escapes <, > and & by default and JavaScript does not, so a record holding
// any of them would differ between the languages. The corpus happens to cover this
// through one fixture's C snippet; this pins it directly so trimming that fixture
// cannot remove the guard silently.
func TestConvertSarifToHDF_RawSourceRecordDoesNotHTMLEscape(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"a && b < c > d"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	rec := result.Baselines[0].Requirements[0].Results[0].RawSourceRecord
	require.NotNil(t, rec)
	// The positive form is the whole guard: had Go escaped them, the content would
	// hold \u0026 and so could not hold the raw text.
	assert.Contains(t, rec.Content, "a && b < c > d")
	escaped := "\\" + "u00"
	assert.NotContains(t, rec.Content, escaped, "no character may be \\u00XX-escaped")
}

// --- Go/TypeScript conformance parity (§3.13.4, §3.4.5) ---

// §3.13.4 makes an empty runs array conformant. Go rejected it while TypeScript
// converted it, so one language refused a file the other accepted. A zero-baseline
// HDF document is schema-valid (baselines has no minItems), so accepting is the
// answer: refusing a conformant document is the worse failure.
func TestConvertSarifToHDF_EmptyRunsIsAccepted(t *testing.T) {
	result, err := ConvertSarifToHDF([]byte(`{"version":"2.1.0","runs":[]}`), testConverterVersion)
	require.NoError(t, err, "an empty runs array is conformant SARIF and must convert")
	assert.Empty(t, result.Baselines, "no runs means no baselines, not an error")
	require.NotNil(t, result.Generator)
}

// §3.4.5 permits an artifactLocation with no uri, because region — which carries the
// line and column — is a SIBLING of artifactLocation, not inside it. So the position
// is known even when the file is not, and discarding it loses data we have because of
// data we do not.
func TestConvertSarifToHDF_UriLessLocationKeepsItsRegion(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"index":0},"region":{"startLine":5,"startColumn":7}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)

	cd := req.Results[0].CodeDesc
	assert.Contains(t, cd, "LINE : 5", "the line is known and must survive")
	assert.Contains(t, cd, "COLUMN : 7")
	assert.NotContains(t, cd, "URL :", "no uri is known, so no empty URL slot may be published")

	require.NotNil(t, req.SourceLocation)
	require.NotNil(t, req.SourceLocation.Line)
	assert.EqualValues(t, 5, *req.SourceLocation.Line)
	assert.Nil(t, req.SourceLocation.Ref, "there is no ref to report")
}

// A bare time.Now() carries the host's zone, so the same input produced a different
// document in a different TZ — and diverged from TypeScript, which always emits Z.
// The canonical HDF form is trimmed-UTC RFC3339.
func TestConvertSarifToHDF_TimestampsAreUTCRegardlessOfHostZone(t *testing.T) {
	// Pin a non-UTC Local for the duration: asserting a zero offset would otherwise
	// pass under TZ=UTC whether or not the converter normalizes, and TZ=UTC is how
	// this suite normally runs — so the test would be vacuous exactly where it runs.
	saved := time.Local
	time.Local = time.FixedZone("TEST+09", 9*60*60)
	t.Cleanup(func() { time.Local = saved })

	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Timestamp)

	_, offset := result.Timestamp.Zone()
	assert.Zero(t, offset, "the document timestamp must carry a zero offset, not the host's")
	_, resultOffset := result.Baselines[0].Requirements[0].Results[0].StartTime.Zone()
	assert.Zero(t, resultOffset, "a result's startTime must carry a zero offset")
}

// SARIF 2.0 support is removed: it was never reachable for a real 2.0 document,
// because the normalization required tool.driver, which 2.1 introduced. Both
// languages now treat such a document the same way — resources.rules is simply not a
// place rules are looked for.
func TestConvertSarifToHDF_SarifTwoZeroResourcesRulesAreNotNormalized(t *testing.T) {
	input := []byte(`{"version":"2.0.0","runs":[{"tool":{"driver":{"name":"T"}},
		"resources":{"rules":[{"id":"R1","name":"RuleOne","defaultConfiguration":{"level":"error"}}]},
		"results":[{"ruleId":"R1","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "m", *req.Title, "the rule is not found, so the message is the title")
	assert.InDelta(t, 0.5, req.Impact, 0.0001, "no rule means the fallback level")
}

// Canonical HDF time is UTC at MILLISECOND precision — hdfutil.NormalizeTimestamp
// exists so Go output is byte-identical to the TypeScript peer. A bare time.Now()
// carried the host's zone, and .UTC() alone would have left Go emitting microseconds
// where JavaScript emits milliseconds, so the fraction length is asserted too.
func TestConvertSarifToHDF_TimestampsAreCanonicalMillisecondUTC(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("TEST+09", 9*60*60)
	t.Cleanup(func() { time.Local = saved })

	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Timestamp)

	for name, ts := range map[string]time.Time{
		"document timestamp": *result.Timestamp,
		"result startTime":   result.Baselines[0].Requirements[0].Results[0].StartTime,
	} {
		_, offset := ts.Zone()
		assert.Zero(t, offset, "%s must carry a zero offset, not the host's", name)
		assert.Zero(t, ts.Nanosecond()%1_000_000,
			"%s must be truncated to milliseconds, which is what JavaScript emits", name)
	}
}

// Refusing an unsupported explicit version is the one new user-visible behaviour in
// dropping SARIF 2.0, and it has to be asserted: without this, replacing the guard call
// with a no-op passes the whole package, and the CLI would silently accept
// --from sarif@2.0 again while doing nothing with it.
func TestConvertSarifToHDF_RefusesAnUnsupportedExplicitVersion(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[]}]}`)

	for _, requested := range []string{"2.0.0", "2.0", "1.0.0", "3.0.0"} {
		t.Run(requested, func(t *testing.T) {
			_, err := ConvertSarifToHDF(input, testConverterVersion, requested)
			require.Error(t, err, "an explicit %q must be refused, not ignored", requested)
			assert.Contains(t, err.Error(), "unsupported input version")
			assert.Contains(t, err.Error(), requested, "the error must name the version asked for")

			// ExpectedRequirementCount shares the guard, so it must refuse identically —
			// the two exist to accept and reject exactly the same inputs.
			_, _, countErr := ExpectedRequirementCount(input, requested)
			require.Error(t, countErr, "the count path must refuse %q too", requested)
		})
	}
}

// The supported version, and an omitted one, both convert.
func TestConvertSarifToHDF_AcceptsTheSupportedExplicitVersion(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`)

	for _, requested := range []string{"", "2.1.0", "2.1"} {
		_, err := ConvertSarifToHDF(input, testConverterVersion, requested)
		require.NoError(t, err, "%q must be accepted", requested)
	}
}

// --- artifactLocation.index resolution (§3.4.5) ---

// sarifWithIndexedLocation builds a run whose single result is addressed by index.
// loc is the raw artifactLocation JSON, so a test can omit index entirely.
func sarifWithIndexedLocation(t *testing.T, artifacts, loc string) []byte {
	t.Helper()
	return []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"artifacts":` + artifacts + `,
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":` + loc + `,
				"region":{"startLine":42,"startColumn":9}}}]}]}]}`)
}

// §3.4.5 guarantees an index when uri is absent, so the path IS recoverable.
func TestConvertSarifToHDF_IndexResolvesToTheArtifactPath(t *testing.T) {
	input := sarifWithIndexedLocation(t,
		`[{"location":{"uri":"src/indexed.c"}},{"location":{"uri":"src/other.c"}}]`,
		`{"index":0}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]

	require.NotNil(t, req.SourceLocation)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "src/indexed.c", *req.SourceLocation.Ref)
	assert.Contains(t, req.Results[0].CodeDesc, "URL : src/indexed.c")
	assert.Contains(t, req.Results[0].CodeDesc, "LINE : 42")
}

// The index must select the artifact it names, not simply the first.
func TestConvertSarifToHDF_IndexSelectsTheNamedArtifact(t *testing.T) {
	input := sarifWithIndexedLocation(t,
		`[{"location":{"uri":"src/first.c"}},{"location":{"uri":"src/second.c"}}]`,
		`{"index":1}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.Equal(t, "src/second.c", *result.Baselines[0].Requirements[0].SourceLocation.Ref)
}

// THE TYPING HAZARD. The schema gives index `default: -1`, so decoding it into a plain
// int makes an ABSENT index arrive as 0 — which would resolve every uri-less location
// to artifacts[0] and invent a path the document never claimed.
func TestConvertSarifToHDF_AbsentIndexDoesNotResolveToTheFirstArtifact(t *testing.T) {
	cases := map[string]string{
		"index absent":   `{}`,
		"index -1":       `{"index":-1}`,
		"out of range":   `{"index":7}`,
		"negative other": `{"index":-5}`,
	}
	for name, loc := range cases {
		t.Run(name, func(t *testing.T) {
			input := sarifWithIndexedLocation(t, `[{"location":{"uri":"src/first.c"}}]`, loc)
			result, err := ConvertSarifToHDF(input, testConverterVersion)
			require.NoError(t, err, "an unresolvable index must fall back, not fail")
			req := result.Baselines[0].Requirements[0]

			if req.SourceLocation != nil && req.SourceLocation.Ref != nil {
				assert.NotEqual(t, "src/first.c", *req.SourceLocation.Ref,
					"%s must not acquire artifacts[0]'s path", name)
			}
			assert.NotContains(t, req.Results[0].CodeDesc, "URL :",
				"%s resolves to no path, so no URL slot", name)
			assert.Contains(t, req.Results[0].CodeDesc, "LINE : 42",
				"the line is still known and must survive")
		})
	}
}

// A run carrying no artifacts table cannot resolve anything.
func TestConvertSarifToHDF_IndexWithoutAnArtifactsTableFallsBack(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"index":0},
				"region":{"startLine":42,"startColumn":9}}}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.NotContains(t, req.Results[0].CodeDesc, "URL :")
	assert.Contains(t, req.Results[0].CodeDesc, "LINE : 42")
}

// An explicit uri outranks an index; §3.4.5's index exists for when uri is ABSENT.
func TestConvertSarifToHDF_ExplicitUriOutranksTheIndex(t *testing.T) {
	input := sarifWithIndexedLocation(t,
		`[{"location":{"uri":"src/indexed.c"}}]`,
		`{"uri":"src/explicit.c","index":0}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.Equal(t, "src/explicit.c", *result.Baselines[0].Requirements[0].SourceLocation.Ref)
}

// An artifact whose own location is index-addressed is NOT followed: resolution is one
// level deep, so a chain cannot loop and a consumer is never handed a path this
// converter inferred transitively.
func TestConvertSarifToHDF_ArtifactIndirectionIsNotFollowed(t *testing.T) {
	input := sarifWithIndexedLocation(t,
		`[{"location":{"index":1}},{"location":{"uri":"src/real.c"}}]`,
		`{"index":0}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.NotContains(t, req.Results[0].CodeDesc, "URL :",
		"artifacts[0] has no uri of its own, and its index is not chased")
	assert.Contains(t, req.Results[0].CodeDesc, "LINE : 42")
}

// The resolved uri must NOT reach the native record: rawSourceRecord is the tool's own
// record, and a uri this converter inferred from the artifacts table is not something
// the tool wrote. Go is structurally safe because the record comes from the unparsed
// bytes, while the TypeScript peer rewrites the parsed object and had to snapshot it
// first — so this pins the invariant on both sides rather than only where it broke.
func TestConvertSarifToHDF_ResolvedUriDoesNotReachTheNativeRecord(t *testing.T) {
	input := sarifWithIndexedLocation(t, `[{"location":{"uri":"src/indexed.c"}}]`, `{"index":0}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	require.Contains(t, req.Results[0].CodeDesc, "URL : src/indexed.c",
		"the mapped output resolves the path")

	rec := req.Results[0].RawSourceRecord
	require.NotNil(t, rec)
	assert.NotContains(t, rec.Content, "src/indexed.c",
		"the record must report what the tool wrote, not what we inferred")

	var back struct {
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation map[string]interface{} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	// Decoded into a typed shape rather than chained interface assertions: a regression
	// that drops locations would panic and abort the binary instead of failing cleanly.
	require.NoError(t, json.Unmarshal([]byte(rec.Content), &back))
	require.Len(t, back.Locations, 1)
	al := back.Locations[0].PhysicalLocation.ArtifactLocation
	assert.NotContains(t, al, "uri", "the source record carried only an index")
	assert.EqualValues(t, 0, al["index"])
}

// extractBacktrace reads code-flow step locations for their uri, and those steps may be
// index-addressed too. Resolving only a result's own locations left a backtrace entry as
// ":7" — an empty path with a bare line, the exact loss index resolution exists to
// prevent — and CodeQL, the heaviest code-flow producer, is the family that hits it.
func TestConvertSarifToHDF_CodeFlowStepsResolveTheirIndex(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}},
		"artifacts":[{"location":{"uri":"src/sink.c"}},{"location":{"uri":"src/flow.c"}}],
		"results":[{"ruleId":"R1","kind":"fail","message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"index":0},"region":{"startLine":42}}}],
			"codeFlows":[{"threadFlows":[{"locations":[
				{"location":{"physicalLocation":{"artifactLocation":{"index":1},"region":{"startLine":7}}}}]}]}]}]}]}`)

	result, err := ConvertSarifToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]

	assert.Contains(t, req.Results[0].CodeDesc, "URL : src/sink.c",
		"the result's own location resolves")
	require.NotEmpty(t, req.Results[0].Backtrace, "the code flow produces a backtrace")
	assert.Contains(t, req.Results[0].Backtrace[0], "src/flow.c",
		"a code-flow step addressed by index must resolve too, not land as \":7\"")
	assert.NotEqual(t, ":7", req.Results[0].Backtrace[0])
}

// §3.27.10 resolves a level PER FAILING RESULT -- the result's own level, else the
// rule default, else warning -- and only then does worst-wins rank them. Ranking the
// raw result levels instead lets an explicitly low level outrank a higher one a
// level-less result inherited from the rule.
func TestResolveRuleLevel_WorstWinsAcrossInheritedLevels(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ruleLevel  string
		results    []SarifResult
		wantLevel  string
		wantSource string
	}{
		{
			name:      "level-less failing result inherits a higher rule default",
			ruleLevel: "error",
			results:   []SarifResult{{Level: "note"}, {Level: ""}},
			// The level-less result inherits error, which outranks the explicit note.
			wantLevel: "error", wantSource: severitySourceRuleDefault,
		},
		{
			name:      "an explicit level still wins when it outranks the default",
			ruleLevel: "note",
			results:   []SarifResult{{Level: "error"}, {Level: ""}},
			wantLevel: "error", wantSource: severitySourceResultLevel,
		},
		{
			name:      "no rule default: a level-less failing result falls back to warning",
			ruleLevel: "",
			results:   []SarifResult{{Level: "note"}, {Level: ""}},
			wantLevel: "warning", wantSource: severitySourceFallback,
		},
		{
			name:      "every failing result level-less: the rule default governs",
			ruleLevel: "error",
			results:   []SarifResult{{Level: ""}, {Level: ""}},
			wantLevel: "error", wantSource: severitySourceRuleDefault,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rule *ReportingDescriptor
			if tc.ruleLevel != "" {
				rule = &ReportingDescriptor{DefaultConfiguration: &ReportingConfiguration{Level: tc.ruleLevel}}
			}
			gotLevel, gotSource := resolveRuleLevel(rule, tc.results)
			assert.Equal(t, tc.wantLevel, gotLevel, "level")
			assert.Equal(t, tc.wantSource, gotSource, "severity source")
		})
	}
}

// SupportedVersions() advertises exactly "2.1.0", so the guard must refuse everything
// else. A prefix test accepted 2.10 and 2.1-beta -- versions the vendored schema's own
// version enum does not admit -- so the advertised contract and the enforcement
// disagreed.
func TestAssertSupportedVersion_AcceptsOnlyTheAdvertisedVersion(t *testing.T) {
	// "2.1" names the same format as "2.1.0" — the minor series has one member — so a
	// caller spelling it either way is being specific and both are accepted.
	for _, v := range []string{"", "2.1.0", "2.1"} {
		assert.NoError(t, assertSupportedVersion(v), "must accept %q", v)
	}
	// None of these designates SARIF 2.1.0. "2" is ambiguous while the unsupported 2.0
	// committee draft exists; the rest are what a prefix match wrongly let through.
	for _, v := range []string{"2.10", "2.1-beta", "2.1garbage", "2.1.1", "2.0.0", "2", "3.0"} {
		assert.Error(t, assertSupportedVersion(v), "must refuse %q", v)
	}
}

// The vendored schema's physicalLocation.anyOf is [{required:[address]},
// {required:[artifactLocation]}], so a conformant location may carry an address and no
// artifactLocation. Gating on artifactLocation alone discarded the region's line, which
// IS representable; gating on physicalLocation alone invented "LINE : 0 COLUMN : 0" for
// an address with no region, which is not. Keep a location when there is something to
// say about it.
func TestConvertSarifToHDF_AddressLocationsKeepOnlyWhatIsRepresentable(t *testing.T) {
	doc := func(physical string) []byte {
		return []byte(`{"version":"2.1.0","runs":[{
			"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
			"results":[{"ruleId":"R1","level":"error","message":{"text":"m"},
				"locations":[{"physicalLocation":` + physical + `}]}]}]}`)
	}
	for _, tc := range []struct {
		name     string
		physical string
		want     string
	}{
		{
			name:     "address with a region keeps the position",
			physical: `{"address":{"absoluteAddress":4198400},"region":{"startLine":42,"startColumn":7}}`,
			want:     "LINE : 42 COLUMN : 7",
		},
		{
			name:     "address with no region has nothing to report",
			physical: `{"address":{"absoluteAddress":4198400}}`,
			want:     "No source location",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ConvertSarifToHDF(doc(tc.physical), testConverterVersion, "")
			require.NoError(t, err)
			require.Len(t, out.Baselines[0].Requirements[0].Results, 1)
			assert.Equal(t, tc.want, out.Baselines[0].Requirements[0].Results[0].CodeDesc)
		})
	}
}

// Decoding into interface{} makes every number a float64, which rounds any integer
// above 2^53 — the record would then report a value the source never contained. The
// tokens below are also the ones where Go and JavaScript disagree if either side
// re-formats: 1.0, 1e5 and -0 all survive a json.Number round trip and all change
// under String()/strconv.
func TestRawSourceRecord_PreservesNumericTokensExactly(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[{"ruleId":"R1","level":"error","message":{"text":"m"},
			"properties":{"big":9007199254740993,"flt":1.0,"exp":1e5,"negz":-0,"tiny":0.1}}]}]}`)
	out, err := ConvertSarifToHDF(input, testConverterVersion, "")
	require.NoError(t, err)
	rec := out.Baselines[0].Requirements[0].Results[0].RawSourceRecord
	require.NotNil(t, rec)
	for _, want := range []string{
		`"big":9007199254740993`,
		`"exp":1e5`,
		`"flt":1.0`,
		`"negz":-0`,
		`"tiny":0.1`,
	} {
		assert.Contains(t, rec.Content, want)
	}
	assert.NotContains(t, rec.Content, "9007199254740992", "the integer must not be rounded")
}

// One SARIF result with several locations expands to several HDF results, but they
// share ONE source record, so exactly one of them carries it. Copying it onto each
// made the output grow with the square of the location count, because the record
// itself contains the locations array.
func TestRawSourceRecord_CarriedOncePerSourceResult(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"T","rules":[{"id":"R1"}]}},
		"results":[{"ruleId":"R1","level":"error","message":{"text":"m"},"locations":[
			{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}},
			{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":2}}},
			{"physicalLocation":{"artifactLocation":{"uri":"c.c"},"region":{"startLine":3}}}]}]}]}`)
	out, err := ConvertSarifToHDF(input, testConverterVersion, "")
	require.NoError(t, err)
	rows := out.Baselines[0].Requirements[0].Results
	require.Len(t, rows, 3, "one HDF result per location")

	withRecord := 0
	for _, r := range rows {
		if r.RawSourceRecord != nil {
			withRecord++
		}
	}
	assert.Equal(t, 1, withRecord, "exactly one result carries the shared record")
	require.NotNil(t, rows[0].RawSourceRecord, "it is the first")
	assert.Equal(t, "/runs/0/results/0", *rows[0].RawSourceRecord.Pointer)
}
