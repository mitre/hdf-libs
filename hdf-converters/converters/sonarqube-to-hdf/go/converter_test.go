package sonarqube

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "test-version"

func TestHasFlows(t *testing.T) {
	assert.True(t, hasFlows(json.RawMessage(`[{"x":1}]`)))
	assert.False(t, hasFlows(json.RawMessage(`[]`)))
	assert.False(t, hasFlows(json.RawMessage(`[ ]`)))
	assert.False(t, hasFlows(json.RawMessage("[\n  ]")))
	assert.False(t, hasFlows(json.RawMessage(`null`)))
	assert.False(t, hasFlows(json.RawMessage(``)))
}

func loadMinimalFixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := filepath.Join(shared.GetConvertersDir(), "sonarqube-to-hdf", "fixtures", "input", "minimal.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read minimal.json fixture")
	return data
}

// ---- Structure and generator tests ----

func TestConvertSonarqubeToHDF_Structure(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	assert.NotNil(t, result.Timestamp, "Timestamp should not be nil")
	assert.NotEmpty(t, result.Baselines, "Baselines should not be empty")

	require.NotNil(t, result.Generator, "Generator should not be nil")
	assert.Equal(t, "sonarqube-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)
}

func TestConvertSonarqubeToHDF_Tool(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "SonarQube", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestConvertSonarqubeToHDF_OneBaselinePerProject(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	// Minimal fixture has 1 project
	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "com.example:myproject", result.Baselines[0].Name)
	assert.NotEmpty(t, result.Baselines[0].Requirements)
}

func TestConvertSonarqubeToHDF_OneRequirementPerRule(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	require.Len(t, baseline.Requirements, 2, "Minimal fixture has 2 rules")

	ids := make(map[string]bool)
	for _, req := range baseline.Requirements {
		ids[req.ID] = true
	}
	assert.True(t, ids["java:S1144"], "expected rule java:S1144")
	assert.True(t, ids["java:S2259"], "expected rule java:S2259")
}

// ---- Correctness tests ----

func TestConvertSonarqubeToHDF_TimestampParsing(t *testing.T) {
	// The minimal fixture has creationDate "2026-01-15T10:30:00+0000" (SonarQube format with +0000,
	// not +00:00). time.RFC3339 would silently produce a zero time; our format must parse it correctly.
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	for _, req := range baseline.Requirements {
		for _, res := range req.Results {
			assert.False(t, res.StartTime.IsZero(),
				"StartTime should be non-zero for rule %s (got %v)", req.ID, res.StartTime)
		}
	}
}

func TestConvertSonarqubeToHDF_ImpactMapping(t *testing.T) {
	input := []byte(`{
		"total": 4, "p": 1, "ps": 100,
		"paging": {"pageIndex": 1, "pageSize": 100, "total": 4},
		"issues": [
			{"key":"k1","rule":"r:CRITICAL","severity":"CRITICAL","component":"proj:file","project":"proj","status":"OPEN","message":"msg","creationDate":"2026-01-01T00:00:00+0000","updateDate":"2026-01-01T00:00:00+0000","type":"VULNERABILITY"},
			{"key":"k2","rule":"r:INFO","severity":"INFO","component":"proj:file","project":"proj","status":"OPEN","message":"msg","creationDate":"2026-01-01T00:00:00+0000","updateDate":"2026-01-01T00:00:00+0000","type":"CODE_SMELL"},
			{"key":"k3","rule":"r:BLOCKER","severity":"BLOCKER","component":"proj:file","project":"proj","status":"OPEN","message":"msg","creationDate":"2026-01-01T00:00:00+0000","updateDate":"2026-01-01T00:00:00+0000","type":"BUG"},
			{"key":"k4","rule":"r:MAJOR","severity":"MAJOR","component":"proj:file","project":"proj","status":"OPEN","message":"msg","creationDate":"2026-01-01T00:00:00+0000","updateDate":"2026-01-01T00:00:00+0000","type":"CODE_SMELL"}
		],
		"components": [], "rules": []
	}`)

	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)

	impactByRule := make(map[string]float64)
	for _, req := range result.Baselines[0].Requirements {
		impactByRule[req.ID] = req.Impact
	}

	assert.Equal(t, 0.7, impactByRule["r:CRITICAL"], "CRITICAL should map to 0.7")
	assert.Equal(t, 0.0, impactByRule["r:INFO"], "INFO should map to 0.0")
	assert.Equal(t, 1.0, impactByRule["r:BLOCKER"], "BLOCKER should map to 1.0")
	assert.Equal(t, 0.5, impactByRule["r:MAJOR"], "MAJOR should map to 0.5")
}

func TestConvertSonarqubeToHDF_CWENISTMapping(t *testing.T) {
	// CWE-476 (NULL Pointer Dereference) maps to SI-10 via cwe.NISTControls.
	// java:S2259 in the minimal fixture has the cwe-476 tag.
	// The NIST controls should be SI-10, not the generic SA-11 default.
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	var ruleWithCWE *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "java:S2259" {
			ruleWithCWE = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, ruleWithCWE, "expected to find rule java:S2259")

	nistVal, ok := ruleWithCWE.Tags["nist"]
	require.True(t, ok, "expected 'nist' tag")

	nistSlice, ok := nistVal.([]string)
	require.True(t, ok, "expected nist to be []string, got %T", nistVal)

	found := false
	for _, ctrl := range nistSlice {
		if ctrl == "SI-10" {
			found = true
			break
		}
	}
	assert.True(t, found, "CWE-476 should produce SI-10 in NIST controls; got %v", nistSlice)

	// Should NOT have fallen back to the generic code-quality default
	for _, ctrl := range nistSlice {
		assert.NotEqual(t, "SA-11", ctrl,
			"CWE-476 should produce SI-10, not the generic SA-11 fallback")
	}
}

// ---- Description and component tests (migrated to testify) ----

func TestExtractDescription(t *testing.T) {
	t.Run("rule is nil with hasRule false returns empty", func(t *testing.T) {
		result := extractDescription(nil, false)
		assert.Equal(t, "", result)
	})

	t.Run("hasRule false returns empty regardless of rule content", func(t *testing.T) {
		rule := &Rule{Name: "some rule", MDDesc: "some desc"}
		result := extractDescription(rule, false)
		assert.Equal(t, "", result)
	})

	t.Run("MDDesc takes priority over HTMLDesc", func(t *testing.T) {
		rule := &Rule{Name: "rule", MDDesc: "markdown desc", HTMLDesc: "<p>html desc</p>"}
		result := extractDescription(rule, true)
		assert.Equal(t, "markdown desc", result)
	})

	t.Run("HTMLDesc is stripped when MDDesc is empty", func(t *testing.T) {
		rule := &Rule{Name: "rule", HTMLDesc: "<p>This is <b>HTML</b> content</p>"}
		result := extractDescription(rule, true)
		assert.NotEmpty(t, result)
		assert.NotContains(t, result, "<p>")
		assert.NotContains(t, result, "<b>")
		assert.Contains(t, result, "HTML")
	})

	t.Run("falls back to rule name when both descs empty", func(t *testing.T) {
		rule := &Rule{Name: "fallback name"}
		result := extractDescription(rule, true)
		assert.Equal(t, "fallback name", result)
	})
}

func TestComponentPathResolution(t *testing.T) {
	t.Run("component with Path uses Path", func(t *testing.T) {
		componentMap := map[string]Component{
			"comp:key": {Key: "comp:key", Path: "src/Main.java", LongName: "com.example.Main"},
		}
		line := 10
		issue := Issue{
			Component:    "comp:key",
			Rule:         "java:S001",
			Severity:     "MAJOR",
			Status:       "OPEN",
			Message:      "issue message",
			CreationDate: "2024-01-01T00:00:00+0000",
			UpdateDate:   "2024-01-01T00:00:00+0000",
			Type:         "CODE_SMELL",
			Line:         &line,
		}
		result := createResultFromIssue(issue, componentMap)
		assert.Contains(t, result.CodeDesc, "src/Main.java")
	})

	t.Run("component with only LongName uses LongName", func(t *testing.T) {
		componentMap := map[string]Component{
			"comp:key": {Key: "comp:key", LongName: "com.example.Main"},
		}
		issue := Issue{
			Component:    "comp:key",
			Rule:         "java:S001",
			Severity:     "MAJOR",
			Status:       "OPEN",
			Message:      "issue message",
			CreationDate: "2024-01-01T00:00:00+0000",
			UpdateDate:   "2024-01-01T00:00:00+0000",
			Type:         "CODE_SMELL",
		}
		result := createResultFromIssue(issue, componentMap)
		assert.Contains(t, result.CodeDesc, "com.example.Main")
	})

	t.Run("component not in map uses issue Component key", func(t *testing.T) {
		componentMap := map[string]Component{}
		issue := Issue{
			Component:    "unknown:component",
			Rule:         "java:S001",
			Severity:     "MAJOR",
			Status:       "OPEN",
			Message:      "issue message",
			CreationDate: "2024-01-01T00:00:00+0000",
			UpdateDate:   "2024-01-01T00:00:00+0000",
			Type:         "CODE_SMELL",
		}
		result := createResultFromIssue(issue, componentMap)
		assert.Contains(t, result.CodeDesc, "unknown:component")
	})
}

func TestExtractTags_KeyValueParsing(t *testing.T) {
	rule := &Rule{
		Key:     "java:S001",
		Name:    "Test Rule",
		Tags:    []string{"cwe-476", "owasp:a01", "category:security", "category:reliability"},
		SysTags: []string{},
	}

	cweIds, owaspTags, allTags := extractTags(rule, true, []Issue{})

	assert.NotEmpty(t, cweIds, "expected at least one CWE ID extracted")
	assert.NotEmpty(t, owaspTags, "expected at least one OWASP tag extracted")

	_, ok := allTags["category"]
	assert.True(t, ok, "expected 'category' key in allTags")
	assert.Len(t, allTags["category"], 2)
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "sonarqube-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertSonarqubeToHDF(input, testConverterVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvertSonarqubeToHDF_MissingIssuesField(t *testing.T) {
	input := []byte(`{"total": 0}`)
	_, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.Error(t, err)
	assert.Equal(t, "invalid SonarQube structure: missing or invalid issues field", err.Error())
}

func TestConvertSonarqubeToHDF_EmptyIssues(t *testing.T) {
	fixturePath := filepath.Join(shared.GetConvertersDir(), "sonarqube-to-hdf", "fixtures", "input", "empty.json")
	input, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "sonarqube-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "SonarQube")
	assert.Contains(t, req.Results[0].CodeDesc, "com.example:myproject")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertSonarqubeToHDF_SeverityMapImpact(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	var blockerRule, majorRule *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		switch baseline.Requirements[i].ID {
		case "java:S2259":
			blockerRule = &baseline.Requirements[i]
		case "java:S1144":
			majorRule = &baseline.Requirements[i]
		}
	}

	require.NotNil(t, blockerRule, "expected rule java:S2259")
	assert.Equal(t, 1.0, blockerRule.Impact, "BLOCKER should have impact 1.0")

	require.NotNil(t, majorRule, "expected rule java:S1144")
	assert.Equal(t, 0.5, majorRule.Impact, "MAJOR should have impact 0.5")
}

func TestConvertSonarqubeToHDF_ExtractCWETags(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	var ruleWithCwe *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "java:S2259" {
			ruleWithCwe = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, ruleWithCwe, "expected rule java:S2259")

	cweTag, ok := ruleWithCwe.Tags["cwe"]
	require.True(t, ok, "expected 'cwe' tag")

	cweSlice, ok := cweTag.([]string)
	require.True(t, ok, "expected cwe to be []string, got %T", cweTag)
	require.NotEmpty(t, cweSlice)

	assert.Contains(t, cweSlice, "CWE-476")
}

func TestConvertSonarqubeToHDF_CreateResultsPerIssue(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.NotEmpty(t, req.Results, "requirement %s should have results", req.ID)
		for _, res := range req.Results {
			assert.NotEmpty(t, res.Status, "result status should not be empty")
			assert.NotEmpty(t, res.CodeDesc, "result codeDesc should not be empty")
		}
	}
}

func TestSonarTimestampFormat_ParsesCorrectly(t *testing.T) {
	// Verify our format constant parses SonarQube timestamps correctly
	ts, err := time.Parse(sonarTimestampFormat, "2026-01-15T10:30:00+0000")
	require.NoError(t, err, "sonarTimestampFormat must parse +0000 timezone format")
	assert.False(t, ts.IsZero())
	assert.Equal(t, 2026, ts.Year())
	assert.Equal(t, time.January, ts.Month())
	assert.Equal(t, 15, ts.Day())
}

func TestMapCWEToNIST_FallsBackWhenNoCWE(t *testing.T) {
	// No CWE IDs → fall back to SA-11 for all issue types
	nist := shared.MapCWEToNIST([]string{}, []string{"SA-11"})
	assert.Equal(t, []string{"SA-11"}, nist)
}

func TestMapCWEToNIST_UsesCWEWhenAvailable(t *testing.T) {
	// CWE-476 → SI-10 (from cwe-nist-mappings.json)
	nist := shared.MapCWEToNIST([]string{"CWE-476"}, []string{"SA-11"})
	assert.Contains(t, nist, "SI-10", "CWE-476 should produce SI-10")
}

func TestMapCWEToNIST_UnknownCWEFallsBack(t *testing.T) {
	// Unknown CWE with no mapping → fall back to SA-11
	nist := shared.MapCWEToNIST([]string{"CWE-999999"}, []string{"SA-11"})
	assert.Equal(t, []string{"SA-11"}, nist)
}

func TestExtractTags_ParsesCWEFromDescription(t *testing.T) {
	rule := &Rule{
		Name:     "Test Rule",
		HTMLDesc: "<p>Related to CWE-476.</p>",
	}
	cweIds, _, _ := extractTags(rule, true, []Issue{})
	assert.Contains(t, cweIds, "CWE-476")
}

func TestConvertSonarqubeToHDF_NistContainsString(t *testing.T) {
	// Verify nist tags are []string (not []interface{}) when accessing directly
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		nistVal, ok := req.Tags["nist"]
		require.True(t, ok, "expected nist tag in requirement %s", req.ID)
		_, isStrSlice := nistVal.([]string)
		assert.True(t, isStrSlice, "nist tag should be []string in requirement %s, got %T", req.ID, nistVal)
	}
}

func TestMapSeverityToImpact(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	var blockerRule *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "java:S2259" {
			blockerRule = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, blockerRule)
	assert.Equal(t, 1.0, blockerRule.Impact)

	var majorRule *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "java:S1144" {
			majorRule = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, majorRule)
	assert.Equal(t, 0.5, majorRule.Impact)
}

func TestConvertSonarqubeToHDF_CWETagsAreStringSlice(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	var ruleWithCwe *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "java:S2259" {
			ruleWithCwe = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, ruleWithCwe)

	cweTag, ok := ruleWithCwe.Tags["cwe"]
	require.True(t, ok)
	_, isStrSlice := cweTag.([]string)
	assert.True(t, isStrSlice, "cwe tag should be []string, got %T", cweTag)

	if isStrSlice {
		hasCWE476 := false
		for _, cweStr := range cweTag.([]string) {
			if cweStr == "CWE-476" {
				hasCWE476 = true
				break
			}
		}
		assert.True(t, hasCWE476)
	}
}

func TestConvertSonarqubeToHDF_NoStringsImportNeeded(t *testing.T) {
	// Regression test: 'strings' package used in converter logic
	input := []byte(`{
		"total": 1, "p": 1, "ps": 100,
		"paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
		"issues": [{"key":"k1","rule":"r:VULNERABILITY","severity":"CRITICAL","component":"proj:file","project":"proj","status":"OPEN","message":"msg","creationDate":"2026-01-01T00:00:00+0000","updateDate":"2026-01-01T00:00:00+0000","type":"VULNERABILITY"}],
		"components": [], "rules": []
	}`)

	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	req := result.Baselines[0].Requirements[0]
	severityTag, ok := req.Tags["severity"]
	require.True(t, ok)
	// Severity tag should be lowercased
	assert.Equal(t, "critical", severityTag.(string))
}

func TestSeverityImpactMappingParity(t *testing.T) {
	// Authoritative mapping from heimdall2 sonarqube-mapper.ts IMPACT_MAPPING.
	// This test ensures our Go mapping stays in sync with the canonical source.
	// Uses the shared SeverityToImpactWithAliases function with sonarqubeAliases.
	expected := map[string]float64{
		"BLOCKER":  1.0,
		"CRITICAL": 0.7,
		"MAJOR":    0.5,
		"MINOR":    0.3,
		"INFO":     0.0,
	}
	for sev, impact := range expected {
		actual := hdfutil.SeverityToImpactWithAliases(sev, sonarqubeAliases, 0.5)
		assert.Equal(t, impact, actual, "Severity %s impact mismatch", sev)
	}
}

// ---- SonarQube 26+ tests (descriptionSections format) ----

func loadSQ26Fixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := filepath.Join(shared.GetConvertersDir(), "sonarqube-to-hdf", "fixtures", "input", "sq26-with-sections.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read sq26-with-sections.json fixture")
	return data
}

func TestExtractTags_CWEFromDescriptionSections(t *testing.T) {
	// SQ 26 format: no tags/sysTags with CWE numbers, but descriptionSections
	// contain CWE references in HTML content
	rule := &Rule{
		Name:    "Credentials rule",
		Tags:    []string{},
		SysTags: []string{"cwe"},
		DescriptionSections: []DescriptionSection{
			{
				Key:     "resources",
				Content: `<ul><li>CWE - <a href="https://cwe.mitre.org/data/definitions/798">CWE-798 - Use of Hard-coded Credentials</a></li></ul>`,
			},
			{
				Key:     "root_cause",
				Content: "<p>Trust boundaries are violated when a secret is exposed.</p>",
			},
		},
	}

	cweIds, _, _ := extractTags(rule, true, []Issue{})
	assert.Contains(t, cweIds, "CWE-798", "should extract CWE-798 from descriptionSections")
}

func TestExtractTags_CWEFromDescriptionSections_MultipleCWEs(t *testing.T) {
	rule := &Rule{
		Name:    "Multi-CWE rule",
		Tags:    []string{},
		SysTags: []string{"cwe"},
		DescriptionSections: []DescriptionSection{
			{
				Key:     "resources",
				Content: `<ul><li>CWE - <a href="https://cwe.mitre.org/data/definitions/798">CWE-798</a></li><li>CWE - <a href="https://cwe.mitre.org/data/definitions/259">CWE-259</a></li></ul>`,
			},
		},
	}

	cweIds, _, _ := extractTags(rule, true, []Issue{})
	assert.Contains(t, cweIds, "CWE-798")
	assert.Contains(t, cweIds, "CWE-259")
	assert.Len(t, cweIds, 2, "should extract exactly 2 CWE IDs")
}

func TestExtractDescription_FallsBackToDescriptionSections(t *testing.T) {
	t.Run("prefers root_cause section", func(t *testing.T) {
		rule := &Rule{
			Name: "Test rule",
			DescriptionSections: []DescriptionSection{
				{Key: "resources", Content: "<p>Some resources</p>"},
				{Key: "root_cause", Content: "<p>Trust boundaries are violated.</p>"},
			},
		}
		result := extractDescription(rule, true)
		assert.Contains(t, result, "Trust boundaries are violated")
		assert.NotContains(t, result, "<p>")
	})

	t.Run("concatenates sections when no root_cause", func(t *testing.T) {
		rule := &Rule{
			Name: "Test rule",
			DescriptionSections: []DescriptionSection{
				{Key: "resources", Content: "<p>Resource info</p>"},
				{Key: "how_to_fix", Content: "<p>Fix it</p>"},
			},
		}
		result := extractDescription(rule, true)
		assert.Contains(t, result, "Resource info")
		assert.Contains(t, result, "Fix it")
	})

	t.Run("does not use descriptionSections when htmlDesc present", func(t *testing.T) {
		rule := &Rule{
			Name:     "Test rule",
			HTMLDesc: "<p>HTML description</p>",
			DescriptionSections: []DescriptionSection{
				{Key: "root_cause", Content: "<p>Section description</p>"},
			},
		}
		result := extractDescription(rule, true)
		assert.Contains(t, result, "HTML description")
		assert.NotContains(t, result, "Section description")
	})
}

func TestConvertSonarqubeToHDF_ControlType(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

// countDistinctSonarqubeProjectRules walks the raw SonarQube document —
// deliberately NOT the converter's structs — and returns the number of distinct
// (project, rule) pairs across issues[]. The converter double-groups: issues by
// project into baselines, then by rule into requirements, so the emission unit
// is one requirement per distinct (project, rule) pair. A plain issues count
// overshoots whenever two issues share both project and rule.
func countDistinctSonarqubeProjectRules(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Issues []struct {
			Project string `json:"project"`
			Rule    string `json:"rule"`
		} `json:"issues"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "failed to parse SonarQube JSON for anchor count")
	distinct := make(map[[2]string]struct{})
	for _, i := range doc.Issues {
		distinct[[2]string{i.Project, i.Rule}] = struct{}{}
	}
	return len(distinct)
}

// Ground-truth anchor: the converter emits one requirement per distinct
// (project, rule) pair. The count is derived independently of the converter's
// parser, so a silent under-extraction (e.g. dropping a rule group) fails even
// when Go/TS golden parity agrees.
func TestConvertSonarqubeToHDF_ProjectRuleAnchor(t *testing.T) {
	input := loadMQRFixture(t)
	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countDistinctSonarqubeProjectRules(t, input),
		"mqr.json: one requirement per distinct (project, rule) pair")
}

// Backfilled source metadata: effort/debt/author (per-issue), lang/langName
// (per-rule), and cleanCodeAttributeCategory (MQR-only, alongside the existing
// cleanCodeAttribute). Values pinned against the mqr.json fixture.
func TestConvertSonarqubeToHDF_MetadataTags(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMQRFixture(t), testConverterVersion)
	require.NoError(t, err)

	var req *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "java:S1186" {
			req = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, req, "java:S1186 requirement not found")

	assert.Equal(t, "5min", req.Tags["effort"], "effort should be pinned from the issue")
	assert.Equal(t, "5min", req.Tags["debt"], "debt should be pinned from the issue")
	assert.Equal(t, "dev@example.com", req.Tags["author"], "author should be pinned from the issue")
	assert.Equal(t, "java", req.Tags["lang"], "lang should be pinned from the rule")
	assert.Equal(t, "Java", req.Tags["langName"], "langName should be pinned from the rule")
	assert.Equal(t, "INTENTIONAL", req.Tags["cleanCodeAttributeCategory"],
		"cleanCodeAttributeCategory should be pinned in MQR mode")
	// The existing cleanCodeAttribute tag must remain untouched.
	assert.Equal(t, "COMPLETE", req.Tags["cleanCodeAttribute"])
}

// The absent branches: author is empty in minimal.json (legacy mode) so its tag
// is omitted, and cleanCodeAttributeCategory is only emitted in MQR mode.
func TestConvertSonarqubeToHDF_MetadataTags_AbsentBranches(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.NotContains(t, req.Tags, "author",
			"requirement %q should omit author when the issue carries none", req.ID)
		assert.NotContains(t, req.Tags, "cleanCodeAttributeCategory",
			"requirement %q should omit cleanCodeAttributeCategory in legacy mode", req.ID)
		// effort/debt/lang/langName are present in the minimal fixture.
		assert.Equal(t, "java", req.Tags["lang"], "lang should still resolve in legacy mode for %q", req.ID)
		assert.Equal(t, "Java", req.Tags["langName"], "langName should still resolve in legacy mode for %q", req.ID)
	}

	var s1144 *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "java:S1144" {
			s1144 = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, s1144)
	assert.Equal(t, "5min", s1144.Tags["effort"])
	assert.Equal(t, "5min", s1144.Tags["debt"])
}

// lang/langName are dropped when the rule is not present in the rules[] lookup.
func TestConvertSonarqubeToHDF_LangOmittedWithoutRule(t *testing.T) {
	input := []byte(`{
		"total": 1, "p": 1, "ps": 100,
		"paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
		"issues": [{"key":"k1","rule":"unknown:rule","severity":"MAJOR","component":"proj:file","project":"proj","status":"OPEN","message":"msg","effort":"3min","creationDate":"2026-01-01T00:00:00+0000","updateDate":"2026-01-01T00:00:00+0000","type":"CODE_SMELL"}],
		"components": [], "rules": []
	}`)

	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.NotContains(t, req.Tags, "lang", "lang should be omitted when the rule is unknown")
	assert.NotContains(t, req.Tags, "langName", "langName should be omitted when the rule is unknown")
	assert.Equal(t, "3min", req.Tags["effort"], "effort still resolves from the issue")
}

// Auxiliary per-issue metadata is emitted under the tool-named namespace
// (sonarqube/hash, /key, /update_date, /flows, /quick_fix_available). Values
// pinned against mqr.json, which carries every field.
func TestConvertSonarqubeToHDF_AuxMetadataTags(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMQRFixture(t), testConverterVersion)
	require.NoError(t, err)

	reqByID := func(id string) *hdf.EvaluatedRequirement {
		for i := range result.Baselines[0].Requirements {
			if result.Baselines[0].Requirements[i].ID == id {
				return &result.Baselines[0].Requirements[i]
			}
		}
		return nil
	}

	// java:S1186: hash/key/update_date present, quick_fix_available true, no flows.
	s1186 := reqByID("java:S1186")
	require.NotNil(t, s1186, "java:S1186 requirement not found")
	assert.Equal(t, "4fa436e830f0433a248778dafd40f373", s1186.Tags["sonarqube/hash"])
	assert.Equal(t, "02e8e9bf-5d42-4729-a087-8b7e56e0e908", s1186.Tags["sonarqube/key"])
	assert.Equal(t, "2026-03-24T03:20:30+0000", s1186.Tags["sonarqube/update_date"])
	assert.Equal(t, true, s1186.Tags["sonarqube/quick_fix_available"])
	assert.NotContains(t, s1186.Tags, "sonarqube/flows",
		"java:S1186 first issue has empty flows, so the tag is omitted")

	// java:S1192: quick_fix_available false, and flows carries secondary locations.
	s1192 := reqByID("java:S1192")
	require.NotNil(t, s1192, "java:S1192 requirement not found")
	assert.Equal(t, false, s1192.Tags["sonarqube/quick_fix_available"],
		"explicit false must be preserved (pointer distinguishes it from absent)")
	require.Contains(t, s1192.Tags, "sonarqube/flows")
	var flows []map[string]interface{}
	require.NoError(t, json.Unmarshal(s1192.Tags["sonarqube/flows"].(json.RawMessage), &flows))
	assert.Len(t, flows, 3, "java:S1192 first issue carries three flow entries")
}

// The absent branches: minimal.json carries hash/key/update_date but no flows
// and no quickFixAvailable, so those two tags must be omitted on every rule.
func TestConvertSonarqubeToHDF_AuxMetadataTags_AbsentBranches(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Contains(t, req.Tags, "sonarqube/hash",
			"minimal.json carries hash for %q", req.ID)
		assert.Contains(t, req.Tags, "sonarqube/key", "minimal.json carries key for %q", req.ID)
		assert.Contains(t, req.Tags, "sonarqube/update_date",
			"minimal.json carries updateDate for %q", req.ID)
		assert.NotContains(t, req.Tags, "sonarqube/flows",
			"minimal.json carries no flows for %q", req.ID)
		assert.NotContains(t, req.Tags, "sonarqube/quick_fix_available",
			"minimal.json carries no quickFixAvailable for %q", req.ID)
	}
}

// An issue carrying none of the auxiliary fields must emit none of the tags.
func TestConvertSonarqubeToHDF_AuxMetadataTags_AllAbsent(t *testing.T) {
	input := []byte(`{
		"total": 1, "p": 1, "ps": 100,
		"paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
		"issues": [{"rule":"java:S100","severity":"MAJOR","component":"proj:file","project":"proj","status":"OPEN","message":"msg","creationDate":"2026-01-01T00:00:00+0000","type":"CODE_SMELL"}],
		"components": [], "rules": []
	}`)

	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	for _, key := range []string{"sonarqube/hash", "sonarqube/key", "sonarqube/update_date", "sonarqube/flows", "sonarqube/quick_fix_available"} {
		assert.NotContains(t, req.Tags, key, "%s must be omitted when the issue carries no aux metadata", key)
	}
}

// An explicit empty flows array is treated as "no flows" and the tag stays off.
func TestConvertSonarqubeToHDF_AuxMetadataTags_EmptyFlows(t *testing.T) {
	input := []byte(`{
		"total": 1, "p": 1, "ps": 100,
		"paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
		"issues": [{"key":"k1","rule":"java:S100","severity":"MAJOR","component":"proj:file","project":"proj","status":"OPEN","message":"msg","flows":[],"quickFixAvailable":false,"creationDate":"2026-01-01T00:00:00+0000","type":"CODE_SMELL"}],
		"components": [], "rules": []
	}`)

	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.NotContains(t, req.Tags, "sonarqube/flows", "empty flows array must not emit the tag")
	assert.Equal(t, false, req.Tags["sonarqube/quick_fix_available"],
		"explicit false quickFixAvailable is still emitted")
}

func TestSnapshots(t *testing.T) {
	// SonarQube issues carry no scan time; conversion-time fallback.
	shared.RunSnapshotTests(t, "sonarqube-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSonarqubeToHDF(input, "1.0.0")
	}, "*")
}

func TestConvert_SQ26Format(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadSQ26Fixture(t), testConverterVersion)
	require.NoError(t, err, "SQ 26 fixture conversion should succeed")
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1, "should have 1 project baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "juice-shop", baseline.Name)
	require.Len(t, baseline.Requirements, 3, "should have 3 requirements (one per rule)")

	// Build a map for easier lookup
	reqMap := make(map[string]*hdf.EvaluatedRequirement)
	for i := range baseline.Requirements {
		reqMap[baseline.Requirements[i].ID] = &baseline.Requirements[i]
	}

	// secrets:S6706 should have CWE-798 and CWE-259 extracted from descriptionSections
	secretsReq := reqMap["secrets:S6706"]
	require.NotNil(t, secretsReq, "expected secrets:S6706 requirement")

	cweVal, ok := secretsReq.Tags["cwe"]
	require.True(t, ok, "expected 'cwe' tag on secrets:S6706")
	cweSlice, ok := cweVal.([]string)
	require.True(t, ok, "cwe tag should be []string")
	assert.Contains(t, cweSlice, "CWE-798", "should extract CWE-798 from descriptionSections")
	assert.Contains(t, cweSlice, "CWE-259", "should extract CWE-259 from descriptionSections")

	// NIST should be derived from CWE mappings, not the SA-11 default
	nistVal, ok := secretsReq.Tags["nist"]
	require.True(t, ok, "expected 'nist' tag on secrets:S6706")
	nistSlice, ok := nistVal.([]string)
	require.True(t, ok, "nist tag should be []string")
	assert.NotEmpty(t, nistSlice, "NIST controls should be populated from CWE mappings")

	// typescript:S7790 should have CWE-20
	tsReq := reqMap["typescript:S7790"]
	require.NotNil(t, tsReq, "expected typescript:S7790 requirement")

	cweTsVal, ok := tsReq.Tags["cwe"]
	require.True(t, ok, "expected 'cwe' tag on typescript:S7790")
	cweTsSlice, ok := cweTsVal.([]string)
	require.True(t, ok, "cwe tag should be []string")
	assert.Contains(t, cweTsSlice, "CWE-20", "should extract CWE-20 from descriptionSections")

	// Web:MouseEventWithoutKeyboardEquivalentCheck should have no CWE
	webReq := reqMap["Web:MouseEventWithoutKeyboardEquivalentCheck"]
	require.NotNil(t, webReq, "expected Web rule requirement")

	cweWebVal, ok := webReq.Tags["cwe"]
	require.True(t, ok, "expected 'cwe' tag on Web rule")
	cweWebSlice, ok := cweWebVal.([]string)
	require.True(t, ok, "cwe tag should be []string")
	assert.Empty(t, cweWebSlice, "Web rule should have no CWE IDs")

	// Web rule should get default SA-11 NIST tag
	nistWebVal, ok := webReq.Tags["nist"]
	require.True(t, ok)
	nistWebSlice, ok := nistWebVal.([]string)
	require.True(t, ok)
	assert.Contains(t, nistWebSlice, "SA-11", "Web rule without CWE should get SA-11 default")

	// Verify descriptions come from descriptionSections
	assert.NotEmpty(t, secretsReq.Descriptions, "should have descriptions")
	desc := secretsReq.Descriptions[0].Data
	assert.Contains(t, desc, "trust boundaries", "description should come from root_cause section")
	assert.NotContains(t, desc, "<p>", "description should be stripped of HTML")
}

func TestConvertSonarqubeToHDF_VerificationMethod(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
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

// ---- MQR (Multi-Quality-Rule / Clean Code) severity tests ----

func loadMQRFixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := filepath.Join(shared.GetConvertersDir(), "sonarqube-to-hdf", "fixtures", "input", "mqr.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read mqr.json fixture")
	return data
}

// In MQR mode the software-quality severity is authoritative — the legacy
// severity must not leak into tags.severity or the impact score.
func TestConvertSonarqubeToHDF_MQRSeverityDrivesSeverityTag(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMQRFixture(t), testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	severityByRule := make(map[string]string)
	impactByRule := make(map[string]float64)
	for _, req := range result.Baselines[0].Requirements {
		severityByRule[req.ID] = req.Tags["severity"].(string)
		impactByRule[req.ID] = req.Impact
	}

	// java:S1186 is legacy CRITICAL but MQR HIGH; java:S1068 is legacy MAJOR but MQR MEDIUM.
	assert.Equal(t, "high", severityByRule["java:S1186"], "MQR HIGH must win over legacy CRITICAL")
	assert.Equal(t, "medium", severityByRule["java:S1068"], "MQR MEDIUM must win over legacy MAJOR")
	assert.Equal(t, "low", severityByRule["java:S1128"], "MQR LOW must win over legacy MINOR")
	assert.Equal(t, "info", severityByRule["java:S1135"])

	assert.Equal(t, 0.7, impactByRule["java:S1186"], "MQR HIGH → 0.7")
	assert.Equal(t, 0.5, impactByRule["java:S1068"], "MQR MEDIUM → 0.5")
	assert.Equal(t, 0.3, impactByRule["java:S1128"], "MQR LOW → 0.3")
	assert.Equal(t, 0.0, impactByRule["java:S1135"], "MQR INFO → 0.0")

	for id, sev := range severityByRule {
		assert.NotContains(t, []string{"critical", "major", "minor"}, sev,
			"requirement %q emitted a legacy-axis severity %q in MQR mode", id, sev)
	}
}

// Both axes are preserved so consumers can select, and severitySource states
// which axis drove severity/impact.
func TestConvertSonarqubeToHDF_MQRPreservesBothAxes(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMQRFixture(t), testConverterVersion)
	require.NoError(t, err)

	var req *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "java:S1186" {
			req = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, req, "java:S1186 requirement not found")

	assert.Equal(t, "mqr", req.Tags["severitySource"])
	assert.Equal(t, "critical", req.Tags["legacySeverity"], "legacy axis must remain available")
	assert.Equal(t, "high", req.Tags["severity"])

	impacts, ok := req.Tags["impacts"].([]Impact)
	require.True(t, ok, "impacts tag should preserve the per-quality MQR array")
	require.NotEmpty(t, impacts)
	assert.Equal(t, "MAINTAINABILITY", impacts[0].SoftwareQuality)
	assert.Equal(t, "HIGH", impacts[0].Severity)
}

// Pre-MQR servers emit no impacts[]; the legacy axis must still drive severity.
func TestConvertSonarqubeToHDF_LegacyFallbackWhenNoImpacts(t *testing.T) {
	result, err := ConvertSonarqubeToHDF(loadMinimalFixture(t), testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, "legacy", req.Tags["severitySource"],
			"requirement %q should report the legacy axis when impacts[] is absent", req.ID)
		assert.NotContains(t, req.Tags, "impacts", "no impacts tag without MQR data")
	}

	severityByRule := make(map[string]string)
	for _, req := range result.Baselines[0].Requirements {
		severityByRule[req.ID] = req.Tags["severity"].(string)
	}
	assert.Equal(t, "major", severityByRule["java:S1144"])
	assert.Equal(t, "blocker", severityByRule["java:S2259"])
}

// Real SonarQube output whose rules rank-diverge across the two axes: every rule
// here is legacy MINOR, yet MQR rates several of them MEDIUM. Reading the legacy
// axis under-rates them, and no global relabelling could recover the MQR value.
func TestConvertSonarqubeToHDF_MQRDivergentAxes(t *testing.T) {
	fixturePath := filepath.Join(shared.GetConvertersDir(), "sonarqube-to-hdf", "fixtures", "input", "mqr-divergent.json")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	result, err := ConvertSonarqubeToHDF(data, testConverterVersion)
	require.NoError(t, err)

	type got struct {
		severity string
		legacy   string
		impact   float64
	}
	byRule := make(map[string]got)
	for _, req := range result.Baselines[0].Requirements {
		byRule[req.ID] = got{
			severity: req.Tags["severity"].(string),
			legacy:   req.Tags["legacySeverity"].(string),
			impact:   req.Impact,
		}
	}

	// Legacy MINOR (0.3) but MQR MEDIUM (0.5) — the old converter under-rated these.
	for _, rule := range []string{"typescript:S7772", "javascript:S7772", "typescript:S7776"} {
		assert.Equal(t, "medium", byRule[rule].severity, "%s should take the MQR severity", rule)
		assert.Equal(t, "minor", byRule[rule].legacy, "%s legacy axis should still be MINOR", rule)
		assert.Equal(t, 0.5, byRule[rule].impact, "%s impact should follow MQR MEDIUM", rule)
	}

	// S7773 is rated on two qualities (MAINTAINABILITY=LOW, RELIABILITY=MEDIUM).
	// The worst rating governs, so naively taking impacts[0] would under-rate it.
	assert.Equal(t, "medium", byRule["typescript:S7773"].severity,
		"multi-impact issue should take the highest severity, not the first")
	assert.Equal(t, 0.5, byRule["typescript:S7773"].impact)

	// A rule where the axes happen to agree still resolves via the MQR axis.
	assert.Equal(t, "high", byRule["go:S3776"].severity)
	assert.Equal(t, "critical", byRule["go:S3776"].legacy)
	assert.Equal(t, 0.7, byRule["go:S3776"].impact)
}

// The legacy→MQR relationship is per-rule, not a constant offset: a rule can be
// legacy MAJOR yet MQR LOW (over-rated) or legacy MAJOR yet MQR HIGH (under-rated).
func TestSelectSeverity_DivergentAxes(t *testing.T) {
	tests := []struct {
		name         string
		issue        Issue
		wantSeverity string
		wantSource   string
		wantImpact   float64
	}{
		{
			name:         "legacy MAJOR but MQR LOW (HDF previously over-rated)",
			issue:        Issue{Severity: "MAJOR", Impacts: []Impact{{SoftwareQuality: "MAINTAINABILITY", Severity: "LOW"}}},
			wantSeverity: "LOW", wantSource: severitySourceMQR, wantImpact: 0.3,
		},
		{
			name:         "legacy MAJOR but MQR HIGH (HDF previously under-rated)",
			issue:        Issue{Severity: "MAJOR", Impacts: []Impact{{SoftwareQuality: "SECURITY", Severity: "HIGH"}}},
			wantSeverity: "HIGH", wantSource: severitySourceMQR, wantImpact: 0.7,
		},
		{
			name:         "legacy CRITICAL but MQR MEDIUM",
			issue:        Issue{Severity: "CRITICAL", Impacts: []Impact{{SoftwareQuality: "MAINTAINABILITY", Severity: "MEDIUM"}}},
			wantSeverity: "MEDIUM", wantSource: severitySourceMQR, wantImpact: 0.5,
		},
		{
			name:         "MQR BLOCKER",
			issue:        Issue{Severity: "MAJOR", Impacts: []Impact{{SoftwareQuality: "SECURITY", Severity: "BLOCKER"}}},
			wantSeverity: "BLOCKER", wantSource: severitySourceMQR, wantImpact: 1.0,
		},
		{
			name: "multiple impacts take the highest severity",
			issue: Issue{Severity: "MINOR", Impacts: []Impact{
				{SoftwareQuality: "MAINTAINABILITY", Severity: "LOW"},
				{SoftwareQuality: "SECURITY", Severity: "HIGH"},
				{SoftwareQuality: "RELIABILITY", Severity: "MEDIUM"},
			}},
			wantSeverity: "HIGH", wantSource: severitySourceMQR, wantImpact: 0.7,
		},
		{
			name:         "no impacts falls back to legacy",
			issue:        Issue{Severity: "CRITICAL"},
			wantSeverity: "CRITICAL", wantSource: severitySourceLegacy, wantImpact: 0.7,
		},
		{
			name:         "empty impacts array falls back to legacy",
			issue:        Issue{Severity: "BLOCKER", Impacts: []Impact{}},
			wantSeverity: "BLOCKER", wantSource: severitySourceLegacy, wantImpact: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity, source := selectSeverity(tt.issue)
			assert.Equal(t, tt.wantSeverity, severity)
			assert.Equal(t, tt.wantSource, source)
			assert.Equal(t, tt.wantImpact, severityToImpactScore(severity, source))
		})
	}
}
