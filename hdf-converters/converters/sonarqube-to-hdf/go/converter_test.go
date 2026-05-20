package sonarqube

import (
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
	input := []byte(`{
		"total": 0, "p": 1, "ps": 100,
		"paging": {"pageIndex": 1, "pageSize": 100, "total": 0},
		"issues": [], "components": [], "rules": []
	}`)

	result, err := ConvertSonarqubeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.Empty(t, result.Baselines, "Expected 0 baselines for empty issues")
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

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "sonarqube-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSonarqubeToHDF(input, "0.1.0")
	})
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
