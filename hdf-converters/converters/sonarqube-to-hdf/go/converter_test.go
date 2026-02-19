package sonarqube

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-schema"
)

func TestConvertSonarqubeToHDF(t *testing.T) {
	// Load minimal fixture
	fixturePath := filepath.Join("..", "fixtures", "input", "minimal.json")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read minimal.json fixture: %v", err)
	}

	result, err := ConvertSonarqubeToHDF(input)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("Output should not be empty")
	}

	var hdfResult hdf.HDFResults
	if err := json.Unmarshal(result, &hdfResult); err != nil {
		t.Fatalf("Failed to unmarshal HDF result: %v", err)
	}

	// Verify HDF structure
	if hdfResult.Timestamp == nil {
		t.Error("Timestamp should not be nil")
	}

	if len(hdfResult.Baselines) == 0 {
		t.Error("Baselines should not be empty")
	}

	if hdfResult.Generator == nil {
		t.Error("Generator should not be nil")
	} else {
		if hdfResult.Generator.Name != "sonarqube-to-hdf" {
			t.Errorf("Expected generator name 'sonarqube-to-hdf', got '%s'", hdfResult.Generator.Name)
		}
		if hdfResult.Generator.Version != "1.0.0" {
			t.Errorf("Expected generator version '1.0.0', got '%s'", hdfResult.Generator.Version)
		}
	}
}

func TestCreateBaselinesPerProject(t *testing.T) {
	fixturePath := filepath.Join("..", "fixtures", "input", "minimal.json")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read minimal.json fixture: %v", err)
	}

	result, err := ConvertSonarqubeToHDF(input)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	var hdfResult hdf.HDFResults
	if err := json.Unmarshal(result, &hdfResult); err != nil {
		t.Fatalf("Failed to unmarshal HDF result: %v", err)
	}

	// Minimal fixture has 1 project
	if len(hdfResult.Baselines) != 1 {
		t.Errorf("Expected 1 baseline, got %d", len(hdfResult.Baselines))
	}

	baseline := hdfResult.Baselines[0]
	if baseline.Name != "com.example:myproject" {
		t.Errorf("Expected baseline name 'com.example:myproject', got '%s'", baseline.Name)
	}

	if len(baseline.Requirements) == 0 {
		t.Error("Requirements should not be empty")
	}
}

func TestCreateRequirementsPerRule(t *testing.T) {
	fixturePath := filepath.Join("..", "fixtures", "input", "minimal.json")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read minimal.json fixture: %v", err)
	}

	result, err := ConvertSonarqubeToHDF(input)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	var hdfResult hdf.HDFResults
	if err := json.Unmarshal(result, &hdfResult); err != nil {
		t.Fatalf("Failed to unmarshal HDF result: %v", err)
	}

	baseline := hdfResult.Baselines[0]

	// Minimal fixture has 2 rules
	if len(baseline.Requirements) != 2 {
		t.Errorf("Expected 2 requirements, got %d", len(baseline.Requirements))
	}

	// Collect rule IDs
	ruleIDs := make([]string, 0, len(baseline.Requirements))
	for _, req := range baseline.Requirements {
		ruleIDs = append(ruleIDs, req.ID)
	}

	// Check for expected rule IDs
	hasS1144 := false
	hasS2259 := false
	for _, id := range ruleIDs {
		if id == "java:S1144" {
			hasS1144 = true
		}
		if id == "java:S2259" {
			hasS2259 = true
		}
	}

	if !hasS1144 {
		t.Error("Expected to find rule java:S1144")
	}
	if !hasS2259 {
		t.Error("Expected to find rule java:S2259")
	}
}

func TestMapSeverityToImpact(t *testing.T) {
	fixturePath := filepath.Join("..", "fixtures", "input", "minimal.json")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read minimal.json fixture: %v", err)
	}

	result, err := ConvertSonarqubeToHDF(input)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	var hdfResult hdf.HDFResults
	if err := json.Unmarshal(result, &hdfResult); err != nil {
		t.Fatalf("Failed to unmarshal HDF result: %v", err)
	}

	baseline := hdfResult.Baselines[0]

	// Find BLOCKER severity rule (java:S2259)
	var blockerRule *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "java:S2259" {
			blockerRule = &baseline.Requirements[i]
			break
		}
	}

	if blockerRule == nil {
		t.Fatal("Expected to find rule java:S2259")
	}

	if blockerRule.Impact != 1.0 {
		t.Errorf("Expected BLOCKER impact 1.0, got %f", blockerRule.Impact)
	}

	// Find MAJOR severity rule (java:S1144)
	var majorRule *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "java:S1144" {
			majorRule = &baseline.Requirements[i]
			break
		}
	}

	if majorRule == nil {
		t.Fatal("Expected to find rule java:S1144")
	}

	if majorRule.Impact != 0.7 {
		t.Errorf("Expected MAJOR impact 0.7, got %f", majorRule.Impact)
	}
}

func TestExtractCWETags(t *testing.T) {
	fixturePath := filepath.Join("..", "fixtures", "input", "minimal.json")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read minimal.json fixture: %v", err)
	}

	result, err := ConvertSonarqubeToHDF(input)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	var hdfResult hdf.HDFResults
	if err := json.Unmarshal(result, &hdfResult); err != nil {
		t.Fatalf("Failed to unmarshal HDF result: %v", err)
	}

	baseline := hdfResult.Baselines[0]

	// Find rule with CWE tag (java:S2259 has cwe-476)
	var ruleWithCwe *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "java:S2259" {
			ruleWithCwe = &baseline.Requirements[i]
			break
		}
	}

	if ruleWithCwe == nil {
		t.Fatal("Expected to find rule java:S2259")
	}

	cweTag, ok := ruleWithCwe.Tags["cwe"]
	if !ok {
		t.Fatal("Expected 'cwe' tag to be present")
	}

	cweSlice, ok := cweTag.([]interface{})
	if !ok {
		t.Fatal("Expected 'cwe' tag to be a slice")
	}

	if len(cweSlice) == 0 {
		t.Fatal("Expected CWE tags to be present")
	}

	hasCWE476 := false
	for _, cwe := range cweSlice {
		if cweStr, ok := cwe.(string); ok && cweStr == "CWE-476" {
			hasCWE476 = true
			break
		}
	}

	if !hasCWE476 {
		t.Error("Expected to find CWE-476 in tags")
	}
}

func TestCreateResultsForEachIssue(t *testing.T) {
	fixturePath := filepath.Join("..", "fixtures", "input", "minimal.json")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read minimal.json fixture: %v", err)
	}

	result, err := ConvertSonarqubeToHDF(input)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	var hdfResult hdf.HDFResults
	if err := json.Unmarshal(result, &hdfResult); err != nil {
		t.Fatalf("Failed to unmarshal HDF result: %v", err)
	}

	baseline := hdfResult.Baselines[0]

	// Each requirement should have results
	for _, req := range baseline.Requirements {
		if len(req.Results) == 0 {
			t.Errorf("Requirement %s should have results", req.ID)
		}

		// Check result structure
		firstResult := req.Results[0]
		if firstResult.Status == "" {
			t.Error("Result status should not be empty")
		}
		if firstResult.CodeDesc == "" {
			t.Error("Result codeDesc should not be empty")
		}
	}
}

func TestInvalidJSON(t *testing.T) {
	_, err := ConvertSonarqubeToHDF([]byte("not valid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestMissingIssuesField(t *testing.T) {
	input := []byte(`{"total": 0}`)
	_, err := ConvertSonarqubeToHDF(input)
	if err == nil {
		t.Error("Expected error for missing issues field")
	}
	if err != nil && err.Error() != "invalid SonarQube structure: missing or invalid issues field" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

func TestExtractDescription(t *testing.T) {
	t.Run("rule is nil with hasRule false returns empty", func(t *testing.T) {
		result := extractDescription(nil, false)
		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})

	t.Run("hasRule false returns empty regardless of rule content", func(t *testing.T) {
		rule := &Rule{Name: "some rule", MDDesc: "some desc"}
		result := extractDescription(rule, false)
		if result != "" {
			t.Errorf("expected empty string for hasRule=false, got %q", result)
		}
	})

	t.Run("MDDesc takes priority over HTMLDesc", func(t *testing.T) {
		rule := &Rule{Name: "rule", MDDesc: "markdown desc", HTMLDesc: "<p>html desc</p>"}
		result := extractDescription(rule, true)
		if result != "markdown desc" {
			t.Errorf("expected MDDesc %q, got %q", "markdown desc", result)
		}
	})

	t.Run("HTMLDesc is stripped when MDDesc is empty", func(t *testing.T) {
		rule := &Rule{Name: "rule", HTMLDesc: "<p>This is <b>HTML</b> content</p>"}
		result := extractDescription(rule, true)
		if result == "" {
			t.Error("expected non-empty stripped text from HTMLDesc")
		}
		if strings.Contains(result, "<p>") || strings.Contains(result, "<b>") {
			t.Errorf("expected HTML tags stripped, got %q", result)
		}
		if !strings.Contains(result, "HTML") {
			t.Errorf("expected text content preserved, got %q", result)
		}
	})

	t.Run("falls back to rule name when both descs empty", func(t *testing.T) {
		rule := &Rule{Name: "fallback name"}
		result := extractDescription(rule, true)
		if result != "fallback name" {
			t.Errorf("expected rule Name %q, got %q", "fallback name", result)
		}
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
			CreationDate: "2024-01-01T00:00:00Z",
			UpdateDate:   "2024-01-01T00:00:00Z",
			Type:         "CODE_SMELL",
			Line:         &line,
		}
		result := createResultFromIssue(issue, componentMap)
		if !strings.Contains(result.CodeDesc, "src/Main.java") {
			t.Errorf("expected CodeDesc to contain Path %q, got %q", "src/Main.java", result.CodeDesc)
		}
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
			CreationDate: "2024-01-01T00:00:00Z",
			UpdateDate:   "2024-01-01T00:00:00Z",
			Type:         "CODE_SMELL",
		}
		result := createResultFromIssue(issue, componentMap)
		if !strings.Contains(result.CodeDesc, "com.example.Main") {
			t.Errorf("expected CodeDesc to use LongName %q, got %q", "com.example.Main", result.CodeDesc)
		}
	})

	t.Run("component not in map uses issue Component key", func(t *testing.T) {
		componentMap := map[string]Component{}
		issue := Issue{
			Component:    "unknown:component",
			Rule:         "java:S001",
			Severity:     "MAJOR",
			Status:       "OPEN",
			Message:      "issue message",
			CreationDate: "2024-01-01T00:00:00Z",
			UpdateDate:   "2024-01-01T00:00:00Z",
			Type:         "CODE_SMELL",
		}
		result := createResultFromIssue(issue, componentMap)
		if !strings.Contains(result.CodeDesc, "unknown:component") {
			t.Errorf("expected CodeDesc to contain issue Component %q, got %q", "unknown:component", result.CodeDesc)
		}
	})
}

func TestExtractTags_KeyValueParsing(t *testing.T) {
	// Exercises the allTagsMap nil check in the tag-splitting loop (line ~329)
	// by providing a rule with "key:value" formatted tags.
	rule := &Rule{
		Key:     "java:S001",
		Name:    "Test Rule",
		Tags:    []string{"cwe-476", "owasp:a01", "category:security", "category:reliability"},
		SysTags: []string{},
	}

	cweIds, owaspTags, allTags := extractTags(rule, true, []Issue{})

	if len(cweIds) == 0 {
		t.Error("expected at least one CWE ID extracted")
	}
	if len(owaspTags) == 0 {
		t.Error("expected at least one OWASP tag extracted")
	}
	// The "category:security" and "category:reliability" tags should produce an
	// "category" entry in allTags, exercising the allTagsMap initialization path.
	if _, ok := allTags["category"]; !ok {
		t.Error("expected 'category' key in allTags from key:value tag parsing")
	}
	categoryVals := allTags["category"]
	if len(categoryVals) != 2 {
		t.Errorf("expected 2 category values, got %d: %v", len(categoryVals), categoryVals)
	}
}

func TestEmptyIssuesArray(t *testing.T) {
	input := []byte(`{
		"total": 0,
		"p": 1,
		"ps": 100,
		"paging": {"pageIndex": 1, "pageSize": 100, "total": 0},
		"issues": [],
		"components": [],
		"rules": []
	}`)

	result, err := ConvertSonarqubeToHDF(input)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	var hdfResult hdf.HDFResults
	if err := json.Unmarshal(result, &hdfResult); err != nil {
		t.Fatalf("Failed to unmarshal HDF result: %v", err)
	}

	if len(hdfResult.Baselines) != 0 {
		t.Errorf("Expected 0 baselines for empty issues, got %d", len(hdfResult.Baselines))
	}
}
