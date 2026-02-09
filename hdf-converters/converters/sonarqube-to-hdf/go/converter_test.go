package sonarqube

import (
	"encoding/json"
	"os"
	"path/filepath"
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
