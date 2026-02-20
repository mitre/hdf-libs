package anchore_grype_to_hdf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-schema"
)

const testConverterVersion = "test-version"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	fixturePath := filepath.Join("..", "fixtures", name)
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", name, err)
	}
	return data
}

func TestConvertAnchoreGrypeToHDF(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	// Check basic structure
	if len(hdfResults.Baselines) != 1 {
		t.Errorf("Expected 1 baseline, got %d", len(hdfResults.Baselines))
	}

	if hdfResults.Generator.Name != "anchore-grype-to-hdf" {
		t.Errorf("Expected generator name 'anchore-grype-to-hdf', got '%s'", hdfResults.Generator.Name)
	}

	if hdfResults.Generator.Version != testConverterVersion {
		t.Errorf("Expected generator version %q, got '%s'", testConverterVersion, hdfResults.Generator.Version)
	}

	expectedTime, _ := time.Parse(time.RFC3339, "2024-01-15T10:30:00Z")
	if hdfResults.Timestamp == nil || !hdfResults.Timestamp.Equal(expectedTime) {
		if hdfResults.Timestamp == nil {
			t.Error("Expected timestamp to be defined")
		} else {
			t.Errorf("Expected timestamp '2024-01-15T10:30:00Z', got '%s'", hdfResults.Timestamp.Format(time.RFC3339))
		}
	}
}

func TestBaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	if hdfResults.Baselines[0].Name != "alpine:3.18" {
		t.Errorf("Expected baseline name 'alpine:3.18', got '%s'", hdfResults.Baselines[0].Name)
	}
}

func TestMatchesConvertedToRequirements(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	requirements := hdfResults.Baselines[0].Requirements
	if len(requirements) != 3 { // 2 matches + 1 ignoredMatch
		t.Errorf("Expected 3 requirements, got %d", len(requirements))
	}

	// Check regular match
	var cve12345 *hdf.EvaluatedRequirement
	for i := range requirements {
		if requirements[i].ID == "Grype/CVE-2023-12345" {
			cve12345 = &requirements[i]
			break
		}
	}

	if cve12345 == nil {
		t.Fatal("Expected requirement 'Grype/CVE-2023-12345' not found")
	}

	if cve12345.Impact != 0.7 { // High severity
		t.Errorf("Expected impact 0.7, got %f", cve12345.Impact)
	}

	if len(cve12345.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(cve12345.Results))
	}

	if cve12345.Results[0].Status != hdf.Failed {
		t.Errorf("Expected status 'failed', got '%s'", cve12345.Results[0].Status)
	}

	// Check critical vulnerability
	var cve67890 *hdf.EvaluatedRequirement
	for i := range requirements {
		if requirements[i].ID == "Grype/CVE-2023-67890" {
			cve67890 = &requirements[i]
			break
		}
	}

	if cve67890 == nil {
		t.Fatal("Expected requirement 'Grype/CVE-2023-67890' not found")
	}

	if cve67890.Impact != 0.9 { // Critical severity
		t.Errorf("Expected impact 0.9, got %f", cve67890.Impact)
	}
}

func TestIgnoredMatches(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	requirements := hdfResults.Baselines[0].Requirements
	var ignored *hdf.EvaluatedRequirement
	for i := range requirements {
		if requirements[i].ID == "Grype-Ignored-Match/CVE-2022-99999" {
			ignored = &requirements[i]
			break
		}
	}

	if ignored == nil {
		t.Fatal("Expected ignored requirement 'Grype-Ignored-Match/CVE-2022-99999' not found")
	}

	if ignored.Results[0].Status != hdf.NotReviewed {
		t.Errorf("Expected status 'notReviewed', got '%s'", ignored.Results[0].Status)
	}

	if ignored.Results[0].Message == nil || !strings.Contains(*ignored.Results[0].Message, "ignored by configured rules") {
		t.Errorf("Expected message to contain 'ignored by configured rules'")
	}
}

func TestNISTAndCCITags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := hdfResults.Baselines[0].Requirements[0]

	if req.Tags == nil {
		t.Fatal("Expected tags to be defined")
	}

	nistVal, hasNist := req.Tags["nist"]
	if !hasNist {
		t.Error("Expected NIST tags to be defined")
	} else {
		nistSlice, ok := nistVal.([]interface{})
		if !ok {
			t.Error("Expected NIST tags to be a slice")
		} else if len(nistSlice) == 0 {
			t.Error("Expected NIST tags to be non-empty")
		} else if len(nistSlice) != 2 {
			t.Errorf("Expected 2 NIST tags, got %d", len(nistSlice))
		}
	}

	// CCI tags should be omitted when empty (SA-11 and RA-5 have no CCI mappings)
	_, hasCci := req.Tags["cci"]
	if hasCci {
		t.Error("Expected CCI tags to be omitted when there are no CCI mappings")
	}
}

func TestDescriptions(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := hdfResults.Baselines[0].Requirements[0]

	descriptions := req.Descriptions
	if len(descriptions) < 3 {
		t.Errorf("Expected at least 3 descriptions, got %d", len(descriptions))
	}

	hasDefault := false
	hasFix := false
	hasCheck := false

	for _, desc := range descriptions {
		if desc.Label == "default" {
			hasDefault = true
		}
		if desc.Label == "fix" {
			hasFix = true
		}
		if desc.Label == "check" {
			hasCheck = true
		}
	}

	if !hasDefault {
		t.Error("Expected 'default' description")
	}
	if !hasFix {
		t.Error("Expected 'fix' description")
	}
	if !hasCheck {
		t.Error("Expected 'check' description")
	}
}

func TestReferences(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := hdfResults.Baselines[0].Requirements[0]

	if len(req.Refs) == 0 {
		t.Error("Expected references to be defined and non-empty")
	}
}

func TestChecksumCalculation(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	hdfResults, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	baseline := hdfResults.Baselines[0]

	if baseline.ResultsChecksum == nil {
		t.Fatal("Expected resultsChecksum to be defined")
	}

	if baseline.ResultsChecksum.Algorithm != hdf.Sha256 {
		t.Errorf("Expected checksum algorithm 'sha256', got '%s'", baseline.ResultsChecksum.Algorithm)
	}

	// SHA256 should be 64 hex characters
	if len(baseline.ResultsChecksum.Value) != 64 {
		t.Errorf("Expected SHA256 checksum to be 64 characters, got %d", len(baseline.ResultsChecksum.Value))
	}
}

func TestInvalidJSON(t *testing.T) {
	input := []byte("not valid json")
	_, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestEmptyInput(t *testing.T) {
	input := []byte("")
	_, err := ConvertAnchoreGrypeToHDF(input, testConverterVersion)

	if err == nil {
		t.Error("Expected error for empty input")
	}
}

func TestGetVulnDescription_RelatedFallback(t *testing.T) {
	t.Run("uses primary description when available", func(t *testing.T) {
		vuln := GrypeVulnerability{
			ID:          "CVE-2023-00001",
			Description: "Primary description",
		}
		result := getDescription(vuln, nil)
		if result != "Primary description" {
			t.Errorf("expected primary description, got %q", result)
		}
	})

	t.Run("falls back to related vuln with matching ID", func(t *testing.T) {
		vuln := GrypeVulnerability{
			ID:          "CVE-2023-00001",
			Description: "",
		}
		related := []GrypeRelatedVulnerability{
			{ID: "CVE-2023-00001", Description: "Related description for same CVE"},
		}
		result := getDescription(vuln, related)
		if result != "Related description for same CVE" {
			t.Errorf("expected related description, got %q", result)
		}
	})

	t.Run("skips related vulns with different ID", func(t *testing.T) {
		vuln := GrypeVulnerability{
			ID:          "CVE-2023-00001",
			Description: "",
		}
		related := []GrypeRelatedVulnerability{
			{ID: "CVE-2023-99999", Description: "Unrelated"},
		}
		result := getDescription(vuln, related)
		// Should fall through to the default format
		if !strings.Contains(result, "CVE-2023-00001") {
			t.Errorf("expected fallback to contain CVE ID, got %q", result)
		}
	})

	t.Run("skips related vuln with empty description", func(t *testing.T) {
		vuln := GrypeVulnerability{
			ID:          "CVE-2023-00001",
			Description: "",
		}
		related := []GrypeRelatedVulnerability{
			{ID: "CVE-2023-00001", Description: ""},
		}
		result := getDescription(vuln, related)
		// Falls through because related description is empty
		if !strings.Contains(result, "CVE-2023-00001") {
			t.Errorf("expected fallback to contain CVE ID, got %q", result)
		}
	})
}

func TestMinimalReport(t *testing.T) {
	minimalReport := `{
		"descriptor": {
			"name": "grype",
			"version": "1.0.0"
		},
		"source": {
			"target": {
				"userInput": "test-image"
			}
		},
		"matches": []
	}`

	hdfResults, err := ConvertAnchoreGrypeToHDF([]byte(minimalReport), testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	if len(hdfResults.Baselines) != 1 {
		t.Errorf("Expected 1 baseline, got %d", len(hdfResults.Baselines))
	}

	if len(hdfResults.Baselines[0].Requirements) != 0 {
		t.Errorf("Expected 0 requirements, got %d", len(hdfResults.Baselines[0].Requirements))
	}
}
