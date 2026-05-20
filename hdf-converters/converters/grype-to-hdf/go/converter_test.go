package grype_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

func TestConvertGrypeToHDF(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	// Check basic structure
	if len(hdfResults.Baselines) != 1 {
		t.Errorf("Expected 1 baseline, got %d", len(hdfResults.Baselines))
	}

	if hdfResults.Generator.Name != "grype-to-hdf" {
		t.Errorf("Expected generator name 'grype-to-hdf', got '%s'", hdfResults.Generator.Name)
	}

	if hdfResults.Generator.Version != testConverterVersion {
		t.Errorf("Expected generator version %q, got '%s'", testConverterVersion, hdfResults.Generator.Version)
	}

	// Timestamp from real Grype output: "2024-08-29T13:47:41.623667-04:00"
	expectedTime, _ := time.Parse(time.RFC3339Nano, "2024-08-29T13:47:41.623667-04:00")
	if hdfResults.Timestamp == nil || !hdfResults.Timestamp.Equal(expectedTime) {
		if hdfResults.Timestamp == nil {
			t.Error("Expected timestamp to be defined")
		} else {
			t.Errorf("Expected timestamp %q, got %q", expectedTime.Format(time.RFC3339Nano), hdfResults.Timestamp.Format(time.RFC3339Nano))
		}
	}
}

func TestConvertGrypeToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	if result.Tool == nil {
		t.Fatal("Expected Tool to be set")
	}
	if result.Tool.Name == nil || *result.Tool.Name != "Grype" {
		t.Errorf("Expected Tool.Name to be 'Grype', got %v", result.Tool.Name)
	}
	if result.Tool.Version == nil || *result.Tool.Version != "0.79.3" {
		t.Errorf("Expected Tool.Version to be '0.79.3', got %v", result.Tool.Version)
	}
	if result.Tool.Format != nil {
		t.Errorf("Expected Tool.Format to be nil, got %v", *result.Tool.Format)
	}
}

func TestBaselineName(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	if hdfResults.Baselines[0].Name != "cloudwatch_to_s3:latest" {
		t.Errorf("Expected baseline name 'cloudwatch_to_s3:latest', got '%s'", hdfResults.Baselines[0].Name)
	}
}

func TestMatchesConvertedToRequirements(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	requirements := hdfResults.Baselines[0].Requirements
	if len(requirements) != 16 {
		t.Errorf("Expected 16 requirements (16 matches), got %d", len(requirements))
	}

	// Check a Low severity match: ALAS-2024-2607 (ca-certificates)
	var alas2607 *hdf.EvaluatedRequirement
	for i := range requirements {
		if requirements[i].ID == "Grype/ALAS-2024-2607" {
			alas2607 = &requirements[i]
			break
		}
	}

	if alas2607 == nil {
		t.Fatal("Expected requirement 'Grype/ALAS-2024-2607' not found")
	}

	if alas2607.Impact != 0.3 { // Low severity
		t.Errorf("Expected impact 0.3 for Low severity, got %f", alas2607.Impact)
	}

	if len(alas2607.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(alas2607.Results))
	}

	if alas2607.Results[0].Status != hdf.Failed {
		t.Errorf("Expected status 'failed', got '%s'", alas2607.Results[0].Status)
	}

	// Check a High severity match: CVE-2024-7592 (python binary)
	var cve7592 *hdf.EvaluatedRequirement
	for i := range requirements {
		if requirements[i].ID == "Grype/CVE-2024-7592" {
			cve7592 = &requirements[i]
			break
		}
	}

	if cve7592 == nil {
		t.Fatal("Expected requirement 'Grype/CVE-2024-7592' not found")
	}

	if cve7592.Impact != 0.7 { // High severity
		t.Errorf("Expected impact 0.7 for High severity, got %f", cve7592.Impact)
	}
}

func TestIgnoredMatches(t *testing.T) {
	// Use inline fixture with ignoredMatches since the real amazon.json
	// scan has no ignored matches. Structure mirrors real Grype output.
	ignoredReport := `{
		"descriptor": {"name": "grype", "version": "0.79.3"},
		"source": {"target": {"userInput": "test-image"}},
		"matches": [],
		"ignoredMatches": [{
			"vulnerability": {
				"id": "CVE-2024-0001",
				"severity": "Low",
				"urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
				"description": "Test ignored vulnerability"
			},
			"matchDetails": [{"type": "exact-direct-match", "matcher": "rpm-matcher"}],
			"artifact": {"name": "test-pkg", "version": "1.0.0", "type": "rpm"}
		}]
	}`

	hdfResults, err := ConvertGrypeToHDF([]byte(ignoredReport), testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	requirements := hdfResults.Baselines[0].Requirements
	var ignored *hdf.EvaluatedRequirement
	for i := range requirements {
		if requirements[i].ID == "Grype-Ignored-Match/CVE-2024-0001" {
			ignored = &requirements[i]
			break
		}
	}

	if ignored == nil {
		t.Fatal("Expected ignored requirement 'Grype-Ignored-Match/CVE-2024-0001' not found")
	}

	if ignored.Results[0].Status != hdf.NotReviewed {
		t.Errorf("Expected status 'notReviewed', got '%s'", ignored.Results[0].Status)
	}

	if ignored.Results[0].Message == nil || !strings.Contains(*ignored.Results[0].Message, "ignored by configured rules") {
		t.Errorf("Expected message to contain 'ignored by configured rules'")
	}
}

func TestNISTAndCCITags(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	req := hdfResults.Baselines[0].Requirements[0]

	if req.Tags == nil {
		t.Fatal("Expected tags to be defined")
	}

	nistVal, hasNist := req.Tags["nist"]
	switch {
	case !hasNist:
		t.Error("Expected NIST tags to be defined")
	default:
		nistSlice, ok := nistVal.([]interface{})
		switch {
		case !ok:
			t.Error("Expected NIST tags to be a slice")
		case len(nistSlice) == 0:
			t.Error("Expected NIST tags to be non-empty")
		case len(nistSlice) != 2:
			t.Errorf("Expected 2 NIST tags, got %d", len(nistSlice))
		}
	}

	// CCI tags should be present — SA-11 maps to CCI-003173, RA-5 maps to CCI-001643
	cciVal, hasCci := req.Tags["cci"]
	if !hasCci {
		t.Fatal("Expected CCI tags to be present for SA-11 and RA-5")
	}
	cciSlice, ok := cciVal.([]interface{})
	if !ok {
		t.Fatal("Expected CCI tags to be a slice")
	}
	if len(cciSlice) != 2 {
		t.Errorf("Expected 2 CCI tags, got %d", len(cciSlice))
	}
	// NISTToCCI returns sorted results
	expectedCCIs := []string{"CCI-001643", "CCI-003173"}
	for i, expected := range expectedCCIs {
		if i < len(cciSlice) {
			if cciSlice[i] != expected {
				t.Errorf("Expected CCI tag %q at index %d, got %q", expected, i, cciSlice[i])
			}
		}
	}
}

func TestDescriptions(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)

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
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)

	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	// First match (ALAS-2024-2607) has URLs including the ALAS advisory URL
	req := hdfResults.Baselines[0].Requirements[0]

	if len(req.Refs) == 0 {
		t.Error("Expected references to be defined and non-empty")
	}
}

func TestChecksumCalculation(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)

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

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "grype-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertGrypeToHDF(input, testConverterVersion) },
		MinimalFixture: "amazon.json",
	})
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

func TestGetCVSSInfo_EmptyVulnerability(t *testing.T) {
	// getCVSSInfo with no CVSS data should return valid JSON
	vuln := GrypeVulnerability{}
	result := getCVSSInfo(vuln, nil)
	if !json.Valid([]byte(result)) {
		t.Errorf("getCVSSInfo should return valid JSON for empty vulnerability, got: %s", result)
	}
}

func TestGetCVSSInfo_WithCVSSData(t *testing.T) {
	vuln := GrypeVulnerability{
		ID: "CVE-2024-1234",
		CVSS: []GrypeCVSS{
			{
				Version: "3.1",
				Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Metrics: &CVSSMetrics{BaseScore: 9.8},
			},
		},
	}
	related := []GrypeRelatedVulnerability{
		{
			ID:         "CVE-2024-1234",
			DataSource: "https://nvd.nist.gov",
			CVSS: []GrypeCVSS{
				{
					Version: "2.0",
					Vector:  "AV:N/AC:L/Au:N/C:C/I:C/A:C",
					Metrics: &CVSSMetrics{BaseScore: 10.0},
				},
			},
		},
	}

	result := getCVSSInfo(vuln, related)
	if !json.Valid([]byte(result)) {
		t.Errorf("getCVSSInfo should return valid JSON, got: %s", result)
	}

	// Verify that the JSON contains both primary and related data
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Failed to parse getCVSSInfo result: %v", err)
	}
	if _, ok := parsed["primary"]; !ok {
		t.Error("Expected 'primary' key in CVSS info")
	}
	if _, ok := parsed["related"]; !ok {
		t.Error("Expected 'related' key in CVSS info")
	}
}

func TestGetCVSSInfo_NilRelated(t *testing.T) {
	vuln := GrypeVulnerability{
		CVSS: []GrypeCVSS{},
	}
	result := getCVSSInfo(vuln, nil)
	if !json.Valid([]byte(result)) {
		t.Errorf("getCVSSInfo should return valid JSON for nil related vulns, got: %s", result)
	}
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

	hdfResults, err := ConvertGrypeToHDF([]byte(minimalReport), testConverterVersion)
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

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "grype-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertGrypeToHDF(input, "0.1.0")
	})
}

func TestConvertGrypeToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	reqs := result.Baselines[0].Requirements
	if len(reqs) == 0 {
		t.Fatal("expected at least one requirement")
	}

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
	if sawDerivation {
		t.Error("grype uses static-fallback NIST only; controlType must be omitted per helper gate")
	}
}

func TestConvertGrypeToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	if len(result.Baselines) == 0 {
		t.Fatal("expected at least one baseline")
	}
	reqs := result.Baselines[0].Requirements
	if len(reqs) == 0 {
		t.Fatal("expected at least one requirement")
	}

	for _, req := range reqs {
		if req.VerificationMethod == nil {
			t.Errorf("requirement %q is missing verificationMethod", req.ID)
			continue
		}
		if *req.VerificationMethod != hdf.VerificationMethodEnumAutomated {
			t.Errorf("requirement %q has verificationMethod %q, want automated",
				req.ID, *req.VerificationMethod)
		}
	}
}
