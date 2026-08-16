package grype_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

	// Real Grype output "2024-08-29T13:47:41.623667-04:00" is normalized by
	// hdfutil.ParseTimestamp to canonical UTC at millisecond precision.
	expectedTime, _ := time.Parse(time.RFC3339Nano, "2024-08-29T17:47:41.623Z")
	if hdfResults.Timestamp == nil || !hdfResults.Timestamp.Equal(expectedTime) {
		if hdfResults.Timestamp == nil {
			t.Error("Expected timestamp to be defined")
		} else {
			t.Errorf("Expected timestamp %q, got %q", expectedTime.Format(time.RFC3339Nano), hdfResults.Timestamp.Format(time.RFC3339Nano))
		}
	}
}

// Grype carries no literal source snippet, so requirement.code holds the raw
// match object serialized as indented JSON. Pin that it is set and round-trips
// byte-structurally back to the source match (Heimdall CODE-tab fidelity).
func TestConvertGrypeToHDF_RequirementCode(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	var raw struct {
		Matches []json.RawMessage `json:"matches"`
	}
	if err := json.Unmarshal(input, &raw); err != nil {
		t.Fatalf("Failed to parse fixture: %v", err)
	}

	reqs := hdfResults.Baselines[0].Requirements
	if len(reqs) != len(raw.Matches) {
		t.Fatalf("Expected %d requirements, got %d", len(raw.Matches), len(reqs))
	}

	for i, req := range reqs {
		if req.Code == nil {
			t.Fatalf("requirement %d: Code is nil; Heimdall CODE tab would be empty", i)
		}
		var got, want interface{}
		if err := json.Unmarshal([]byte(*req.Code), &got); err != nil {
			t.Fatalf("requirement %d: Code is not valid JSON: %v", i, err)
		}
		if err := json.Unmarshal(raw.Matches[i], &want); err != nil {
			t.Fatalf("match %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("requirement %d: Code does not round-trip to source match object", i)
		}
	}
}

func TestConvertGrypeToHDF_TitleAndStartTime(t *testing.T) {
	input := loadFixture(t, "input/amazon.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	req := hdfResults.Baselines[0].Requirements[0]

	// Title names the CVE and the scan target (parity with heimdall2's grype mapper).
	if req.Title == nil ||
		!strings.HasPrefix(*req.Title, "Grype found a vulnerability to ") ||
		!strings.HasSuffix(*req.Title, " in cloudwatch_to_s3:latest") {
		t.Errorf("unexpected title: %v", req.Title)
	}

	// Result start_time is anchored to the scan timestamp, not Go zero time.
	want, _ := time.Parse(time.RFC3339Nano, "2024-08-29T17:47:41.623Z")
	if got := req.Results[0].StartTime; !got.Equal(want) {
		t.Errorf("expected result start_time %q, got %q", want, got)
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
	alas2607 := shared.MustFindRequirement(t, requirements, "Grype/ALAS-2024-2607")

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
	cve7592 := shared.MustFindRequirement(t, requirements, "Grype/CVE-2024-7592")

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
	ignored := shared.MustFindRequirement(t, requirements, "Grype-Ignored-Match/CVE-2024-0001")

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

	reqs := hdfResults.Baselines[0].Requirements
	if len(reqs) != 1 {
		t.Fatalf("Expected 1 synthesized placeholder requirement, got %d", len(reqs))
	}
	if reqs[0].ID != "grype-no-findings" {
		t.Errorf("Expected placeholder id 'grype-no-findings', got %q", reqs[0].ID)
	}
	if reqs[0].Results[0].Status != hdf.Passed {
		t.Errorf("Expected placeholder status 'passed', got %q", reqs[0].Results[0].Status)
	}
	if !strings.Contains(reqs[0].Results[0].CodeDesc, "Grype") || !strings.Contains(reqs[0].Results[0].CodeDesc, "test-image") {
		t.Errorf("Expected codeDesc to mention Grype and the target, got %q", reqs[0].Results[0].CodeDesc)
	}
}

func TestEmptyFixtureSynthesizesPlaceholder(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	hdfResults, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}

	if len(hdfResults.Baselines) != 1 {
		t.Fatalf("Expected 1 baseline, got %d", len(hdfResults.Baselines))
	}
	reqs := hdfResults.Baselines[0].Requirements
	if len(reqs) != 1 {
		t.Fatalf("Expected exactly 1 synthesized placeholder, got %d", len(reqs))
	}
	if reqs[0].ID != "grype-no-findings" {
		t.Errorf("Expected id 'grype-no-findings', got %q", reqs[0].ID)
	}
	if reqs[0].Results[0].Status != hdf.Passed {
		t.Errorf("Expected status 'passed', got %q", reqs[0].Results[0].Status)
	}
	if !strings.Contains(reqs[0].Results[0].CodeDesc, "Grype") {
		t.Errorf("Expected codeDesc to contain 'Grype', got %q", reqs[0].Results[0].CodeDesc)
	}
	if !strings.Contains(reqs[0].Results[0].CodeDesc, "alpine:3.20") {
		t.Errorf("Expected codeDesc to contain target 'alpine:3.20', got %q", reqs[0].Results[0].CodeDesc)
	}
}

func TestSnapshots(t *testing.T) {
	// grype output carries no scan time (zero-time sentinel).
	shared.RunSnapshotTests(t, "grype-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertGrypeToHDF(input, "1.0.0")
	}, "*")
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

// Ground-truth anchor: Grype emits one requirement per matches[] entry (plus
// ignoredMatches[], which anchore_grype.json has none of). The count is derived
// generically from the raw JSON, independent of the converter's structs, so a
// silent under-extraction fails even where TS/Go golden parity would agree.
func TestConvertGrypeToHDF_MatchesAnchor(t *testing.T) {
	input := loadFixture(t, "input/anchore_grype.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "matches"),
		"anchore_grype.json: one requirement per matches[] (no ignoredMatches)")
}

func TestBuildCvssEntries_MissingMetrics(t *testing.T) {
	vuln := GrypeVulnerability{
		ID: "CVE-2021-0001",
		CVSS: []GrypeCVSS{
			{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, // metrics absent
			{Version: "3.1"}, // neither score nor vector -> dropped
			{Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", Metrics: &CVSSMetrics{BaseScore: 3.4}},
		},
	}
	got := buildCvssEntries(vuln)
	if len(got) != 2 {
		t.Fatalf("expected 2 cvss entries (neither-score-nor-vector dropped), got %d", len(got))
	}
	if got[0].BaseScore != nil {
		t.Errorf("metrics-less entry must omit baseScore, got %v", *got[0].BaseScore)
	}
	if got[0].BaseSeverity != nil {
		t.Errorf("metrics-less entry must omit baseSeverity")
	}
	if got[0].BaseVector == nil {
		t.Errorf("metrics-less entry must preserve baseVector")
	}
	if got[1].BaseScore == nil || *got[1].BaseScore != 3.4 {
		t.Errorf("entry with metrics must keep baseScore 3.4, got %v", got[1].BaseScore)
	}
}

// Pins the containerImage component surfaced from source.target + distro for an
// image scan. anchore_grype.json carries repoDigests, imageID, manifestDigest,
// architecture and an alpine distro.
func TestConvertGrypeToHDF_ContainerImageComponent(t *testing.T) {
	input := loadFixture(t, "input/anchore_grype.json")
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	if len(result.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(result.Components))
	}
	c := result.Components[0]

	if c.Type != hdf.ContainerImage {
		t.Errorf("component Type = %q, want containerImage", c.Type)
	}
	const wantRepoDigest = "golang@sha256:3f8e3ad3e7c128d29ac3004ac8314967c5ddbfa5bfa7caa59b0de493fc01686a"
	if c.Name != wantRepoDigest {
		t.Errorf("component Name = %q, want first repoDigest %q", c.Name, wantRepoDigest)
	}
	if c.ImageID == nil || *c.ImageID != "sha256:9d993b748f324b8291a4f202c2bc07b3485f7b9c7c799ee8925f657a760749cd" {
		t.Errorf("component ImageID = %v, want the source imageID", c.ImageID)
	}
	if c.Image == nil || *c.Image != wantRepoDigest {
		t.Errorf("component Image = %v, want repoDigest", c.Image)
	}
	if c.OSName == nil || *c.OSName != "alpine" {
		t.Errorf("component OSName = %v, want alpine", c.OSName)
	}
	if c.OSVersion == nil || *c.OSVersion != "3.11.3" {
		t.Errorf("component OSVersion = %v, want 3.11.3", c.OSVersion)
	}
	if len(c.Integrity) != 1 {
		t.Fatalf("expected 1 integrity checksum, got %d", len(c.Integrity))
	}
	if c.Integrity[0].Algorithm != hdf.Sha256 {
		t.Errorf("integrity algorithm = %q, want sha256", c.Integrity[0].Algorithm)
	}
	// manifestDigest with the "sha256:" prefix stripped.
	if want := "5b6d42c254b9928b3cbc541bbcd52c6e91b239d2246e8e6f9825246980ed1664"; c.Integrity[0].Value != want {
		t.Errorf("integrity value = %q, want stripped manifestDigest %q", c.Integrity[0].Value, want)
	}
	if c.Labels["architecture"] != "arm64" {
		t.Errorf("label architecture = %q, want arm64", c.Labels["architecture"])
	}
}

// Falls back to a bare artifact component when source.target carries no image
// identity (e.g. a directory scan) — the NOT-IN-SOURCE branch.
func TestConvertGrypeToHDF_ArtifactFallbackComponent(t *testing.T) {
	input := []byte(`{"descriptor":{"name":"grype","version":"0.74.0"},"source":{"type":"directory","target":{"userInput":"dir:/app"}},"matches":[]}`)
	result, err := ConvertGrypeToHDF(input, testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	if len(result.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(result.Components))
	}
	c := result.Components[0]
	if c.Type != hdf.Artifact {
		t.Errorf("component Type = %q, want artifact", c.Type)
	}
	if c.Name != "dir:/app" {
		t.Errorf("component Name = %q, want dir:/app", c.Name)
	}
	if c.ImageID != nil || c.Image != nil || c.OSName != nil || len(c.Integrity) != 0 || len(c.Labels) != 0 {
		t.Errorf("artifact fallback must carry no image identity, got %+v", c)
	}
}

func TestConvertGrypeToHDF_Sha512ManifestDigest(t *testing.T) {
	// Regression (fpx5): a sha512 manifest digest must be labeled sha512 with the
	// prefix stripped, not mislabeled as sha256 with the "sha512:" prefix retained.
	report := `{"matches":[],"source":{"target":{"userInput":"img","manifestDigest":"sha512:deadbeef"}},"descriptor":{"name":"grype","version":"0.1.0"}}`
	res, err := ConvertGrypeToHDF([]byte(report), testConverterVersion)
	if err != nil {
		t.Fatalf("Conversion failed: %v", err)
	}
	if len(res.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(res.Components))
	}
	ck := res.Components[0].Integrity
	if len(ck) != 1 {
		t.Fatalf("expected 1 integrity checksum, got %d", len(ck))
	}
	if ck[0].Algorithm != hdf.Sha512 {
		t.Errorf("expected sha512 algorithm, got %q", ck[0].Algorithm)
	}
	if ck[0].Value != "deadbeef" {
		t.Errorf("expected value 'deadbeef' (prefix stripped), got %q", ck[0].Value)
	}
}
