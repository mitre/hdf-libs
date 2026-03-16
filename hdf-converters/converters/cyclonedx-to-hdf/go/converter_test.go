package cyclonedx_to_hdf

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConvertCycloneDX_EmptyInput(t *testing.T) {
	_, err := ConvertCycloneDXToHDF([]byte(""), testVersion)
	assert.Error(t, err)
}

func TestConvertCycloneDX_InvalidJSON(t *testing.T) {
	_, err := ConvertCycloneDXToHDF([]byte("not json"), testVersion)
	assert.Error(t, err)
}

func TestConvertCycloneDX_MissingBomFormat(t *testing.T) {
	_, err := ConvertCycloneDXToHDF([]byte(`{"specVersion":"1.5"}`), testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bomFormat")
}

func TestConvertCycloneDX_MissingComponentsAndVulns(t *testing.T) {
	_, err := ConvertCycloneDXToHDF([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`), testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "neither components nor vulnerabilities")
}

// ---- Minimal fixture: baseline structure ----

func TestConvertCycloneDX_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// minimal-vulns.json has 3 vulnerabilities
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertCycloneDX_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "CycloneDX Scan", result.Baselines[0].Name)
}

func TestConvertCycloneDX_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertCycloneDX_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "cyclonedx-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- DataSource ----

func TestConvertCycloneDX_DataSource(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.DataSource)
	require.NotNil(t, result.DataSource.Name)
	assert.Equal(t, "CycloneDX", *result.DataSource.Name)
	require.NotNil(t, result.DataSource.Format)
	assert.Equal(t, "JSON", *result.DataSource.Format)
}

// ---- Impact from CVSS score ----

func TestConvertCycloneDX_ImpactFromCVSSScore(t *testing.T) {
	// vex.json has ratings with scores: 7.5, 8.2, 0.0
	// max CVSS score = 8.2, impact = 8.2 / 10 = 0.82
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "CVE-2020-25649")
	require.NotNil(t, req)
	assert.InDelta(t, 0.82, req.Impact, 0.001)
}

// ---- Impact from severity string ----

func TestConvertCycloneDX_Severity(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// low → 0.3
	low := findRequirement(reqs, "GHSA-5mg8-w23w-74h3")
	require.NotNil(t, low, "expected low vuln GHSA-5mg8-w23w-74h3")
	assert.InDelta(t, 0.3, low.Impact, 0.001)

	// medium → 0.5
	medium := findRequirement(reqs, "GHSA-7g45-4rm6-3mm3")
	require.NotNil(t, medium, "expected medium vuln GHSA-7g45-4rm6-3mm3")
	assert.InDelta(t, 0.5, medium.Impact, 0.001)

	// critical → 0.9
	critical := findRequirement(reqs, "GHSA-5p34-5m6p-p58g")
	require.NotNil(t, critical, "expected critical vuln GHSA-5p34-5m6p-p58g")
	assert.InDelta(t, 0.9, critical.Impact, 0.001)
}

// ---- CWE → NIST mapping ----

func TestConvertCycloneDX_CweToNist(t *testing.T) {
	// vex.json has cwes: [611]
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "CVE-2020-25649")
	require.NotNil(t, req)

	nist := shared.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
}

func TestConvertCycloneDX_FallbackNist(t *testing.T) {
	// CWE 99999 has no mapping → should fall back to defaults
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "TEST-NO-MAPPING",
			"ratings": [{"severity": "high"}],
			"cwes": [99999],
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	nist := shared.SafeStringSlice(result.Baselines[0].Requirements[0].Tags["nist"])
	require.NotNil(t, nist)
	assert.Contains(t, nist, "SA-11")
	assert.Contains(t, nist, "RA-5")
}

// ---- Tags ----

func TestConvertCycloneDX_Tags(t *testing.T) {
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "CVE-2020-25649")
	require.NotNil(t, req)

	// nist
	nist := shared.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.NotEmpty(t, nist)

	// cci
	cciSlice := shared.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cciSlice)
	assert.NotEmpty(t, cciSlice)

	// cweid
	cweid, ok := req.Tags["cweid"].([]string)
	require.True(t, ok)
	assert.Contains(t, cweid, "CWE-611")

	// ratings
	ratings, ok := req.Tags["ratings"].(string)
	require.True(t, ok)
	assert.Contains(t, ratings, "NVD - high")
}

// ---- Result code_desc ----

func TestConvertCycloneDX_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	// GHSA-5mg8-w23w-74h3 affects guava (com.google.guava/guava@24.1.1-jre)
	req := findRequirement(result.Baselines[0].Requirements, "GHSA-5mg8-w23w-74h3")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Results)
	assert.Contains(t, req.Results[0].CodeDesc, "com.google.guava/guava@24.1.1-jre")
	assert.Contains(t, req.Results[0].CodeDesc, "is vulnerable")
}

func TestConvertCycloneDX_CodeDescNoGroup(t *testing.T) {
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "TEST-NO-GROUP",
			"ratings": [{"severity": "high"}],
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "bare-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Component bare-lib is vulnerable", result.Baselines[0].Requirements[0].Results[0].CodeDesc)
}

// ---- Result status ----

func TestConvertCycloneDX_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all CycloneDX vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- Info/unknown severity skip ----

func TestConvertCycloneDX_InfoUnknownSkip(t *testing.T) {
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [
			{"id": "TEST-INFO", "ratings": [{"severity": "info"}], "affects": [{"ref": "comp-1"}]},
			{"id": "TEST-UNKNOWN", "ratings": [{"severity": "unknown"}], "affects": [{"ref": "comp-1"}]}
		],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.NotReviewed, r.Status)
			require.NotNil(t, r.Message)
			assert.Contains(t, *r.Message, "Manual review required")
		}
	}
}

func TestConvertCycloneDX_MixedSeverityNotSkipped(t *testing.T) {
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "TEST-MIXED",
			"ratings": [{"severity": "info"}, {"severity": "high"}],
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, hdf.Failed, result.Baselines[0].Requirements[0].Results[0].Status)
}

// ---- No-vuln SBOM ----

func TestConvertCycloneDX_NoVulnSBOM(t *testing.T) {
	input := loadFixture(t, "input/spdx-to-cyclonedx.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 0)
}

// ---- VEX format ----

func TestConvertCycloneDX_VEX(t *testing.T) {
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	assert.Equal(t, "CVE-2020-25649", reqs[0].ID)
}

func TestConvertCycloneDX_VEXCodeDesc(t *testing.T) {
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Baselines[0].Requirements[0].Results)
	codeDesc := result.Baselines[0].Requirements[0].Results[0].CodeDesc
	assert.Contains(t, codeDesc, "is vulnerable")
}

// ---- Descriptions ----

func TestConvertCycloneDX_FixDescription(t *testing.T) {
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "CVE-2020-25649")
	require.NotNil(t, req)

	desc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, desc, "expected a 'fix' description")
	assert.Contains(t, desc.Data, "Upgrade")
}

func TestConvertCycloneDX_DefaultDescription(t *testing.T) {
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "CVE-2020-25649")
	require.NotNil(t, req)

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.Contains(t, desc.Data, "jackson-databind")
	assert.Contains(t, desc.Data, "XXE Injection")
}

// ---- Full fixture smoke test ----

func TestConvertCycloneDX_FullFixture(t *testing.T) {
	input := loadFixture(t, "input/dropwizard-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.Len(t, reqs, 87)

	// Every requirement should have at least one result
	for _, req := range reqs {
		assert.NotEmpty(t, req.Results, "requirement %s should have results", req.ID)
	}
}

// ---- Helper: severityToImpact ----

func TestSeverityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 0.9},
		{"CRITICAL", 0.9},
		{"high", 0.7},
		{"HIGH", 0.7},
		{"medium", 0.5},
		{"MEDIUM", 0.5},
		{"low", 0.3},
		{"LOW", 0.3},
		{"info", 0.0},
		{"none", 0.0},
		{"unknown", 0.5},
		{"", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, severityToImpact(tc.severity), 0.001)
		})
	}
}
