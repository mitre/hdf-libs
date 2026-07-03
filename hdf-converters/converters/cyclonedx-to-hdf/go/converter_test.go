package cyclonedx_to_hdf

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "cyclonedx-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertCycloneDXToHDF(input, testVersion) },
		MinimalFixture: "minimal-vulns.json",
	})
}

func TestConvertCycloneDX_ControlType(t *testing.T) {
	input := loadFixture(t, "input/dropwizard-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

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

// ---- Tool ----

func TestConvertCycloneDX_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "CycloneDX", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "JSON", *result.Tool.Format)
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

	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
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

	nist := hdfutil.SafeStringSlice(result.Baselines[0].Requirements[0].Tags["nist"])
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
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.NotEmpty(t, nist)

	// cci
	cciSlice := hdfutil.SafeStringSlice(req.Tags["cci"])
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

// ---- Info/unknown severity — still Failed ----

func TestConvertCycloneDX_InfoUnknownStillFailed(t *testing.T) {
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

	// Info/unknown severity vulns are still Failed — a vuln is a finding
	// regardless of severity confidence. Impact reflects the severity.
	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status)
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

// ---- No-vuln SBOM: rejected with helpful message ----

func TestConvertCycloneDX_NoVulnSBOM_Rejected(t *testing.T) {
	input := loadFixture(t, "input/spdx-to-cyclonedx.json")
	_, err := ConvertCycloneDXToHDF(input, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SBOM inventory with no vulnerabilities")
	assert.Contains(t, err.Error(), "hdf system create <sbom-file> --component-name <name>")
	// Plain-SBOM branch must not suggest the AI-BOM path.
	assert.NotContains(t, err.Error(), "cyclonedx-mlbom")
}

func TestConvertCycloneDX_NoVulnAIBOM_Rejected(t *testing.T) {
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": [
			{"type": "machine-learning-model", "name": "stable-diffusion", "bom-ref": "model-a"}
		]
	}`)
	_, err := ConvertCycloneDXToHDF(input, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AI-BOM")
	assert.Contains(t, err.Error(), "hdf system create <file> --from cyclonedx-mlbom")
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

// ---- Component boms[] attachment (ADR-0001 Phase 3) ----

func TestConvertCycloneDX_ComponentBoms(t *testing.T) {
	// minimal-vulns.json has 2 components → boms[] carries normalized packages
	// plus the raw document passthrough.
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	boms := result.Components[0].Boms
	require.Len(t, boms, 1)
	assert.Equal(t, "sbom", boms[0].BOMType)
	assert.Equal(t, "cyclonedx", boms[0].Format)
	assert.NotEmpty(t, boms[0].Packages, "component input should yield normalized packages")
	assert.NotNil(t, boms[0].Document, "raw manifest should be carried via document passthrough")
}

func TestConvertCycloneDX_ComponentBomsVulnOnly(t *testing.T) {
	// vex.json has no components → boms[] carries the document only, no packages.
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	boms := result.Components[0].Boms
	require.Len(t, boms, 1)
	assert.Equal(t, "sbom", boms[0].BOMType)
	assert.Equal(t, "cyclonedx", boms[0].Format)
	assert.Empty(t, boms[0].Packages, "vuln-only input should carry no packages")
	assert.NotNil(t, boms[0].Document, "raw manifest should be carried via document passthrough")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "cyclonedx-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertCycloneDXToHDF(input, "0.1.0")
	})
}

func TestConvertCycloneDX_VerificationMethodNotSet(t *testing.T) {
	input := loadFixture(t, "input/dropwizard-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// CycloneDX carries both automated SBOM vuln data and human-authored VEX
	// statements; the converter cannot tell them apart, so it must not stamp
	// a verificationMethod.
	for _, req := range reqs {
		assert.Nil(t, req.VerificationMethod,
			"requirement %q: cyclonedx must not assert verificationMethod (VEX may be human-authored)", req.ID)
	}
}
