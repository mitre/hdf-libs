package cyclonedx_to_hdf

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

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
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
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

// ---- Impact from CVSS score ----

func TestConvertCycloneDX_ImpactFromCVSSScore(t *testing.T) {
	// vex.json has ratings with scores: 7.5, 8.2, 0.0
	// max CVSS score = 8.2, impact = 8.2 / 10 = 0.82
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")
	assert.InDelta(t, 0.82, req.Impact, 0.001)
}

// ---- Impact from severity string ----

func TestConvertCycloneDX_Severity(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// low → 0.3
	low := shared.MustFindRequirement(t, reqs, "GHSA-5mg8-w23w-74h3")
	assert.InDelta(t, 0.3, low.Impact, 0.001)

	// medium → 0.5
	medium := shared.MustFindRequirement(t, reqs, "GHSA-7g45-4rm6-3mm3")
	assert.InDelta(t, 0.5, medium.Impact, 0.001)

	// critical → 0.9
	critical := shared.MustFindRequirement(t, reqs, "GHSA-5p34-5m6p-p58g")
	assert.InDelta(t, 0.9, critical.Impact, 0.001)
}

// ---- CWE → NIST mapping ----

func TestConvertCycloneDX_CweToNist(t *testing.T) {
	// vex.json has cwes: [611]
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")

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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")

	// nist
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.NotEmpty(t, nist)

	// cci
	cciSlice := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cciSlice)
	assert.NotEmpty(t, cciSlice)

	// The old freetext scoring tags moved to structured fields.
	assert.NotContains(t, req.Tags, "cweid", "cweid moved to requirement.cwe[]")
	assert.NotContains(t, req.Tags, "ratings", "ratings moved to requirement.cvss[]")
}

// ---- Structured CVSS ----

func TestConvertCycloneDX_Cvss(t *testing.T) {
	// vex.json has 3 CVSSv31 ratings: NVD 7.5, SNYK 8.2, Acme Inc 0.0, each with
	// a base vector.
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")
	require.Len(t, req.Cvss, 3)

	// entry 0: NVD 7.5 → high, v3.1, vector preserved
	require.NotNil(t, req.Cvss[0].BaseScore)
	assert.InDelta(t, 7.5, *req.Cvss[0].BaseScore, 0.001)
	require.NotNil(t, req.Cvss[0].BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityHigh, *req.Cvss[0].BaseSeverity)
	assert.Equal(t, hdf.The31, req.Cvss[0].Version)
	require.NotNil(t, req.Cvss[0].BaseVector)
	assert.Equal(t, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", *req.Cvss[0].BaseVector)
	require.NotNil(t, req.Cvss[0].Source)
	assert.Equal(t, "NVD", *req.Cvss[0].Source)

	// entry 1: SNYK 8.2 → high
	require.NotNil(t, req.Cvss[1].BaseScore)
	assert.InDelta(t, 8.2, *req.Cvss[1].BaseScore, 0.001)
	require.NotNil(t, req.Cvss[1].Source)
	assert.Equal(t, "SNYK", *req.Cvss[1].Source)

	// entry 2: Acme Inc 0.0 → none band
	require.NotNil(t, req.Cvss[2].BaseScore)
	assert.InDelta(t, 0.0, *req.Cvss[2].BaseScore, 0.001)
	require.NotNil(t, req.Cvss[2].BaseSeverity)
	assert.Equal(t, hdf.None, *req.Cvss[2].BaseSeverity)
}

func TestConvertCycloneDX_NoCvssWhenNoScore(t *testing.T) {
	// minimal-vulns.json ratings use method "other" with only a severity — no
	// CVSS score/vector, so no cvss[] entries are emitted.
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Empty(t, req.Cvss, "vuln %s has no CVSS metrics → cvss[] omitted", req.ID)
	}
}

func TestConvertCycloneDX_CvssVectorOnlyNoSource(t *testing.T) {
	// A CVSS-method rating carrying a vector but no score and no source: still an
	// entry (vector present), version defaults to 3.1, source omitted.
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "TEST-VECTOR-ONLY",
			"ratings": [{"method": "CVSSv3", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Cvss, 1)
	assert.Nil(t, req.Cvss[0].BaseScore, "no score supplied")
	assert.Nil(t, req.Cvss[0].Source, "no source supplied")
	assert.Equal(t, hdf.The31, req.Cvss[0].Version)
	require.NotNil(t, req.Cvss[0].BaseVector)
	assert.Equal(t, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", *req.Cvss[0].BaseVector)
}

// ---- Structured CWE ----

func TestConvertCycloneDX_Cwe(t *testing.T) {
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")
	assert.Equal(t, []string{"CWE-611"}, req.Cwe)

	// The CWE→NIST mapping is retained.
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	assert.NotEmpty(t, nist)
}

func TestConvertCycloneDX_CweMulti(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "GHSA-5mg8-w23w-74h3")
	assert.Equal(t, []string{"CWE-173", "CWE-200", "CWE-378", "CWE-732"}, req.Cwe)
}

func TestConvertCycloneDX_NoCweWhenAbsent(t *testing.T) {
	// A vulnerability with no cwes[] → requirement.cwe[] omitted.
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "TEST-NO-CWE",
			"ratings": [{"severity": "high"}],
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Empty(t, result.Baselines[0].Requirements[0].Cwe)
}

// ---- Result code_desc ----

func TestConvertCycloneDX_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	// GHSA-5mg8-w23w-74h3 affects guava (com.google.guava/guava@24.1.1-jre)
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "GHSA-5mg8-w23w-74h3")
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")

	desc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, desc, "expected a 'fix' description")
	assert.Contains(t, desc.Data, "Upgrade")
}

func TestConvertCycloneDX_DefaultDescription(t *testing.T) {
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.Contains(t, desc.Data, "jackson-databind")
	assert.Contains(t, desc.Data, "XXE Injection")
}

// ---- External references (refs[]) ----

func refURLs(refs []hdf.Reference) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.URL != nil {
			out = append(out, *r.URL)
		}
	}
	return out
}

func TestConvertCycloneDX_Refs(t *testing.T) {
	// vex.json carries all three link sources: source.url, references[].source.url,
	// and advisories[].url. Emitted de-duplicated in first-seen order.
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")
	assert.Equal(t, []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2020-25649",
		"https://security.snyk.io/vuln/SNYK-JAVA-COMFASTERXMLJACKSONCORE-1048302",
		"https://github.com/FasterXML/jackson-databind/commit/612f971b78c60202e9cd75a299050c8f2d724a59",
		"https://github.com/FasterXML/jackson-databind/issues/2589",
		"https://bugzilla.redhat.com/show_bug.cgi?id=1887664",
	}, refURLs(req.Refs))
}

func TestConvertCycloneDX_RefsSourceURLOnly(t *testing.T) {
	// minimal-vulns.json carries only vuln.source.url (no references/advisories).
	input := loadFixture(t, "input/minimal-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "GHSA-5mg8-w23w-74h3")
	assert.Equal(t, []string{"https://github.com/advisories"}, refURLs(req.Refs))
}

func TestConvertCycloneDX_RefsAbsent(t *testing.T) {
	// A vulnerability with no source, references, or advisories → refs[] omitted.
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "TEST-NO-REFS",
			"ratings": [{"severity": "high"}],
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Nil(t, result.Baselines[0].Requirements[0].Refs)
}

func TestConvertCycloneDX_RefsDedupAndSkip(t *testing.T) {
	// Exercises de-dup (source.url repeated as an advisory url), the empty-url
	// skip, and a reference entry with no source.
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "TEST-DEDUP",
			"source": {"name": "NVD", "url": "https://example.com/a"},
			"references": [
				{"id": "REF-NO-SOURCE"},
				{"id": "REF-1", "source": {"name": "SNYK", "url": "https://example.com/b"}}
			],
			"advisories": [
				{"title": "dup", "url": "https://example.com/a"},
				{"title": "empty", "url": ""},
				{"title": "new", "url": "https://example.com/c"}
			],
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"https://example.com/a",
		"https://example.com/b",
		"https://example.com/c",
	}, refURLs(result.Baselines[0].Requirements[0].Refs))
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
	// vex.json carries no metadata.timestamp, so its startTime is synthesized
	// (conversion time); mask only it. The SBOM fixtures derive startTime from
	// metadata.timestamp and are asserted.
	shared.RunSnapshotTests(t, "cyclonedx-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertCycloneDXToHDF(input, "1.0.0")
	}, "vex.json")
}

// Ground-truth anchor: the converter emits one requirement per BOM
// vulnerabilities[] entry (no grouping/dedup). The array count is derived
// independently of the converter's parser, so a silent under-extraction fails
// even when Go/TS golden parity agrees. dropwizard-vulns.json carries 87
// vulnerabilities.
func TestConvertCycloneDX_VulnerabilityAnchor(t *testing.T) {
	input := loadFixture(t, "input/dropwizard-vulns.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "vulnerabilities"),
		"dropwizard-vulns.json: one requirement per vulnerabilities[]")
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

// ---- VEX analysis → structured status override ----

func TestConvertCycloneDX_VEXAnalysisOverride(t *testing.T) {
	// vex.json carries analysis.state "not_affected", justification
	// "code_not_reachable", response [will_not_fix, update]. That reconstructs a
	// falsePositive override: raw stays Failed, effectiveStatus becomes
	// notApplicable (a vuln scan), with the attributed, expiring override present.
	input := loadFixture(t, "input/vex.json")
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2020-25649")

	// raw result unchanged
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Failed, req.Results[0].Status, "raw result stays failed")

	// effective status + disposition flipped
	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.NotApplicable, *req.EffectiveStatus)
	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.FalsePositive, *req.Disposition)

	// structured override
	require.Len(t, req.StatusOverrides, 1)
	ov := req.StatusOverrides[0]
	assert.Equal(t, hdf.FalsePositive, ov.Type)
	require.NotNil(t, ov.Status)
	assert.Equal(t, hdf.NotApplicable, *ov.Status)
	assert.Equal(t, "cyclonedx analysis", ov.AppliedBy.Identifier)
	assert.Equal(t, hdf.IdentityTypeOther, ov.AppliedBy.Type)
	require.NotNil(t, ov.Justification)
	assert.Equal(t, hdf.VulnerableCodeNotInExecutePath, *ov.Justification)
	assert.Contains(t, ov.Reason, "vulnerable code is not reachable")
	assert.Contains(t, ov.Reason, "Response: will_not_fix, update")

	// appliedAt derived from the vuln updated time; expiresAt = +1 year.
	assert.Equal(t, "2021-10-26T00:00:00Z", ov.AppliedAt.UTC().Format(time.RFC3339))
	assert.Equal(t, "2022-10-26T00:00:00Z", ov.ExpiresAt.UTC().Format(time.RFC3339))
}

func TestConvertCycloneDX_VEXResolvedAttestation(t *testing.T) {
	// A resolved (remediated) VEX state reconstructs an attestation override:
	// effectiveStatus passed, raw stays Failed.
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [{
			"id": "CVE-RESOLVED",
			"ratings": [{"severity": "high"}],
			"published": "2023-01-15T00:00:00Z",
			"analysis": {"state": "resolved", "detail": "Patched in 2.1.0"},
			"affects": [{"ref": "comp-1"}]
		}],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.Passed, *req.EffectiveStatus)
	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.Attestation, *req.Disposition)
	require.Len(t, req.StatusOverrides, 1)
	assert.Equal(t, hdf.Attestation, req.StatusOverrides[0].Type)
	assert.Equal(t, "Patched in 2.1.0", req.StatusOverrides[0].Reason)
	assert.Nil(t, req.StatusOverrides[0].Justification, "no justification supplied")
	assert.Equal(t, "2023-01-15T00:00:00Z", req.StatusOverrides[0].AppliedAt.UTC().Format(time.RFC3339))
}

func TestConvertCycloneDX_VEXNoOverrideBranches(t *testing.T) {
	// exploitable / in_triage / no-analysis leave the finding actionable: raw
	// Failed, no override, no effectiveStatus/disposition.
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"vulnerabilities": [
			{"id": "CVE-EXPLOIT", "ratings": [{"severity": "high"}], "analysis": {"state": "exploitable", "detail": "reachable"}, "affects": [{"ref": "comp-1"}]},
			{"id": "CVE-TRIAGE", "ratings": [{"severity": "high"}], "analysis": {"state": "in_triage"}, "affects": [{"ref": "comp-1"}]},
			{"id": "CVE-NONE", "ratings": [{"severity": "high"}], "affects": [{"ref": "comp-1"}]}
		],
		"components": [{"type": "library", "name": "test-lib", "bom-ref": "comp-1"}]
	}`)
	result, err := ConvertCycloneDXToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, hdf.Failed, req.Results[0].Status, "%s raw status", req.ID)
		assert.Empty(t, req.StatusOverrides, "%s gets no override", req.ID)
		assert.Nil(t, req.EffectiveStatus, "%s effectiveStatus unset", req.ID)
		assert.Nil(t, req.Disposition, "%s disposition unset", req.ID)
	}
}

func TestVexJustificationMapping(t *testing.T) {
	cases := map[string]*hdf.Justification{
		"code_not_present":                ptrJ(hdf.VulnerableCodeNotPresent),
		"code_not_reachable":              ptrJ(hdf.VulnerableCodeNotInExecutePath),
		"requires_configuration":          ptrJ(hdf.RequiresConfiguration),
		"requires_dependency":             ptrJ(hdf.RequiresDependency),
		"requires_environment":            ptrJ(hdf.RequiresEnvironment),
		"protected_by_compiler":           ptrJ(hdf.ProtectedByCompiler),
		"protected_at_runtime":            ptrJ(hdf.ProtectedAtRuntime),
		"protected_at_perimeter":          ptrJ(hdf.ProtectedAtPerimeter),
		"protected_by_mitigating_control": ptrJ(hdf.InlineMitigationsAlreadyExist),
		"":                                nil,
		"some_future_value":               nil,
	}
	for in, want := range cases {
		got := vexJustification(in)
		if want == nil {
			assert.Nil(t, got, "justification %q", in)
			continue
		}
		require.NotNil(t, got, "justification %q", in)
		assert.Equal(t, *want, *got, "justification %q", in)
	}
}

func ptrJ(j hdf.Justification) *hdf.Justification { return &j }

func TestCvssVersionFromMethod(t *testing.T) {
	cases := []struct {
		name   string
		method string
		vector string
		want   hdf.Version
	}{
		{"v2 bare vector rescued by method", "CVSSv2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", hdf.The20},
		{"v4 bare vector rescued by method", "CVSSv4", "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", hdf.The40},
		{"prefixed vector wins over method (3.0)", "CVSSv31", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", hdf.The30},
		{"prefixed vector wins over method (3.1)", "CVSSv3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", hdf.The31},
		{"prefixless v3 keeps 3.1 default", "CVSSv3", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", hdf.The31},
		{"v31 no vector defaults", "CVSSv31", "", hdf.The31},
		{"empty method and vector defaults", "", "", hdf.The31},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, cvssVersionFromMethod(c.method, c.vector))
		})
	}
}
